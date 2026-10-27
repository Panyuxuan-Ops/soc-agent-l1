"""命令行入口：demo / serve / consume / seed / trace / export。"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import httpx

from . import __version__
from .approval import ApprovalStore, create_approval_app
from .bridge import create_bridge_app
from .config import Settings
from .consumer import Consumer
from .dify_client import create_dify_runner
from .knowledge import create_knowledge_backend
from .log import configure_logging, get_logger
from .mock_dify import create_mock_dify_app
from .models import L1Output
from .prompts import DIFY_AGENT_INSTRUCTION, L1_SYSTEM_PROMPT
from .queue import create_dedup, create_queue
from .tool_schemas import FETCH_ALERTS_SCHEMA, SEARCH_KNOWLEDGE_SCHEMA
from .tool_service import ToolService
from .trace import TraceStore
from .wazuh import create_wazuh_backend

log = get_logger("cli")

DEFAULT_PORTS = {
    "bridge": 8000,
    "tools": 8001,
    "approval": 8002,
    "mock-dify": 8003,
}


def _settings(args: argparse.Namespace) -> Settings:
    settings = Settings.from_env()
    if getattr(args, "log_level", None):
        configure_logging(args.log_level)
    settings.ensure_dirs()
    return settings


def build_tools(settings: Settings) -> ToolService:
    return ToolService(settings, create_wazuh_backend(settings), create_knowledge_backend(settings))


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    settings = _settings(args)
    result = asyncio.run(run_demo(settings, limit=args.limit, llm=args.llm))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = _settings(args)
    port = args.port or DEFAULT_PORTS[args.service]
    if args.service == "tools":
        from .apps.tools_app import create_tools_app

        app = create_tools_app(settings)
    elif args.service == "approval":
        app = create_approval_app(settings)
    elif args.service == "bridge":
        queue = create_queue(settings)
        app = create_bridge_app(settings, queue)

        @app.on_event("shutdown")
        async def _close_queue() -> None:
            await queue.close()
    elif args.service == "mock-dify":
        app = create_mock_dify_app(settings)
    else:
        raise SystemExit(f"未知服务: {args.service}")
    print(f"启动 {args.service} on http://{args.host}:{port} (docs=/docs)")
    uvicorn.run(app, host=args.host, port=port, log_level=args.log_level.lower())
    return 0


async def _consume(settings: Settings) -> None:
    trace = TraceStore(settings)
    tools = build_tools(settings)
    approvals = ApprovalStore(settings, trace)
    queue = create_queue(settings)
    dify = create_dify_runner(settings, tools, trace, approvals)
    consumer = Consumer(settings, queue, dify, trace, approvals, dedup=create_dedup(settings))
    try:
        await consumer.run_forever()
    finally:
        await consumer.close()
        await tools.close()


def cmd_consume(args: argparse.Namespace) -> int:
    settings = _settings(args)
    if settings.dify_mode == "api" and not settings.dify_api_key:
        print("错误：DIFY_MODE=api 但未设置 DIFY_API_KEY", file=sys.stderr)
        return 2
    try:
        asyncio.run(_consume(settings))
    except KeyboardInterrupt:
        print("\n已停止消费者")
    return 0


async def _seed(settings: Settings, url: str, limit: int) -> int:
    path = Path(settings.project_root) / "data" / "sample_alerts.json"
    with path.open("r", encoding="utf-8") as fh:
        alerts = json.load(fh)[:limit]
    headers = {}
    if settings.bridge_token:
        headers["X-Bridge-Token"] = settings.bridge_token
    failed = 0
    async with httpx.AsyncClient(timeout=20) as client:
        for index, alert in enumerate(alerts, start=1):
            try:
                response = await client.post(url, json=alert, headers=headers)
                if response.status_code == 202:
                    data = response.json()
                    print(f"[{index}] 202 trace_id={data.get('trace_id')} alert_id={data.get('alert_id')}")
                else:
                    failed += 1
                    print(f"[{index}] {response.status_code} {response.text[:200]}")
            except httpx.HTTPError as exc:
                failed += 1
                print(f"[{index}] 连接失败: {exc}")
    if failed:
        print(f"失败 {failed} 条；请确认 bridge 已启动: python -m soc_agent serve bridge")
    return 0 if not failed else 1


def cmd_seed(args: argparse.Namespace) -> int:
    settings = _settings(args)
    url = args.url or f"http://127.0.0.1:{DEFAULT_PORTS['bridge']}/ingest/wazuh"
    return asyncio.run(_seed(settings, url, args.limit))


def cmd_stats(args: argparse.Namespace) -> int:
    settings = _settings(args)
    stats = TraceStore(settings).stats()
    print(json.dumps(stats, ensure_ascii=False, indent=2, default=str))
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    settings = _settings(args)
    trace = TraceStore(settings)
    if args.id:
        run = trace.get_run(args.id)
        if not run:
            print(f"未找到 trace: {args.id}", file=sys.stderr)
            return 1
        print(json.dumps(run, ensure_ascii=False, indent=2, default=str))
        return 0
    rows = trace.list_runs(args.limit)
    print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    settings = _settings(args)
    deleted = TraceStore(settings).prune(args.days)
    print(f"已删除 {deleted} 条过期 run")
    return 0


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"写入 {path}")


def cmd_export_schemas(args: argparse.Namespace) -> int:
    settings = _settings(args)
    out = Path(args.out or (settings.project_root / "schemas"))
    _write_json(out / "l1_output.schema.json", L1Output.model_json_schema())
    _write_json(out / "tool_fetch_wazuh_alerts.schema.json", FETCH_ALERTS_SCHEMA)
    _write_json(out / "tool_search_attack_knowledge.schema.json", SEARCH_KNOWLEDGE_SCHEMA)
    return 0


def _knowledge_markdown(settings: Settings) -> tuple[str, str]:
    attack_path = Path(settings.project_root) / "data" / "attack_techniques.json"
    with attack_path.open("r", encoding="utf-8") as fh:
        techniques = json.load(fh)
    attack_lines = [
        "# MITRE ATT&CK 技术摘要（L1 精简版）",
        "",
        "> 本文件用于 Dify 知识库。内容为 ATT&CK Enterprise 的小型子集，不是全量 ATT&CK。",
        "",
    ]
    for item in techniques:
        attack_lines += [
            f"## {item['technique_id']} - {item['name']}",
            "",
            f"- Tactics: {', '.join(item.get('tactics') or [])}",
            f"- Keywords: {', '.join(item.get('keywords') or [])}",
            f"- URL: {item.get('url', '')}",
            "",
            item.get("description", ""),
            "",
            f"检测提示：{item.get('detection', '')}",
            "",
        ]
    ioc_path = Path(settings.project_root) / "data" / "iocs.csv"
    import csv

    ioc_lines = [
        "# IOC 观察列表（合成演示数据）",
        "",
        "> 这些 IP / 域名 / 哈希是文档保留地址或随机占位值，仅用于演示，不代表真实威胁情报。",
        "",
    ]
    with ioc_path.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            ioc_lines += [
                f"## IOC {row.get('value', '')}",
                "",
                f"- Type: {row.get('type', '')}",
                f"- Threat: {row.get('threat', '')}",
                f"- Confidence: {row.get('confidence', '')}",
                f"- Source: {row.get('source', '')}",
                f"- First seen: {row.get('first_seen', '')}",
                f"- Note: {row.get('note', '')}",
                "",
            ]
    return "\n".join(attack_lines), "\n".join(ioc_lines)


def cmd_export_dify(args: argparse.Namespace) -> int:
    settings = _settings(args)
    root = settings.project_root
    prompts = root / "dify" / "prompts"
    knowledge = root / "dify" / "knowledge"
    prompts.mkdir(parents=True, exist_ok=True)
    knowledge.mkdir(parents=True, exist_ok=True)
    (prompts / "l1_system.md").write_text(L1_SYSTEM_PROMPT + "\n", encoding="utf-8")
    (prompts / "l1_agent_instruction.md").write_text(
        DIFY_AGENT_INSTRUCTION + "\n", encoding="utf-8"
    )
    attack_md, ioc_md = _knowledge_markdown(settings)
    (knowledge / "attack_techniques.md").write_text(attack_md + "\n", encoding="utf-8")
    (knowledge / "iocs.md").write_text(ioc_md + "\n", encoding="utf-8")
    print(f"写入 {prompts / 'l1_system.md'}")
    print(f"写入 {prompts / 'l1_agent_instruction.md'}")
    print(f"写入 {knowledge / 'attack_techniques.md'}")
    print(f"写入 {knowledge / 'iocs.md'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description="Wazuh -> Redis Stream -> Dify -> L1 SOC triage agent (MVP)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="本地跑通 5 条告警（无需 Redis/Dify）")
    demo.add_argument("--limit", type=int, default=5)
    demo.add_argument("--llm", action="store_true", help="使用 DeepSeek（需要 DEEPSEEK_API_KEY）")
    demo.add_argument("--json", action="store_true")
    demo.set_defaults(func=cmd_demo)

    serve = sub.add_parser("serve", help="启动单个服务")
    serve.add_argument("service", choices=["bridge", "tools", "approval", "mock-dify"])
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=0)
    serve.set_defaults(func=cmd_serve)

    consume = sub.add_parser("consume", help="启动 Redis 消费者")
    consume.set_defaults(func=cmd_consume)

    seed = sub.add_parser("seed", help="把 sample_alerts.json 发给 bridge")
    seed.add_argument("--url", default="")
    seed.add_argument("--limit", type=int, default=5)
    seed.set_defaults(func=cmd_seed)

    stats = sub.add_parser("stats", help="查看 trace 统计")
    stats.set_defaults(func=cmd_stats)

    trace = sub.add_parser("trace", help="查看决策链")
    trace.add_argument("--id", default="")
    trace.add_argument("--limit", type=int, default=20)
    trace.set_defaults(func=cmd_trace)

    prune = sub.add_parser("prune", help="清理过期 trace")
    prune.add_argument("--days", type=int, default=7)
    prune.set_defaults(func=cmd_prune)

    export_schemas = sub.add_parser("export-schemas", help="导出 JSON Schema")
    export_schemas.add_argument("--out", default="")
    export_schemas.set_defaults(func=cmd_export_schemas)

    export_dify = sub.add_parser("export-dify", help="生成 Dify Prompt 与知识库 Markdown")
    export_dify.set_defaults(func=cmd_export_dify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
