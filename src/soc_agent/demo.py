"""一条命令跑通 5 条告警的本地闭环。

链路与生产一致的部分：
  告警 -> InMemoryQueue（替代 Redis Stream）-> Consumer -> Dify HTTP API
  -> Mock Dify（替代真实 Dify）-> L1Agent -> 两个工具 -> 审批 -> Trace
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from .approval import ApprovalStore
from .config import Settings
from .consumer import Consumer
from .dify_client import DifyClient
from .knowledge import create_knowledge_backend
from .mock_dify import create_mock_dify_app
from .queue import InMemoryDedup, InMemoryQueue
from .tool_service import ToolService
from .trace import TraceStore
from .util import new_trace_id
from .wazuh import create_wazuh_backend


def _load_samples(settings: Settings, limit: int) -> list[dict[str, Any]]:
    path = Path(settings.project_root) / "data" / "sample_alerts.json"
    if not path.exists():
        path = Path(settings.data_dir) / "sample_alerts.json"
    with path.open("r", encoding="utf-8") as fh:
        alerts = json.load(fh)
    if not isinstance(alerts, list):
        raise ValueError("sample_alerts.json 必须是数组")
    return alerts[:limit]


def _short(value: Any, limit: int = 160) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str) if not isinstance(value, str) else value
    text = " ".join(text.split())
    return text[: limit - 3] + "..." if len(text) > limit else text


def _print_run(index: int, run: dict[str, Any] | None) -> None:
    if not run:
        print(f"[{index}] 未找到 trace")
        return
    output = run.get("output_json") or {}
    approval = run.get("approval_id") or "-"
    print(
        f"[{index}] {run.get('alert_id'):<12} "
        f"{str(output.get('verdict')):<8} "
        f"risk={str(output.get('risk_score')):<3} "
        f"conf={str(output.get('confidence')):<5} "
        f"tools={str(output.get('tool_calls_used')):<2} "
        f"approval={approval}"
    )
    print(f"    {output.get('summary', '')}")


def _print_chain(run: dict[str, Any] | None) -> None:
    if not run:
        return
    print("\n" + "=" * 78)
    print(f"决策链 trace_id={run.get('trace_id')}  alert={run.get('alert_id')}")
    print("=" * 78)
    for step in run.get("steps", []):
        tool = step.get("tool") or "-"
        print(
            f"  #{step.get('seq')} [{step.get('phase')}] {tool} "
            f"status={step.get('status')} latency={step.get('latency_ms')}ms"
        )
        if step.get("args_json"):
            print(f"      args   : {_short(step['args_json'], 220)}")
        if step.get("result_json"):
            print(f"      result : {_short(step['result_json'], 300)}")
    output = run.get("output_json") or {}
    print("\n裁决理由：")
    print(f"  {output.get('reason', '')}")
    print("\n证据：")
    for item in output.get("evidence", []):
        print(f"  - [{item.get('source')}] {item.get('detail')}")
    print("\n建议动作：")
    for action in output.get("recommended_actions", []):
        print(
            f"  - {action.get('action')} target={action.get('target')} "
            f"destructive={action.get('destructive')} approval={action.get('requires_approval')}"
        )
    approvals = run.get("approvals") or []
    if approvals:
        for approval in approvals:
            print(
                f"\n审批：{approval.get('approval_id')} status={approval.get('status')} "
                f"expires={approval.get('expires_at')}"
            )
            print(
                "  要点击日志里的批准/拒绝链接：把 SOC_TRACE_DB 指向上面的 trace 目录，"
                "再运行 `python -m soc_agent serve approval`。"
            )


async def run_demo(
    settings: Settings,
    *,
    limit: int = 5,
    llm: bool = False,
    quiet: bool = False,
) -> dict[str, Any]:
    run_dir = Path(settings.data_dir) / "demo_runs" / datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    settings = replace(
        settings,
        trace_db=run_dir / "traces.sqlite3",
        trace_jsonl=run_dir / "traces.jsonl",
        agent_mode="deepseek" if llm and settings.deepseek_api_key else "deterministic",
        queue_mode="memory",
        wazuh_mode="mock",
    )
    settings.ensure_dirs()

    if llm and not settings.deepseek_api_key:
        print("警告：未设置 DEEPSEEK_API_KEY，回退到 deterministic 模式。")

    trace = TraceStore(settings)
    tools = ToolService(settings, create_wazuh_backend(settings), create_knowledge_backend(settings))
    approvals = ApprovalStore(settings, trace)
    mock_app = create_mock_dify_app(settings, tools=tools, trace=trace, approvals=approvals)

    http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_app),
        base_url="http://mock-dify/v1",
        headers={"Authorization": f"Bearer {settings.dify_mock_api_key}"},
        timeout=httpx.Timeout(120.0),
    )
    dify = DifyClient(settings, http_client=http_client)
    queue = InMemoryQueue(max_retries=settings.max_retries)
    consumer = Consumer(
        settings,
        queue,
        dify,
        trace,
        approvals,
        dedup=InMemoryDedup(),
    )

    alerts = _load_samples(settings, limit)
    trace_ids: list[str] = []
    for alert in alerts:
        trace_id = new_trace_id()
        trace_ids.append(trace_id)
        await queue.publish(alert, trace_id)

    if not quiet:
        print(f"队列已入队 {len(alerts)} 条告警，开始消费（agent_mode={settings.agent_mode}）...\n")

    results = await consumer.drain(max_messages=len(alerts) + 5)

    if not quiet:
        print("-" * 78)
        print(f"{'#':<3}{'alert':<13}{'verdict':<9}{'risk':<6}{'conf':<7}{'tools':<7}approval")
        print("-" * 78)
        runs: list[dict[str, Any] | None] = []
        for index, trace_id in enumerate(trace_ids, start=1):
            run = trace.get_run(trace_id)
            runs.append(run)
            _print_run(index, run)
        print("-" * 78)
        print(f"消费结果：{len(results)} 条；trace 目录：{run_dir}")
        stats = trace.stats()
        print(
            f"统计：runs={stats['runs']} succeeded={stats['succeeded']} failed={stats['failed']} "
            f"verdicts={stats['verdicts']} avg={stats['avg_latency_ms']}ms p95={stats['p95_latency_ms']}ms"
        )
        escalate_run = next(
            (
                run
                for run in runs
                if run and (run.get("output_json") or {}).get("verdict") == "escalate"
            ),
            runs[0] if runs else None,
        )
        _print_chain(escalate_run)

    await consumer.close()
    await http_client.aclose()
    await tools.close()

    return {
        "run_dir": str(run_dir),
        "results": [asdict(result) for result in results],
        "trace_ids": trace_ids,
        "stats": trace.stats(),
    }
