"""两个 L1 工具的实现与统一入口。"""

from __future__ import annotations

import time
from typing import Any

from pydantic import ValidationError

from .alert import normalize_alert
from .config import Settings
from .knowledge import CombinedKnowledgeBackend
from .models import FetchAlertsArgs, SearchKnowledgeArgs
from .util import json_dumps
from .wazuh import IndexerWazuhBackend, MockWazuhBackend


class ToolValidationError(ValueError):
    def __init__(self, tool: str, errors: list[dict[str, Any]]):
        self.tool = tool
        self.errors = errors
        super().__init__(f"{tool} 参数校验失败")


class ToolService:
    def __init__(
        self,
        settings: Settings,
        wazuh: MockWazuhBackend | IndexerWazuhBackend,
        knowledge: CombinedKnowledgeBackend,
    ):
        self.settings = settings
        self.wazuh = wazuh
        self.knowledge = knowledge

    async def fetch_wazuh_alerts(self, args: FetchAlertsArgs) -> dict[str, Any]:
        started = time.perf_counter()
        result = await self.wazuh.search(
            limit=args.limit,
            min_level=args.min_level,
            src_ip=args.src_ip,
        )
        alerts = []
        for raw in result.alerts:
            view = normalize_alert(raw)
            alerts.append(
                {
                    "alert_id": view.alert_id,
                    "timestamp": view.timestamp,
                    "rule_id": view.rule_id,
                    "level": view.rule_level,
                    "description": view.rule_description,
                    "agent": view.agent_name,
                    "src_ip": view.src_ip,
                    "mitre_ids": view.mitre_ids,
                }
            )
        repeat_count = result.total if args.src_ip else 0
        data = {
            "window_minutes": result.window_minutes,
            "query": {
                "limit": args.limit,
                "min_level": args.min_level,
                "src_ip": args.src_ip,
            },
            "total": result.total,
            "repeat_count": repeat_count,
            "is_repeat": repeat_count >= 3,
            "unique_src_ips": result.unique_src_ips,
            "max_level": result.max_level,
            "first_seen": result.first_seen,
            "last_seen": result.last_seen,
            "alerts": alerts,
        }
        return {
            "ok": True,
            "tool": "fetch_wazuh_alerts",
            "data": data,
            "meta": {
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "backend": result.source,
            },
        }

    async def search_attack_knowledge(self, args: SearchKnowledgeArgs) -> dict[str, Any]:
        started = time.perf_counter()
        result = await self.knowledge.search(args.query, args.top_k)
        return {
            "ok": True,
            "tool": "search_attack_knowledge",
            "data": {
                "query": result.query,
                "top_k": result.top_k,
                "results": result.results,
            },
            "meta": {
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "backend": result.backend,
            },
        }

    async def execute_tool(self, name: str, raw_args: dict[str, Any] | None) -> dict[str, Any]:
        raw_args = raw_args or {}
        try:
            if name == "fetch_wazuh_alerts":
                return await self.fetch_wazuh_alerts(FetchAlertsArgs.model_validate(raw_args))
            if name == "search_attack_knowledge":
                return await self.search_attack_knowledge(
                    SearchKnowledgeArgs.model_validate(raw_args)
                )
        except ValidationError as exc:
            raise ToolValidationError(name, exc.errors()) from exc
        raise ToolValidationError(name, [{"msg": f"未知工具: {name}"}])

    async def close(self) -> None:
        await self.wazuh.close()
        await self.knowledge.close()


def compact_tool_result(result: dict[str, Any], max_chars: int = 6000) -> dict[str, Any]:
    """给 LLM 的工具结果做兜底截断，避免异常大数据撑爆上下文。"""

    text = json_dumps(result)
    if len(text) <= max_chars:
        return result
    return {
        "ok": result.get("ok", True),
        "tool": result.get("tool"),
        "data": {"truncated": True, "preview": text[:max_chars]},
        "meta": result.get("meta", {}),
    }
