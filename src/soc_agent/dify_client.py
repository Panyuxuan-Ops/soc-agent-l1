"""Dify Workflow API 客户端。

生产路径：consumer 调用 Dify ``POST /v1/workflows/run``（blocking）。
本地演示：``MockDifyRuntime`` 提供相同输出形状，避免为了跑通闭环而安装 Dify。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .alert import alert_json_for_llm
from .config import Settings
from .log import get_logger
from .models import L1Output
from .util import new_trace_id

log = get_logger("dify")


class DifyRunError(RuntimeError):
    pass


@dataclass(slots=True)
class DifyRunResult:
    workflow_run_id: str
    task_id: str
    outputs: dict[str, Any]
    output: L1Output
    approval_id: str | None = None
    elapsed_ms: int = 0
    total_tokens: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def _parse_outputs(outputs: dict[str, Any], trace_id: str, alert_id: str = "") -> L1Output:
    payload = outputs.get("result_json") or outputs.get("result") or outputs.get("text")
    if payload is None:
        raise DifyRunError("Dify 输出缺少 result_json")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise DifyRunError(f"result_json 不是合法 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise DifyRunError("result_json 必须是 object")
    try:
        output = L1Output.model_validate(payload)
    except Exception as exc:  # noqa: BLE001
        raise DifyRunError(f"Dify 输出不符合 L1 Schema: {exc}") from exc
    output.bind_context(alert_id=alert_id, trace_id=trace_id)
    return output


class DifyClient:
    def __init__(
        self,
        settings: Settings,
        http_client: httpx.AsyncClient | None = None,
    ):
        self.settings = settings
        self._owns_client = http_client is None
        self.client = http_client or httpx.AsyncClient(
            base_url=settings.dify_api_base,
            timeout=httpx.Timeout(settings.dify_workflow_timeout_s),
            headers={"Authorization": f"Bearer {settings.dify_api_key}"},
        )

    async def run(self, alert: dict[str, Any], trace_id: str | None = None) -> DifyRunResult:
        trace_id = trace_id or new_trace_id()
        started = time.perf_counter()
        payload = {
            "inputs": {
                "alert_json": alert_json_for_llm(alert),
                "trace_id": trace_id,
            },
            "response_mode": "blocking",
            "user": "soc-l1-consumer",
        }
        response = await self.client.post("/workflows/run", json=payload)
        if response.status_code >= 400:
            raise DifyRunError(f"Dify HTTP {response.status_code}: {response.text[:500]}")
        body = response.json()
        data = body.get("data") or {}
        status = data.get("status")
        if status != "succeeded":
            raise DifyRunError(f"Dify run status={status}: {data.get('error') or body}")
        outputs = data.get("outputs") or {}
        alert_id = str(alert.get("id") or alert.get("alert_id") or "")
        output = _parse_outputs(outputs, trace_id, alert_id)
        approval_raw = outputs.get("approval_id")
        approval_id = None if approval_raw in (None, "", "null") else str(approval_raw)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        try:
            elapsed_ms = int(float(data.get("elapsed_time") or 0) * 1000) or elapsed_ms
        except (TypeError, ValueError):
            pass
        return DifyRunResult(
            workflow_run_id=str(body.get("workflow_run_id") or data.get("workflow_id") or ""),
            task_id=str(body.get("task_id") or data.get("id") or ""),
            outputs=outputs,
            output=output,
            approval_id=approval_id,
            elapsed_ms=elapsed_ms,
            total_tokens=int(data.get("total_tokens") or 0),
            raw=body,
        )

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()


def create_dify_runner(settings: Settings, tools, trace, approvals):
    if settings.dify_mode == "mock":
        from .mock_dify import MockDifyRuntime

        return MockDifyRuntime(settings, tools, trace, approvals)
    return DifyClient(settings)
