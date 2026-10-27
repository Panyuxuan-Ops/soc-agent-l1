"""Wazuh -> Redis Stream 桥接。

Wazuh integratord 通过 stdin 把告警交给脚本，脚本 POST 到本服务；
本服务只做校验、脱敏、分配 trace_id、XADD，然后立即返回 202。
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .alert import alert_json_for_llm, normalize_alert
from .config import Settings
from .log import get_logger
from .queue import StreamQueue
from .util import deep_sanitize_alert, new_trace_id

log = get_logger("bridge")


class BatchIngest(BaseModel):
    alerts: list[dict[str, Any]]


def create_bridge_app(settings: Settings, queue: StreamQueue) -> FastAPI:
    app = FastAPI(title="Wazuh -> Redis Bridge", version="0.1.0")

    def auth(
        x_bridge_token: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> None:
        if not settings.bridge_token:
            return
        supplied = x_bridge_token
        if not supplied and authorization and authorization.startswith("Bearer "):
            supplied = authorization[7:]
        if supplied != settings.bridge_token:
            raise HTTPException(status_code=401, detail="invalid bridge token")

    async def _publish(alert: dict[str, Any]) -> dict[str, Any]:
        # 触发一次归一化校验；不合法直接 422，不进入队列
        try:
            view = normalize_alert(alert)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"invalid Wazuh alert: {exc}") from exc
        trace_id = new_trace_id()
        # 队列里保留脱敏后的告警；原始告警仍由 Wazuh 自己保存
        safe_alert = deep_sanitize_alert(alert, log_limit=2000)
        stream_id = await queue.publish(safe_alert, trace_id)
        log.info(
            "alert enqueued",
            extra={"trace_id": trace_id, "alert_id": view.alert_id},
        )
        return {
            "accepted": True,
            "trace_id": trace_id,
            "alert_id": view.alert_id,
            "stream_id": stream_id,
        }

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": await queue.health(), "service": "bridge", "stream": settings.stream_key}

    @app.post("/ingest/wazuh", status_code=202, dependencies=[Depends(auth)])
    async def ingest(alert: dict[str, Any]) -> dict[str, Any]:
        return await _publish(alert)

    @app.post("/ingest/wazuh/batch", status_code=202, dependencies=[Depends(auth)])
    async def ingest_batch(payload: BatchIngest) -> dict[str, Any]:
        if len(payload.alerts) > 100:
            raise HTTPException(status_code=422, detail="单批最多 100 条")
        accepted = []
        for alert in payload.alerts:
            accepted.append(await _publish(alert))
        return {"accepted": len(accepted), "items": accepted}

    @app.get("/preview/{alert_id}", dependencies=[Depends(auth)])
    async def preview(alert_id: str) -> dict[str, Any]:
        """调试辅助：不回查队列，仅说明生产环境应从 Wazuh 检索原始告警。"""
        return {"alert_id": alert_id, "note": "原始告警保留在 Wazuh，Dify 只接收脱敏摘要。"}

    return app


def sanitized_for_llm(alert: dict[str, Any]) -> dict[str, Any]:
    """保留给测试/调试的快捷函数。"""

    return json.loads(alert_json_for_llm(alert))
