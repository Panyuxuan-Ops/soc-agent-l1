"""Wazuh 桥接服务入口。"""

from __future__ import annotations

from fastapi import FastAPI

from ..bridge import create_bridge_app
from ..config import Settings
from ..queue import create_queue

settings = Settings.from_env()
queue = create_queue(settings)
app: FastAPI = create_bridge_app(settings, queue)


@app.on_event("shutdown")
async def _close_queue() -> None:
    await queue.close()
