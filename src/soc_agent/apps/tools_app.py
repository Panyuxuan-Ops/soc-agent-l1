"""两个只读工具的 HTTP 服务。

Dify 的自定义工具通过 OpenAPI 调用这里。参数校验失败返回 422，
不会把非法参数传给 Wazuh 或知识库。
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ..config import Settings
from ..knowledge import create_knowledge_backend
from ..log import get_logger
from ..models import FetchAlertsArgs, SearchKnowledgeArgs
from ..tool_schemas import AGENT_TOOLS
from ..tool_service import ToolService, ToolValidationError
from ..wazuh import create_wazuh_backend

log = get_logger("tools_app")


def create_tools_app(settings: Settings, tools: ToolService | None = None) -> FastAPI:
    if tools is None:
        tools = ToolService(
            settings,
            create_wazuh_backend(settings),
            create_knowledge_backend(settings),
        )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await tools.close()

    app = FastAPI(
        title="SOC L1 Tools",
        version="0.1.0",
        description="L1 分诊只读工具：Wazuh 告警查询 + ATT&CK/IOC 检索。",
        lifespan=lifespan,
    )

    def auth(
        authorization: str | None = Header(default=None),
        x_tool_token: str | None = Header(default=None),
    ) -> None:
        if not settings.tool_api_token:
            return
        expected = f"Bearer {settings.tool_api_token}"
        if authorization != expected and x_tool_token != settings.tool_api_token:
            raise HTTPException(status_code=401, detail="invalid tool token")

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error": {
                    "code": "INVALID_ARGUMENTS",
                    "message": "工具参数不符合 JSON Schema",
                    "details": jsonable_encoder(exc.errors()),
                },
            },
        )

    @app.exception_handler(ToolValidationError)
    async def tool_validation_handler(_request, exc: ToolValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "tool": exc.tool,
                "error": {
                    "code": "INVALID_ARGUMENTS",
                    "message": str(exc),
                    "details": jsonable_encoder(exc.errors),
                },
            },
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True, "service": "tools", "wazuh_mode": settings.wazuh_mode}

    @app.get("/tools")
    async def list_tools() -> dict[str, Any]:
        return {"tools": AGENT_TOOLS}

    @app.post("/tools/fetch_wazuh_alerts", dependencies=[Depends(auth)])
    async def fetch_alerts(args: FetchAlertsArgs) -> dict[str, Any]:
        return await tools.fetch_wazuh_alerts(args)

    @app.post("/tools/search_attack_knowledge", dependencies=[Depends(auth)])
    async def search_knowledge(args: SearchKnowledgeArgs) -> dict[str, Any]:
        return await tools.search_attack_knowledge(args)

    return app


app = create_tools_app(Settings.from_env())
