"""本地 Dify 测试替身。

它模拟 Dify Workflow API 的请求/响应形状，内部用 L1Agent 执行同样的
“工具调用 -> 裁决 -> 审批”闭环。生产环境把 DIFY_MODE 切到 api 即可，
消费端代码路径不变。它不是 Dify 的替代品，只用于离线开发与测试。
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .agent import L1Agent
from .approval import ApprovalStore, create_approval_app
from .config import Settings
from .dify_client import DifyRunResult
from .log import get_logger
from .tool_service import ToolService
from .trace import TraceStore
from .util import new_trace_id

log = get_logger("mock_dify")


class MockDifyRuntime:
    def __init__(
        self,
        settings: Settings,
        tools: ToolService,
        trace: TraceStore,
        approvals: ApprovalStore,
    ):
        self.settings = settings
        self.tools = tools
        self.trace = trace
        self.approvals = approvals
        self.agent = L1Agent(settings, tools, trace)

    async def run(self, alert: dict[str, Any], trace_id: str | None = None) -> DifyRunResult:
        trace_id = trace_id or new_trace_id()
        started = time.perf_counter()
        try:
            agent_run = await self.agent.run(alert, trace_id)
            approval_id = None
            if agent_run.output.requires_human_approval:
                record = await self.approvals.create(
                    trace_id=trace_id,
                    alert_id=agent_run.output.alert_id,
                    result=agent_run.output,
                )
                approval_id = record.approval_id if record else None
            self.trace.finish_run(
                trace_id=trace_id,
                status="succeeded",
                output=agent_run.output,
                approval_id=approval_id,
                prompt_tokens=agent_run.prompt_tokens,
                completion_tokens=agent_run.completion_tokens,
                total_tokens=agent_run.total_tokens,
                workflow_run_id=f"mock-{trace_id}",
            )
            outputs = {
                "result_json": json.dumps(
                    agent_run.output.to_standard_dict(), ensure_ascii=False
                ),
                "verdict": agent_run.output.verdict,
                "approval_id": approval_id or "",
                "requires_human_approval": "true" if agent_run.output.requires_human_approval else "false",
            }
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return DifyRunResult(
                workflow_run_id=f"mock-{trace_id}",
                task_id=f"task-{uuid.uuid4().hex[:12]}",
                outputs=outputs,
                output=agent_run.output,
                approval_id=approval_id,
                elapsed_ms=elapsed_ms,
                total_tokens=agent_run.total_tokens,
                raw={"mock": True, "outputs": outputs},
            )
        except Exception as exc:
            self.trace.finish_run(trace_id=trace_id, status="failed", error=str(exc)[:1000])
            raise


class WorkflowRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    inputs: dict[str, Any] = Field(default_factory=dict)
    response_mode: str = "blocking"
    user: str = "soc-l1-consumer"


def create_mock_dify_app(
    settings: Settings,
    tools: ToolService | None = None,
    trace: TraceStore | None = None,
    approvals: ApprovalStore | None = None,
) -> FastAPI:
    trace = trace or TraceStore(settings)
    if tools is None:
        from .knowledge import create_knowledge_backend
        from .wazuh import create_wazuh_backend

        tools = ToolService(settings, create_wazuh_backend(settings), create_knowledge_backend(settings))
    approvals = approvals or ApprovalStore(settings, trace)
    runtime = MockDifyRuntime(settings, tools, trace, approvals)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await tools.close()

    app = FastAPI(title="SOC L1 Mock Dify", version="0.1.0", lifespan=lifespan)
    app.state.runtime = runtime
    app.state.trace = trace

    def auth(authorization: str | None = Header(default=None)) -> None:
        expected = f"Bearer {settings.dify_mock_api_key}"
        if settings.dify_mock_api_key and authorization != expected:
            raise HTTPException(status_code=401, detail="invalid mock Dify API key")

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True, "service": "mock-dify", "mode": settings.dify_mode}

    @app.post("/v1/workflows/run", dependencies=[Depends(auth)])
    async def run_workflow(payload: WorkflowRunRequest) -> dict[str, Any]:
        inputs = payload.inputs
        raw_alert = inputs.get("alert_json") or inputs.get("alert")
        if raw_alert is None:
            raise HTTPException(status_code=422, detail="inputs.alert_json is required")
        try:
            alert = json.loads(raw_alert) if isinstance(raw_alert, str) else raw_alert
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"alert_json invalid: {exc}") from exc
        if not isinstance(alert, dict):
            raise HTTPException(status_code=422, detail="alert_json must be object")
        trace_id = str(inputs.get("trace_id") or new_trace_id())
        started = time.time()
        result = await runtime.run(alert, trace_id)
        return {
            "workflow_run_id": result.workflow_run_id,
            "task_id": result.task_id,
            "data": {
                "id": result.task_id,
                "workflow_id": "mock-l1-workflow",
                "status": "succeeded",
                "outputs": result.outputs,
                "error": None,
                "elapsed_time": round(time.time() - started, 3),
                "total_tokens": result.total_tokens,
                "created_at": int(started),
            },
        }

    @app.get("/v1/traces/{trace_id}")
    async def get_trace(trace_id: str) -> dict[str, Any]:
        run = trace.get_run(trace_id)
        if not run:
            raise HTTPException(status_code=404, detail="trace not found")
        return run

    # 复用审批 API，便于单进程演示；生产建议独立部署
    approval_app = create_approval_app(settings, trace=trace, store=approvals)
    app.mount("/approval", approval_app)
    return app
