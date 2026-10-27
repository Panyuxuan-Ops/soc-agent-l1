from __future__ import annotations

import httpx
import pytest

from soc_agent.agent import L1Agent
from soc_agent.approval import ApprovalStore
from soc_agent.consumer import Consumer
from soc_agent.dify_client import DifyClient, DifyRunResult
from soc_agent.models import L1Output
from soc_agent.mock_dify import create_mock_dify_app
from soc_agent.queue import InMemoryDedup, InMemoryQueue
from soc_agent.tool_service import ToolService
from soc_agent.trace import TraceStore
from soc_agent.util import new_trace_id
from soc_agent.wazuh import create_wazuh_backend
from soc_agent.knowledge import create_knowledge_backend

from conftest import load_samples


def _watch_output(alert_id: str = "wazuh-1001") -> L1Output:
    return L1Output.model_validate(
        {
            "alert_id": alert_id,
            "trace_id": "trc_0123456789abcdef",
            "verdict": "watch",
            "risk_score": 40,
            "confidence": 0.7,
            "summary": "watch",
            "reason": "test",
            "evidence": [{"source": "alert_rule", "detail": "level=6"}],
            "mitre_techniques": [],
            "recommended_actions": [
                {"action": "monitor", "target": "10.0.0.1", "reason": "观察"}
            ],
            "tool_calls_used": 0,
            "requires_human_approval": False,
            "escalate_to_l2": False,
            "limitations": [],
        }
    )


class FakeRunner:
    def __init__(self, output: L1Output | None = None, error: Exception | None = None):
        self.output = output or _watch_output()
        self.error = error
        self.calls = 0

    async def run(self, alert, trace_id=None):
        self.calls += 1
        if self.error:
            raise self.error
        return DifyRunResult(
            workflow_run_id="fake-run",
            task_id="fake-task",
            outputs={"result_json": self.output.model_dump_json()},
            output=self.output,
            approval_id=None,
            elapsed_ms=1,
        )


@pytest.mark.asyncio
async def test_consumer_mock_dify_end_to_end(settings):
    trace = TraceStore(settings)
    tools = ToolService(settings, create_wazuh_backend(settings), create_knowledge_backend(settings))
    approvals = ApprovalStore(settings, trace)
    mock_app = create_mock_dify_app(settings, tools=tools, trace=trace, approvals=approvals)
    http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_app),
        base_url="http://mock-dify/v1",
        headers={"Authorization": f"Bearer {settings.dify_mock_api_key}"},
    )
    dify = DifyClient(settings, http_client=http_client)
    queue = InMemoryQueue()
    consumer = Consumer(settings, queue, dify, trace, approvals, dedup=InMemoryDedup())
    alerts = load_samples(2)
    for alert in alerts:
        await queue.publish(alert, new_trace_id())
    results = await consumer.drain(max_messages=5)
    assert [r.status for r in results] == ["succeeded", "succeeded"]
    assert results[0].verdict == "escalate"
    assert results[0].approval_id
    run = trace.get_run(results[0].trace_id)
    assert run["status"] == "succeeded"
    assert run["output_json"]["verdict"] == "escalate"
    assert run["steps"]
    assert run["approvals"][0]["status"] == "pending"
    await consumer.close()
    await http_client.aclose()
    await tools.close()


@pytest.mark.asyncio
async def test_consumer_dedup(settings, trace):
    queue = InMemoryQueue()
    approvals = ApprovalStore(settings, trace)
    runner = FakeRunner()
    consumer = Consumer(settings, queue, runner, trace, approvals, dedup=InMemoryDedup())
    alert = load_samples(1)[0]
    await queue.publish(alert, new_trace_id())
    await queue.publish(alert, new_trace_id())
    results = await consumer.drain(max_messages=5)
    assert [r.status for r in results] == ["succeeded", "duplicate"]
    assert runner.calls == 1
    await consumer.close()


@pytest.mark.asyncio
async def test_consumer_failure_retries_then_dlq(settings, trace):
    queue = InMemoryQueue(max_retries=2)
    approvals = ApprovalStore(settings, trace)
    consumer = Consumer(settings, queue, FakeRunner(error=RuntimeError("upstream down")), trace, approvals)
    await queue.publish(load_samples(1)[0], new_trace_id())
    results = await consumer.drain(max_messages=5)
    assert [r.status for r in results] == ["retry", "dead"]
    assert len(queue.dead_letters) == 1
    await consumer.close()


@pytest.mark.asyncio
async def test_agent_via_mock_dify_contract(settings, trace):
    tools = ToolService(settings, create_wazuh_backend(settings), create_knowledge_backend(settings))
    approvals = ApprovalStore(settings, trace)
    mock_app = create_mock_dify_app(settings, tools=tools, trace=trace, approvals=approvals)
    http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_app),
        base_url="http://mock-dify/v1",
        headers={"Authorization": f"Bearer {settings.dify_mock_api_key}"},
    )
    dify = DifyClient(settings, http_client=http_client)
    alert = load_samples(1)[0]
    trace_id = new_trace_id()
    result = await dify.run(alert, trace_id)
    assert result.output.alert_id == alert["id"]
    assert result.output.trace_id == trace_id
    assert result.output.verdict == "escalate"
    assert result.approval_id
    assert result.outputs["verdict"] == "escalate"
    assert "result_json" in result.outputs
    await http_client.aclose()
    await tools.close()
