from __future__ import annotations

import pytest

from soc_agent.agent import L1Agent
from soc_agent.models import L1Output
from soc_agent.util import new_trace_id

from conftest import load_samples


EXPECTED = {
    "wazuh-1001": "escalate",
    "wazuh-2001": "watch",
    "wazuh-3001": "close",
    "wazuh-4001": "escalate",
    "wazuh-5001": "watch",
}


@pytest.mark.asyncio
async def test_five_alerts_expected_verdicts(settings, tools, trace):
    agent = L1Agent(settings, tools, trace)
    alerts = load_samples(5)
    for alert in alerts:
        trace_id = new_trace_id()
        run = await agent.run(alert, trace_id)
        output = run.output
        assert output.verdict == EXPECTED[alert["id"]], alert["id"]
        assert 0 <= output.risk_score <= 100
        assert 0 <= output.confidence <= 1
        assert output.tool_calls_used <= 3
        assert output.escalate_to_l2 == (output.verdict == "escalate")
        assert output.requires_human_approval == any(
            action.destructive for action in output.recommended_actions
        )
        L1Output.model_validate(output.model_dump())


@pytest.mark.asyncio
async def test_ssh_prompt_injection_is_ignored(settings, tools, trace):
    agent = L1Agent(settings, tools, trace)
    alert = load_samples(1)[0]
    run = await agent.run(alert, new_trace_id())
    output = run.output
    assert output.verdict == "escalate"
    assert "203.0.113.45" in output.summary
    assert any(item.source == "policy" and "指令性文本" in item.detail for item in output.evidence)
    assert any(action.action == "block_ip" and action.destructive for action in output.recommended_actions)


@pytest.mark.asyncio
async def test_fast_close_uses_zero_tools(settings, tools, trace):
    agent = L1Agent(settings, tools, trace)
    noise = load_samples(5)[2]
    trace_id = new_trace_id()
    run = await agent.run(noise, trace_id)
    assert run.output.verdict == "close"
    assert run.output.tool_calls_used == 0
    trace_data = trace.get_run(trace_id)
    tool_steps = [s for s in trace_data["steps"] if s["phase"] == "tool"]
    assert tool_steps == []


@pytest.mark.asyncio
async def test_fim_isolates_host_with_approval(settings, tools, trace):
    agent = L1Agent(settings, tools, trace)
    alert = load_samples(5)[3]
    run = await agent.run(alert, new_trace_id())
    output = run.output
    assert output.verdict == "escalate"
    assert output.risk_score >= 70
    actions = {action.action: action for action in output.recommended_actions}
    assert "isolate_host" in actions
    assert actions["isolate_host"].destructive is True
    assert actions["isolate_host"].requires_approval is True
    assert output.requires_human_approval is True


@pytest.mark.asyncio
async def test_web_scan_prefers_alert_mitre_id(settings, tools, trace):
    agent = L1Agent(settings, tools, trace)
    alert = load_samples(5)[1]
    run = await agent.run(alert, new_trace_id())
    ids = [item.technique_id for item in run.output.mitre_techniques]
    assert ids[0] == "T1595"


@pytest.mark.asyncio
async def test_trace_reconstructs_tool_chain(settings, tools, trace):
    agent = L1Agent(settings, tools, trace)
    alert = load_samples(5)[0]
    trace_id = new_trace_id()
    await agent.run(alert, trace_id)
    run = trace.get_run(trace_id)
    assert run is not None
    assert run["status"] == "running"  # finish 由 Dify/consumer 负责
    phases = [step["phase"] for step in run["steps"]]
    assert "tool" in phases
    tools_called = [step["tool"] for step in run["steps"] if step["phase"] == "tool"]
    assert tools_called == ["search_attack_knowledge", "fetch_wazuh_alerts"]
