from __future__ import annotations

import pytest
from pydantic import ValidationError

from soc_agent.models import FetchAlertsArgs, SearchKnowledgeArgs
from soc_agent.tool_service import ToolValidationError


@pytest.mark.asyncio
async def test_fetch_repeat_count(tools):
    result = await tools.fetch_wazuh_alerts(
        FetchAlertsArgs(src_ip="203.0.113.45", min_level=8, limit=20)
    )
    data = result["data"]
    assert data["repeat_count"] == 6
    assert data["is_repeat"] is True
    assert data["max_level"] == 12
    assert data["window_minutes"] == 15
    assert data["alerts"]
    assert result["meta"]["backend"] == "mock"


@pytest.mark.asyncio
async def test_fetch_without_src_ip(tools):
    result = await tools.fetch_wazuh_alerts(FetchAlertsArgs(limit=3))
    assert result["data"]["total"] >= 3
    assert len(result["data"]["alerts"]) == 3


@pytest.mark.asyncio
async def test_knowledge_attack_and_ioc(tools):
    attack = await tools.search_attack_knowledge(
        SearchKnowledgeArgs(query="ssh brute force T1110", top_k=5)
    )
    results = attack["data"]["results"]
    assert any(item["technique_id"] == "T1110" for item in results)
    assert attack["meta"]["backend"].startswith("local-bm25")

    ioc = await tools.search_attack_knowledge(
        SearchKnowledgeArgs(query="203.0.113.45 ssh", top_k=5)
    )
    assert any(item["type"] == "ioc" for item in ioc["data"]["results"])


@pytest.mark.asyncio
async def test_execute_tool_rejects_extra_and_bad_ip(tools):
    with pytest.raises(ToolValidationError):
        await tools.execute_tool("fetch_wazuh_alerts", {"src_ip": "999.1.1.1"})
    with pytest.raises(ToolValidationError):
        await tools.execute_tool("fetch_wazuh_alerts", {"foo": "bar"})
    with pytest.raises(ToolValidationError):
        await tools.execute_tool("unknown_tool", {})


def test_fetch_args_pydantic_direct():
    with pytest.raises(ValidationError):
        FetchAlertsArgs(limit=0)
    with pytest.raises(ValidationError):
        FetchAlertsArgs(limit=21)
