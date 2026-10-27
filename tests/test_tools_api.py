from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from soc_agent.apps.tools_app import create_tools_app
from soc_agent.tool_service import ToolService
from soc_agent.wazuh import create_wazuh_backend
from soc_agent.knowledge import create_knowledge_backend


def _tools(settings) -> ToolService:
    return ToolService(settings, create_wazuh_backend(settings), create_knowledge_backend(settings))


@pytest.mark.asyncio
async def test_tools_api_valid_and_invalid(settings):
    tools = _tools(settings)
    app = create_tools_app(settings, tools=tools)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/tools/fetch_wazuh_alerts",
            json={"src_ip": "203.0.113.45", "min_level": 8, "limit": 20},
        )
        assert response.status_code == 200, response.text
        assert response.json()["data"]["repeat_count"] == 6

        response = await client.post(
            "/tools/fetch_wazuh_alerts",
            json={"src_ip": "203.0.113.45", "unexpected": True},
        )
        assert response.status_code == 422
        body = response.json()
        assert body["ok"] is False
        assert body["error"]["code"] == "INVALID_ARGUMENTS"

        response = await client.post(
            "/tools/fetch_wazuh_alerts",
            json={"src_ip": "999.1.1.1"},
        )
        assert response.status_code == 422

        response = await client.post(
            "/tools/search_attack_knowledge",
            json={"query": "T1110", "top_k": 3},
        )
        assert response.status_code == 200
        assert response.json()["data"]["results"]

        response = await client.post(
            "/tools/search_attack_knowledge",
            json={"query": "", "top_k": 3},
        )
        assert response.status_code == 422
    await tools.close()


@pytest.mark.asyncio
async def test_tools_api_auth(settings):
    secured = replace(settings, tool_api_token="secret")
    tools = _tools(secured)
    app = create_tools_app(secured, tools=tools)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/tools/search_attack_knowledge", json={"query": "T1110"})
        assert response.status_code == 401
        response = await client.post(
            "/tools/search_attack_knowledge",
            json={"query": "T1110"},
            headers={"Authorization": "Bearer secret"},
        )
        assert response.status_code == 200
    await tools.close()
