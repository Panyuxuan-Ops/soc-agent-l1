from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from soc_agent.bridge import create_bridge_app
from soc_agent.queue import InMemoryQueue

from conftest import load_samples


@pytest.mark.asyncio
async def test_bridge_enqueues_alert(settings):
    queue = InMemoryQueue()
    app = create_bridge_app(settings, queue)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/ingest/wazuh", json=load_samples(1)[0])
        assert response.status_code == 202, response.text
        body = response.json()
        assert body["accepted"] is True
        assert body["trace_id"].startswith("trc_")
        message = await queue.consume(block_ms=50)
        assert message is not None
        assert message.alert["id"] == "wazuh-1001"


@pytest.mark.asyncio
async def test_bridge_batch(settings):
    queue = InMemoryQueue()
    app = create_bridge_app(settings, queue)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/ingest/wazuh/batch", json={"alerts": load_samples(2)})
        assert response.status_code == 202
        assert response.json()["accepted"] == 2


@pytest.mark.asyncio
async def test_bridge_auth(settings):
    secured = replace(settings, bridge_token="secret")
    queue = InMemoryQueue()
    app = create_bridge_app(secured, queue)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/ingest/wazuh", json=load_samples(1)[0])
        assert response.status_code == 401
        response = await client.post(
            "/ingest/wazuh",
            json=load_samples(1)[0],
            headers={"X-Bridge-Token": "secret"},
        )
        assert response.status_code == 202


@pytest.mark.asyncio
async def test_bridge_rejects_non_object(settings):
    queue = InMemoryQueue()
    app = create_bridge_app(settings, queue)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/ingest/wazuh", json=["not-an-object"])
        assert response.status_code == 422
