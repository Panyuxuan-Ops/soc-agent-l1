from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
from fastapi import FastAPI

from soc_agent.approval import ApprovalStore, create_approval_app
from soc_agent.models import L1Output


def _output(alert_id: str = "wazuh-1001", destructive: bool = True) -> L1Output:
    actions = [
        {"action": "escalate_l2", "target": alert_id, "reason": "转 L2"},
        {"action": "collect_evidence", "target": "web-01", "reason": "取证"},
    ]
    if destructive:
        actions.append(
            {
                "action": "block_ip",
                "target": "203.0.113.45",
                "destructive": True,
                "requires_approval": True,
                "reason": "阻断",
            }
        )
    return L1Output.model_validate(
        {
            "alert_id": alert_id,
            "trace_id": "trc_0123456789abcdef",
            "verdict": "escalate",
            "risk_score": 85,
            "confidence": 0.9,
            "summary": "SSH 暴力破解",
            "reason": "重复触发",
            "evidence": [{"source": "alert_rule", "detail": "level=12"}],
            "mitre_techniques": [{"technique_id": "T1110", "name": "Brute Force"}],
            "recommended_actions": actions,
            "tool_calls_used": 2,
            "requires_human_approval": destructive,
            "escalate_to_l2": True,
            "limitations": [],
        }
    )


@pytest.mark.asyncio
async def test_approval_token_single_use(settings, trace):
    store = ApprovalStore(settings, trace)
    record = await store.create(
        trace_id="trc_0123456789abcdef",
        alert_id="wazuh-1001",
        result=_output(),
    )
    assert record is not None
    assert record.status == "pending"
    assert record.approval_id.startswith("apr_")
    assert "token=" in record.approve_url

    public = store.get(record.approval_id)
    assert public is not None
    assert "token_hash" not in public

    ok, result = store.decide(record.approval_id, "wrong-token", "approve", "tester")
    assert ok is False
    assert result == "invalid_token"

    ok, result = store.decide(record.approval_id, record.token, "approve", "tester", "ok")
    assert ok is True
    assert result == "approve"
    assert store.get(record.approval_id)["status"] == "approve"

    ok, result = store.decide(record.approval_id, record.token, "reject", "tester")
    assert ok is False
    assert result == "already_decided"


@pytest.mark.asyncio
async def test_non_destructive_does_not_create_approval(settings, trace):
    store = ApprovalStore(settings, trace)
    record = await store.create(
        trace_id="trc_0123456789abcdef",
        alert_id="wazuh-2001",
        result=_output("wazuh-2001", destructive=False),
    )
    assert record is None


@pytest.mark.asyncio
async def test_expired_approval(settings, trace):
    expired = replace(settings, approval_ttl_hours=-1)
    store = ApprovalStore(expired, trace)
    record = await store.create(
        trace_id="trc_0123456789abcdef",
        alert_id="wazuh-1001",
        result=_output(),
    )
    assert record is not None
    ok, result = store.decide(record.approval_id, record.token, "approve", "tester")
    assert ok is False
    assert result == "expired"


@pytest.mark.asyncio
async def test_approval_http_api(settings, trace):
    store = ApprovalStore(settings, trace)
    app: FastAPI = create_approval_app(settings, trace=trace, store=store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/approvals",
            json={
                "trace_id": "trc_0123456789abcdef",
                "alert_id": "wazuh-1001",
                "result_json": _output().model_dump_json(),
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        approval_id = body["approval_id"]
        assert body["status"] == "pending"
        assert body["preview"]["approve_url"].startswith("http://testserver/approvals/")

        response = await client.get(
            f"/approvals/{approval_id}",
        )
        assert response.status_code == 200
        assert response.json()["status"] == "pending"

        link = httpx.URL(body["preview"]["approve_url"])
        response = await client.get(link.raw_path.decode())
        assert response.status_code == 200
        assert "已批准" in response.text

        response = await client.get(
            f"/approvals/{approval_id}",
        )
        assert response.json()["status"] == "approve"

        response = await client.get(link.raw_path.decode())
        assert response.status_code == 400
        assert "不能重复提交" in response.text


@pytest.mark.asyncio
async def test_approval_api_not_required(settings, trace):
    store = ApprovalStore(settings, trace)
    app = create_approval_app(settings, trace=trace, store=store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/approvals",
            json={
                "trace_id": "trc_0123456789abcdef",
                "alert_id": "wazuh-2001",
                "result_json": _output("wazuh-2001", destructive=False).model_dump_json(),
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "not_required"


@pytest.mark.asyncio
async def test_approval_api_auth(settings, trace):
    secured = replace(settings, approval_api_token="secret")
    store = ApprovalStore(secured, trace)
    app = create_approval_app(secured, trace=trace, store=store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "trace_id": "trc_0123456789abcdef",
            "alert_id": "wazuh-1001",
            "result_json": _output().model_dump_json(),
        }
        response = await client.post("/approvals", json=payload)
        assert response.status_code == 401
        response = await client.post(
            "/approvals", json=payload, headers={"Authorization": "Bearer secret"}
        )
        assert response.status_code == 200
