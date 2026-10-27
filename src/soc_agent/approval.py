"""人在回路（HITL）审批服务。

L1 只产生“建议”，不执行任何破坏性动作。命中破坏性建议时：
1. 创建 approval 记录（默认 24h 过期，token 单次使用）；
2. 通过钉钉/邮件把 approve/reject 链接发给分析师；
3. 记录审批结果，供 L2 执行前校验。

注意：即使 approved，本服务也不会执行 block_ip/isolate_host。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import secrets
import smtplib
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings
from .log import get_logger
from .models import L1Output
from .trace import TraceStore
from .util import iso, utc_now

log = get_logger("approval")


@dataclass(slots=True)
class ApprovalRecord:
    approval_id: str
    trace_id: str
    alert_id: str
    token: str
    approve_url: str
    reject_url: str
    status: str
    expires_at: str
    summary: str
    actions: list[dict[str, Any]]


class NotificationService:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def send(self, record: ApprovalRecord) -> None:
        log.warning(
            "approval required: %s (%s)",
            record.approval_id,
            record.summary,
            extra={"trace_id": record.trace_id},
        )
        if self.settings.approval_expose_links:
            log.warning(
                "approval links: approve=%s reject=%s",
                record.approve_url,
                record.reject_url,
                extra={"trace_id": record.trace_id},
            )
        if self.settings.dingtalk_webhook:
            try:
                await self._send_dingtalk(record)
            except Exception as exc:  # noqa: BLE001
                log.error("dingtalk notification failed: %s", exc)
        if self.settings.smtp_host and self.settings.smtp_to:
            try:
                await asyncio.to_thread(self._send_smtp, record)
            except Exception as exc:  # noqa: BLE001
                log.error("smtp notification failed: %s", exc)

    async def _send_dingtalk(self, record: ApprovalRecord) -> None:
        url = self.settings.dingtalk_webhook
        if self.settings.dingtalk_secret:
            timestamp = str(round(time.time() * 1000))
            string_to_sign = f"{timestamp}\n{self.settings.dingtalk_secret}"
            digest = hmac.new(
                self.settings.dingtalk_secret.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
            sign = base64.b64encode(digest).decode("utf-8")
            url += f"&timestamp={timestamp}&sign={sign}"
        text = (
            f"### SOC L1 审批请求\n\n"
            f"- 审批号：{record.approval_id}\n"
            f"- 告警：{record.alert_id}\n"
            f"- 结论：{record.summary}\n"
            f"- 动作：{', '.join(a.get('action', '') for a in record.actions)}\n\n"
            f"[批准]({record.approve_url}) | [拒绝]({record.reject_url})\n\n"
            f"> 批准后仍需 L2 执行器复核；本链接单次有效。"
        )
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                url, json={"msgtype": "markdown", "markdown": {"title": "SOC L1 审批", "text": text}}
            )
            response.raise_for_status()

    def _send_smtp(self, record: ApprovalRecord) -> None:
        message = MIMEMultipart("alternative")
        message["Subject"] = f"[SOC L1] 审批请求 {record.approval_id} - {record.alert_id}"
        message["From"] = self.settings.smtp_from or self.settings.smtp_user
        message["To"] = self.settings.smtp_to
        text = (
            f"审批号: {record.approval_id}\n告警: {record.alert_id}\n结论: {record.summary}\n"
            f"批准: {record.approve_url}\n拒绝: {record.reject_url}\n"
        )
        html_body = f"""
        <h2>SOC L1 审批请求</h2>
        <p><b>审批号：</b>{html.escape(record.approval_id)}</p>
        <p><b>告警：</b>{html.escape(record.alert_id)}</p>
        <p><b>结论：</b>{html.escape(record.summary)}</p>
        <ul>{''.join(f'<li>{html.escape(str(a.get("action")))} → {html.escape(str(a.get("target")))}</li>' for a in record.actions)}</ul>
        <p><a href="{html.escape(record.approve_url)}">批准</a> | <a href="{html.escape(record.reject_url)}">拒绝</a></p>
        <p>链接单次有效，批准后仍需 L2 执行器复核。</p>
        """
        message.attach(MIMEText(text, "plain", "utf-8"))
        message.attach(MIMEText(html_body, "html", "utf-8"))
        if self.settings.smtp_port == 465:
            with smtplib.SMTP_SSL(self.settings.smtp_host, self.settings.smtp_port, timeout=15) as server:
                if self.settings.smtp_user:
                    server.login(self.settings.smtp_user, self.settings.smtp_password)
                server.sendmail(message["From"], self.settings.smtp_to.split(","), message.as_string())
        else:
            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=15) as server:
                server.starttls()
                if self.settings.smtp_user:
                    server.login(self.settings.smtp_user, self.settings.smtp_password)
                server.sendmail(message["From"], self.settings.smtp_to.split(","), message.as_string())


class ApprovalStore:
    def __init__(self, settings: Settings, trace: TraceStore, notifier: NotificationService | None = None):
        self.settings = settings
        self.trace = trace
        self.notifier = notifier or NotificationService(settings)

    async def create(
        self,
        *,
        trace_id: str,
        alert_id: str,
        result: L1Output,
        summary: str | None = None,
    ) -> ApprovalRecord | None:
        destructive = [a.model_dump() for a in result.recommended_actions if a.destructive]
        if not destructive:
            return None
        approval_id = "apr_" + uuid.uuid4().hex[:12]
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = iso(utc_now() + timedelta(hours=self.settings.approval_ttl_hours))
        summary_text = summary or result.summary
        self.trace.create_approval(
            approval_id=approval_id,
            trace_id=trace_id,
            alert_id=alert_id,
            actions=destructive,
            summary=summary_text,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        base = self.settings.approval_public_url.rstrip("/")
        approve_url = (
            f"{base}/approvals/{approval_id}/decide?token={token}&decision=approve&by=email-link"
        )
        reject_url = (
            f"{base}/approvals/{approval_id}/decide?token={token}&decision=reject&by=email-link"
        )
        record = ApprovalRecord(
            approval_id=approval_id,
            trace_id=trace_id,
            alert_id=alert_id,
            token=token,
            approve_url=approve_url,
            reject_url=reject_url,
            status="pending",
            expires_at=expires_at,
            summary=summary_text,
            actions=destructive,
        )
        await self.notifier.send(record)
        return record

    def decide(
        self, approval_id: str, token: str, decision: str, decided_by: str, note: str = ""
    ) -> tuple[bool, str]:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return self.trace.decide_approval(
            approval_id=approval_id,
            token_hash=token_hash,
            decision=decision,
            decided_by=decided_by,
            note=note,
        )

    def get(self, approval_id: str) -> dict[str, Any] | None:
        return self.trace.get_approval(approval_id)

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.trace.list_approvals(limit)


class ApprovalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(..., min_length=1, max_length=64)
    alert_id: str = Field(..., min_length=1, max_length=200)
    result_json: str = Field(..., min_length=2, max_length=30_000)
    summary: str | None = Field(None, max_length=500)
    severity: str | None = Field(None, max_length=20)


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(..., min_length=10, max_length=200)
    decision: str = Field(..., pattern=r"^(approve|reject)$")
    by: str = Field("api", min_length=1, max_length=200)
    note: str = Field("", max_length=1000)


def _check_auth(settings: Settings, authorization: str | None) -> None:
    if not settings.approval_api_token:
        return
    expected = f"Bearer {settings.approval_api_token}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="invalid approval token")


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:760px;margin:48px auto;padding:0 20px;color:#1f2937;background:#f8fafc}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:28px;box-shadow:0 8px 30px rgba(15,23,42,.06)}}
.ok{{color:#047857}} .bad{{color:#b91c1c}} code{{background:#f1f5f9;padding:2px 6px;border-radius:6px}}
a{{color:#1d4ed8}} .muted{{color:#64748b;font-size:14px}}
</style></head><body><div class="card"><h1>{html.escape(title)}</h1>{body}</div></body></html>"""


def create_approval_app(
    settings: Settings,
    trace: TraceStore | None = None,
    store: ApprovalStore | None = None,
) -> FastAPI:
    trace = trace or TraceStore(settings)
    store = store or ApprovalStore(settings, trace)
    app = FastAPI(title="SOC L1 Approval API", version="0.1.0")

    def auth(authorization: str | None = Header(default=None)) -> None:
        _check_auth(settings, authorization)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        items = store.list(500)
        pending = sum(1 for item in items if item.get("status") == "pending")
        return {"ok": True, "service": "approval", "pending": pending}

    @app.post("/approvals", dependencies=[Depends(auth)])
    async def create_approval(payload: ApprovalCreate) -> dict[str, Any]:
        try:
            result = L1Output.model_validate_json(payload.result_json)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"result_json 不符合 L1 Schema: {exc}") from exc
        record = await store.create(
            trace_id=payload.trace_id,
            alert_id=payload.alert_id,
            result=result,
            summary=payload.summary,
        )
        if not record:
            return {"approval_id": None, "status": "not_required", "actions": []}
        response: dict[str, Any] = {
            "approval_id": record.approval_id,
            "status": record.status,
            "expires_at": record.expires_at,
            "summary": record.summary,
            "actions": record.actions,
        }
        if settings.approval_expose_links:
            response["preview"] = {
                "approve_url": record.approve_url,
                "reject_url": record.reject_url,
            }
        return response

    @app.get("/approvals")
    async def list_approvals(
        limit: int = Query(50, ge=1, le=200),
        _: None = Depends(auth),
    ) -> dict[str, Any]:
        return {"items": store.list(limit)}

    @app.get("/approvals/{approval_id}")
    async def get_approval(approval_id: str) -> dict[str, Any]:
        item = store.get(approval_id)
        if not item:
            raise HTTPException(status_code=404, detail="approval not found")
        return item

    @app.get("/approvals/{approval_id}/decide", response_class=HTMLResponse)
    async def decide_by_link(
        approval_id: str,
        token: str = Query(...),
        decision: str = Query(...),
        by: str = Query("email-link"),
        note: str = Query(""),
    ) -> HTMLResponse:
        if decision not in {"approve", "reject"}:
            return HTMLResponse(_page("参数错误", "<p class='bad'>decision 必须是 approve 或 reject。</p>"), status_code=400)
        item = store.get(approval_id)
        if not item:
            return HTMLResponse(_page("审批不存在", "<p class='bad'>未找到该审批记录。</p>"), status_code=404)
        ok, result = store.decide(approval_id, token, decision, by, note)
        if not ok:
            reason = {
                "already_decided": "该审批已处理，不能重复提交。",
                "invalid_token": "链接无效或已被使用。",
                "expired": "审批已过期。",
                "not_found": "审批不存在。",
                "invalid_decision": "审批动作不合法。",
            }.get(result, result)
            return HTMLResponse(_page("审批失败", f"<p class='bad'>{html.escape(reason)}</p>"), status_code=400)
        label = "已批准" if decision == "approve" else "已拒绝"
        body = (
            f"<p class='ok'><b>{label}</b></p>"
            f"<p>审批号：<code>{html.escape(approval_id)}</code></p>"
            f"<p class='muted'>这是一条单次有效的审批记录；L1 不会执行任何阻断动作，"
            f"L2 执行器仍需校验本审批结果。</p>"
        )
        return HTMLResponse(_page(f"审批{label}", body))

    @app.post("/approvals/{approval_id}/decide")
    async def decide_by_api(approval_id: str, payload: DecisionBody) -> dict[str, Any]:
        ok, result = store.decide(
            approval_id, payload.token, payload.decision, payload.by, payload.note
        )
        if not ok:
            raise HTTPException(status_code=400, detail=result)
        return {"ok": True, "approval_id": approval_id, "status": payload.decision}

    return app
