"""Wazuh 告警归一化、脱敏与提示词注入防护。"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from typing import Any

from .models import AlertView
from .util import deep_sanitize_alert, iso, parse_iso, sanitize_text, stable_hash, utc_now

_IP_SPLIT = re.compile(r"[\s,;]+")


def _first_ip(value: Any) -> str | None:
    if value is None:
        return None
    candidates: list[Any]
    if isinstance(value, (list, tuple)):
        candidates = list(value)
    else:
        candidates = _IP_SPLIT.split(str(value))
    for candidate in candidates:
        text = str(candidate).strip().strip("[]")
        if not text:
            continue
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            continue
    return None


def _mitre_ids(rule: dict[str, Any]) -> list[str]:
    mitre = rule.get("mitre")
    values: list[Any] = []
    if isinstance(mitre, dict):
        raw = mitre.get("id") or mitre.get("technique_id") or []
        values = raw if isinstance(raw, list) else [raw]
    elif isinstance(mitre, list):
        for item in mitre:
            if isinstance(item, dict):
                values.append(item.get("id"))
            else:
                values.append(item)
    elif isinstance(mitre, str):
        values = [mitre]
    # 兼容 alert_for_llm 的压缩格式 rule.mitre_ids
    if not values:
        compact = rule.get("mitre_ids")
        if isinstance(compact, list):
            values = compact
        elif compact:
            values = [compact]
    result: list[str] = []
    for value in values:
        text = str(value or "").strip().upper()
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", text) and text not in result:
            result.append(text)
    return result


def normalize_alert(raw: dict[str, Any], now: datetime | None = None) -> AlertView:
    """把 Wazuh 的宽松 JSON 转成稳定视图。

    对缺失字段保持宽容（不同 Wazuh 版本字段有差异），但保留原始告警的
    rule.level / rule.description / agent.name / data.srcip / full_log。
    """

    if not isinstance(raw, dict):
        raise ValueError("告警必须是 JSON object")

    now = now or utc_now()
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}

    level_raw = rule.get("level", raw.get("level", 0))
    try:
        level = int(level_raw)
    except (TypeError, ValueError):
        level = 0
    level = max(0, min(16, level))

    src_ip = _first_ip(
        data.get("srcip")
        or data.get("src_ip")
        or data.get("src_ipv4")
        or data.get("src_ipv6")
        or (data.get("win", {}).get("eventdata", {}) if isinstance(data.get("win"), dict) else {}).get(
            "ipAddress"
        )
        or raw.get("srcip")
    )

    dst_user = (
        data.get("dstuser")
        or data.get("dst_user")
        or (
            data.get("win", {}).get("eventdata", {})
            if isinstance(data.get("win"), dict)
            else {}
        ).get("targetUserName")
    )

    timestamp_raw = raw.get("timestamp") or raw.get("@timestamp")
    try:
        timestamp = iso(parse_iso(str(timestamp_raw))) if timestamp_raw else iso(now)
    except ValueError:
        timestamp = iso(now)

    alert_id = str(raw.get("id") or raw.get("alert_id") or "").strip()
    if not alert_id:
        alert_id = "wazuh-" + stable_hash(
            timestamp, rule.get("id"), rule.get("level"), agent.get("name"), src_ip
        )
    alert_id = sanitize_text(alert_id, 200)

    groups = raw.get("rule", {}).get("groups") if isinstance(raw.get("rule"), dict) else []
    if not isinstance(groups, list):
        groups = [groups] if groups else []

    description = sanitize_text(rule.get("description") or raw.get("description") or "unknown", 500)
    full_log = sanitize_text(raw.get("full_log") or raw.get("log") or "", 2000)

    return AlertView(
        alert_id=alert_id,
        timestamp=timestamp,
        rule_id=sanitize_text(rule.get("id") or "", 64),
        rule_level=level,
        rule_description=description,
        agent_id=sanitize_text(agent.get("id") or "", 64),
        agent_name=sanitize_text(agent.get("name") or "", 200),
        src_ip=src_ip,
        dst_user=sanitize_text(dst_user, 200) if dst_user else None,
        full_log=full_log,
        location=sanitize_text(raw.get("location") or "", 300),
        mitre_ids=_mitre_ids(rule),
        groups=[sanitize_text(g, 100) for g in groups[:20]],
        raw=raw,
    )


def alert_for_llm(raw: dict[str, Any], max_log: int = 2000) -> dict[str, Any]:
    """发送给 Dify / LLM 前的最小化 + 脱敏版本。"""

    sanitized = deep_sanitize_alert(raw, log_limit=max_log)
    # 只保留分诊需要的字段，降低 token 与提示注入面
    view = normalize_alert(sanitized)
    return view.brief()


def alert_json_for_llm(raw: dict[str, Any], max_log: int = 2000) -> str:
    return json.dumps(alert_for_llm(raw, max_log=max_log), ensure_ascii=False, separators=(",", ":"))
