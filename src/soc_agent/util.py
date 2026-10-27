"""通用工具函数。"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from copy import deepcopy
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any

_SENSITIVE_KEY = re.compile(r"(pass(word|wd)?|secret|token|authorization|api[_-]?key|cookie)", re.I)
_SECRET_IN_TEXT = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization)\b(\s*[:=]\s*)([^\s,;\"']+)"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    dt = dt or utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def new_trace_id() -> str:
    return "trc_" + secrets.token_hex(8)


def stable_hash(*parts: Any, length: int = 16) -> str:
    raw = "|".join(str(part) for part in parts).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:length]


def json_dumps(value: Any, *, pretty: bool = False) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        default=str,
    )


def strip_code_fence(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def sanitize_text(text: Any, limit: int = 4000) -> str:
    value = "" if text is None else str(text)
    value = _CONTROL.sub("", value)
    value = _SECRET_IN_TEXT.sub(lambda m: f"{m.group(1)}{m.group(2)}***", value)
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value


def redact(value: Any, *, max_text: int = 4000) -> Any:
    """递归脱敏，用于 trace 落盘；不修改原始告警。"""

    if hasattr(value, "model_dump") and callable(value.model_dump):
        return redact(value.model_dump(), max_text=max_text)
    if is_dataclass(value) and not isinstance(value, type):
        return redact(asdict(value), max_text=max_text)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _SENSITIVE_KEY.search(key_text):
                result[key_text] = "***"
            else:
                result[key_text] = redact(item, max_text=max_text)
        return result
    if isinstance(value, list):
        return [redact(item, max_text=max_text) for item in value[:50]]
    if isinstance(value, str):
        return sanitize_text(value, max_text)
    return value


def deep_sanitize_alert(alert: dict[str, Any], *, log_limit: int = 2000) -> dict[str, Any]:
    """发给 LLM 前的告警脱敏与截断。"""

    copy = redact(deepcopy(alert), max_text=log_limit)
    full_log = copy.get("full_log")
    if isinstance(full_log, str) and len(full_log) > log_limit:
        copy["full_log"] = full_log[: log_limit - 3] + "..."
    return copy


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
