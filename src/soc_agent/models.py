"""严格的数据契约。

对外 L1 输出（``L1Output``）固定为四个字段：

``decision / confidence / reason / evidence``

并对 ``additionalProperties`` 做严格禁止。为了兼容现有审批、Trace 和旧测试，
模型内部仍可读取旧版富字段（``verdict / risk_score / recommended_actions`` 等），
但这些字段不会出现在导出的 JSON Schema 中，也不会要求 LLM 输出。

Function Calling 的工具参数同样使用 Pydantic 模型 + ``extra="forbid"``。
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

Verdict = Literal["close", "watch", "escalate"]

DESTRUCTIVE_ACTIONS = frozenset(
    {"block_ip", "isolate_host", "reset_credentials", "disable_account"}
)
ALLOWED_ACTIONS = frozenset(
    {
        "close_alert",
        "monitor",
        "collect_evidence",
        "escalate_l2",
        "notify_owner",
        *DESTRUCTIVE_ACTIONS,
    }
)

# 旧版输出字段：只在兼容读取时使用，不进入对外 Schema。
_LEGACY_FIELDS = frozenset(
    {
        "schema_version",
        "alert_id",
        "trace_id",
        "verdict",
        "risk_score",
        "summary",
        "mitre_techniques",
        "recommended_actions",
        "tool_calls_used",
        "requires_human_approval",
        "escalate_to_l2",
        "limitations",
    }
)

# evidence.tool 允许的来源；policy 用于放“建议动作”，不表示已执行。
EvidenceTool = Literal[
    "fetch_wazuh_alerts",
    "search_attack_knowledge",
    "alert_rule",
    "policy",
]


class FetchAlertsArgs(BaseModel):
    """fetch_wazuh_alerts 的参数；未声明的字段一律拒绝。"""

    model_config = ConfigDict(extra="forbid")

    limit: int = Field(5, ge=1, le=20, description="返回条数，默认 5，最大 20")
    min_level: int | None = Field(
        None, ge=0, le=16, description="最低 Wazuh rule.level；不传则不过滤"
    )
    src_ip: str | None = Field(
        None, min_length=2, max_length=64, description="源 IP（IPv4 或 IPv6）"
    )

    @field_validator("src_ip")
    @classmethod
    def _valid_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("src_ip 不能为空字符串")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(f"非法 IP 地址: {value}") from exc


class SearchKnowledgeArgs(BaseModel):
    """search_attack_knowledge 的参数。"""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(
        ..., min_length=1, max_length=500, description="告警关键词或技术 ID"
    )
    top_k: int = Field(3, ge=1, le=10, description="返回条数，默认 3")

    @field_validator("query")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("query 不能为空")
        return value


class MitreTechnique(BaseModel):
    """内部/旧版富输出使用；新标准输出不再单独列出 MITRE 字段。"""

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(..., pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str = Field(..., min_length=1, max_length=120)
    tactic: str | None = Field(None, max_length=80)
    url: str | None = Field(None, max_length=300)
    confidence: float = Field(0.5, ge=0.0, le=1.0)

    @field_validator("technique_id", mode="before")
    @classmethod
    def _upper_id(cls, value: str) -> str:
        return value.strip().upper() if isinstance(value, str) else value


class EvidenceItem(BaseModel):
    """标准 evidence 项：工具名、调用参数、关键发现。"""

    model_config = ConfigDict(extra="forbid")

    tool: EvidenceTool = Field(..., description="证据来源/工具名")
    params: dict[str, Any] = Field(..., description="工具调用参数；无参数时传空对象")
    key_finding: str = Field(..., min_length=1, max_length=500, description="关键发现")

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        legacy_shape = any(key in data for key in ("source", "detail", "tool_call_index"))
        if "tool" not in data and "source" in data:
            data["tool"] = data.pop("source")
        if "key_finding" not in data and "detail" in data:
            data["key_finding"] = data.pop("detail")
        params = data.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise ValueError("evidence.params 必须是 object")
        if "tool_call_index" in data:
            index = data.pop("tool_call_index")
            if index is not None:
                params = {**params, "tool_call_index": index}
        if legacy_shape or "params" in data:
            data["params"] = params
        return data

    @property
    def source(self) -> str:
        """旧版字段兼容。"""

        return self.tool

    @property
    def detail(self) -> str:
        """旧版字段兼容。"""

        return self.key_finding


class RecommendedAction(BaseModel):
    """内部/旧版富输出使用的建议动作；新标准输出通过 policy evidence 携带。"""

    model_config = ConfigDict(extra="forbid")

    action: Literal[
        "close_alert",
        "monitor",
        "collect_evidence",
        "escalate_l2",
        "notify_owner",
        "block_ip",
        "isolate_host",
        "reset_credentials",
        "disable_account",
    ]
    target: str | None = Field(None, max_length=200)
    destructive: bool = False
    requires_approval: bool = False
    reason: str = Field(..., min_length=1, max_length=300)

    @model_validator(mode="after")
    def _safety(self) -> "RecommendedAction":
        if self.action in DESTRUCTIVE_ACTIONS:
            if not self.target:
                raise ValueError(f"{self.action} 必须给出 target")
            if not self.destructive:
                raise ValueError(f"{self.action} 必须标记 destructive=true")
            if not self.requires_approval:
                raise ValueError(f"{self.action} 必须 requires_approval=true")
        elif self.destructive:
            raise ValueError(f"非破坏性动作 {self.action} 不应标记 destructive=true")
        return self


class L1Output(BaseModel):
    """标准 L1 输出：decision / confidence / reason / evidence。"""

    model_config = ConfigDict(extra="forbid")

    decision: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str = Field(..., min_length=1, max_length=50, description="不超过 50 字")
    evidence: list[EvidenceItem] = Field(..., max_length=8)

    _legacy: dict[str, Any] = PrivateAttr(default_factory=dict)
    _context: dict[str, str] = PrivateAttr(default_factory=dict)

    @model_validator(mode="wrap")
    @classmethod
    def _compat_input(cls, data: Any, handler: Any) -> Any:
        if not isinstance(data, dict):
            return handler(data)

        raw = dict(data)
        legacy: dict[str, Any] = {}
        legacy_mode = "decision" not in raw and "verdict" in raw

        if legacy_mode:
            for key in _LEGACY_FIELDS:
                if key in raw:
                    legacy[key] = raw.pop(key)
            if "reason" in raw:
                legacy["full_reason"] = raw.pop("reason")
            raw["decision"] = legacy.get("verdict")
            source_reason = legacy.get("summary") or legacy.get("full_reason") or ""
            raw["reason"] = str(source_reason).strip()[:50] or "证据不足，转人工复核。"
            raw.setdefault("confidence", 0.5)
            raw.setdefault("evidence", [])
        else:
            # 标准输入也允许携带旧 Trace 上下文；只读取，不要求。
            for key in _LEGACY_FIELDS:
                if key in raw:
                    legacy[key] = raw.pop(key)

        output = handler(raw)
        output._legacy = to_jsonable_python(legacy)
        if legacy_mode:
            output._validate_legacy()
        return output

    def _validate_legacy(self) -> None:
        """旧版富字段的一致性校验，保持原有安全约束。"""

        verdict = self._legacy.get("verdict")
        if verdict is not None and verdict != self.decision:
            raise ValueError("旧版 verdict 与 decision 不一致")

        raw_actions = self._legacy.get("recommended_actions") or []
        if not isinstance(raw_actions, list):
            raise ValueError("recommended_actions 必须是数组")
        actions = [RecommendedAction.model_validate(item) for item in raw_actions]
        destructive = any(action.destructive for action in actions)

        if (
            "requires_human_approval" in self._legacy
            and bool(self._legacy["requires_human_approval"]) != destructive
        ):
            raise ValueError("requires_human_approval 必须等于是否存在破坏性建议")
        if (
            "escalate_to_l2" in self._legacy
            and bool(self._legacy["escalate_to_l2"]) != (verdict == "escalate")
        ):
            raise ValueError("escalate_to_l2 必须与 verdict=escalate 保持一致")

        has_escalate = any(action.action == "escalate_l2" for action in actions)
        if verdict == "escalate" and not has_escalate:
            raise ValueError("verdict=escalate 时必须包含 escalate_l2 建议")
        if verdict != "escalate" and has_escalate:
            raise ValueError("非 escalate 裁决不能包含 escalate_l2 建议")

    def bind_context(self, *, alert_id: str | None = None, trace_id: str | None = None) -> None:
        """绑定调用上下文；不写入对外 JSON Schema。"""

        if alert_id:
            self._context["alert_id"] = str(alert_id)
        if trace_id:
            self._context["trace_id"] = str(trace_id)

    # ---- 旧版字段兼容属性 ----
    @property
    def verdict(self) -> str:
        return self.decision

    @property
    def alert_id(self) -> str:
        return self._context.get("alert_id") or str(self._legacy.get("alert_id") or "")

    @property
    def trace_id(self) -> str:
        return self._context.get("trace_id") or str(self._legacy.get("trace_id") or "")

    @property
    def schema_version(self) -> str:
        return str(self._legacy.get("schema_version") or "1.0")

    @property
    def summary(self) -> str:
        return str(self._legacy.get("summary") or self.reason)

    @property
    def risk_score(self) -> int:
        if "risk_score" in self._legacy:
            try:
                return max(0, min(100, int(self._legacy["risk_score"])))
            except (TypeError, ValueError):
                pass
        return {"close": 5, "watch": 50, "escalate": 80}.get(self.decision, 50)

    @property
    def mitre_techniques(self) -> list[MitreTechnique]:
        raw = self._legacy.get("mitre_techniques") or []
        if not isinstance(raw, list):
            return []
        return [MitreTechnique.model_validate(item) for item in raw]

    @property
    def recommended_actions(self) -> list[RecommendedAction]:
        raw = self._legacy.get("recommended_actions")
        if isinstance(raw, list):
            return [RecommendedAction.model_validate(item) for item in raw]

        # 标准输出：policy evidence 的 params 可携带建议动作。
        actions: list[RecommendedAction] = []
        for item in self.evidence:
            if item.tool != "policy":
                continue
            action = item.params.get("action")
            if not isinstance(action, str) or not action:
                continue
            payload = {
                "action": action,
                "target": item.params.get("target"),
                "destructive": bool(item.params.get("destructive", False)),
                "requires_approval": bool(item.params.get("requires_approval", False)),
                "reason": item.key_finding,
            }
            try:
                actions.append(RecommendedAction.model_validate(payload))
            except ValueError:
                # 非法建议动作不进入审批，避免模型输出导致执行链异常。
                continue
        return actions

    @property
    def tool_calls_used(self) -> int:
        if "tool_calls_used" in self._legacy:
            try:
                return max(0, min(3, int(self._legacy["tool_calls_used"])))
            except (TypeError, ValueError):
                pass
        count = sum(
            1
            for item in self.evidence
            if item.tool in ("fetch_wazuh_alerts", "search_attack_knowledge")
        )
        return min(3, count)

    @property
    def requires_human_approval(self) -> bool:
        if "requires_human_approval" in self._legacy:
            return bool(self._legacy["requires_human_approval"])
        return any(action.destructive for action in self.recommended_actions)

    @property
    def escalate_to_l2(self) -> bool:
        if "escalate_to_l2" in self._legacy:
            return bool(self._legacy["escalate_to_l2"])
        return self.decision == "escalate"

    @property
    def limitations(self) -> list[str]:
        raw = self._legacy.get("limitations") or []
        return [str(item) for item in raw] if isinstance(raw, list) else []

    def to_standard_dict(self) -> dict[str, Any]:
        """只输出四字段标准格式，供 Dify/MockDify 的 ``result_json`` 使用。

        旧版破坏性建议会折叠成 ``policy`` evidence，审批仍可从标准输出中恢复。
        """

        items = [item.model_dump() for item in self.evidence]
        seen = {
            (
                item.params.get("action"),
                item.params.get("target"),
            )
            for item in self.evidence
            if item.tool == "policy"
        }
        for action in self.recommended_actions:
            if not action.destructive:
                continue
            key = (action.action, action.target)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                {
                    "tool": "policy",
                    "params": {
                        "action": action.action,
                        "target": action.target,
                        "destructive": True,
                        "requires_approval": True,
                    },
                    "key_finding": action.reason,
                }
            )
        return {
            "decision": self.decision,
            "confidence": self.confidence,
            "reason": self.reason,
            "evidence": items[:8],
        }

    # ---- 序列化兼容 ----
    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        data = super().model_dump(*args, **kwargs)
        if kwargs.get("include") is None and kwargs.get("exclude") is None:
            for key, value in self._legacy.items():
                if key == "full_reason":
                    continue
                data.setdefault(key, value)
        return data

    def model_dump_json(self, *args: Any, **kwargs: Any) -> str:
        # 保持旧测试/HTTP 审批请求可读取富字段；标准 Dify 输出没有 legacy。
        return json.dumps(self.model_dump(*args, **kwargs), ensure_ascii=False, default=str)


@dataclass(slots=True)
class AlertView:
    """归一化后的只读告警视图。"""

    alert_id: str
    timestamp: str
    rule_id: str
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    src_ip: str | None
    dst_user: str | None
    full_log: str
    location: str
    mitre_ids: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def has_src_ip(self) -> bool:
        return bool(self.src_ip)

    def brief(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "rule": {
                "id": self.rule_id,
                "level": self.rule_level,
                "description": self.rule_description,
                "mitre_ids": self.mitre_ids,
                "groups": self.groups,
            },
            "agent": {"id": self.agent_id, "name": self.agent_name},
            "data": {"src_ip": self.src_ip, "dst_user": self.dst_user},
            "location": self.location,
            "full_log": self.full_log,
        }
