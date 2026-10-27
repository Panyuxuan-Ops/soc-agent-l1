from __future__ import annotations

import pytest
from pydantic import ValidationError

from soc_agent.models import (
    EvidenceItem,
    FetchAlertsArgs,
    L1Output,
    MitreTechnique,
    RecommendedAction,
    SearchKnowledgeArgs,
)


def base_output(**overrides):
    data = {
        "alert_id": "wazuh-1001",
        "trace_id": "trc_0123456789abcdef",
        "verdict": "watch",
        "risk_score": 40,
        "confidence": 0.7,
        "summary": "测试摘要",
        "reason": "测试理由",
        "evidence": [{"source": "alert_rule", "detail": "rule.level=6"}],
        "mitre_techniques": [{"technique_id": "T1110", "name": "Brute Force"}],
        "recommended_actions": [
            {"action": "monitor", "target": "10.0.0.1", "reason": "观察"}
        ],
        "tool_calls_used": 2,
        "requires_human_approval": False,
        "escalate_to_l2": False,
        "limitations": ["测试"],
    }
    data.update(overrides)
    return data


def test_valid_output():
    output = L1Output.model_validate(base_output())
    assert output.verdict == "watch"
    assert output.mitre_techniques[0].technique_id == "T1110"


def test_lowercase_mitre_id_normalized():
    output = L1Output.model_validate(
        base_output(mitre_techniques=[{"technique_id": "t1110", "name": "Brute Force"}])
    )
    assert output.mitre_techniques[0].technique_id == "T1110"


def test_extra_field_rejected():
    data = base_output()
    data["unexpected"] = "x"
    with pytest.raises(ValidationError):
        L1Output.model_validate(data)


def test_destructive_action_requires_flags():
    with pytest.raises(ValidationError):
        RecommendedAction(action="block_ip", target="1.2.3.4", reason="阻断")
    action = RecommendedAction(
        action="block_ip",
        target="1.2.3.4",
        destructive=True,
        requires_approval=True,
        reason="阻断",
    )
    assert action.destructive is True


def test_destructive_action_requires_target():
    with pytest.raises(ValidationError):
        RecommendedAction(
            action="isolate_host",
            destructive=True,
            requires_approval=True,
            reason="隔离",
        )


def test_human_approval_must_match_destructive():
    data = base_output(
        verdict="escalate",
        escalate_to_l2=True,
        requires_human_approval=False,
        recommended_actions=[
            {"action": "escalate_l2", "target": "wazuh-1001", "reason": "转 L2"},
            {
                "action": "block_ip",
                "target": "1.2.3.4",
                "destructive": True,
                "requires_approval": True,
                "reason": "阻断",
            },
        ],
    )
    with pytest.raises(ValidationError):
        L1Output.model_validate(data)


def test_escalate_must_have_escalate_action():
    data = base_output(
        verdict="escalate",
        escalate_to_l2=True,
        requires_human_approval=False,
        recommended_actions=[{"action": "monitor", "target": "x", "reason": "观察"}],
    )
    with pytest.raises(ValidationError):
        L1Output.model_validate(data)


def test_non_escalate_cannot_escalate_l2():
    data = base_output(
        verdict="watch",
        recommended_actions=[{"action": "escalate_l2", "target": "x", "reason": "转"}],
    )
    with pytest.raises(ValidationError):
        L1Output.model_validate(data)


def test_fetch_args_extra_rejected_and_ip_validated():
    with pytest.raises(ValidationError):
        FetchAlertsArgs(limit=5, unexpected=True)
    with pytest.raises(ValidationError):
        FetchAlertsArgs(src_ip="999.1.1.1")
    assert FetchAlertsArgs(src_ip="203.0.113.45").src_ip == "203.0.113.45"


def test_search_args_required_query():
    with pytest.raises(ValidationError):
        SearchKnowledgeArgs(query="   ")
    assert SearchKnowledgeArgs(query="T1110").top_k == 3


def test_evidence_source_literal():
    with pytest.raises(ValidationError):
        EvidenceItem(source="shell", detail="x")
    with pytest.raises(ValidationError):
        MitreTechnique(technique_id="1110", name="bad")


def test_standard_output_rejects_noncompliant_json():
    valid = {
        "decision": "close",
        "confidence": 0.9,
        "reason": "等级低且无源 IP，按噪声关闭。",
        "evidence": [
            {
                "tool": "alert_rule",
                "params": {"rule_id": "31151"},
                "key_finding": "rule.level=3, src_ip=None",
            }
        ],
    }
    output = L1Output.model_validate(valid)
    assert output.decision == "close"
    assert output.evidence[0].tool == "alert_rule"
    assert output.evidence[0].key_finding.startswith("rule.level=3")

    invalid = [
        {**valid, "decision": "ignore"},
        {**valid, "confidence": 1.5},
        {**valid, "reason": "x" * 51},
        {**valid, "evidence": [{"tool": "alert_rule", "key_finding": "缺 params"}]},
        {**valid, "evidence": [{"tool": "shell", "params": {}, "key_finding": "非法工具"}]},
        {**valid, "unexpected": "x"},
    ]
    for payload in invalid:
        with pytest.raises(ValidationError):
            L1Output.model_validate(payload)

    with pytest.raises(ValidationError):
        L1Output.model_validate_json('{"decision": "close",')
