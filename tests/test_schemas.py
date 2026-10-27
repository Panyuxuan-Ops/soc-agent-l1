from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from soc_agent.models import L1Output

ROOT = Path(__file__).resolve().parents[1]


def test_exported_schemas_exist_and_validate():
    output_schema_path = ROOT / "schemas" / "l1_output.schema.json"
    fetch_schema_path = ROOT / "schemas" / "tool_fetch_wazuh_alerts.schema.json"
    search_schema_path = ROOT / "schemas" / "tool_search_attack_knowledge.schema.json"
    for path in (output_schema_path, fetch_schema_path, search_schema_path):
        assert path.exists(), path
        json.loads(path.read_text(encoding="utf-8"))

    schema = json.loads(output_schema_path.read_text(encoding="utf-8"))
    payload = {
        "decision": "watch",
        "confidence": 0.7,
        "reason": "测试",
        "evidence": [
            {"tool": "alert_rule", "params": {}, "key_finding": "level=6"}
        ],
    }
    jsonschema.validate(payload, schema)


def test_output_schema_forbids_extra_properties():
    schema = L1Output.model_json_schema()
    assert schema.get("additionalProperties") is False


def test_tool_schemas_forbid_extra_properties():
    for name in ("tool_fetch_wazuh_alerts", "tool_search_attack_knowledge"):
        data = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))
        assert data["function"]["parameters"]["additionalProperties"] is False
