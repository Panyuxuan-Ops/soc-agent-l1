from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_dify_dsl_structure_and_code_compiles():
    path = ROOT / "dify" / "l1-triage.workflow.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["kind"] == "app"
    assert data["version"] == "0.7.0"
    graph = data["workflow"]["graph"]
    node_ids = {node["id"] for node in graph["nodes"]}
    assert {"start", "normalize", "agent", "validate", "approval", "end"} <= node_ids
    for edge in graph["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids

    nodes = {node["id"]: node for node in graph["nodes"]}
    assert nodes["start"]["data"]["type"] == "start"
    assert nodes["agent"]["data"]["type"] == "agent"
    assert nodes["agent"]["data"]["agent_parameters"]["tools"]["value"] == []
    assert nodes["approval"]["data"]["type"] == "http-request"
    assert nodes["end"]["data"]["type"] == "end"

    for node in graph["nodes"]:
        if node["data"]["type"] == "code":
            compile(node["data"]["code"], f"<dify-{node['id']}>", "exec")

    instruction = nodes["agent"]["data"]["agent_parameters"]["instruction"]["value"]
    assert "最多 3 次" in instruction
    assert "不可信数据" in instruction
    assert "破坏性建议" in instruction
