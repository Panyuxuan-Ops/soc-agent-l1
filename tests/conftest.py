from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_agent.approval import ApprovalStore  # noqa: E402
from soc_agent.config import Settings  # noqa: E402
from soc_agent.knowledge import create_knowledge_backend  # noqa: E402
from soc_agent.tool_service import ToolService  # noqa: E402
from soc_agent.trace import TraceStore  # noqa: E402
from soc_agent.wazuh import create_wazuh_backend  # noqa: E402


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    base = Settings.for_test(tmp_path)
    result = replace(
        base,
        project_root=ROOT,
        approval_public_url="http://testserver",
        approval_base_url="http://testserver",
        approval_expose_links=True,
        bridge_token="",
        tool_api_token="",
        approval_api_token="",
        dify_mock_api_key="test-mock-key",
    )
    result.ensure_dirs()
    return result


@pytest.fixture()
def trace(settings: Settings) -> TraceStore:
    return TraceStore(settings)


@pytest.fixture()
async def tools(settings: Settings):
    service = ToolService(
        settings,
        create_wazuh_backend(settings),
        create_knowledge_backend(settings),
    )
    yield service
    await service.close()


@pytest.fixture()
def approvals(settings: Settings, trace: TraceStore) -> ApprovalStore:
    return ApprovalStore(settings, trace)


def load_samples(limit: int = 5) -> list[dict]:
    with (ROOT / "data" / "sample_alerts.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)[:limit]
