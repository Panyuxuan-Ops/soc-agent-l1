"""Wazuh 查询后端：mock（本地演示）与 Wazuh Indexer（生产）。"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx

from .config import Settings
from .log import get_logger
from .util import iso, utc_now

log = get_logger("wazuh")


@dataclass(slots=True)
class WazuhSearchResult:
    window_minutes: int
    total: int
    alerts: list[dict[str, Any]] = field(default_factory=list)
    unique_src_ips: int = 0
    max_level: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    source: str = "mock"


class MockWazuhBackend:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.path = Path(settings.project_root) / "data" / "mock_alerts.json"
        if not self.path.exists():
            self.path = Path(settings.data_dir) / "mock_alerts.json"

    def _load(self) -> list[dict[str, Any]]:
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError("mock_alerts.json 必须是数组")
        return data

    async def search(
        self,
        *,
        limit: int,
        min_level: int | None,
        src_ip: str | None,
        now=None,
    ) -> WazuhSearchResult:
        now = now or utc_now()
        window = self.settings.wazuh_window_minutes
        matched: list[dict[str, Any]] = []
        for item in self._load():
            alert = dict(item)
            offset = int(alert.pop("_demo_offset_minutes", 0))
            if offset > window:
                continue
            alert["timestamp"] = iso(now - timedelta(minutes=offset))
            level = int((alert.get("rule") or {}).get("level") or 0)
            if min_level is not None and level < min_level:
                continue
            item_src = str((alert.get("data") or {}).get("srcip") or "")
            if src_ip and item_src != src_ip:
                continue
            matched.append(alert)
        matched.sort(key=lambda a: str(a.get("timestamp", "")), reverse=True)
        stats = summarize(matched)
        return WazuhSearchResult(
            window_minutes=window,
            total=len(matched),
            alerts=matched[:limit],
            unique_src_ips=stats["unique_src_ips"],
            max_level=stats["max_level"],
            first_seen=stats["first_seen"],
            last_seen=stats["last_seen"],
            source="mock",
        )

    async def close(self) -> None:
        return None


class IndexerWazuhBackend:
    """Wazuh Indexer / OpenSearch 查询。

    只读，查询窗口由服务端固定为 ``WAZUH_WINDOW_MINUTES``，
    不接受模型传入任意时间范围或 URL。
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = httpx.AsyncClient(
            base_url=settings.wazuh_indexer_url,
            auth=(settings.wazuh_indexer_user, settings.wazuh_indexer_password),
            verify=settings.wazuh_verify_tls,
            timeout=httpx.Timeout(10.0),
        )

    async def search(
        self,
        *,
        limit: int,
        min_level: int | None,
        src_ip: str | None,
        now=None,
    ) -> WazuhSearchResult:
        window = self.settings.wazuh_window_minutes
        filters: list[dict[str, Any]] = [
            {"range": {"@timestamp": {"gte": f"now-{window}m"}}},
        ]
        if min_level is not None:
            filters.append({"range": {"rule.level": {"gte": min_level}}})
        if src_ip:
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"data.srcip": src_ip}},
                            {"term": {"data.src_ip": src_ip}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )
        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}},
        }
        response = await self.client.post(
            f"/{self.settings.wazuh_indexer_index}/_search",
            json=body,
        )
        response.raise_for_status()
        payload = response.json()
        hits = ((payload.get("hits") or {}).get("hits")) or []
        alerts: list[dict[str, Any]] = []
        for hit in hits:
            source = hit.get("_source") or {}
            source.setdefault("id", hit.get("_id"))
            alerts.append(source)
        stats = summarize(alerts)
        return WazuhSearchResult(
            window_minutes=window,
            total=int(((payload.get("hits") or {}).get("total") or {}).get("value", len(alerts)))
            if isinstance((payload.get("hits") or {}).get("total"), dict)
            else int((payload.get("hits") or {}).get("total") or len(alerts)),
            alerts=alerts,
            unique_src_ips=stats["unique_src_ips"],
            max_level=stats["max_level"],
            first_seen=stats["first_seen"],
            last_seen=stats["last_seen"],
            source="wazuh-indexer",
        )

    async def close(self) -> None:
        await self.client.aclose()


def summarize(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    src_ips: set[str] = set()
    levels: list[int] = []
    timestamps: list[str] = []
    for alert in alerts:
        data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
        src = data.get("srcip") or data.get("src_ip")
        if src:
            src_ips.add(str(src))
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        try:
            levels.append(int(rule.get("level") or 0))
        except (TypeError, ValueError):
            levels.append(0)
        ts = alert.get("timestamp") or alert.get("@timestamp")
        if ts:
            timestamps.append(str(ts))
    return {
        "unique_src_ips": len(src_ips),
        "max_level": max(levels) if levels else 0,
        "first_seen": min(timestamps) if timestamps else None,
        "last_seen": max(timestamps) if timestamps else None,
    }


def create_wazuh_backend(settings: Settings) -> MockWazuhBackend | IndexerWazuhBackend:
    if settings.wazuh_mode == "indexer":
        return IndexerWazuhBackend(settings)
    return MockWazuhBackend(settings)
