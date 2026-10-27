"""MITRE ATT&CK + IOC 轻量检索。

生产：调用 Dify 知识库 Retrieve API（Dify 持有向量库）。
演示：本地 BM25，零额外服务，保证 4GB 云主机不引入重型 JVM 组件。
"""

from __future__ import annotations

import csv
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .config import Settings
from .log import get_logger
from .util import sanitize_text

log = get_logger("knowledge")

_TOKEN_RE = re.compile(r"[a-z0-9_.\-]{2,}")
_CJK_RE = re.compile(r"[\u4e00-\u9fff]+")
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def tokenize(text: str) -> list[str]:
    lowered = text.lower()
    tokens = _TOKEN_RE.findall(lowered)
    for seq in _CJK_RE.findall(lowered):
        if len(seq) == 1:
            tokens.append(seq)
        else:
            tokens.extend(seq[i : i + 2] for i in range(len(seq) - 1))
    return tokens


@dataclass(slots=True)
class KnowledgeDoc:
    doc_id: str
    doc_type: str
    title: str
    content: str
    url: str | None = None
    tactics: list[str] | None = None
    technique_id: str | None = None
    raw: dict[str, Any] | None = None


@dataclass(slots=True)
class KnowledgeSearchResult:
    query: str
    top_k: int
    results: list[dict[str, Any]]
    backend: str


class LocalKnowledgeBackend:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.docs: list[KnowledgeDoc] = []
        self._load_attack()
        self._load_iocs()
        self._build_index()

    def _load_attack(self) -> None:
        path = Path(self.settings.project_root) / "data" / "attack_techniques.json"
        if not path.exists():
            path = Path(self.settings.data_dir) / "attack_techniques.json"
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data:
            keywords = " ".join(item.get("keywords") or [])
            content = " ".join(
                [
                    item.get("name", ""),
                    " ".join(item.get("tactics") or []),
                    keywords,
                    item.get("description", ""),
                    item.get("detection", ""),
                ]
            )
            self.docs.append(
                KnowledgeDoc(
                    doc_id=item["technique_id"],
                    doc_type="attack",
                    title=f"{item['technique_id']} - {item['name']}",
                    content=content,
                    url=item.get("url"),
                    tactics=item.get("tactics") or [],
                    technique_id=item["technique_id"],
                    raw=item,
                )
            )

    def _load_iocs(self) -> None:
        path = Path(self.settings.project_root) / "data" / "iocs.csv"
        if not path.exists():
            path = Path(self.settings.data_dir) / "iocs.csv"
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                value = (row.get("value") or "").strip()
                if not value:
                    continue
                content = " ".join(
                    [
                        value,
                        row.get("type", ""),
                        row.get("threat", ""),
                        row.get("source", ""),
                        row.get("note", ""),
                    ]
                )
                self.docs.append(
                    KnowledgeDoc(
                        doc_id=f"ioc:{value}",
                        doc_type="ioc",
                        title=value,
                        content=content,
                        url=None,
                        raw=row,
                    )
                )

    def _build_index(self) -> None:
        self._term_freq: list[dict[str, int]] = []
        self._doc_len: list[int] = []
        self._doc_freq: dict[str, int] = {}
        for doc in self.docs:
            tokens = tokenize(doc.content)
            tf: dict[str, int] = {}
            for token in tokens:
                tf[token] = tf.get(token, 0) + 1
            self._term_freq.append(tf)
            self._doc_len.append(len(tokens))
            for token in tf:
                self._doc_freq[token] = self._doc_freq.get(token, 0) + 1
        self._avg_len = sum(self._doc_len) / len(self._doc_len) if self._doc_len else 0.0

    def _bm25(self, query_tokens: list[str], doc_index: int) -> float:
        k1, b = 1.2, 0.75
        tf = self._term_freq[doc_index]
        length = self._doc_len[doc_index]
        score = 0.0
        for token in query_tokens:
            freq = tf.get(token, 0)
            if not freq:
                continue
            df = self._doc_freq.get(token, 0)
            idf = math.log(1 + (len(self.docs) - df + 0.5) / (df + 0.5))
            denom = freq + k1 * (1 - b + b * length / (self._avg_len or 1))
            score += idf * freq * (k1 + 1) / denom
        return score

    def search(self, query: str, top_k: int = 3) -> KnowledgeSearchResult:
        query_tokens = tokenize(query)
        query_lower = query.lower()
        scored: list[tuple[float, int]] = []
        for index, doc in enumerate(self.docs):
            score = self._bm25(query_tokens, index)
            if doc.technique_id and doc.technique_id.lower() in query_lower:
                score += 50.0
            if doc.doc_type == "ioc" and doc.title.lower() in query_lower:
                score += 100.0
            if score > 0:
                scored.append((score, index))
        scored.sort(key=lambda item: item[0], reverse=True)
        results = [self._format(doc=self.docs[i], score=score) for score, i in scored[:top_k]]
        return KnowledgeSearchResult(query=query, top_k=top_k, results=results, backend="local-bm25")

    def _format(self, *, doc: KnowledgeDoc, score: float) -> dict[str, Any]:
        if doc.doc_type == "attack":
            raw = doc.raw or {}
            excerpt = sanitize_text(raw.get("description", ""), 260)
            return {
                "doc_id": doc.doc_id,
                "type": "attack",
                "title": doc.title,
                "technique_id": doc.technique_id,
                "tactics": doc.tactics or [],
                "score": round(score, 4),
                "excerpt": excerpt,
                "url": doc.url,
                "source": "mitre-attack-enterprise-subset",
            }
        raw = doc.raw or {}
        return {
            "doc_id": doc.doc_id,
            "type": "ioc",
            "title": doc.title,
            "technique_id": None,
            "tactics": [],
            "score": round(score, 4),
            "excerpt": sanitize_text(
                f"{raw.get('threat', '')}，置信度 {raw.get('confidence', '')}，来源 {raw.get('source', '')}",
                260,
            ),
            "url": None,
            "source": "synthetic-ioc-demo",
        }


class DifyKnowledgeBackend:
    """调用 Dify 知识库检索 API；失败时降级到本地 BM25。"""

    def __init__(self, settings: Settings, local: LocalKnowledgeBackend | None = None):
        self.settings = settings
        self.local = local or LocalKnowledgeBackend(settings)
        self.client = httpx.AsyncClient(
            base_url=settings.dify_api_base,
            headers={"Authorization": f"Bearer {settings.dify_dataset_api_key}"},
            timeout=httpx.Timeout(15.0),
        )

    async def search(self, query: str, top_k: int = 3) -> KnowledgeSearchResult:
        payload = {
            "query": query,
            "retrieval_model": {
                "search_method": self.settings.dify_retrieval_method,
                "reranking_enable": False,
                "top_k": top_k,
                "score_threshold_enabled": False,
            },
        }
        try:
            response = await self.client.post(
                f"/datasets/{self.settings.dify_dataset_id}/retrieve", json=payload
            )
            response.raise_for_status()
            data = response.json()
            records = data.get("records") or []
            results = [self._format_record(record) for record in records[:top_k]]
            if results:
                return KnowledgeSearchResult(
                    query=query, top_k=top_k, results=results, backend="dify-knowledge"
                )
            log.warning("dify knowledge returned no records, fallback to local")
        except Exception as exc:  # noqa: BLE001 - 知识库故障不应阻断分诊
            log.warning("dify knowledge failed, fallback to local: %s", exc)
        fallback = self.local.search(query, top_k)
        fallback.backend = "local-bm25-fallback"
        return fallback

    @staticmethod
    def _format_record(record: dict[str, Any]) -> dict[str, Any]:
        segment = record.get("segment") or {}
        content = sanitize_text(segment.get("content") or "", 600)
        technique_match = _TECHNIQUE_RE.search(content)
        technique_id = technique_match.group(0) if technique_match else None
        first_line = next((line.strip("# ").strip() for line in content.splitlines() if line.strip()), content[:80])
        doc_type = "ioc" if "IOC" in content[:200].upper() and not technique_id else "attack"
        return {
            "doc_id": segment.get("document_id") or segment.get("id") or "dify-segment",
            "type": doc_type,
            "title": first_line or content[:80],
            "technique_id": technique_id,
            "tactics": [],
            "score": round(float(record.get("score") or 0.0), 4),
            "excerpt": content[:300],
            "url": f"https://attack.mitre.org/techniques/{technique_id}/" if technique_id else None,
            "source": "dify-knowledge",
        }

    async def close(self) -> None:
        await self.client.aclose()


class CombinedKnowledgeBackend:
    def __init__(self, settings: Settings):
        self.local = LocalKnowledgeBackend(settings)
        self.settings = settings
        self.remote = (
            DifyKnowledgeBackend(settings, local=self.local)
            if settings.knowledge_mode == "dify" and settings.dify_dataset_id and settings.dify_dataset_api_key
            else None
        )

    async def search(self, query: str, top_k: int = 3) -> KnowledgeSearchResult:
        if self.remote:
            return await self.remote.search(query, top_k)
        return self.local.search(query, top_k)

    async def close(self) -> None:
        if self.remote:
            await self.remote.close()


def create_knowledge_backend(settings: Settings) -> CombinedKnowledgeBackend:
    return CombinedKnowledgeBackend(settings)
