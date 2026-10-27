"""可重建决策链的追踪存储。

SQLite 负责查询，JSONL 负责追加审计。每个工具调用都记录
tool / args / result / latency / status；每次裁决记录 verdict / reason。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from statistics import mean
from typing import Any

from .config import Settings
from .util import iso, json_dumps, redact, utc_now

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  trace_id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL,
  received_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  status TEXT NOT NULL,
  mode TEXT,
  model TEXT,
  verdict TEXT,
  risk_score INTEGER,
  confidence REAL,
  latency_ms INTEGER,
  workflow_run_id TEXT,
  approval_id TEXT,
  alert_json TEXT,
  output_json TEXT,
  error TEXT,
  prompt_tokens INTEGER DEFAULT 0,
  completion_tokens INTEGER DEFAULT 0,
  total_tokens INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trace_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL,
  phase TEXT NOT NULL,
  tool TEXT,
  args_json TEXT,
  result_json TEXT,
  latency_ms INTEGER,
  status TEXT NOT NULL,
  detail_json TEXT,
  UNIQUE(trace_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_steps_trace ON steps(trace_id, seq);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  status TEXT NOT NULL,
  actions_json TEXT,
  summary TEXT,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT,
  note TEXT,
  expires_at TEXT,
  token_hash TEXT
);
"""


class TraceStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.db_path = Path(settings.trace_db)
        self.jsonl_path = Path(settings.trace_jsonl)
        self._lock = threading.Lock()
        self.settings.ensure_dirs()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(approvals)")}
            if "token_hash" not in columns:
                conn.execute("ALTER TABLE approvals ADD COLUMN token_hash TEXT")

    def _append_jsonl(self, event: dict[str, Any]) -> None:
        try:
            with self.jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        except OSError:
            # 审计写入不应阻断主流程
            pass

    def start_run(
        self,
        *,
        trace_id: str,
        alert_id: str,
        mode: str,
        model: str = "",
        alert: dict[str, Any] | None = None,
        received_at: str | None = None,
    ) -> None:
        now = iso()
        safe_alert = redact(alert or {}, max_text=2000)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (trace_id, alert_id, received_at, started_at, status, mode, model, alert_json)
                VALUES (?, ?, ?, ?, 'running', ?, ?, ?)
                ON CONFLICT(trace_id) DO UPDATE SET
                  alert_id=excluded.alert_id,
                  started_at=COALESCE(runs.started_at, excluded.started_at),
                  status=CASE WHEN runs.status='succeeded' THEN runs.status ELSE 'running' END,
                  mode=excluded.mode,
                  model=excluded.model,
                  alert_json=excluded.alert_json
                """,
                (
                    trace_id,
                    alert_id,
                    received_at or now,
                    now,
                    mode,
                    model,
                    json_dumps(safe_alert),
                ),
            )
        self._append_jsonl(
            {"ts": now, "event": "run_start", "trace_id": trace_id, "alert_id": alert_id, "mode": mode}
        )

    def record_step(
        self,
        *,
        trace_id: str,
        phase: str,
        tool: str | None = None,
        args: Any = None,
        result: Any = None,
        latency_ms: int | None = None,
        status: str = "ok",
        detail: Any = None,
    ) -> int:
        now = iso()
        safe_args = redact(args, max_text=2000)
        safe_result = redact(result, max_text=4000)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM steps WHERE trace_id=?", (trace_id,)
            ).fetchone()
            seq = int(row["next_seq"]) if row else 1
            conn.execute(
                """
                INSERT INTO steps (trace_id, seq, ts, phase, tool, args_json, result_json, latency_ms, status, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trace_id,
                    seq,
                    now,
                    phase,
                    tool,
                    json_dumps(safe_args),
                    json_dumps(safe_result),
                    latency_ms,
                    status,
                    json_dumps(redact(detail, max_text=2000)),
                ),
            )
        self._append_jsonl(
            {
                "ts": now,
                "event": "step",
                "trace_id": trace_id,
                "seq": seq,
                "phase": phase,
                "tool": tool,
                "args": safe_args,
                "result": safe_result,
                "latency_ms": latency_ms,
                "status": status,
            }
        )
        return seq

    def finish_run(
        self,
        *,
        trace_id: str,
        status: str,
        output: Any = None,
        error: str | None = None,
        workflow_run_id: str | None = None,
        approval_id: str | None = None,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int = 0,
    ) -> None:
        now = iso()
        if output is None:
            output_json = None
        else:
            payload = output if isinstance(output, dict) else output.model_dump()
            payload = dict(payload)
            # 兼容旧 trace 查询：标准输出只有 decision，内部仍补 verdict/risk_score。
            payload.setdefault("verdict", getattr(output, "verdict", None) if not isinstance(output, dict) else output.get("verdict"))
            payload.setdefault("risk_score", getattr(output, "risk_score", None) if not isinstance(output, dict) else output.get("risk_score"))
            output_json = json_dumps(redact(payload, max_text=4000))
        verdict = getattr(output, "verdict", None) if not isinstance(output, dict) else output.get("verdict")
        risk_score = (
            getattr(output, "risk_score", None) if not isinstance(output, dict) else output.get("risk_score")
        )
        confidence = (
            getattr(output, "confidence", None) if not isinstance(output, dict) else output.get("confidence")
        )
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT started_at FROM runs WHERE trace_id=?", (trace_id,)).fetchone()
            latency_ms = None
            if row and row["started_at"]:
                try:
                    from .util import parse_iso

                    latency_ms = int((utc_now() - parse_iso(row["started_at"])).total_seconds() * 1000)
                except ValueError:
                    latency_ms = None
            conn.execute(
                """
                UPDATE runs SET finished_at=?, status=?, verdict=?, risk_score=?, confidence=?,
                  latency_ms=?, workflow_run_id=COALESCE(?, workflow_run_id),
                  approval_id=COALESCE(?, approval_id), output_json=?, error=?,
                  prompt_tokens=?, completion_tokens=?, total_tokens=?
                WHERE trace_id=?
                """,
                (
                    now,
                    status,
                    verdict,
                    risk_score,
                    confidence,
                    latency_ms,
                    workflow_run_id,
                    approval_id,
                    output_json,
                    error,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    trace_id,
                ),
            )
        self._append_jsonl(
            {
                "ts": now,
                "event": "run_finish",
                "trace_id": trace_id,
                "status": status,
                "verdict": verdict,
                "approval_id": approval_id,
                "error": error,
            }
        )

    def record_approval(
        self,
        *,
        approval_id: str,
        trace_id: str,
        alert_id: str,
        status: str,
        actions: Any,
        summary: str,
        expires_at: str,
        decided_at: str | None = None,
        decided_by: str | None = None,
        note: str | None = None,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (approval_id, trace_id, alert_id, status, actions_json, summary,
                  created_at, decided_at, decided_by, note, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(approval_id) DO UPDATE SET
                  status=excluded.status, decided_at=excluded.decided_at,
                  decided_by=excluded.decided_by, note=excluded.note
                """,
                (
                    approval_id,
                    trace_id,
                    alert_id,
                    status,
                    json_dumps(redact(actions)),
                    summary,
                    iso(),
                    decided_at,
                    decided_by,
                    note,
                    expires_at,
                ),
            )
            conn.execute(
                "UPDATE runs SET approval_id=? WHERE trace_id=?",
                (approval_id, trace_id),
            )

    def create_approval(
        self,
        *,
        approval_id: str,
        trace_id: str,
        alert_id: str,
        actions: Any,
        summary: str,
        token_hash: str,
        expires_at: str,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (approval_id, trace_id, alert_id, status, actions_json, summary,
                  created_at, expires_at, token_hash)
                VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    trace_id,
                    alert_id,
                    json_dumps(redact(actions)),
                    summary,
                    iso(),
                    expires_at,
                    token_hash,
                ),
            )
            conn.execute("UPDATE runs SET approval_id=? WHERE trace_id=?", (approval_id, trace_id))
        self._append_jsonl(
            {
                "ts": iso(),
                "event": "approval_created",
                "trace_id": trace_id,
                "approval_id": approval_id,
                "summary": summary,
            }
        )

    def get_approval(self, approval_id: str, *, include_hash: bool = False) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        if item.get("actions_json"):
            try:
                item["actions_json"] = json.loads(item["actions_json"])
            except (TypeError, json.JSONDecodeError):
                pass
        if not include_hash:
            item.pop("token_hash", None)
        return item

    def decide_approval(
        self,
        *,
        approval_id: str,
        token_hash: str,
        decision: str,
        decided_by: str,
        note: str = "",
    ) -> tuple[bool, str]:
        if decision not in {"approve", "reject"}:
            return False, "invalid_decision"
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT status, expires_at, token_hash FROM approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
            if not row:
                return False, "not_found"
            if row["status"] != "pending":
                return False, "already_decided"
            if row["token_hash"] != token_hash:
                return False, "invalid_token"
            if row["expires_at"] and row["expires_at"] < iso():
                conn.execute(
                    "UPDATE approvals SET status='expired' WHERE approval_id=?", (approval_id,)
                )
                return False, "expired"
            conn.execute(
                """
                UPDATE approvals SET status=?, decided_at=?, decided_by=?, note=?
                WHERE approval_id=? AND status='pending'
                """,
                (decision, iso(), decided_by[:200], note[:1000], approval_id),
            )
        self._append_jsonl(
            {
                "ts": iso(),
                "event": "approval_decided",
                "approval_id": approval_id,
                "decision": decision,
                "decided_by": decided_by,
            }
        )
        return True, decision

    def list_approvals(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT approval_id, trace_id, alert_id, status, summary, created_at, decided_at, "
                "decided_by, expires_at FROM approvals ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_run(self, trace_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            run = conn.execute("SELECT * FROM runs WHERE trace_id=?", (trace_id,)).fetchone()
            if not run:
                return None
            steps = conn.execute(
                "SELECT * FROM steps WHERE trace_id=? ORDER BY seq", (trace_id,)
            ).fetchall()
            approvals = conn.execute(
                "SELECT * FROM approvals WHERE trace_id=? ORDER BY created_at", (trace_id,)
            ).fetchall()
        result = dict(run)
        for key in ("alert_json", "output_json"):
            if result.get(key):
                try:
                    result[key] = json.loads(result[key])
                except (TypeError, json.JSONDecodeError):
                    pass
        result["steps"] = []
        for step in steps:
            item = dict(step)
            for key in ("args_json", "result_json", "detail_json"):
                if item.get(key):
                    try:
                        item[key] = json.loads(item[key])
                    except (TypeError, json.JSONDecodeError):
                        pass
            result["steps"].append(item)
        result["approvals"] = []
        for approval in approvals:
            item = dict(approval)
            if item.get("actions_json"):
                try:
                    item["actions_json"] = json.loads(item["actions_json"])
                except (TypeError, json.JSONDecodeError):
                    pass
            result["approvals"].append(item)
        return result

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT trace_id, alert_id, started_at, status, verdict, risk_score, confidence, "
                "latency_ms, approval_id FROM runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            run_rows = conn.execute("SELECT * FROM runs").fetchall()
            step_count = conn.execute("SELECT COUNT(*) AS c FROM steps").fetchone()["c"]
            approval_rows = conn.execute("SELECT status, COUNT(*) AS c FROM approvals GROUP BY status").fetchall()
        latency = [int(r["latency_ms"]) for r in run_rows if r["latency_ms"] is not None]
        verdicts: dict[str, int] = {}
        for row in run_rows:
            if row["verdict"]:
                verdicts[row["verdict"]] = verdicts.get(row["verdict"], 0) + 1
        p95 = 0
        if latency:
            ordered = sorted(latency)
            p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
        return {
            "runs": len(run_rows),
            "succeeded": sum(1 for r in run_rows if r["status"] == "succeeded"),
            "failed": sum(1 for r in run_rows if r["status"] == "failed"),
            "verdicts": verdicts,
            "avg_latency_ms": int(mean(latency)) if latency else 0,
            "p95_latency_ms": p95,
            "steps": step_count,
            "approvals": {row["status"]: row["c"] for row in approval_rows},
        }

    def prune(self, days: int) -> int:
        cutoff = iso(utc_now().replace(microsecond=0))
        # 简化：按 finished_at 文本比较（ISO8601 UTC 可直接字典序比较）
        from datetime import timedelta

        cutoff = iso(utc_now() - timedelta(days=max(1, days)))
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM runs WHERE finished_at IS NOT NULL AND finished_at < ?", (cutoff,)
            )
            deleted = cur.rowcount
            conn.execute(
                "DELETE FROM steps WHERE trace_id NOT IN (SELECT trace_id FROM runs)"
            )
        return int(deleted)
