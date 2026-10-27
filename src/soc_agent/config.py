"""运行时配置。

所有配置只从环境变量读取，避免把 API Key、密码写进仓库。
测试可以通过 ``Settings.for_test()`` 构造隔离配置。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None or value == "" else value


def _bool_env(name: str, default: bool = False) -> bool:
    raw = _env(name, "true" if default else "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


def _default_root() -> Path:
    explicit = os.getenv("SOC_PROJECT_ROOT", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    cwd = Path.cwd()
    if (cwd / "data").is_dir() and (cwd / "schemas").is_dir():
        return cwd
    # src/soc_agent/config.py -> <project root>
    return Path(__file__).resolve().parents[2]


@dataclass(slots=True)
class Settings:
    # 路径
    project_root: Path
    data_dir: Path
    trace_db: Path
    trace_jsonl: Path

    # 队列
    queue_mode: str
    redis_url: str
    stream_key: str
    consumer_group: str
    dlq_key: str
    consumer_name: str
    max_retries: int
    claim_idle_ms: int
    consumer_workers: int

    # Wazuh
    wazuh_mode: str
    wazuh_indexer_url: str
    wazuh_indexer_index: str
    wazuh_indexer_user: str
    wazuh_indexer_password: str
    wazuh_verify_tls: bool
    wazuh_window_minutes: int

    # Dify
    dify_mode: str
    dify_api_base: str
    dify_api_key: str
    dify_workflow_timeout_s: float
    dify_mock_api_key: str

    # Agent
    agent_mode: str
    deepseek_api_key: str
    deepseek_base_url: str
    deepseek_model: str
    deepseek_timeout_s: float

    # 知识库
    knowledge_mode: str
    dify_dataset_id: str
    dify_dataset_api_key: str
    dify_retrieval_method: str

    # 鉴权
    tool_api_token: str
    approval_api_token: str

    # 审批
    approval_base_url: str
    approval_public_url: str
    approval_ttl_hours: int
    approval_expose_links: bool
    dingtalk_webhook: str
    dingtalk_secret: str
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    smtp_to: str

    # 桥接
    bridge_token: str
    bridge_host: str
    bridge_port: int

    log_level: str
    trace_retention_days: int

    @classmethod
    def from_env(cls) -> "Settings":
        root = _default_root()
        data_dir = Path(_env("SOC_DATA_DIR", str(root / "data"))).expanduser()
        if not data_dir.is_absolute():
            data_dir = (root / data_dir).resolve()
        return cls(
            project_root=root,
            data_dir=data_dir,
            trace_db=Path(_env("SOC_TRACE_DB", str(data_dir / "traces.sqlite3"))),
            trace_jsonl=Path(_env("SOC_TRACE_JSONL", str(data_dir / "traces.jsonl"))),
            queue_mode=_env("SOC_QUEUE_MODE", "redis").strip().lower(),
            redis_url=_env("REDIS_URL", "redis://127.0.0.1:6379/0"),
            stream_key=_env("REDIS_STREAM", "wazuh:alerts"),
            consumer_group=_env("REDIS_GROUP", "soc-l1"),
            dlq_key=_env("REDIS_DLQ", "wazuh:alerts:dlq"),
            consumer_name=_env("REDIS_CONSUMER", "soc-l1-worker-1"),
            max_retries=_int_env("REDIS_MAX_RETRIES", 3),
            claim_idle_ms=_int_env("REDIS_CLAIM_IDLE_MS", 60_000),
            consumer_workers=_int_env("CONSUMER_WORKERS", 2),
            wazuh_mode=_env("WAZUH_MODE", "mock").strip().lower(),
            wazuh_indexer_url=_env("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/"),
            wazuh_indexer_index=_env("WAZUH_INDEXER_INDEX", "wazuh-alerts-*"),
            wazuh_indexer_user=_env("WAZUH_INDEXER_USER", "admin"),
            wazuh_indexer_password=_env("WAZUH_INDEXER_PASSWORD", ""),
            wazuh_verify_tls=_bool_env("WAZUH_INDEXER_VERIFY_TLS", False),
            wazuh_window_minutes=_int_env("WAZUH_WINDOW_MINUTES", 15),
            dify_mode=_env("DIFY_MODE", "mock").strip().lower(),
            dify_api_base=_env("DIFY_API_BASE", "http://127.0.0.1:5001/v1").rstrip("/"),
            dify_api_key=_env("DIFY_API_KEY", ""),
            dify_workflow_timeout_s=_float_env("DIFY_WORKFLOW_TIMEOUT_S", 90.0),
            dify_mock_api_key=_env("DIFY_MOCK_API_KEY", "dev-mock-key"),
            agent_mode=_env("AGENT_MODE", "deterministic").strip().lower(),
            deepseek_api_key=_env("DEEPSEEK_API_KEY", ""),
            deepseek_base_url=_env("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/"),
            deepseek_model=_env("DEEPSEEK_MODEL", "deepseek-chat"),
            deepseek_timeout_s=_float_env("DEEPSEEK_TIMEOUT_S", 45.0),
            knowledge_mode=_env("KNOWLEDGE_MODE", "local").strip().lower(),
            dify_dataset_id=_env("DIFY_DATASET_ID", ""),
            dify_dataset_api_key=_env("DIFY_DATASET_API_KEY", ""),
            dify_retrieval_method=_env("DIFY_RETRIEVAL_METHOD", "hybrid_search"),
            tool_api_token=_env("TOOL_API_TOKEN", ""),
            approval_api_token=_env("APPROVAL_API_TOKEN", ""),
            approval_base_url=_env("APPROVAL_BASE_URL", "http://127.0.0.1:8002").rstrip("/"),
            approval_public_url=_env("APPROVAL_PUBLIC_URL", "http://127.0.0.1:8002").rstrip("/"),
            approval_ttl_hours=_int_env("APPROVAL_TTL_HOURS", 24),
            approval_expose_links=_bool_env("APPROVAL_EXPOSE_LINKS", True),
            dingtalk_webhook=_env("DINGTALK_WEBHOOK", ""),
            dingtalk_secret=_env("DINGTALK_SECRET", ""),
            smtp_host=_env("SMTP_HOST", ""),
            smtp_port=_int_env("SMTP_PORT", 465),
            smtp_user=_env("SMTP_USER", ""),
            smtp_password=_env("SMTP_PASSWORD", ""),
            smtp_from=_env("SMTP_FROM", ""),
            smtp_to=_env("SMTP_TO", ""),
            bridge_token=_env("BRIDGE_TOKEN", ""),
            bridge_host=_env("BRIDGE_HOST", "0.0.0.0"),
            bridge_port=_int_env("BRIDGE_PORT", 8000),
            log_level=_env("SOC_LOG_LEVEL", "INFO").upper(),
            trace_retention_days=_int_env("SOC_TRACE_RETENTION_DAYS", 7),
        )

    @classmethod
    def for_test(cls, tmp_dir: Path) -> "Settings":
        """测试用配置：不连外部服务，不写真实数据目录。"""

        tmp_dir = Path(tmp_dir)
        base = cls.from_env()
        return replace(
            base,
            data_dir=tmp_dir,
            trace_db=tmp_dir / "traces.sqlite3",
            trace_jsonl=tmp_dir / "traces.jsonl",
            queue_mode="memory",
            wazuh_mode="mock",
            dify_mode="mock",
            agent_mode="deterministic",
            knowledge_mode="local",
            dify_api_key="",
            dify_mock_api_key="test-mock-key",
            deepseek_api_key="",
            tool_api_token="",
            approval_api_token="",
            approval_expose_links=True,
            bridge_token="",
            consumer_workers=1,
            max_retries=2,
            claim_idle_ms=50,
            approval_ttl_hours=24,
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.trace_db.parent.mkdir(parents=True, exist_ok=True)
        self.trace_jsonl.parent.mkdir(parents=True, exist_ok=True)
