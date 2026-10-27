"""Redis Stream 队列抽象 + 内存实现（演示/测试）。

生产路径：Wazuh bridge -> XADD -> consumer group -> XREADGROUP -> XACK。
失败消息留在 PENDING，由 XAUTOCLAIM 重试；超过上限写入 DLQ。
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from .config import Settings
from .log import get_logger
from .util import iso, json_dumps

log = get_logger("queue")


@dataclass(slots=True)
class QueueMessage:
    id: str
    alert: dict[str, Any]
    trace_id: str
    attempts: int = 0
    raw_fields: dict[str, str] = field(default_factory=dict)


class StreamQueue(Protocol):
    async def publish(self, alert: dict[str, Any], trace_id: str) -> str: ...
    async def consume(self, *, block_ms: int = 2000) -> QueueMessage | None: ...
    async def ack(self, message: QueueMessage) -> None: ...
    async def fail(self, message: QueueMessage, error: str) -> bool: ...
    async def health(self) -> bool: ...
    async def close(self) -> None: ...


class InMemoryQueue:
    """没有 Redis 时的本地闭环；语义与 Redis 版保持一致。"""

    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries
        self._queue: asyncio.Queue[QueueMessage] = asyncio.Queue()
        self._pending: dict[str, QueueMessage] = {}
        self.dead_letters: list[QueueMessage] = []
        self.published = 0

    async def publish(self, alert: dict[str, Any], trace_id: str) -> str:
        message_id = f"mem-{self.published + 1}-{uuid.uuid4().hex[:6]}"
        self.published += 1
        message = QueueMessage(id=message_id, alert=alert, trace_id=trace_id)
        self._pending[message_id] = message
        await self._queue.put(message)
        return message_id

    async def consume(self, *, block_ms: int = 2000) -> QueueMessage | None:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=max(0.01, block_ms / 1000))
        except asyncio.TimeoutError:
            return None

    async def ack(self, message: QueueMessage) -> None:
        self._pending.pop(message.id, None)

    async def fail(self, message: QueueMessage, error: str) -> bool:
        message.attempts += 1
        self._pending.pop(message.id, None)
        if message.attempts >= self.max_retries:
            self.dead_letters.append(message)
            log.error("message moved to dead-letter", extra={"trace_id": message.trace_id})
            return True
        await asyncio.sleep(0.01 * message.attempts)
        self._pending[message.id] = message
        await self._queue.put(message)
        log.warning(
            "message requeued",
            extra={"trace_id": message.trace_id},
        )
        return False

    async def health(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class RedisStreamQueue:
    def __init__(self, settings: Settings, client: Redis | None = None):
        self.settings = settings
        self.client = client or Redis.from_url(settings.redis_url, decode_responses=True)
        self.stream = settings.stream_key
        self.group = settings.consumer_group
        self.dlq = settings.dlq_key
        self.consumer = settings.consumer_name
        self.max_retries = settings.max_retries
        self.claim_idle_ms = settings.claim_idle_ms

    async def ensure_group(self) -> None:
        try:
            await self.client.xgroup_create(self.stream, self.group, id="0", mkstream=True)
            log.info("redis consumer group created", extra={"phase": "queue"})
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def publish(self, alert: dict[str, Any], trace_id: str) -> str:
        message_id = await self.client.xadd(
            self.stream,
            {
                "alert": json_dumps(alert),
                "trace_id": trace_id,
                "received_at": iso(),
                "source": "wazuh",
            },
            maxlen=10_000,
            approximate=True,
        )
        return str(message_id)

    async def _attempts(self, message_id: str) -> int:
        key = f"{self.stream}:attempts:{message_id}"
        count = int(await self.client.incr(key))
        await self.client.expire(key, 3600)
        return count

    def _parse(self, message_id: str, fields: dict[str, Any], attempts: int = 0) -> QueueMessage:
        raw_alert = fields.get("alert", "{}")
        try:
            alert = json.loads(raw_alert) if isinstance(raw_alert, str) else raw_alert
        except json.JSONDecodeError:
            alert = {"_raw": raw_alert, "_parse_error": True}
        return QueueMessage(
            id=str(message_id),
            alert=alert,
            trace_id=str(fields.get("trace_id") or ""),
            attempts=attempts,
            raw_fields={k: str(v) for k, v in fields.items()},
        )

    async def consume(self, *, block_ms: int = 2000) -> QueueMessage | None:
        await self.ensure_group()
        # 先回收长时间未 ACK 的消息
        try:
            claimed = await self.client.xautoclaim(
                self.stream, self.group, self.consumer, self.claim_idle_ms, start_id="0-0", count=5
            )
            claimed_messages = claimed[1] if isinstance(claimed, (list, tuple)) and len(claimed) > 1 else []
            if claimed_messages:
                message_id, fields = claimed_messages[0]
                attempts = await self._attempts(str(message_id))
                log.info("claimed stale message", extra={"trace_id": fields.get("trace_id")})
                return self._parse(str(message_id), fields, attempts)
        except (ResponseError, AttributeError):
            pass

        response = await self.client.xreadgroup(
            groupname=self.group,
            consumername=self.consumer,
            streams={self.stream: ">"},
            count=1,
            block=block_ms,
        )
        if not response:
            return None
        _stream, messages = response[0]
        if not messages:
            return None
        message_id, fields = messages[0]
        return self._parse(str(message_id), fields, 0)

    async def ack(self, message: QueueMessage) -> None:
        await self.client.xack(self.stream, self.group, message.id)
        await self.client.delete(f"{self.stream}:attempts:{message.id}")

    async def fail(self, message: QueueMessage, error: str) -> bool:
        attempts = max(message.attempts, await self._attempts(message.id))
        if attempts >= self.max_retries:
            await self.client.xadd(
                self.dlq,
                {
                    **message.raw_fields,
                    "error": error[:1000],
                    "attempts": str(attempts),
                    "failed_at": iso(),
                },
                maxlen=5000,
                approximate=True,
            )
            await self.client.xack(self.stream, self.group, message.id)
            await self.client.delete(f"{self.stream}:attempts:{message.id}")
            log.error("message moved to DLQ", extra={"trace_id": message.trace_id})
            return True
        log.warning("message will be retried", extra={"trace_id": message.trace_id})
        return False

    async def health(self) -> bool:
        try:
            return bool(await self.client.ping())
        except Exception:
            return False

    async def close(self) -> None:
        await self.client.aclose()


class InMemoryDedup:
    def __init__(self, ttl_seconds: int = 86400):
        self.ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}

    async def claim(self, key: str) -> bool:
        """返回 True 表示抢到处理权；False 表示已处理或正在处理。"""
        now = time.time()
        expired = [k for k, ts in self._seen.items() if now - ts > self.ttl_seconds]
        for k in expired:
            self._seen.pop(k, None)
        if key in self._seen:
            return False
        self._seen[key] = now
        return True

    async def commit(self, key: str) -> None:
        # 内存实现中 claim 已经占位，无需额外操作
        return None

    async def release(self, key: str) -> None:
        self._seen.pop(key, None)

    async def seen(self, key: str) -> bool:
        return not await self.claim(key)


class RedisDedup:
    def __init__(self, client: Redis, ttl_seconds: int = 86400):
        self.client = client
        self.ttl_seconds = ttl_seconds

    async def claim(self, key: str) -> bool:
        result = await self.client.set(
            f"soc:l1:seen:{key}", "processing", nx=True, ex=self.ttl_seconds
        )
        return bool(result)

    async def commit(self, key: str) -> None:
        await self.client.set(f"soc:l1:seen:{key}", "done", ex=self.ttl_seconds)

    async def release(self, key: str) -> None:
        await self.client.delete(f"soc:l1:seen:{key}")

    async def seen(self, key: str) -> bool:
        return not await self.claim(key)


def create_queue(settings: Settings) -> StreamQueue:
    if settings.queue_mode == "memory":
        return InMemoryQueue(max_retries=settings.max_retries)
    return RedisStreamQueue(settings)


def create_dedup(settings: Settings, client: Redis | None = None):
    if settings.queue_mode == "memory":
        return InMemoryDedup()
    if client is None:
        client = Redis.from_url(settings.redis_url, decode_responses=True)
    return RedisDedup(client)
