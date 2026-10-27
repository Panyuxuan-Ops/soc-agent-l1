from __future__ import annotations

import json

import pytest

from soc_agent.queue import InMemoryDedup, InMemoryQueue, RedisStreamQueue


@pytest.mark.asyncio
async def test_in_memory_queue_publish_consume_ack():
    queue = InMemoryQueue(max_retries=2)
    alert = {"id": "wazuh-1", "rule": {"level": 5}}
    stream_id = await queue.publish(alert, "trc_0123456789abcdef")
    message = await queue.consume(block_ms=100)
    assert message is not None
    assert message.id == stream_id
    assert message.alert["id"] == "wazuh-1"
    await queue.ack(message)
    assert await queue.consume(block_ms=10) is None


@pytest.mark.asyncio
async def test_in_memory_queue_retry_then_dlq():
    queue = InMemoryQueue(max_retries=2)
    await queue.publish({"id": "wazuh-2"}, "trc_0123456789abcdef")
    first = await queue.consume(block_ms=100)
    assert first is not None
    dead = await queue.fail(first, "boom")
    assert dead is False
    second = await queue.consume(block_ms=100)
    assert second is not None
    assert second.attempts == 1
    dead = await queue.fail(second, "boom again")
    assert dead is True
    assert len(queue.dead_letters) == 1


@pytest.mark.asyncio
async def test_in_memory_dedup():
    dedup = InMemoryDedup(ttl_seconds=60)
    assert await dedup.seen("wazuh-1") is False
    assert await dedup.seen("wazuh-1") is True
    assert await dedup.seen("wazuh-2") is False


@pytest.mark.asyncio
async def test_redis_stream_queue_with_fakeredis(settings):
    fakeredis = pytest.importorskip("fakeredis")
    from fakeredis.aioredis import FakeRedis

    client = FakeRedis(decode_responses=True)
    queue = RedisStreamQueue(settings, client=client)
    stream_id = await queue.publish({"id": "wazuh-3", "rule": {"level": 6}}, "trc_0123456789abcdef")
    assert stream_id
    message = await queue.consume(block_ms=10)
    assert message is not None
    assert message.alert["id"] == "wazuh-3"
    await queue.ack(message)
    await client.aclose()


@pytest.mark.asyncio
async def test_redis_dlq_with_fakeredis(settings):
    fakeredis = pytest.importorskip("fakeredis")
    from fakeredis.aioredis import FakeRedis

    client = FakeRedis(decode_responses=True)
    queue = RedisStreamQueue(settings, client=client)
    await queue.publish({"id": "wazuh-4"}, "trc_0123456789abcdef")
    message = await queue.consume(block_ms=10)
    assert message is not None
    for _ in range(settings.max_retries):
        dead = await queue.fail(message, "boom")
    assert dead is True
    dlq_items = await client.xrange(settings.dlq_key)
    assert dlq_items
    fields = dlq_items[0][1]
    assert fields["error"] == "boom"
    await client.aclose()
