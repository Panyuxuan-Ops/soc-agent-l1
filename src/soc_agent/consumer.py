"""Redis Stream 消费者：背压、幂等、失败重试、可观测性。"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from .alert import normalize_alert
from .approval import ApprovalStore
from .config import Settings
from .dify_client import DifyRunResult
from .log import get_logger
from .queue import InMemoryDedup, QueueMessage, RedisDedup, StreamQueue
from .trace import TraceStore
from .util import new_trace_id

log = get_logger("consumer")


@dataclass(slots=True)
class HandleResult:
    status: str
    trace_id: str
    alert_id: str
    verdict: str | None = None
    approval_id: str | None = None
    error: str | None = None


class Consumer:
    def __init__(
        self,
        settings: Settings,
        queue: StreamQueue,
        dify,
        trace: TraceStore,
        approvals: ApprovalStore,
        dedup: InMemoryDedup | RedisDedup | None = None,
    ):
        self.settings = settings
        self.queue = queue
        self.dify = dify
        self.trace = trace
        self.approvals = approvals
        self.dedup = dedup or InMemoryDedup()

    async def handle(self, message: QueueMessage) -> HandleResult:
        trace_id = message.trace_id or new_trace_id()
        try:
            view = normalize_alert(message.alert)
        except Exception as exc:  # noqa: BLE001
            await self.queue.fail(message, f"invalid alert: {exc}")
            return HandleResult(status="invalid", trace_id=trace_id, alert_id="", error=str(exc))

        if not await self.dedup.claim(view.alert_id):
            await self.queue.ack(message)
            log.info("duplicate alert skipped", extra={"trace_id": trace_id, "alert_id": view.alert_id})
            return HandleResult(status="duplicate", trace_id=trace_id, alert_id=view.alert_id)

        self.trace.start_run(
            trace_id=trace_id,
            alert_id=view.alert_id,
            mode=f"dify:{self.settings.dify_mode}",
            model=self.settings.deepseek_model,
            alert=message.alert,
            received_at=view.timestamp,
        )

        try:
            result: DifyRunResult = await asyncio.wait_for(
                self.dify.run(message.alert, trace_id),
                timeout=self.settings.dify_workflow_timeout_s + 15,
            )
            approval_id = result.approval_id
            if result.output.requires_human_approval and not approval_id:
                record = await self.approvals.create(
                    trace_id=trace_id,
                    alert_id=result.output.alert_id,
                    result=result.output,
                )
                approval_id = record.approval_id if record else None

            self.trace.finish_run(
                trace_id=trace_id,
                status="succeeded",
                output=result.output,
                workflow_run_id=result.workflow_run_id,
                approval_id=approval_id,
                total_tokens=result.total_tokens,
            )
            await self.dedup.commit(view.alert_id)
            await self.queue.ack(message)
            log.info(
                "alert triaged",
                extra={
                    "trace_id": trace_id,
                    "alert_id": view.alert_id,
                    "verdict": result.output.verdict,
                },
            )
            return HandleResult(
                status="succeeded",
                trace_id=trace_id,
                alert_id=view.alert_id,
                verdict=result.output.verdict,
                approval_id=approval_id,
            )
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
            self.trace.finish_run(trace_id=trace_id, status="failed", error=error[:1000])
            await self.dedup.release(view.alert_id)
            dead = await self.queue.fail(message, error)
            log.error(
                "alert triage failed%s: %s",
                " (DLQ)" if dead else "",
                error,
                extra={"trace_id": trace_id, "alert_id": view.alert_id},
            )
            return HandleResult(
                status="dead" if dead else "retry",
                trace_id=trace_id,
                alert_id=view.alert_id,
                error=error,
            )

    async def run_forever(self, workers: int | None = None) -> None:
        workers = workers or self.settings.consumer_workers
        await asyncio.gather(*(self._worker(index) for index in range(workers)))

    async def _worker(self, index: int) -> None:
        log.info("consumer worker started", extra={"phase": f"worker-{index}"})
        while True:
            try:
                message = await self.queue.consume(block_ms=2000)
                if message is None:
                    continue
                await self.handle(message)
            except asyncio.CancelledError:
                log.info("consumer worker cancelled", extra={"phase": f"worker-{index}"})
                raise
            except Exception as exc:  # noqa: BLE001
                log.error("consumer loop error: %s", exc)
                await asyncio.sleep(1)

    async def drain(self, max_messages: int = 100) -> list[HandleResult]:
        """演示/测试：消费当前队列中的消息，直到为空。"""

        results: list[HandleResult] = []
        for _ in range(max_messages):
            message = await self.queue.consume(block_ms=50)
            if message is None:
                break
            results.append(await self.handle(message))
        return results

    async def close(self) -> None:
        await self.queue.close()
        close = getattr(self.dify, "close", None)
        if close:
            await close()
