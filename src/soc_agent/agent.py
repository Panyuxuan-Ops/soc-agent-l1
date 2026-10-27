"""L1 分诊 Agent。

两种执行模式：
- deterministic：规则 + 两个工具，离线可复现，用于测试和演示。
- deepseek：本地测试替身中的 Function Calling 实现；生产由 Dify Agent 节点编排。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .alert import normalize_alert
from .config import Settings
from .log import get_logger
from .models import (
    AlertView,
    EvidenceItem,
    FetchAlertsArgs,
    L1Output,
    MitreTechnique,
    RecommendedAction,
    SearchKnowledgeArgs,
)
from .prompts import FINAL_JSON_INSTRUCTION, L1_SYSTEM_PROMPT, L1_USER_TEMPLATE
from .tool_schemas import AGENT_TOOLS
from .tool_service import ToolService, compact_tool_result
from .trace import TraceStore
from .util import clamp, json_dumps, strip_code_fence, utc_now

log = get_logger("agent")

SENSITIVE_TACTICS = {
    "Credential Access",
    "Lateral Movement",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Exfiltration",
    "Impact",
    "Command and Control",
}

_INJECTION_MARKERS = re.compile(
    r"(ignore (all )?(previous|prior) instructions|忽略(之前|以上|所有)指令|system note|you are now)",
    re.I,
)


@dataclass(slots=True)
class ToolCallRecord:
    index: int
    name: str
    args: dict[str, Any]
    result: dict[str, Any]
    latency_ms: int
    status: str = "ok"


@dataclass(slots=True)
class AgentRun:
    output: L1Output
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model: str = "deterministic"


class L1Agent:
    def __init__(self, settings: Settings, tools: ToolService, trace: TraceStore):
        self.settings = settings
        self.tools = tools
        self.trace = trace
        self._techniques = self._load_techniques()

    def _load_techniques(self) -> dict[str, dict[str, Any]]:
        mapping: dict[str, dict[str, Any]] = {}
        try:
            for doc in self.tools.knowledge.local.docs:
                if doc.doc_type == "attack" and doc.technique_id:
                    raw = doc.raw or {}
                    mapping[doc.technique_id] = {
                        "name": raw.get("name") or doc.title,
                        "tactics": doc.tactics or [],
                        "url": doc.url,
                    }
        except Exception:  # noqa: BLE001
            pass
        return mapping

    async def run(self, alert_raw: dict[str, Any], trace_id: str) -> AgentRun:
        view = normalize_alert(alert_raw)
        model = self.settings.deepseek_model if self.settings.agent_mode == "deepseek" else "deterministic"
        self.trace.start_run(
            trace_id=trace_id,
            alert_id=view.alert_id,
            mode=f"agent:{self.settings.agent_mode}",
            model=model,
            alert=alert_raw,
            received_at=view.timestamp,
        )

        if view.rule_level <= 3 and not view.has_src_ip:
            output = self._fast_close(view, trace_id)
            self.trace.record_step(
                trace_id=trace_id,
                phase="policy",
                tool="fast_close",
                args={"rule_level": view.rule_level, "src_ip": view.src_ip},
                result=output.model_dump(),
                status="ok",
            )
            return AgentRun(output=output, model="deterministic-fast-path")

        if self.settings.agent_mode == "deepseek" and self.settings.deepseek_api_key:
            try:
                return await self._run_deepseek(view, trace_id)
            except Exception as exc:  # noqa: BLE001 - 任何 LLM 故障都降级，不让告警丢失
                log.error("deepseek agent failed, fallback to deterministic: %s", exc)
                self.trace.record_step(
                    trace_id=trace_id,
                    phase="llm",
                    tool="deepseek",
                    args={"model": self.settings.deepseek_model},
                    result={"error": str(exc)},
                    status="error",
                )

        return await self._run_deterministic(view, trace_id)

    def _fast_close(self, view: AlertView, trace_id: str) -> L1Output:
        output = L1Output(
            alert_id=view.alert_id,
            trace_id=trace_id,
            verdict="close",
            risk_score=5,
            confidence=0.9,
            summary=f"{view.agent_name or '主机'} 的 level-{view.rule_level} 日志「{view.rule_description}」无源 IP，判定为规则级噪声。",
            reason="规则等级 <= 3 且告警不含 src_ip，未达到调用 LLM 或外部工具的门槛；走低成本快速通道。",
            evidence=[
                EvidenceItem(
                    source="alert_rule",
                    detail=f"rule.level={view.rule_level}, rule.id={view.rule_id}, src_ip=None",
                ),
                EvidenceItem(source="policy", detail="level<=3 且无源 IP 的快速关闭策略"),
            ],
            recommended_actions=[
                RecommendedAction(
                    action="close_alert",
                    target=view.alert_id,
                    reason="无源 IP 的低等级访问日志，按噪声关闭。",
                )
            ],
            tool_calls_used=0,
            requires_human_approval=False,
            escalate_to_l2=False,
            limitations=["快速通道未调用 LLM，若该规则近期被篡改请人工复核。"],
        )
        return output

    async def _call_tool(
        self,
        *,
        trace_id: str,
        name: str,
        args: dict[str, Any],
        calls: list[ToolCallRecord],
    ) -> dict[str, Any]:
        if len(calls) >= 3:
            return {
                "ok": False,
                "tool": name,
                "error": {"code": "TOOL_BUDGET_EXCEEDED", "message": "L1 最多允许 3 次工具调用"},
            }
        started = time.perf_counter()
        status = "ok"
        try:
            result = await self.tools.execute_tool(name, args)
        except Exception as exc:  # noqa: BLE001
            status = "error"
            result = {
                "ok": False,
                "tool": name,
                "error": {"code": "TOOL_ERROR", "message": str(exc)[:500]},
            }
        latency_ms = int((time.perf_counter() - started) * 1000)
        result = compact_tool_result(result)
        record = ToolCallRecord(
            index=len(calls) + 1,
            name=name,
            args=args,
            result=result,
            latency_ms=latency_ms,
            status=status,
        )
        calls.append(record)
        self.trace.record_step(
            trace_id=trace_id,
            phase="tool",
            tool=name,
            args=args,
            result=result,
            latency_ms=latency_ms,
            status=status,
        )
        return result

    async def _run_deterministic(self, view: AlertView, trace_id: str) -> AgentRun:
        calls: list[ToolCallRecord] = []
        query = " ".join(
            [view.rule_description, " ".join(view.mitre_ids), view.src_ip or "", view.agent_name]
        ).strip()[:500]
        if not query:
            query = "security alert"
        kb = await self._call_tool(
            trace_id=trace_id,
            name="search_attack_knowledge",
            args={"query": query, "top_k": 3},
            calls=calls,
        )
        fetch_args: dict[str, Any] = (
            {
                "src_ip": view.src_ip,
                "min_level": max(3, view.rule_level - 4),
                "limit": 20,
            }
            if view.src_ip
            else {"min_level": max(0, view.rule_level - 3), "limit": 5}
        )
        fetched = await self._call_tool(
            trace_id=trace_id,
            name="fetch_wazuh_alerts",
            args=fetch_args,
            calls=calls,
        )
        output = self._decide(view, trace_id, kb, fetched, calls)
        self.trace.record_step(
            trace_id=trace_id,
            phase="decision",
            tool="deterministic_policy",
            args={"verdict": output.verdict, "risk_score": output.risk_score},
            result=output.model_dump(),
            status="ok",
        )
        return AgentRun(output=output, tool_calls=calls, model="deterministic")

    def _decide(
        self,
        view: AlertView,
        trace_id: str,
        kb: dict[str, Any],
        fetched: dict[str, Any],
        calls: list[ToolCallRecord],
    ) -> L1Output:
        kb_data = kb.get("data") if kb.get("ok") else {}
        results = (kb_data or {}).get("results") or []
        attacks = [r for r in results if r.get("type") == "attack"]
        iocs = [r for r in results if r.get("type") == "ioc"]
        # 告警自带的 MITRE ID 优先级最高；按告警给出的顺序选择，知识库只补名称与战术。
        top_attack = None
        for technique_id in view.mitre_ids:
            top_attack = next(
                (r for r in attacks if r.get("technique_id") == technique_id),
                None,
            )
            if top_attack is not None:
                break
        if top_attack is None and attacks:
            top_attack = attacks[0]
        top_attack_score = float(top_attack.get("score") or 0) if top_attack else 0.0

        fetch_data = fetched.get("data") if fetched.get("ok") else {}
        repeat_count = int(fetch_data.get("repeat_count") or 0)
        total = int(fetch_data.get("total") or 0)
        max_level = int(fetch_data.get("max_level") or 0)
        fetch_backend = (fetched.get("meta") or {}).get("backend", "unknown")

        sensitive_hit = False
        if top_attack:
            sensitive_hit = any(t in SENSITIVE_TACTICS for t in (top_attack.get("tactics") or []))

        level_signal = view.rule_level / 16
        repeat_signal = min(repeat_count / 5, 1.0) if view.src_ip else 0.0
        kb_signal = min(top_attack_score / 12, 1.0)
        ioc_signal = 1.0 if iocs else 0.0
        tactic_signal = 1.0 if sensitive_hit else 0.0
        risk = int(
            round(
                100
                * clamp(
                    0.45 * level_signal
                    + 0.25 * repeat_signal
                    + 0.15 * kb_signal
                    + 0.10 * ioc_signal
                    + 0.05 * tactic_signal,
                    0,
                    1,
                )
            )
        )

        verdict = "close"
        if iocs and view.rule_level >= 7:
            verdict = "escalate"
        elif view.rule_level >= 12:
            verdict = "escalate"
        elif repeat_count >= 3 and view.rule_level >= 10:
            verdict = "escalate"
        elif sensitive_hit and view.rule_level >= 10 and top_attack_score >= 3:
            verdict = "escalate"
        elif view.rule_level >= 7 or repeat_count >= 3:
            verdict = "watch"
        elif view.rule_level >= 5:
            verdict = "watch"
        else:
            verdict = "close"

        # 规则级风险下限：避免 /etc/sudoers 这类高等级单点告警因“无重复”被算成低风险。
        if iocs and view.rule_level >= 7:
            risk = max(risk, 75)
        if repeat_count >= 3 and view.rule_level >= 10:
            risk = max(risk, 70)
        if view.rule_level >= 12:
            risk = max(risk, 70)
        elif view.rule_level >= 10:
            risk = max(risk, 55)
        if verdict == "escalate":
            risk = max(risk, 65)
        risk = min(risk, 100)

        if verdict == "escalate":
            confidence = 0.88
            if repeat_count >= 3:
                confidence += 0.03
            if iocs:
                confidence += 0.03
            if kb.get("meta", {}).get("backend", "").startswith("local"):
                confidence -= 0.02
        elif verdict == "watch":
            confidence = 0.74
            if total >= 2:
                confidence += 0.04
        else:
            confidence = 0.84
        confidence = round(clamp(confidence, 0.55, 0.95), 2)

        technique_id = top_attack.get("technique_id") if top_attack else None
        technique_name = top_attack.get("title", "").split(" - ", 1)[-1] if top_attack else ""
        mitre: list[MitreTechnique] = []
        seen: set[str] = set()
        ordered_attacks = ([top_attack] if top_attack else []) + [
            result for result in attacks if result is not top_attack
        ]
        for result in ordered_attacks[:3]:
            tid = result.get("technique_id")
            if not tid or tid in seen:
                continue
            seen.add(tid)
            title = str(result.get("title") or tid)
            mitre.append(
                MitreTechnique(
                    technique_id=tid,
                    name=title.split(" - ", 1)[-1][:120],
                    tactic=(result.get("tactics") or [None])[0],
                    url=result.get("url"),
                    confidence=0.8,
                )
            )
        for tid in view.mitre_ids:
            if tid in seen or len(mitre) >= 5:
                continue
            meta = self._techniques.get(tid, {})
            mitre.append(
                MitreTechnique(
                    technique_id=tid,
                    name=str(meta.get("name") or tid)[:120],
                    tactic=(meta.get("tactics") or [None])[0],
                    url=meta.get("url"),
                    confidence=0.7,
                )
            )
            seen.add(tid)

        evidence: list[EvidenceItem] = [
            EvidenceItem(
                source="alert_rule",
                detail=(
                    f"rule.level={view.rule_level}, rule.id={view.rule_id}, "
                    f"agent={view.agent_name or '-'}, src_ip={view.src_ip or '-'}"
                ),
            )
        ]
        if fetched.get("ok"):
            if view.src_ip:
                evidence.append(
                    EvidenceItem(
                        source="fetch_wazuh_alerts",
                        detail=(
                            f"最近 {fetch_data.get('window_minutes', 15)} 分钟内同源 IP 触发 "
                            f"{repeat_count} 条告警，最高 level={max_level}，后端={fetch_backend}"
                        ),
                        tool_call_index=2,
                    )
                )
            else:
                evidence.append(
                    EvidenceItem(
                        source="fetch_wazuh_alerts",
                        detail=f"告警无 src_ip；最近窗口内查询到 {total} 条高等级告警，最高 level={max_level}",
                        tool_call_index=2,
                    )
                )
        else:
            evidence.append(
                EvidenceItem(
                    source="fetch_wazuh_alerts",
                    detail=f"Wazuh 查询失败：{json_dumps(fetched.get('error', {}))[:180]}",
                    tool_call_index=2,
                )
            )
        if top_attack:
            evidence.append(
                EvidenceItem(
                    source="search_attack_knowledge",
                    detail=f"ATT&CK 命中 {top_attack.get('technique_id')}（{technique_name}），score={top_attack_score:.2f}",
                    tool_call_index=1,
                )
            )
        if iocs:
            evidence.append(
                EvidenceItem(
                    source="search_attack_knowledge",
                    detail=f"IOC 命中 {iocs[0].get('title')}：{iocs[0].get('excerpt', '')[:120]}",
                    tool_call_index=1,
                )
            )
        if _INJECTION_MARKERS.search(view.full_log):
            evidence.append(
                EvidenceItem(
                    source="policy",
                    detail="full_log 中发现指令性文本，已按不可信数据处理并忽略。",
                )
            )

        actions: list[RecommendedAction] = []
        target_agent = view.agent_name or view.alert_id
        if verdict == "close":
            actions.append(
                RecommendedAction(
                    action="close_alert",
                    target=view.alert_id,
                    reason="低风险/无重复，未发现需要升级的技术或 IOC 信号。",
                )
            )
        elif verdict == "watch":
            actions.append(
                RecommendedAction(
                    action="monitor",
                    target=view.src_ip or target_agent,
                    reason="存在可疑信号但证据不足以升级，建议持续观察同源行为。",
                )
            )
            actions.append(
                RecommendedAction(
                    action="collect_evidence",
                    target=target_agent,
                    reason="保留登录日志、进程树与网络连接，供后续关联分析。",
                )
            )
        else:
            actions.append(
                RecommendedAction(
                    action="escalate_l2",
                    target=view.alert_id,
                    reason="高等级/重复触发/高危技术或 IOC 命中，建议转 L2 深度调查。",
                )
            )
            actions.append(
                RecommendedAction(
                    action="collect_evidence",
                    target=target_agent,
                    reason="在隔离或阻断前固化主机日志与网络证据。",
                )
            )
            if view.src_ip:
                actions.append(
                    RecommendedAction(
                        action="block_ip",
                        target=view.src_ip,
                        destructive=True,
                        requires_approval=True,
                        reason="同源 IP 短时间重复触发高等级认证失败，建议在边界阻断。",
                    )
                )
            elif view.rule_level >= 12:
                actions.append(
                    RecommendedAction(
                        action="isolate_host",
                        target=target_agent,
                        destructive=True,
                        requires_approval=True,
                        reason="主机出现高等级完整性变更且无源 IP，建议隔离并取证。",
                    )
                )

        requires_approval = any(a.destructive for a in actions)
        summary = self._summary(view, verdict, repeat_count, top_attack, iocs)
        reason = self._reason(view, verdict, repeat_count, total, top_attack, iocs, fetch_backend)
        limitations: list[str] = []
        if not view.src_ip:
            limitations.append("告警缺少 src_ip，无法做同源重复分析。")
        if (kb.get("meta") or {}).get("backend", "").startswith("local"):
            limitations.append("知识库使用本地 ATT&CK 子集，非全量 ATT&CK。")
        if fetch_backend == "mock":
            limitations.append("Wazuh 数据来自 mock 后端，仅用于演示。")
        if not kb.get("ok") or not fetched.get("ok"):
            limitations.append("至少一个工具调用失败，结论置信度已下调。")
        if not limitations:
            limitations.append("L1 仅做快速分诊，未执行主机取证或横向关联。")

        output = L1Output(
            alert_id=view.alert_id,
            trace_id=trace_id,
            verdict=verdict,
            risk_score=risk,
            confidence=confidence,
            summary=summary,
            reason=reason,
            evidence=evidence[:6],
            mitre_techniques=mitre[:5],
            recommended_actions=actions,
            tool_calls_used=len(calls),
            requires_human_approval=requires_approval,
            escalate_to_l2=verdict == "escalate",
            limitations=limitations[:5],
        )
        return L1Output.model_validate(output.model_dump())

    @staticmethod
    def _summary(
        view: AlertView,
        verdict: str,
        repeat_count: int,
        top_attack: dict[str, Any] | None,
        iocs: list[dict[str, Any]],
    ) -> str:
        tech = f"（疑似 {top_attack.get('technique_id')}）" if top_attack else ""
        ioc = f"，命中 IOC {iocs[0].get('title')}" if iocs else ""
        repeat = (
            f"同源 IP 15 分钟内 {repeat_count} 次"
            if view.src_ip
            else "告警不含源 IP，无法做同源重复分析"
        )
        if verdict == "escalate":
            return (
                f"{view.agent_name or '目标主机'} 触发 level-{view.rule_level} 告警「{view.rule_description}」"
                f"{tech}；{repeat}{ioc}，建议转 L2。"
            )[:500]
        if verdict == "watch":
            return (
                f"{view.agent_name or '目标主机'} 出现 level-{view.rule_level} 可疑行为「{view.rule_description}」"
                f"{tech}；{repeat}，当前证据不足以升级，建议观察。"
            )[:500]
        return (
            f"level-{view.rule_level} 告警「{view.rule_description}」风险较低，"
            f"{repeat}，建议关闭。"
        )[:500]

    @staticmethod
    def _reason(
        view: AlertView,
        verdict: str,
        repeat_count: int,
        total: int,
        top_attack: dict[str, Any] | None,
        iocs: list[dict[str, Any]],
        fetch_backend: str,
    ) -> str:
        parts = [
            f"告警规则为 {view.rule_id or '-'}，等级 {view.rule_level}，描述「{view.rule_description}」。",
        ]
        if view.src_ip:
            parts.append(
                f"Wazuh 查询后端 {fetch_backend}，窗口内同源告警 {repeat_count} 条，总匹配 {total} 条。"
            )
        else:
            parts.append(
                f"告警不含 src_ip，无法统计同源重复；Wazuh 查询后端 {fetch_backend}，窗口内总匹配 {total} 条。"
            )
        if top_attack:
            parts.append(
                f"知识库最高命中 {top_attack.get('technique_id')} {top_attack.get('title')}，"
                f"tactics={','.join(top_attack.get('tactics') or [])}。"
            )
        if iocs:
            parts.append(f"IOC 精确命中 {iocs[0].get('title')}。")
        if verdict == "escalate":
            parts.append("满足升级条件（高等级/重复触发/高危技术/IOC），转 L2。")
        elif verdict == "watch":
            parts.append("存在可疑信号但重复度或技术严重性不足，选择 watch。")
        else:
            parts.append("未发现重复、高危技术或 IOC 命中，选择 close。")
        return " ".join(parts)[:1200]

    async def _run_deepseek(self, view: AlertView, trace_id: str) -> AgentRun:
        calls: list[ToolCallRecord] = []
        prompt_tokens = completion_tokens = 0
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": L1_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": L1_USER_TEMPLATE.format(alert_json=json_dumps(view.brief(), pretty=True)),
            },
        ]
        async with httpx.AsyncClient(
            base_url=self.settings.deepseek_base_url,
            timeout=httpx.Timeout(self.settings.deepseek_timeout_s),
            headers={
                "Authorization": f"Bearer {self.settings.deepseek_api_key}",
                "Content-Type": "application/json",
            },
        ) as client:
            final_text = ""
            for _ in range(3):
                response = await client.post(
                    "/chat/completions",
                    json={
                        "model": self.settings.deepseek_model,
                        "messages": messages,
                        "tools": AGENT_TOOLS,
                        "tool_choice": "auto",
                        "temperature": 0.1,
                        "max_tokens": 1500,
                    },
                )
                response.raise_for_status()
                payload = response.json()
                usage = payload.get("usage") or {}
                prompt_tokens += int(usage.get("prompt_tokens") or 0)
                completion_tokens += int(usage.get("completion_tokens") or 0)
                message = (payload.get("choices") or [{}])[0].get("message") or {}
                tool_calls = message.get("tool_calls") or []
                if not tool_calls:
                    final_text = message.get("content") or ""
                    break
                messages.append(
                    {
                        "role": "assistant",
                        "content": message.get("content") or "",
                        "tool_calls": tool_calls,
                    }
                )
                for call in tool_calls:
                    if len(calls) >= 3:
                        break
                    function = call.get("function") or {}
                    name = str(function.get("name") or "")
                    raw_args = function.get("arguments") or "{}"
                    try:
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    except json.JSONDecodeError:
                        args = {}
                    result = await self._call_tool(
                        trace_id=trace_id, name=name, args=args, calls=calls
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.get("id"),
                            "content": json_dumps(result),
                        }
                    )
                if len(calls) >= 3:
                    break

            if not final_text:
                messages.append({"role": "user", "content": FINAL_JSON_INSTRUCTION})
                response = await client.post(
                    "/chat/completions",
                    json={
                        "model": self.settings.deepseek_model,
                        "messages": messages,
                        "temperature": 0.1,
                        "max_tokens": 1500,
                        "response_format": {"type": "json_object"},
                    },
                )
                response.raise_for_status()
                payload = response.json()
                usage = payload.get("usage") or {}
                prompt_tokens += int(usage.get("prompt_tokens") or 0)
                completion_tokens += int(usage.get("completion_tokens") or 0)
                final_text = (((payload.get("choices") or [{}])[0].get("message") or {}).get("content")) or ""

        cleaned = strip_code_fence(final_text)
        try:
            output = L1Output.model_validate(json.loads(cleaned))
            source = "deepseek"
        except Exception as exc:  # noqa: BLE001
            log.warning("LLM output invalid, fallback deterministic: %s", exc)
            self.trace.record_step(
                trace_id=trace_id,
                phase="llm",
                tool="deepseek",
                args={"model": self.settings.deepseek_model},
                result={"raw": cleaned[:3000], "error": str(exc)},
                status="error",
            )
            fallback = await self._run_deterministic(view, trace_id)
            fallback.output.limitations = (
                list(fallback.output.limitations)
                + ["LLM 输出未通过 Schema 校验，已降级为规则分诊。"]
            )[:5]
            fallback.prompt_tokens = prompt_tokens
            fallback.completion_tokens = completion_tokens
            fallback.total_tokens = prompt_tokens + completion_tokens
            fallback.model = f"{self.settings.deepseek_model}->deterministic"
            return fallback

        self.trace.record_step(
            trace_id=trace_id,
            phase="llm",
            tool="deepseek",
            args={"model": self.settings.deepseek_model},
            result={
                "verdict": output.verdict,
                "risk_score": output.risk_score,
                "confidence": output.confidence,
                "reason": output.reason,
            },
            status="ok",
            detail={"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
        )
        return AgentRun(
            output=output,
            tool_calls=calls,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            model=self.settings.deepseek_model,
        )
