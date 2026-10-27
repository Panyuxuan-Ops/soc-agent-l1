# 可观测性与决策链

## 1. 目标

一条告警从进入系统到给出裁决，必须能回答：

1. 原始告警是什么？
2. Agent 调用了哪些工具？参数是什么？返回了什么？
3. 为什么给出 `close / watch / escalate`？
4. 是否有破坏性建议？是否创建审批？谁批的？什么时候？
5. 哪一步失败/超时？

对应实现：`src/soc_agent/trace.py`，同时写 SQLite 和 JSONL。

---

## 2. 存储结构

### 2.1 `runs`

| 字段 | 含义 |
| --- | --- |
| `trace_id` | 全链路 ID，主键 |
| `alert_id` | Wazuh 告警 ID |
| `received_at` / `started_at` / `finished_at` | 时间 |
| `status` | `running / succeeded / failed` |
| `mode` | `dify:api` / `dify:mock` |
| `model` | 模型 ID |
| `verdict` | `close / watch / escalate` |
| `risk_score` / `confidence` | 风险分/置信度 |
| `latency_ms` | 端到端耗时 |
| `workflow_run_id` | Dify 运行 ID |
| `approval_id` | 审批单 ID |
| `alert_json` | 脱敏后的告警快照 |
| `output_json` | 完整 L1 输出 |
| `error` | 失败原因 |
| `prompt_tokens` / `completion_tokens` / `total_tokens` | token 用量（Dify 返回时） |

### 2.2 `steps`

| 字段 | 含义 |
| --- | --- |
| `trace_id` / `seq` | 归属与顺序 |
| `ts` | 时间 |
| `phase` | `tool` / `decision` / `policy` |
| `tool` | 工具名或 `deterministic_policy` |
| `args_json` | 参数（脱敏） |
| `result_json` | 返回（脱敏、截断） |
| `latency_ms` | 工具耗时 |
| `status` | `ok / error / timeout` |
| `detail_json` | 补充信息 |

### 2.3 `approvals`

| 字段 | 含义 |
| --- | --- |
| `approval_id` | `apr_...` |
| `trace_id` / `alert_id` | 关联 |
| `status` | `pending / approve / reject / expired` |
| `actions_json` | 审批的动作列表 |
| `summary` | 审批摘要 |
| `created_at` / `decided_at` | 时间 |
| `decided_by` / `note` | 决策人/备注 |
| `expires_at` | 过期时间 |
| `token_hash` | token 的 SHA-256，不存明文 |

### 2.4 JSONL

`data/traces.jsonl` 追加事件：

```json
{"ts":"2026-10-20T14:23:40.518Z","event":"run_start","trace_id":"trc_...","alert_id":"wazuh-1001","mode":"dify:mock"}
{"ts":"2026-10-20T14:23:40.520Z","event":"step","trace_id":"trc_...","seq":1,"phase":"tool","tool":"search_attack_knowledge","args":{...},"result":{...},"latency_ms":0,"status":"ok"}
{"ts":"2026-10-20T14:23:40.530Z","event":"approval_created","trace_id":"trc_...","approval_id":"apr_...","summary":"..."}
{"ts":"2026-10-20T14:23:40.540Z","event":"run_finish","trace_id":"trc_...","status":"succeeded","verdict":"escalate","approval_id":"apr_..."}
```

JSONL 用于追加审计/外部采集；SQLite 用于查询。JSONL 写失败不会阻断主流程。

---

## 3. CLI

```powershell
# 最近 20 条
python -m soc_agent trace --limit 20

# 完整决策链
python -m soc_agent trace --id trc_4cb2029043e0ce54

# 统计
python -m soc_agent stats
```

`stats` 输出：

```json
{
  "runs": 5,
  "succeeded": 5,
  "failed": 0,
  "verdicts": {"escalate": 2, "watch": 2, "close": 1},
  "avg_latency_ms": 123,
  "p95_latency_ms": 179,
  "steps": 13,
  "approvals": {"pending": 2}
}
```

> 这些数字来自本地 `deterministic` + mock，不是真实 LLM 延迟。真实 DeepSeek 的端到端延迟会高一个数量级，需单独测。

---

## 4. SQL 查询

### 4.1 最近裁决

```sql
SELECT trace_id, alert_id, status, verdict, risk_score, confidence,
       latency_ms, approval_id, finished_at
FROM runs
ORDER BY started_at DESC
LIMIT 20;
```

### 4.2 重建一条决策链

```sql
SELECT seq, phase, tool, status, latency_ms,
       args_json, result_json
FROM steps
WHERE trace_id = 'trc_...'
ORDER BY seq;
```

### 4.3 某条告警的所有尝试

```sql
SELECT trace_id, status, error, started_at
FROM runs
WHERE alert_id = 'wazuh-1001'
ORDER BY started_at DESC;
```

### 4.4 审批积压

```sql
SELECT approval_id, alert_id, summary, created_at, expires_at
FROM approvals
WHERE status = 'pending'
ORDER BY created_at;
```

### 4.5 失败率 / 裁决分布

```sql
SELECT status, COUNT(*) AS n FROM runs GROUP BY status;
SELECT verdict, COUNT(*) AS n FROM runs GROUP BY verdict;
```

### 4.6 Token 用量（如果 Dify 返回）

```sql
SELECT SUM(prompt_tokens) AS prompt,
       SUM(completion_tokens) AS completion,
       SUM(total_tokens) AS total
FROM runs
WHERE finished_at >= date('now', '-1 day');
```

### 4.7 慢请求

```sql
SELECT trace_id, alert_id, latency_ms, verdict
FROM runs
WHERE status = 'succeeded'
ORDER BY latency_ms DESC
LIMIT 10;
```

---

## 5. 建议监控的指标

| 指标 | 来源 | 告警建议 |
| --- | --- | --- |
| 队列长度 | `XLEN wazuh:alerts` | 持续 > 1000 告警 |
| pending 数 | `XPENDING wazuh:alerts soc-l1` | 持续 > 100 或最老 > 5 分钟 |
| DLQ 增长 | `XLEN wazuh:alerts:dlq` | 5 分钟新增 > 0 |
| 消费成功率 | `runs.status` | 失败率 > 5% |
| 端到端 P95 | `runs.latency_ms` | 超过 SLA（如 30s） |
| Dify 5xx/超时 | consumer 日志 | 连续 3 次 |
| 工具错误率 | `steps.status='error'` | > 10% |
| 审批积压 | `approvals.status='pending'` | 超过 30 分钟未处理 |
| 审批过期 | `approvals.status='expired'` | 任何新增都值得关注 |
| 内存 | `docker stats` | Dify 整栈 > 3GB |
| 磁盘 | `data/` | 低于 20% 或 trace 超保留期 |

简单的 Prometheus 接法：

- 用 `sqlite_exporter` 或自己写 `/metrics` 端点；
- Redis 用 `redis_exporter`；
- Dify 用容器指标 + 日志；
- 不要为了监控再把 Elasticsearch 拉起来。

---

## 6. 日志字段

应用日志是 JSON lines（`src/soc_agent/log.py`）：

```json
{"ts":"...","level":"INFO","logger":"soc_agent.consumer","msg":"alert triaged","trace_id":"trc_...","alert_id":"wazuh-1001","verdict":"escalate"}
```

关键字段：

- `trace_id`：跨服务关联；
- `alert_id`：Wazuh 告警；
- `verdict` / `risk_score`；
- `approval_id`；
- `error`（失败时）。

采集建议：

- Docker：`docker compose logs --since 1h consumer`；
- systemd：`journalctl -u soc-consumer -o cat`；
- 生产：Loki/ELK/云日志，按 `trace_id` 建索引；
- 不要把 `full_log` 全量写日志；trace 里已经截断到 2000 字符。

---

## 7. 脱敏与保留

`redact()` 会递归处理：

- 键名包含 `password / passwd / token / secret / authorization / api_key` → `***`；
- 字符串超过 `max_text` 截断；
- 工具结果最多 4000 字符，告警最多 2000 字符。

注意：

- 脱敏是“避免明显泄露”，不是完整 DLP；
- 用户名、IP、文件路径仍可能敏感；
- trace DB 权限要限制（建议 640，owner `socagent`）；
- 保留天数：`SOC_TRACE_RETENTION_DAYS`，用 `python -m soc_agent prune --days 7` 清理；
- 审批 token 明文只在创建时返回一次，DB 只存 hash；生产不要把链接打进日志。

---

## 8. 一次完整重建示例

```text
1. runs 表按 trace_id 找到告警、裁决、风险分、审批 id；
2. steps 表按 seq 找到：
   - search_attack_knowledge 的 query 和返回的 T1110/IOC；
   - fetch_wazuh_alerts 的 src_ip、min_level、repeat_count；
   - deterministic_policy / LLM 的裁决理由；
3. approvals 表找到审批人、时间、备注；
4. JSONL 按时间顺序验证没有丢步骤；
5. 如果 status=failed，看 error 和最后一个 step 的 status。
```

示例（本地 demo）：

```powershell
python -m soc_agent trace --id trc_4cb2029043e0ce54
```

输出包含：

```text
#1 [tool] search_attack_knowledge args={"query":"... T1110 203.0.113.45 ..."}
#2 [tool] fetch_wazuh_alerts args={"src_ip":"203.0.113.45","min_level":8,"limit":20}
#3 [decision] deterministic_policy args={"verdict":"escalate","risk_score":89}
evidence: alert_rule / fetch_wazuh_alerts / search_attack_knowledge / policy
recommended_actions: escalate_l2 / collect_evidence / block_ip(destructive=true)
approval: apr_... status=pending
```

---

## 9. 可观测性缺口

- 没有接入 OpenTelemetry；跨服务 trace 目前靠 `trace_id` 字符串传递。
- 没有自动指标端点；`stats()` 是手工查询。
- Dify 内部的 LLM token、节点耗时，只能从 Dify 运行详情或 API 返回里拿；本项目目前只存 `total_tokens`。
- Redis Stream 的 pending 细节（idle、delivery count）需要 `XPENDING`/`XAUTOCLAIM` 查看，未做成面板。
- 生产建议补：`/metrics`、Grafana 面板、DLQ 告警、审批 SLA 告警。
