# SOC L1 告警研判闭环：5 分钟演示脚本

> **演示目标**：用 5 分钟讲清一批告警如何从 Wazuh 进入系统，经过异步队列、Dify Agent 研判、人工审批，最后落到可查询、可追溯的 SQLite 审计库。
>
> **一句话主线**：`Wazuh → Bridge(202) → Redis Stream → Consumer → Dify Agent → Approval → SQLite/JSONL`。
>
> **演示重点**：全链路闭环 + 安全机制。安全机制包括异步解耦、破坏性动作不自动执行、审批 token 单次有效、防重放、审计可重建。
>
> **口径说明（很重要）**：`scripts/inject_soc_alert.py` 默认是**直连 Redis** 的旁路注入，不经过 Bridge，所以不会打印 202。为了满足“脚本注入同时看到 Bridge 202”的演示要求，脚本新增了可选参数 `--via-bridge`；默认行为保持不变。本次演示使用：
>
> ```bash
> .venv/bin/python scripts/inject_soc_alert.py --via-bridge
> ```
>
> 不加 `--via-bridge` 时仍然是原来的 Redis 直连模式，答辩时不要把两种入口混为一谈。
>
> **敏感信息**：本文所有 IP、SSH 用户、密钥、token 均使用占位符。真实值只放在服务器 `/etc/soc-agent-l1.env` 和你的本地 SSH 配置里，不要写进文档、截图或提交记录。

---

## 0. 演示前 15 分钟：准备、清理与兜底

### 0.1 先建立 SSH 隧道（推荐）

Dify 的 `8081` 可能受云安全组限制，审批服务的 `8002` 只对 Docker 网段开放，外网直接点审批链接会失败。最稳的方式是本地 SSH 隧道：

```bash
ssh -N \
  -i <SSH_KEY> \
  -L 8081:127.0.0.1:8081 \
  -L 8002:127.0.0.1:8002 \
  <USER>@<YOUR_IP>
```

- 如果本地 `8081` 已被占用，把本地端口换成 `18081`，浏览器打开 `http://127.0.0.1:18081`；审批链接仍然是 `8002`，不要改。
- 本地 `8002` 必须空闲；如果被占用，先释放，或把审批链接里的 `8002` 改成你本地的转发端口（例如 `18002`），并相应调整 `-L 18002:127.0.0.1:8002`。
- 不建议为了演示把 `8002` 直接开放到公网；审批链接带 token，SSH 隧道足够。
- 隧道窗口保持打开，演示结束后再关闭。
- 验证：

```bash
curl -I http://127.0.0.1:8081
curl -fsS http://127.0.0.1:8002/health
```

预期：Dify 返回 `200/302`，审批服务返回类似：

```json
{"ok":true,"service":"approval","pending":0}
```

### 0.2 临时把审批链接改成隧道地址

服务器当前 `APPROVAL_PUBLIC_URL` 指向公网 IP，但 UFW 只允许 `172.16.0.0/12` 访问 `8002`，外网浏览器点不开。演示时临时改成 `127.0.0.1:8002`，让链接走本地 SSH 隧道。

```bash
sudo cp /etc/soc-agent-l1.env /etc/soc-agent-l1.env.demo.bak
sudo sed -i 's#^APPROVAL_PUBLIC_URL=.*#APPROVAL_PUBLIC_URL=http://127.0.0.1:8002#' /etc/soc-agent-l1.env
sudo systemctl restart soc-approval soc-consumer
```

确认审批链接会暴露、且地址正确：

```bash
sudo grep -E '^(APPROVAL_PUBLIC_URL|APPROVAL_EXPOSE_LINKS)=' /etc/soc-agent-l1.env
```

预期：

```text
APPROVAL_PUBLIC_URL=http://127.0.0.1:8002
APPROVAL_EXPOSE_LINKS=true
```

> `APPROVAL_EXPOSE_LINKS=true` 时，审批链接才会出现在 Dify 节点响应和 `soc-approval` 日志里；如果为 `false`，第 5.1 步拿不到链接。

> **演示后必须恢复**：
>
> ```bash
> sudo mv /etc/soc-agent-l1.env.demo.bak /etc/soc-agent-l1.env
> sudo systemctl restart soc-approval soc-consumer
> ```
>
> 如果不想改配置，也可以保留公网地址，生成链接后手动把 `http://<YOUR_IP>:8002` 替换成 `http://127.0.0.1:8002`，token 不变。现场演示推荐前者，操作更顺。
>
> 如果你是在**服务器本机**的浏览器里演示，`127.0.0.1:8002` 可以直接打开；如果你在**本地电脑**浏览器里演示，必须保持 0.1 的 SSH 隧道。

### 0.3 清空 Redis Stream（保留 DLQ）

> 以下命令在服务器 `/opt/soc-agent-l1` 上执行，会删除队列消息和消费组，属于**破坏性操作**。只在演示环境执行，执行前确认当前没有正在处理的告警。
>
> DLQ（死信队列）里的 21 条历史消息建议**保留**，它是“失败重试/死信机制”的现场证据；只有明确要演示“全新 DLQ”时才清空。

```bash
# 停写：bridge 可能继续入队，consumer/approval 会写 SQLite
sudo systemctl stop soc-bridge soc-consumer soc-approval

# 删除 Stream（连同消费组一起删除）
sudo docker exec soc-agent-l1-redis-1 redis-cli DEL wazuh:alerts

# 显式重建消费组；consumer 启动时也会 ensure_group，这一步只是让干净状态更直观
sudo docker exec soc-agent-l1-redis-1 redis-cli XGROUP CREATE wazuh:alerts soc-l1 0 MKSTREAM

# 清去重键（演示环境专用；生产不要用 KEYS）
sudo docker exec soc-agent-l1-redis-1 redis-cli EVAL \
  "local ks=redis.call('keys','soc:l1:seen:*'); for i=1,#ks do redis.call('del',ks[i]) end; return #ks" 0

# 清历史重试计数
sudo docker exec soc-agent-l1-redis-1 redis-cli EVAL \
  "local ks=redis.call('keys','wazuh:alerts:attempts:*'); for i=1,#ks do redis.call('del',ks[i]) end; return #ks" 0
```

查看 DLQ（预期仍是 21）：

```bash
sudo docker exec soc-agent-l1-redis-1 redis-cli XLEN wazuh:alerts:dlq
```

如果确实要连 DLQ 一起清空：

```bash
# 不推荐在“死信机制”演示前执行
sudo docker exec soc-agent-l1-redis-1 redis-cli DEL wazuh:alerts:dlq
```

### 0.4 清空 SQLite 审计表与 JSONL

服务器没有 `sqlite3` 命令行，直接用项目 `.venv` 里的 Python 标准库操作。先备份，再清空。

```bash
cd /opt/soc-agent-l1

# 仍保持 bridge / consumer / approval 停止
sudo systemctl stop soc-bridge soc-consumer soc-approval

# 1) 备份：一份当次回滚，一份当现场兜底
sudo -u socagent .venv/bin/python - <<'PY'
import sqlite3
from pathlib import Path

src = sqlite3.connect("runtime/traces.sqlite3")
backup_dir = Path("runtime/backup")
backup_dir.mkdir(parents=True, exist_ok=True)

for name in ("traces-before-demo.sqlite3", "demo-fallback.sqlite3"):
    dst = sqlite3.connect(backup_dir / name)
    with dst:
        src.backup(dst)
    dst.close()

src.close()
print("backup ok: runtime/backup/")
PY

sudo -u socagent cp runtime/traces.jsonl runtime/backup/traces-before-demo.jsonl 2>/dev/null || true

# 2) 清空三张审计表 + JSONL
sudo -u socagent .venv/bin/python - <<'PY'
import sqlite3
from pathlib import Path

with sqlite3.connect("runtime/traces.sqlite3") as conn:
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for table in ("steps", "approvals", "runs"):
        conn.execute(f"DELETE FROM {table}")
    try:
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'steps'")
    except sqlite3.OperationalError:
        pass
    conn.commit()

Path("runtime/traces.jsonl").write_text("", encoding="utf-8")
print("cleared: runs / steps / approvals / traces.jsonl")
PY
```

> **清理顺序不能反**：先停 `soc-bridge`、`soc-consumer` 和 `soc-approval`，再删表；否则 consumer 可能在清理过程中写回一条新 run。这里用 `DELETE` 而不是 `DROP`，保留表结构，服务重启即可继续写。
>
> `steps` 表在本批 Dify API 模式下可能为 0 行，这是正常的；工具调用证据在 `runs.output_json.evidence` 和 Dify 节点详情里，不要口述“每一步工具调用都写进了 steps 表”。

### 0.5 重启并验收“干净状态”

```bash
sudo systemctl start soc-bridge
sudo systemctl start soc-approval
sudo systemctl start soc-consumer
sleep 2

sudo systemctl is-active soc-tools soc-approval soc-bridge soc-consumer
```

预期四行都是：

```text
active
active
active
active
```

Redis 干净状态：

```bash
sudo docker exec soc-agent-l1-redis-1 redis-cli XLEN wazuh:alerts
sudo docker exec soc-agent-l1-redis-1 redis-cli XINFO GROUPS wazuh:alerts
```

预期：

```text
0
name=soc-l1 consumers=1 pending=0 last-delivered-id=0-0 entries-read=0 lag=0
```

审批服务干净状态：

```bash
curl -fsS http://127.0.0.1:8002/health
```

预期：

```json
{"ok":true,"service":"approval","pending":0}
```

SQLite 干净状态：

```bash
sudo -u socagent .venv/bin/python - <<'PY'
import sqlite3

with sqlite3.connect("runtime/traces.sqlite3") as conn:
    for table in ("runs", "steps", "approvals"):
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"{table}: {count}")
PY
```

预期：

```text
runs: 0
steps: 0
approvals: 0
```

> **Dify 历史日志说明**：Dify 的 run 历史不能像 SQLite 一样彻底清空。演示时按时间倒序看**最新 3 条**即可，不要声称“Dify 日志已经全部清空”。

### 0.6 窗口布局（建议 3 个终端 + 1 个浏览器）

```text
┌──────────────────────────────────┬──────────────────────────────────┐
│ 终端 A（左上）                    │ 浏览器（右上）                    │
│ 注入 / Redis / SQLite 命令        │ Dify → 日志与标注                 │
│                                  │                                  │
├──────────────────────────────────┼──────────────────────────────────┤
│ 终端 B（左下）                    │ 浏览器（右下，或同窗口第二个标签）│
│ journalctl -f（consumer/approval）│ 审批链接 → 已批准 → 重复点击失败   │
└──────────────────────────────────┴──────────────────────────────────┘
```

- 终端 C 可以做成终端 B 的一个标签，专门放 SQLite 查询，避免现场切目录。
- 终端字体调到 **16–18pt**，浏览器缩放到 **110%–125%**，保证录屏能看清。
- 提前关闭微信、钉钉、系统更新等通知；浏览器只留 Dify 和审批两个标签。
- Dify 提前登录，停在“工作室 → SOC L1 告警研判 → 日志与标注”页面，不要现场找入口。
- 长命令提前写进 shell 历史，或保存成 `runtime/demo_*.py`，现场用 `↑` 调出，减少手敲。

### 0.7 防翻车兜底（网络/现场故障）

**演示前必须准备：**

1. **本地录屏一份**：完整录一遍 5 分钟流程，保存到本地，不提交仓库。
2. **关键截图 5 张**：干净 Redis、Dify 三条 run、审批成功页、重复点击失败页、SQLite 审计输出。
3. **兜底数据库**：`runtime/backup/demo-fallback.sqlite3`，里面保留上一批真实结果；Dify 或网络挂了就用它讲审计。
4. **兜底命令**：把本文第 2–5 节的命令复制到一个本地文本文件，现场直接粘贴。

**现场故障处置：**

| 故障 | 30 秒内怎么办 |
|---|---|
| Dify UI 打不开 | 不现场修网络。切到 `journalctl -u soc-consumer` + 兜底 SQLite，口述“Dify 节点日志和本地审计库都能证明结果”，继续第 4–5 分钟。 |
| Dify 模型超时 | 不要等。展示队列 `pending` 和 consumer 日志，说明异步重试；切到兜底库展示上一批完整结果。 |
| 审批链接打不开 | 先确认 SSH 隧道还在；仍不行就在服务器本机执行 `curl` 打开链接（见 5.5 兜底），把返回页截图/展示。 |
| Redis 或 consumer 挂了 | `sudo systemctl restart soc-consumer`，等 5 秒；仍不行就跳过实时消费，用兜底库。 |
| 8081 页面卡顿 | 降低浏览器缩放，关闭其他标签；不要在现场反复刷新。 |
| 投影/共享屏幕延迟 | 直接讲结论，操作放慢；把终端字体再调大。 |

> **原则**：现场只排障 30 秒。超过 30 秒立即切录屏/截图/兜底库，不要在一个错误上耗尽 5 分钟。

---

## 1. 5 分钟时间轴总览

| 时间 | 画面 | 你要做的事 | 口播重点 |
|---|---|---|---|
| 0:00–1:00 | 架构图 + 终端 A | 展示干净 Redis / SQLite / 服务状态 | 数据流、异步解耦、干净环境 |
| 1:00–2:00 | 终端 A | `inject_soc_alert.py --via-bridge`，看到 3 个 202；查 `XLEN` | Bridge 只入队，不阻塞；异步消费 |
| 2:00–3:00 | 浏览器 Dify | 刷新日志，打开 3 条 run | 误报 close；高危 escalate；工具/证据 |
| 3:00–4:00 | 终端 B + 浏览器审批 | 从日志取审批链接，approve；再点一次 | 人在回路；token 单次；`already_decided` |
| 4:00–5:00 | 终端 C | 查 `runs` / `approvals` / evidence / latency | trace_id 串起裁决、证据、审批、耗时 |
| 5:00–5:10 | 回到架构图 | 一句话收尾 | 4C4G + Dify 1.17 下仍实现高可用闭环 |

> **超时取舍**：如果 Dify 页面慢，2–3 分钟只看 `close` 和一条 `escalate`；4–5 分钟先给三条汇总，再只展开一条高危 evidence。不要为了“三条都点开”而挤掉最后的总结。

---

## 2. 第 0–1 分钟：架构与干净环境

### 2.1 展示服务与干净队列

终端 A：

```bash
cd /opt/soc-agent-l1

sudo systemctl is-active soc-tools soc-approval soc-bridge soc-consumer

sudo docker exec soc-agent-l1-redis-1 redis-cli XLEN wazuh:alerts
sudo docker exec soc-agent-l1-redis-1 redis-cli XINFO GROUPS wazuh:alerts
sudo docker exec soc-agent-l1-redis-1 redis-cli XLEN wazuh:alerts:dlq

curl -fsS http://127.0.0.1:8002/health
```

预期：

```text
active
active
active
active
0
name=soc-l1 consumers=1 pending=0 last-delivered-id=0-0 entries-read=0 lag=0
21
{"ok":true,"service":"approval","pending":0}
```

### 2.2 展示 SQLite 空表

终端 A 继续：

```bash
sudo -u socagent .venv/bin/python - <<'PY'
import sqlite3

with sqlite3.connect("runtime/traces.sqlite3") as conn:
    for table in ("runs", "steps", "approvals"):
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"{table}: {count}")
PY
```

预期：

```text
runs: 0
steps: 0
approvals: 0
```

### 2.3 口述架构

> **此时你应该口述：**
>
> “现在是干净状态：Redis Stream 0 条，消费组 lag 为 0，SQLite 三张表全空。数据流是 Wazuh 产生告警，Bridge 做校验、脱敏、分配 trace_id 后写入 Redis Stream，Consumer 异步取出，交给 Dify Agent 研判；如果 Agent 建议阻断这类破坏性动作，不会直接执行，而是创建人工审批。整个过程会写进 runs、approvals 和 JSONL 审计日志。”
>
> “DLQ 里保留的 21 条是历史死信，用来证明失败重试和死信机制，不是本次演示的脏数据。”

---

## 3. 第 1–2 分钟：告警注入与异步解耦

### 3.1 通过 Bridge 注入 3 条告警

在服务器 `/opt/soc-agent-l1` 上执行。先读取 Bridge token 到环境变量（不打印 token）：

```bash
cd /opt/soc-agent-l1
export BRIDGE_TOKEN="$(sudo bash -c 'set -a; . /etc/soc-agent-l1.env; printf %s "$BRIDGE_TOKEN"')"

.venv/bin/python scripts/inject_soc_alert.py --via-bridge
```

> **先在终端 B 打开审批日志跟随**，否则第 5 步可能错过审批链接：
>
> ```bash
> sudo journalctl -u soc-approval -f -o cat \
>   | grep --line-buffered -o 'http://[^" ]*/approvals/[^" ]*'
> ```
>
> 日志是 JSON 行，上面这条命令只提取可点击的 approve/reject URL。让窗口一直开着，等两条 URL 出现。

预期输出（batch/trace 每次不同）：

```text
Mode:   Bridge HTTP 202
Bridge: http://127.0.0.1:8000/ingest/wazuh
Stream: wazuh:alerts (Bridge 写入)
Batch:  <BATCH_ID>

[1/3] HTTP 202 trace_id=trc_<...> stream_id=<...>
[2/3] HTTP 202 trace_id=trc_<...> stream_id=<...>
[3/3] HTTP 202 trace_id=trc_<...> stream_id=<...>

[OK] Bridge 已接收 3 条告警（202），consumer 将异步消费。
[NEXT] 在 Dify 日志查看 run；用 XLEN / XINFO GROUPS 查看 Stream。
```

> **关键点**：三个 `HTTP 202` 应该在一瞬间连续出现。Bridge 不等 Dify 研判，它只做校验、脱敏、分配 trace_id、`XADD`，然后立即返回。

### 3.2 立刻看队列

```bash
sudo docker exec soc-agent-l1-redis-1 redis-cli XLEN wazuh:alerts
sudo docker exec soc-agent-l1-redis-1 redis-cli XINFO GROUPS wazuh:alerts
```

预期：

```text
3
name=soc-l1 consumers=1 pending=<0~3> last-delivered-id=<...> entries-read=<0~3> lag=<0~3>
```

几秒后再次执行，会收敛到：

```text
3
name=soc-l1 consumers=1 pending=0 last-delivered-id=<...> entries-read=3 lag=0
```

> **解释口径**：`XLEN` 仍是 3，是因为 Redis Stream 的 `XACK` 只确认“已处理”，不会删除条目；`pending=0 / lag=0` 才表示 3 条都消费完了。不要把 `XLEN=3` 说成“还没消费”。

### 3.3 口播异步解耦

> **此时你应该口述：**
>
> “大家看，Bridge 连续返回了 202，三条告警已经可靠入队。202 不代表研判完成，只代表系统已经接收；真正的 Agent 调用在 Consumer 后面异步发生。这样即使 Dify 慢一点、模型超时，入口也不会被拖死，队列还能重试和进 DLQ。这就是异步解耦的价值。”

---

## 4. 第 2–3 分钟：Dify 智能体实时研判

### 4.1 切到 Dify 日志

浏览器打开：

```text
http://127.0.0.1:8081
```

（如果本地端口改成 `18081`，用 `http://127.0.0.1:18081`。）

操作路径：

1. 进入 **工作室**（Studio）。
2. 打开 **SOC L1 告警研判** 工作流。
3. 点击 **日志与标注**（Logs & Annotations）。
4. 刷新一次，按时间倒序看最新 3 条 run。

> 如果状态还是 `running`，等 3–5 秒再刷新；三条应该都会变成 `succeeded`。如果超过 30 秒仍未完成，按 0.7 的兜底处理，不要在现场等。

预期看到 3 条新 run，分别对应：

| 告警 | level | 预期裁决 | 预期置信度 | 参考耗时 |
|---|---:|---|---:|---:|
| 暴力破解 | 10 | `escalate` | 0.85 | ≈2506ms |
| 健康检查误报 | 3 | `close` | 0.95 | ≈2238ms |
| 可疑 PowerShell | 12 | `escalate` | 0.90 | ≈2766ms |

> 上表是上一轮参考批次的实测值；现场会有小幅波动，但量级和裁决方向应一致。

### 4.2 先打开 level 3 的误报

点开 `false-positive` 这条 run，展示：

- `verdict = close`
- `confidence = 0.95`
- `latency_ms` 约 2.2 秒
- `evidence` 只有 `alert_rule`，没有实际工具调用
- 没有 `approval_id`

口述要点：这条是 `GET /health` 的 kube-probe 健康检查，规则本身已经足够判断，Agent 没有调用额外工具，直接 close，所以最快。

### 4.3 再打开 level 10 / 12 的高危告警

分别点开 `brute-force` 和 `suspicious-process`，展示：

- `verdict = escalate`
- `confidence = 0.85 / 0.90`
- `evidence` 中包含 `alert_rule`、`policy` 等工具证据
- 出现 `approval_id`（格式 `apr_...`）
- 在 Agent 节点详情里可以看到工具调用参数和返回结果

> **口径提醒**：Dify 展示的是**节点级执行过程和工具调用记录**，不是模型的完整思维链（chain-of-thought）。答辩时说“可查看节点执行过程与工具证据”，不要说“展示了模型的全部思考过程”。
>
> 如果现场 Dify 版本只展示节点输出、不展示逐次工具调用，不要卡住；直接切到第 6 步，用 `runs.output_json.evidence` 展示工具名和参数。

### 4.4 口播研判结果

> **此时你应该口述：**
>
> “最新三条就是刚才的批次。level 3 的健康检查只引用了规则本身，没有额外工具调用，2.2 秒直接 close；level 10 的暴力破解和 level 12 的 PowerShell 都触发了工具查询，给出了 escalate 和证据，所以进入人工审批。这里 Agent 只给建议，不会自己执行阻断。”

---

## 5. 第 3–4 分钟：人在回路与审批防重放

### 5.1 从后台日志拿到审批链接

终端 B 如果已经在 3.1 提前跟随日志，直接看最新输出；如果没开，用最近 10 分钟的历史日志补查：

```bash
sudo journalctl -u soc-approval --since "10 minutes ago" -o cat \
  | grep -o 'http://[^" ]*/approvals/[^" ]*' | tail -2
```

预期输出两条 URL（第一条 approve，第二条 reject）：

```text
http://127.0.0.1:8002/approvals/apr_<...>/decide?token=<TOKEN>&decision=approve&by=email-link
http://127.0.0.1:8002/approvals/apr_<...>/decide?token=<TOKEN>&decision=reject&by=email-link
```

如果还没出现，执行 `sudo journalctl -u soc-approval -f -o cat | grep --line-buffered -o 'http://[^" ]*/approvals/[^" ]*'` 等待新日志。

> 历史日志里可能还有旧审批链接；清库后旧链接已经失效。只取**本轮最新**的两条 URL，不要点旧链接。

- 复制 `approve=` 后面的完整 URL。
- 如果链接里还是公网 IP，把 `http://<YOUR_IP>:8002` 替换成 `http://127.0.0.1:8002`；token 不要改。
- 如果邮件/钉钉已配置，也可以直接切到邮件/钉钉点“批准”；日志方式是现场最稳的兜底。
- 录屏时建议把 `token=` 后面的部分打码或快速带过；这是单次有效 token，但仍属于敏感信息。

> 也可以在 Dify 的“创建人工审批”节点输出里找 `preview.approve_url`，效果一样；日志方式更快。

### 5.2 批准一次

把 `approve` URL 粘贴到浏览器地址栏，回车。

> 注意：审批链接是 GET 请求，打开即生效，没有二次确认。复制时看清 URL 里是 `decision=approve`，不要误点 `decision=reject`。

预期页面：

```text
审批已批准
审批号：apr_<...>
这是一条单次有效的审批记录；L1 不会执行任何阻断动作，L2 执行器仍需校验本审批结果。
```

### 5.3 再点一次，展示防重放

刷新页面，或重新粘贴同一个 URL 再回车。

预期页面：

```text
审批失败
该审批已处理，不能重复提交。
```

后端返回的状态是 `already_decided`：审批表的 `status` 已经不是 `pending`，状态机在 token 校验之前就直接拒绝，避免重复批准、重复执行。

### 5.4 可选：用 API 展示字面量 `already_decided`

如果评委想看 JSON 字面量，终端 A 执行（把 `<APPROVAL_ID>` 换成页面上的审批号）：

```bash
curl -s -X POST "http://127.0.0.1:8002/approvals/<APPROVAL_ID>/decide" \
  -H "Content-Type: application/json" \
  -d '{"token":"replay-demo","decision":"approve","by":"demo"}'
```

预期：

```json
{"detail":"already_decided"}
```

> 这里用 dummy token 也能得到 `already_decided`，因为状态检查在 token 校验之前；这正好说明“已处理”是状态机层面的硬保护，不是靠前端按钮置灰。

### 5.5 兜底：链接打不开时

如果 SSH 隧道失效，在服务器本机执行（把 `<TOKEN>` 换成日志里的 token）：

```bash
curl -s "http://127.0.0.1:8002/approvals/<APPROVAL_ID>/decide?token=<TOKEN>&decision=approve&by=fallback" \
  | sed -n '1,40p'
```

再用同一个 URL 执行一次，预期返回“该审批已处理，不能重复提交”。把两次 HTML 输出展示给评委即可，不要在现场修隧道。

### 5.6 口播人在回路

> **此时你应该口述：**
>
> “这里是人在回路。Agent 判断需要阻断源 IP，但它不会自己执行，而是创建审批记录，把 approve/reject 链接发给分析师。批准一次后，同一个链接再点，后端直接返回 already_decided，页面提示已处理。也就是说，破坏性动作必须经过人，而且审批 token 单次有效，能防止重放和重复执行。”

---

## 6. 第 4–5 分钟：可观测性与审计溯源

### 6.1 查询三条 run 的裁决、证据和耗时

终端 C：

```bash
cd /opt/soc-agent-l1

sudo -u socagent .venv/bin/python - <<'PY'
import json
import sqlite3

conn = sqlite3.connect("runtime/traces.sqlite3")
conn.row_factory = sqlite3.Row

rows = conn.execute(
    """
    SELECT trace_id, alert_id, verdict, confidence, latency_ms, approval_id, output_json
    FROM runs
    ORDER BY received_at DESC
    LIMIT 3
    """
).fetchall()

for row in rows:
    output = json.loads(row["output_json"] or "{}")
    print(row["trace_id"])
    print(f'  alert={row["alert_id"]}')
    print(
        f'  decision={row["verdict"]}  '
        f'confidence={row["confidence"]}  '
        f'latency={row["latency_ms"]}ms  '
        f'approval={row["approval_id"]}'
    )
    print(f'  reason={output.get("reason", "")}')
    for ev in output.get("evidence", []):
        # 完整 evidence：tool / params / key_finding 都打印
        print(f'    - {json.dumps(ev, ensure_ascii=False)}')
    print()
PY
```

预期输出（ID 和数值现场会不同）：

```text
trc_<...>
  alert=inject-<...>-suspicious-process
  decision=escalate  confidence=0.9  latency=2766ms  approval=apr_<...>
  reason=...
    - {"tool": "alert_rule", "params": {"rule_id": "100201"}, "key_finding": "..."}
    - {"tool": "search_attack_knowledge", "params": {...}, "key_finding": "..."}
    - {"tool": "fetch_wazuh_alerts", "params": {...}, "key_finding": "..."}
    - {"tool": "policy", "params": {"action": "isolate_host", ...}, "key_finding": "..."}
    - {"tool": "policy", "params": {"action": "escalate_l2", ...}, "key_finding": "..."}

trc_<...>
  alert=inject-<...>-false-positive
  decision=close  confidence=0.95  latency=2238ms  approval=None
  reason=...
    - {"tool": "alert_rule", "params": {"rule_id": "31533"}, "key_finding": "..."}

trc_<...>
  alert=inject-<...>-brute-force
  decision=escalate  confidence=0.85  latency=2506ms  approval=apr_<...>
  reason=...
    - {"tool": "alert_rule", "params": {"rule_id": "5712"}, "key_finding": "..."}
    - {"tool": "fetch_wazuh_alerts", "params": {"src_ip": "203.0.113.45", ...}, "key_finding": "..."}
    - {"tool": "policy", "params": {"action": "block_ip", ...}, "key_finding": "..."}
```

等价 SQL（如果评委只想看 SQL，可以直接投屏）：

```sql
SELECT trace_id, alert_id, verdict AS decision, confidence, latency_ms, approval_id
FROM runs
ORDER BY received_at DESC
LIMIT 3;
```

> `runs` 表字段名是 `verdict`，展示时别名成 `decision`，和演示口径一致；完整 evidence 在 `output_json` 里，需要用 Python/JSON 解析。

### 6.2 查询审批状态

```bash
sudo -u socagent .venv/bin/python - <<'PY'
import sqlite3

conn = sqlite3.connect("runtime/traces.sqlite3")
conn.row_factory = sqlite3.Row

for row in conn.execute(
    """
    SELECT approval_id, trace_id, status, decided_by, decided_at
    FROM approvals
    ORDER BY created_at DESC
    """
):
    print(dict(row))
PY
```

预期（现场只批准了一条，另一条保持 pending）：

```text
{'approval_id': 'apr_<...>', 'trace_id': 'trc_<...>', 'status': 'approve', 'decided_by': 'email-link', ...}
{'approval_id': 'apr_<...>', 'trace_id': 'trc_<...>', 'status': 'pending', 'decided_by': None, ...}
```

> 如果两条都处理了，状态会是 `approve` / `reject`。状态值是 `approve`、`reject`、`pending`，不是 `approved` / `rejected`，答辩时按库里的值说。

### 6.3 最后确认队列收敛

```bash
sudo docker exec soc-agent-l1-redis-1 redis-cli XLEN wazuh:alerts
sudo docker exec soc-agent-l1-redis-1 redis-cli XPENDING wazuh:alerts soc-l1
sudo docker exec soc-agent-l1-redis-1 redis-cli XINFO GROUPS wazuh:alerts
```

预期：

```text
3
（XPENDING 返回空或 0 条）
name=soc-l1 consumers=1 pending=0 last-delivered-id=<...> entries-read=3 lag=0
```

### 6.4 口播审计链

> **此时你应该口述：**
>
> “最后回到审计库。每条 run 的 trace_id 能串起 decision、confidence、完整 evidence、approval_id 和 latency；审批表里能看到谁在什么时候批准或拒绝。刚才三条的端到端耗时大约 2.2 到 2.8 秒，队列最终 pending=0、lag=0。也就是说，这条告警从进入到审批，再到审计，是全链路可重建的。”

> **口径提醒**：本批的 `steps` 表可能为空；完整 evidence 在 `runs.output_json`，工具调用过程在 Dify 节点详情里。不要声称 `steps` 表有逐工具审计行。

---

## 7. 收尾：一句话总结

> **此时你应该口述：**
>
> “以上就是一个 5 分钟可复现的闭环：Bridge 异步接入不阻塞，Dify Agent 给出带证据的裁决，破坏性动作必须经过人工审批，审批 token 单次有效、能防重放，最后所有结果落到可查询的审计库。在 4C4G 的受限资源和 Dify 1.17 的兼容性约束下，这套系统仍然实现了高可用闭环：接入、研判、审批和审计。我的演示到这里，谢谢各位老师。”

---

## 8. 演示后恢复

1. 关闭审批链接和 Dify 页面。
2. 恢复 `APPROVAL_PUBLIC_URL`：

```bash
sudo mv /etc/soc-agent-l1.env.demo.bak /etc/soc-agent-l1.env
sudo systemctl restart soc-approval soc-consumer
```

3. 确认恢复：

```bash
sudo grep '^APPROVAL_PUBLIC_URL=' /etc/soc-agent-l1.env
```

4. 关闭 SSH 隧道。
5. 如果需要保留本轮演示数据，先备份：

```bash
cd /opt/soc-agent-l1
sudo -u socagent .venv/bin/python - <<'PY'
import sqlite3

src = sqlite3.connect("runtime/traces.sqlite3")
dst = sqlite3.connect("runtime/backup/demo-final.sqlite3")
with dst:
    src.backup(dst)
src.close()
dst.close()
print("saved: runtime/backup/demo-final.sqlite3")
PY
```

6. 不要把 `runtime/backup/`、录屏、截图、真实 `.env` 提交到 Git。录屏、截图或导出的 `journalctl` 里可能有审批 token，提交前打码或删除。

---

## 附录 A：审批链路的三种取链接方式

按现场稳定性排序：

1. **后台日志（推荐）**：`sudo journalctl -u soc-approval -f -o cat`，等 `approval links:` 行。
2. **Dify 节点输出**：打开 escalate run → “创建人工审批”节点 → 响应体 → `preview.approve_url`。
3. **邮件/钉钉**：如果 SMTP/DingTalk 已配置，直接点消息里的“批准”。

SQLite 只存 `token_hash`，**不能**从数据库反推出审批链接；链接只在创建响应、通知和日志里出现。这是 token 安全设计的一部分。

---

## 附录 B：常见现场问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `inject_soc_alert.py` 没有 202 | 没加 `--via-bridge`，走的是直连 Redis | 加 `--via-bridge`，或明确说这是旁路注入 |
| Bridge 返回 401 | `BRIDGE_TOKEN` 没导出或值不对 | 重新执行 3.1 的 `export BRIDGE_TOKEN=...`，不要打印 token |
| `XLEN=3` 但 `pending=0` | `XACK` 不删除 Stream 条目 | 正常现象，看 `pending/lag` 判断消费完成 |
| Dify 日志没有新 run | consumer 未消费、Dify API 配置错误、模型超时 | 看 `journalctl -u soc-consumer -n 50`；超过 30 秒切兜底库 |
| 审批链接 404/401 | 链接被换行截断、token 不完整、host 不对 | 从日志重新复制完整 URL；公网 IP 换成 `127.0.0.1` |
| 第二次点击仍显示成功 | 浏览器缓存了页面 | `Ctrl+Shift+R` 或重新粘贴 URL；看后端页面文案 |
| Dify 显示旧 run | Dify 历史不能像 SQLite 一样清空 | 按时间倒序看最新 3 条，不要声称全清 |
| 现场裁决与参考不一致 | 模型有随机性，或告警上下文变化 | 讲证据链和审批状态，不强行解释；必要时用兜底库的参考批次 |
| SQLite 查询为空 | 演示批次还没落库，或查错 DB | 等 2 秒；确认路径是 `runtime/traces.sqlite3` |

---

## 附录 C：演示前 15 分钟检查清单

- [ ] SSH 隧道 `8081` / `8002` 已建立，`curl` 健康检查通过。
- [ ] `APPROVAL_PUBLIC_URL` 已临时改成 `http://127.0.0.1:8002`，审批服务已重启。
- [ ] Dify 已登录，工作流和“日志与标注”页面已打开。
- [ ] 四个 systemd 服务都是 `active`。
- [ ] Redis Stream 已清空，消费组已重建，DLQ 保留 21 条。
- [ ] SQLite 三张表为 0，JSONL 已清空。
- [ ] 审批服务 `pending=0`。
- [ ] 已跑过一次 warm-up，确认 Dify 模型可用；warm-up 后重新执行清理。
- [ ] 已备份 `runtime/backup/demo-fallback.sqlite3`。
- [ ] 本地录屏、5 张截图已就绪。
- [ ] 终端字号、浏览器缩放、通知静音已调整。
- [ ] 审批链接获取方式（日志/Dify/邮件）已确认。
- [ ] 计时器已准备，5 分钟节点心里有数。

---

## 附录 D：本次演示的真实数据参考

上一轮参考批次（仅用于说明量级，现场会生成新的 trace_id）：

| trace | 告警 | 裁决 | 置信度 | 延迟 | 审批 |
|---|---|---|---:|---:|---|
| `trc_inject_6e4fab24_1` | brute-force | `escalate` | 0.85 | 2506ms | `apr_822e3700760e`，已 reject |
| `trc_inject_6e4fab24_2` | false-positive | `close` | 0.95 | 2238ms | 无 |
| `trc_inject_6e4fab24_3` | suspicious-process | `escalate` | 0.90 | 2766ms | `apr_8bcdbcc1c979`，已 approve |

误报的 evidence 只有 `alert_rule`，没有实际工具调用；这条可以作为“零工具调用、快速 close”的实证。高危两条的 evidence 在 `runs.output_json` 中，包含策略/规则等证据。
