# 云端 E2E 验收清单

> 适用拓扑：云端 4C4G 运行 Dify + SOC Redis；本地 Windows 运行 Bridge、tools、approval、consumer、Wazuh 模拟脚本。
>
> 本文按 **consumer 在本地运行、SQLite Trace 也保存在本地** 编写。如果 consumer 在云端，把 SQLite 路径换成云端 `data/traces.sqlite3`，其余步骤不变。
>
> 云端 Dify/Redis 的前置部署见 [CLOUD_DEPLOY.md](CLOUD_DEPLOY.md)。
>
> 所有 `$...` 都是占位符，不要把真实密码、Token、公网 IP 提交到 Git。

---

## 0. 验收目标与变量

### 0.1 通过标准

本次 E2E 至少确认以下链路：

```text
inject_soc_alert.py
  -> 云端 Redis Stream wazuh:alerts
  -> consumer
  -> 云端 Dify /v1/workflows/run
  -> Agent 调用 tools（最多 3 次）
  -> 标准四字段输出
  -> 本地 SQLite / JSONL Trace
  -> 破坏性建议生成审批记录
```

必须满足：

- [ ] 3 条告警全部进入 `wazuh:alerts`；
- [ ] consumer 消费 3 条，没有进入 DLQ；
- [ ] Dify 每次运行都有 `workflow_run_id`；
- [ ] Dify 运行记录能看到 Agent 节点和工具调用；
- [ ] 单次工具调用次数不超过 3；
- [ ] 输出严格为 `decision / confidence / reason / evidence` 四字段；
- [ ] 本地 SQLite `runs` 有对应 `trace_id`；
- [ ] 至少一条 `escalate` 告警产生审批记录与审批 Token 哈希；
- [ ] 审批链接单次有效，重复使用被拒绝；
- [ ] 记录真实平均/P95 延迟，稍后回填简历中的 `[X]`。

### 0.2 先设置变量

PowerShell 示例：

```powershell
$CLOUD_IP       = "203.0.113.10"          # 换成云端公网/内网 IP
$DIFY_URL       = "https://dify.example.com"
$TOOLS_URL      = "https://soc-tools.example.com"
$APPROVAL_URL   = "https://soc-approval.example.com"
$REDIS_HOST     = "127.0.0.1"             # SSH 隧道本地端
$REDIS_PORT     = "6379"
$REDIS_PASSWORD = ""                      # 没有密码就留空
```

Linux/macOS 示例：

```bash
export CLOUD_IP="203.0.113.10"
export DIFY_URL="https://dify.example.com"
export TOOLS_URL="https://soc-tools.example.com"
export APPROVAL_URL="https://soc-approval.example.com"
export REDIS_HOST="127.0.0.1"
export REDIS_PORT="6379"
export REDIS_PASSWORD=""
```

> **本地 Python 不会自动读取 `.env`。** 项目通过环境变量读取配置；本地启动 tools/approval/bridge/consumer 前，必须在当前终端显式设置变量。云端 Docker Compose 才通过 `env_file` 读取 `.env`。

---

## 1. 准备阶段

### 1.1 云端检查 Dify 和 Redis

```bash
# 云端 Dify 目录
cd /opt/dify/docker
docker compose ps
docker stats --no-stream
```

确认：

- [ ] Dify `api/worker/web/nginx` 均为 `running`；
- [ ] 没有容器反复 `Restarting` 或 `Exited (137)`；
- [ ] Dify 整栈内存约 3GB，没有持续逼近 4GB。

启动 SOC Redis（如果还没启动）：

```bash
cd /opt/soc-agent-l1
docker compose -f deploy/docker-compose.yml up -d redis
docker compose -f deploy/docker-compose.yml ps redis
```

检查 Redis 只监听 loopback：

```bash
docker ps --format '{{.Names}}\t{{.Ports}}' | grep redis
# 期望：127.0.0.1:6379->6379/tcp
# 如果出现 0.0.0.0:6379->6379/tcp，先停止并修 compose
```

检查淘汰策略必须是 `noeviction`，不能是 `allkeys-lru`：

```bash
docker compose -f deploy/docker-compose.yml exec redis \
  redis-cli CONFIG GET maxmemory maxmemory-policy
# 期望：
# maxmemory        268435456
# maxmemory-policy noeviction
```

> 如果 Redis 设置了密码，后续 `redis-cli` 加 `-a "$REDIS_PASSWORD"`，或使用 `REDISCLI_AUTH` 环境变量。不要把密码写在命令历史里。

### 1.2 本地建立 SSH 隧道

本地 PowerShell 新开一个终端并保持运行：

```powershell
ssh -N -L 6379:127.0.0.1:6379 deploy@$CLOUD_IP
```

排查时加 `-v`：

```powershell
ssh -v -N -L 6379:127.0.0.1:6379 deploy@$CLOUD_IP
```

另开一个本地终端验证：

```powershell
# 有 redis-cli
redis-cli -h 127.0.0.1 -p 6379 ping
# PONG

# 没有 redis-cli，用 Python
python -c "import os,redis; print(redis.Redis(host='127.0.0.1', port=6379, password=os.getenv('REDIS_PASSWORD') or None).ping())"
```

同时从公网侧确认 6379 不可达：

```powershell
Test-NetConnection $CLOUD_IP -Port 6379
# 期望 TcpTestSucceeded : False
```

- [ ] SSH 隧道保持运行；
- [ ] 本地 `PING` 返回 `PONG`；
- [ ] 公网 6379 不可达；
- [ ] 云端 `docker ps` 显示 Redis 只绑定 `127.0.0.1`。

### 1.3 本地启动 tools / approval / bridge

先安装依赖（只需一次）：

```powershell
python -m pip install -e ".[dev]"
```

在本地开三个终端。**每个终端都要设置环境变量**。

终端 A：tools

```powershell
$env:TOOL_API_TOKEN="<TOOL_API_TOKEN>"
$env:WAZUH_MODE="mock"                 # 真实 Wazuh 改为 indexer
$env:WAZUH_INDEXER_URL="https://<wazuh-indexer>:9200"
$env:SOC_PROJECT_ROOT="E:\毕业设计\soc-agent-l1"
python -m soc_agent serve tools --host 0.0.0.0 --port 8001
```

终端 B：approval

```powershell
$env:APPROVAL_API_TOKEN="<APPROVAL_API_TOKEN>"
$env:APPROVAL_PUBLIC_URL=$APPROVAL_URL
$env:APPROVAL_EXPOSE_LINKS="true"      # 仅 E2E 测试；生产建议 false
$env:SOC_DATA_DIR="E:\毕业设计\soc-agent-l1\data"
python -m soc_agent serve approval --host 0.0.0.0 --port 8002
```

终端 C：bridge（本次注入脚本直接写 Redis，可以先不启；完整 Wazuh 链路需要）

```powershell
$env:BRIDGE_TOKEN="<BRIDGE_TOKEN>"
$env:REDIS_URL="redis://127.0.0.1:6379/0"
$env:SOC_QUEUE_MODE="redis"
python -m soc_agent serve bridge --host 127.0.0.1 --port 8000
```

本地健康检查：

```powershell
curl.exe -s http://127.0.0.1:8001/health
curl.exe -s http://127.0.0.1:8002/health
curl.exe -s http://127.0.0.1:8000/health
```

- [ ] tools 返回 `ok: true`；
- [ ] approval 返回 `ok: true`；
- [ ] bridge 返回 `ok: true`（如果启动）。

如果 Dify 在云端、tools/approval 在本地，需要通过 Cloudflare Tunnel/Tailscale/frp 暴露：

```powershell
# 示例：临时 Cloudflare Tunnel
cloudflared tunnel --url http://127.0.0.1:8001
cloudflared tunnel --url http://127.0.0.1:8002
```

把输出的 HTTPS 地址填入 `$TOOLS_URL` 和 `$APPROVAL_URL`。不要填 `host.docker.internal`：云端容器里的它指向云服务器，不是你的笔记本。

从 Dify 容器验证能否访问 tools。下面命令在 **云端 shell** 执行，把地址换成实际隧道/宿主机地址：

```bash
cd /opt/dify/docker
docker compose exec api python -c \
  "import urllib.request; print(urllib.request.urlopen('https://soc-tools.example.com/health', timeout=5).read().decode())"
```

如果 tools 与 Dify 在同一台云主机，把 URL 换成 `http://host.docker.internal:8001/health`。

- [ ] Dify 容器内请求返回 `ok: true`；
- [ ] 如果失败，先修网络，不要继续在 Dify UI 里点“测试”。

### 1.4 运行注入脚本

先本地 dry-run，确认 3 条告警内容：

```powershell
$env:SOC_PROJECT_ROOT="E:\毕业设计\soc-agent-l1"
cd $env:SOC_PROJECT_ROOT
python scripts/inject_soc_alert.py --dry-run
```

再写入云端 Redis：

```powershell
$env:REDIS_HOST="127.0.0.1"
$env:REDIS_PORT="6379"
$env:REDIS_PASSWORD=""                # 有密码就填
python scripts/inject_soc_alert.py
```

> 该脚本**直接写 Redis Stream**，故意绕过 Bridge，用来单独验证“本地 -> 云端 Redis -> consumer -> Dify”的跨网络链路。它不验证 Wazuh Webhook/Bridge 的归一化；Bridge 链路请另用 `python -m soc_agent seed` 或后续的 `simulate_wazuh.py` 验证。

期望输出类似：

```text
[OK] 已写入 3 条告警到 Stream 'wazuh:alerts'
[OK] 当前 Stream 长度: 3
```

> `XLEN` 是 Stream 当前总长度，不是“本次写入 3 条”。如果之前有历史消息，长度会大于 3，这是正常的。

- [ ] 3 条都显示 `XADD ok`；
- [ ] 最后打印的 Stream 长度增加 3；
- [ ] 本地没有 `ConnectionError` / `AuthenticationError`。

### 1.5 云端查看写入与消费情况

查看 Stream 长度和最后 3 条：

```bash
cd /opt/soc-agent-l1

docker compose -f deploy/docker-compose.yml exec redis \
  redis-cli XLEN wazuh:alerts

docker compose -f deploy/docker-compose.yml exec redis \
  redis-cli XRANGE wazuh:alerts - + COUNT 3
```

检查字段必须是：

```text
alert        JSON 字符串
trace_id     trc_inject_...
received_at  ISO 时间
source       wazuh
```

检查 consumer group：

```bash
docker compose -f deploy/docker-compose.yml exec redis \
  redis-cli XINFO GROUPS wazuh:alerts
```

期望看到 group `soc-l1`，以及：

```text
pending       0 或 consumer 处理中的数量
consumers     consumer 启动后的消费者数量
last-delivered-id  接近最新消息 ID
```

> 只有在 consumer 启动后，group 和 consumer 才会出现。`XLEN` 在 ACK 后不会减少；判断消费进度看 `XINFO GROUPS` / `XPENDING`，不要只看 `XLEN`。

- [ ] `XLEN` 比注入前多 3；
- [ ] `XRANGE` 能看到 `alert/trace_id/received_at/source`；
- [ ] `XINFO GROUPS` 出现 `soc-l1`；
- [ ] 没有大量 `pending` 长期不处理。

---

## 2. Dify 阶段

### 2.1 导入 DSL

1. 云端 Dify 安装插件：
   - `langgenius/agent`
   - `langgenius/deepseek`
2. 工作室 -> 导入 DSL -> 选择 `dify/l1-triage.workflow.yml`；
3. 打开 Agent 节点，选择当前工作区可用的 DeepSeek 聊天模型；
4. 确认 `maximum_iterations=3`；
5. 此时 Agent 的工具列表为空，这是正常的，下一步手动绑定。

- [ ] DSL 导入成功；
- [ ] 模型可用，不是红色报错；
- [ ] Agent 节点显示 `maximum_iterations=3`；
- [ ] 没有删除 DSL 顶部的 `dependencies`。

### 2.2 创建并测试两个自定义工具

路径：

```text
工具 -> 自定义 -> 创建自定义工具 -> 从 OpenAPI 导入
```

分别导入：

```text
dify/tools/fetch_wazuh_alerts.openapi.yaml
dify/tools/search_attack_knowledge.openapi.yaml
```

Server URL 必须按实际位置填写：

| tools 位置 | Dify 工具 Server URL |
| --- | --- |
| 与 Dify 同一台云服务器宿主机 | `http://host.docker.internal:8001` |
| 本地电脑，经 Cloudflare/Tailscale/frp | `https://soc-tools.example.com` |
| 与 Dify 在同一个 compose 网络 | `http://tools:8001` |

**禁止**：

```text
http://127.0.0.1:8001       # 在 Dify 容器里是容器自己
http://localhost:8001       # 同上
```

> 如果 tools 在云服务器宿主机、准备使用 `host.docker.internal`，先确认 `deploy/dify-cloud-4c4g.override.yml` 的 `extra_hosts` 已生效；Linux Docker 默认不解析这个名字。

认证配置：

```text
类型：API Key / Bearer
Header：Authorization
Value：Bearer <TOOL_API_TOKEN>
```

如果 Dify 的认证类型已经自动添加 `Bearer ` 前缀，则只填 token，避免出现 `Bearer Bearer ...`。

工具调试请求：

```json
{
  "limit": 5,
  "min_level": 5,
  "src_ip": "203.0.113.45"
}
```

```json
{
  "query": "T1110 ssh brute force",
  "top_k": 3
}
```

- [ ] `fetch_wazuh_alerts` 测试返回 HTTP 200 / `ok: true`；
- [ ] `search_attack_knowledge` 测试返回 HTTP 200 / `ok: true`；
- [ ] 没有 401（Token 不匹配）或 422（参数不匹配）。

### 2.3 绑定到 Agent 节点

```text
工作室 -> 打开「SOC L1 告警分诊」
  -> 点击 Agent 节点
  -> 右侧「工具 / Tools」
  -> 添加工具
  -> 勾选 fetch_wazuh_alerts
  -> 勾选 search_attack_knowledge
  -> 保存
  -> 发布
```

- [ ] Agent 节点显示两个工具；
- [ ] 没有只绑定一个；
- [ ] 发布成功；
- [ ] 访问 API -> 创建应用 API Key（`<YOUR_API_KEY>`）。

### 2.4 工作流冒烟测试

在 Dify 运行面板输入：

```json
{
  "alert_json": "{\"id\":\"wazuh-smoke-001\",\"rule\":{\"level\":12,\"description\":\"sshd: brute force\",\"mitre\":{\"id\":[\"T1110\"]}},\"agent\":{\"name\":\"web-01\"},\"data\":{\"srcip\":\"203.0.113.45\"},\"full_log\":\"Failed password for root\"}",
  "trace_id": "trc_smoke_001"
}
```

期望：

- [ ] 工作流运行成功；
- [ ] 输出包含 `decision / confidence / reason / evidence`；
- [ ] 不含旧字段 `verdict/risk_score/recommended_actions` 作为标准输出；
- [ ] 如果产生破坏性建议，`policy` evidence 中有 `block_ip`/`isolate_host` 等 action；
- [ ] 如果审批服务可达，输出 `approval_id`；
- [ ] 如果审批服务不可达，工作流仍能完成（HTTP 节点不应拖垮整个裁决）。

查看 Dify 日志：

```bash
cd /opt/dify/docker
docker compose logs -f api worker
```

同时打开 Dify 应用的 **日志与标注（Logs & Annotations）**，找到这次运行，展开 Agent/工具节点，记录：

- 是否触发 Agent；
- 调用了哪个工具；
- 工具状态是否成功；
- 本次运行耗时（elapsed）；
- token 用量（如果显示）。

- [ ] Agent 节点执行；
- [ ] 至少一次工具调用成功；
- [ ] 工具调用次数不超过 3；
- [ ] 记录了本次耗时。

### 2.5 配置本地 consumer

本地 `.env`/环境变量至少包含：

```dotenv
SOC_QUEUE_MODE=redis
REDIS_URL=redis://127.0.0.1:6379/0

DIFY_MODE=api
DIFY_API_BASE=https://dify.example.com/v1
DIFY_API_KEY=<YOUR_API_KEY>

TOOL_API_TOKEN=<与 Dify 工具认证一致>
APPROVAL_API_TOKEN=<与 Dify 审批 HTTP 节点一致>
APPROVAL_BASE_URL=http://127.0.0.1:8002
APPROVAL_PUBLIC_URL=https://soc-approval.example.com

WAZUH_MODE=mock
```

PowerShell 逐项设置：

```powershell
$env:SOC_QUEUE_MODE="redis"
$env:REDIS_URL="redis://127.0.0.1:6379/0"
$env:DIFY_MODE="api"
$env:DIFY_API_BASE="$DIFY_URL/v1"
$env:DIFY_API_KEY="<YOUR_API_KEY>"
$env:TOOL_API_TOKEN="<TOOL_API_TOKEN>"
$env:APPROVAL_API_TOKEN="<APPROVAL_API_TOKEN>"
$env:APPROVAL_BASE_URL="http://127.0.0.1:8002"
$env:APPROVAL_PUBLIC_URL="$APPROVAL_URL"
$env:WAZUH_MODE="mock"
```

- [ ] `DIFY_API_BASE` 走 nginx 的 443/80，不是容器内 `api:5001`；
- [ ] 应用 API Key 不是 Dataset API Key；
- [ ] `APPROVAL_BASE_URL` 是本地 consumer/approval 的地址；
- [ ] `APPROVAL_PUBLIC_URL` 是审批人浏览器能打开的地址。

---

## 3. 端到端测试

### 3.1 启动 consumer

```powershell
cd E:\毕业设计\soc-agent-l1
python -m soc_agent consume 2>&1 | Tee-Object -FilePath data\consumer-e2e.log
```

如果 consumer 在云端：

```bash
docker compose logs -f consumer
```

- [ ] 日志出现 `consumer worker started`；
- [ ] 没有 `DIFY_MODE=api 但未设置 DIFY_API_KEY`；
- [ ] 没有 Redis 连接错误。

### 3.2 注入 3 条告警

另开本地终端：

```powershell
cd E:\毕业设计\soc-agent-l1
$env:REDIS_HOST="127.0.0.1"
$env:REDIS_PORT="6379"
$env:REDIS_PASSWORD=""
python scripts/inject_soc_alert.py 2>&1 | Tee-Object -FilePath data\inject-e2e.log
```

从输出记下 3 个 `trace_id`：

```text
trc_inject_<run_id>_1
trc_inject_<run_id>_2
trc_inject_<run_id>_3
```

- [ ] 脚本写入 3 条；
- [ ] consumer 日志出现 3 次 `alert triaged`；
- [ ] 日志中的 trace_id 与脚本输出一致；
- [ ] 没有 `message moved to DLQ`。

### 3.3 观察 Dify 运行记录

对每个 `trace_id`：

1. 打开 Dify 应用 -> **日志与标注**；
2. 按运行时间找到本次记录；
3. 展开运行详情；
4. 查看 Agent 节点、工具节点、结束节点；
5. 记录 `elapsed` 或运行详情中的耗时。

也可以从 SQLite 的 `workflow_run_id` 反查 Dify：

```powershell
python -m soc_agent trace --limit 10
```

重点检查：

- [ ] 3 次运行都有 `workflow_run_id`；
- [ ] Agent 节点被触发；
- [ ] 工具调用显示成功；
- [ ] 没有工具调用超过 3 次；
- [ ] 低等级误报没有被过度升级（示例 level=3 的告警应倾向 `close`/`watch`）；
- [ ] 高等级可疑进程可能倾向 `watch`/`escalate`，以实际 evidence 为准。

如果 Dify 日志里没有 Agent 节点：

- 检查 Agent 节点的工具是否绑定；
- 检查模型是否可用；
- 检查工作流是否发布的是最新版本；
- 检查运行输入是否为 `alert_json` + `trace_id`。

### 3.4 检查 SQLite 审计

先看整体统计：

```powershell
python -m soc_agent stats
```

期望类似：

```json
{
  "runs": 3,
  "succeeded": 3,
  "failed": 0,
  "verdicts": {"close": 1, "watch": 1, "escalate": 1},
  "avg_latency_ms": 0,
  "p95_latency_ms": 0,
  "steps": 0,
  "approvals": {"pending": 1}
}
```

> `steps` 在真实 Dify 路径下可能为 0：Dify 内部的 Agent/工具节点记录在 Dify 运行详情里，本地 SQLite 主要记录 `runs`、最终 `output_json`、`workflow_run_id` 和 `approvals`。不要因为 `steps=0` 就判定 E2E 失败。

查看具体 run：

```powershell
python -m soc_agent trace --id <trace_id>
```

检查：

- [ ] `status=succeeded`；
- [ ] `workflow_run_id` 非空；
- [ ] `output_json.decision` 是 `close/watch/escalate`；
- [ ] `output_json.confidence` 在 0 到 1；
- [ ] `output_json.reason` 不超过 50 字；
- [ ] `evidence` 每项都有 `tool/params/key_finding`；
- [ ] 高等级告警的 `evidence` 中有工具结果或 `alert_rule`；
- [ ] 破坏性建议只出现在 `policy` evidence 的 `params`，没有声称“已执行”。

> Dify 返回给 consumer 的标准输出只有四字段。`TraceStore.finish_run()` 为了兼容旧查询，会在 SQLite 的 `output_json` 里额外补 `verdict`、`risk_score`；看到这两个内部字段不代表 Dify 违反了四字段 Schema，判断标准以 Dify 运行结果和 `decision/confidence/reason/evidence` 为准。

直接查 SQLite（没有 `sqlite3` 命令时）：

```powershell
python -c "import sqlite3; c=sqlite3.connect('data/traces.sqlite3'); c.row_factory=sqlite3.Row; [print(dict(r)) for r in c.execute('SELECT trace_id,alert_id,status,verdict,confidence,latency_ms,workflow_run_id,approval_id FROM runs ORDER BY started_at DESC LIMIT 10')]"
```

检查审批表：

```powershell
python -c "import sqlite3; c=sqlite3.connect('data/traces.sqlite3'); c.row_factory=sqlite3.Row; [print(dict(r)) for r in c.execute('SELECT approval_id,trace_id,status,expires_at,length(token_hash) AS token_hash_len FROM approvals ORDER BY created_at DESC LIMIT 10')]"
```

- [ ] 有审批记录（至少一条 `escalate`）；
- [ ] `status=pending`（测试开始时）；
- [ ] `token_hash_len=64`（SHA-256 十六进制长度）；
- [ ] 数据库中没有明文 token 字段。

> 审批 Token 明文只应出现在审批链接/日志中，不应落库。数据库保存 `token_hash` 是正确行为。

### 3.5 审批 Token 单次使用测试

从 approval 服务日志中找到审批链接（测试环境设置了 `APPROVAL_EXPOSE_LINKS=true`）：

```powershell
# 如果 approval 日志已重定向
Select-String -Path data\approval-e2e.log -Pattern "approval links"

# 或在 approval 终端查看
# approval links: approve=... reject=...
```

用浏览器或 curl 打开 `approve_url`：

```powershell
curl.exe -i "<approve_url>"
```

然后用同一链接再打开一次：

```powershell
curl.exe -i "<approve_url>"
```

期望：

- [ ] 第一次显示审批成功；
- [ ] 第二次显示“该审批已处理，不能重复提交”；
- [ ] 数据库 `approvals.status` 变为 `approved`；
- [ ] `decided_at`、`decided_by` 有值；
- [ ] 重复使用不会改变最终状态；
- [ ] 审批通过不会自动执行 `block_ip`/`isolate_host`，只代表 L2 可继续复核。

如果 3 条告警都没有产生审批：

1. 检查高等级告警的 Dify 输出是否有 `policy` evidence；
2. 检查 `params.action` 是否为 `block_ip`/`isolate_host` 等破坏性动作；
3. 检查 `destructive=true` 与 `requires_approval=true`；
4. 不要为了测试审批而伪造“已执行”动作；必要时调整提示词/模型后重新跑高等级告警。

### 3.6 记录真实延迟

从三处记录：

| 数据源 | 字段/位置 |
| --- | --- |
| Dify 运行详情 | 本次运行 `elapsed` |
| 本地 SQLite `runs` | `latency_ms` |
| `python -m soc_agent stats` | `avg_latency_ms`、`p95_latency_ms` |

建议记录：

```text
实测告警 1（暴力破解 level=10）：Dify elapsed = [X] ms；本地 latency_ms = [X] ms
实测告警 2（误报 level=3）：Dify elapsed = [X] ms；本地 latency_ms = [X] ms
实测告警 3（可疑进程 level=12）：Dify elapsed = [X] ms；本地 latency_ms = [X] ms
平均延迟：[X] ms
P95 延迟：[X] ms
```

- [ ] 记录 3 条告警的真实耗时；
- [ ] 记录 Agent 工具调用次数；
- [ ] 记录 Dify 是否超时/重试；
- [ ] 这些 `[X]` 后续回填 README 和简历。

### 3.7 失败重试与 DLQ 抽查（建议做）

1. 临时把 `DIFY_API_BASE` 改成一个不可达地址；
2. 注入 1 条告警；
3. 观察 consumer 重试，超过 `REDIS_MAX_RETRIES=3` 后进入 DLQ；
4. 检查：

```bash
docker compose -f deploy/docker-compose.yml exec redis \
  redis-cli XLEN wazuh:alerts:dlq

docker compose -f deploy/docker-compose.yml exec redis \
  redis-cli XRANGE wazuh:alerts:dlq - + COUNT 1
```

5. 恢复正确 `DIFY_API_BASE`，重新启动 consumer。

- [ ] 失败消息不会被无提示丢弃；
- [ ] DLQ 中有 `error`、`attempts`、`failed_at`；
- [ ] 恢复配置后新告警可以正常消费。

> 不要在共享环境反复制造失败；测试前记录当前 Stream 长度，避免误判。

---

## 4. 常见报错与排查命令

### 4.1 本地注入脚本

| 报错/现象 | 可能原因 | 排查命令 |
| --- | --- | --- |
| `ConnectionError` / `Connection refused` | SSH 隧道没开、端口错误 | `Test-NetConnection 127.0.0.1 -Port 6379`；重开 `ssh -N -L ...` |
| `AuthenticationError` / `NOAUTH` | 密码错误或没传 | `$env:REDIS_PASSWORD`；`redis-cli -a ... ping` |
| `WRONGPASS` | Redis ACL 用户/密码不匹配 | 检查 `requirepass`/ACL；确认 URL 密码 |
| `XLEN` 为 0 | 写到了另一个 Redis/DB | 检查 `REDIS_HOST/PORT`、`REDIS_URL`、`INFO keyspace` |
| 脚本成功但 consumer 没反应 | Stream/Group 不一致 | `XINFO GROUPS wazuh:alerts`；检查 `REDIS_STREAM`、`REDIS_GROUP` |
| 重复注入后 consumer 跳过 | `alert_id` 重复，触发去重 | 脚本每次生成新的 `run_id`；检查日志 `duplicate alert skipped` |
| `ModuleNotFoundError: redis` | 依赖没装 | `python -m pip install -r requirements.txt` |

### 4.2 Redis / SSH 隧道

| 报错/现象 | 可能原因 | 排查命令 |
| --- | --- | --- |
| 本地 6379 被占用 | 本机已有 Redis | `Get-NetTCPConnection -LocalPort 6379`；换本地端口或停旧 Redis |
| 隧道建立后立刻断开 | SSH 认证/网络问题 | `ssh -v -N -L ...` |
| 云端 6379 公网可达 | compose 绑定了 `0.0.0.0` | `docker ps`；改回 `127.0.0.1:6379:6379`；检查安全组 |
| `XINFO GROUPS` 报 `NOGROUP` | consumer 未启动，group 未创建 | 先启动 consumer；或 `XGROUP CREATE ... MKSTREAM` |
| `XLEN` 不减少 | ACK 不会删除 Stream 条目 | 看 `XINFO GROUPS`、`XPENDING`；需要时用 `XTRIM` |
| pending 很多 | consumer 崩溃/处理慢 | `XPENDING wazuh:alerts soc-l1`；`XAUTOCLAIM` 由代码自动处理 |
| `OOM command not allowed` | Redis 达到 maxmemory 且 noeviction | `INFO memory`；清理/扩容；不要改 allkeys-lru |

### 4.3 Dify 工具/工作流

| 报错/现象 | 可能原因 | 排查命令/处理 |
| --- | --- | --- |
| 工具连接超时 | Dify 填了 `127.0.0.1` | 改 `host.docker.internal` 或隧道 URL；`docker compose exec api ...` |
| `host.docker.internal` 解析失败 | Linux 无 extra_hosts | 加 `host-gateway`；`getent hosts` |
| 工具 401 | Token 不一致/重复 Bearer | 对齐 `TOOL_API_TOKEN`；检查 `Bearer Bearer` |
| 工具 422 | 请求体不符合 OpenAPI | 用 Dify 工具调试页发最小请求体 |
| 工具 404 | URL 路径/Operation 不对 | 检查 `/tools/fetch_wazuh_alerts`；OpenAPI 重新导入 |
| Agent 没有工具 | 未手动绑定 | Agent 节点 -> 工具 -> 添加两个工具 |
| Agent 超过 3 次调用 | 提示词/模型不遵守 | 确认 `maximum_iterations=3`；检查系统指令 |
| Dify 工作流 502 | api/worker OOM 或未启动 | `docker compose ps`；`docker stats`；`docker compose logs api` |
| Dify 运行成功但输出解析失败 | 输出不是四字段 JSON | 查看运行详情；检查 `validate` 代码节点；不要改标准 Schema |
| 审批节点连接失败 | 仍指向 `host.docker.internal` 但 approval 在本地 | 改成 `$APPROVAL_URL/approvals`；检查 Bearer Token |
| Dify 日志看不到工具调用 | 看错位置 | 打开应用“日志与标注”运行详情，而不是只看容器 stdout |

### 4.4 SQLite / 审批

| 报错/现象 | 可能原因 | 排查命令 |
| --- | --- | --- |
| `sqlite3: command not found` | Windows 未安装 sqlite3 | 用文中的 Python `sqlite3` 一行命令 |
| `database is locked` | 多进程写同一 DB/外部工具占用 | 关闭 DB 浏览器；确认只有一个 consumer；WAL 已开启 |
| `runs` 没有记录 | consumer 未处理/Dify 调用前失败 | 看 consumer 日志、DLQ、`stats` |
| `steps` 为空 | 真实 Dify 路径不在本地记录内部节点 | 以 Dify 运行详情为准，不要误判 |
| `approvals` 为空 | 没有破坏性建议/审批节点失败 | 检查 `policy` evidence 和 `requires_approval` |
| `token_hash_len != 64` | 旧库结构/异常数据 | 检查 migrations；新建测试库 |
| 审批链接 invalid/已使用 | Token 单次使用或已过期 | 重新创建审批；检查 `expires_at` 与系统时间 |
| 审批链接打不开 | `APPROVAL_PUBLIC_URL` 不可公网访问 | 改 HTTPS 隧道域名；不要暴露裸 8002 |

### 4.5 时间与编码

| 现象 | 处理 |
| --- | --- |
| 审批刚创建就过期 | 校准云端/本地时间：`timedatectl`、Windows `w32tm /resync` |
| 中文乱码 | PowerShell 设置 `$env:PYTHONIOENCODING="utf-8"`；终端使用 UTF-8 |
| JSON 解析失败 | 检查 `alert_json` 是否被二次转义；用 `--dry-run` 对比 |

---

## 5. 验收签字表

| 检查项 | 期望 | 实测/证据 |
| --- | --- | --- |
| 云端 Redis | `noeviction`，仅 loopback |  |
| SSH 隧道 | 本地 `PING` 成功，公网 6379 关闭 |  |
| 注入脚本 | 3 条 XADD 成功 |  |
| Stream 字段 | `alert/trace_id/received_at/source` |  |
| consumer | 3 条 `alert triaged` |  |
| Dify 运行 | 3 个 `workflow_run_id` |  |
| Agent | 已触发，工具调用 ≤3 |  |
| 工具 | 两个工具至少一个成功 |  |
| 输出 | 标准四字段 |  |
| SQLite | `runs`、`output_json` 落库 |  |
| 审批 | `approvals` 有记录，`token_hash` 64 位 |  |
| 单次 Token | 第二次使用被拒绝 |  |
| 延迟 | 已记录 avg/P95 `[X]` ms |  |
| 失败链路 | DLQ 可观察（可选） |  |

---

## 6. 清理

```powershell
# 停止本地 consumer：Ctrl+C
# 关闭 SSH 隧道：Ctrl+C
# 如启动了临时 Cloudflare Tunnel：Ctrl+C
```

- [ ] 不在公网保留 6379/8001/8002；
- [ ] 测试 Token 如泄露到截图/日志，立即轮换；
- [ ] 保留 `data/traces.sqlite3`、`data/traces.jsonl`、`data/consumer-e2e.log` 作为联调证据；
- [ ] 将真实延迟和工具调用次数回填到 README/简历的 `[X]` 占位符。
