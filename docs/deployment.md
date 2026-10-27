# 部署手册

本文按“先本地、再单机 Docker、最后 systemd”的顺序写。所有命令以 Windows PowerShell 和 Linux bash 分别标注；没有标注的命令两边通用。

> 本地开发机没有 Docker/Wazuh/Dify 环境；Dify + DeepSeek 已在云端按本文完成部署与闭环验证，Wazuh 侧仍使用 mock 注入。以下步骤同时作为可执行清单，第一次部署请按“冒烟测试”逐段验证。

---

## 0. 前置条件

| 组件 | 版本 / 说明 |
| --- | --- |
| Python | 3.11+ |
| Redis | 7.x，开启 AOF；Stream 不能被 `allkeys-lru` 淘汰 |
| Dify | 1.16.x，DSL 0.7.0 |
| Wazuh | 4.x manager + indexer（生产） |
| DeepSeek | API Key；Dify 安装 `langgenius/deepseek` 插件 |
| 服务器 | 4C4G 起步；Dify 整栈约 3GB，见内存预算 |

> 3GB 预算只覆盖 Dify + 本项目。Wazuh manager/indexer 是既有 SIEM 组件，建议独立机器或使用已有集群；Wazuh Indexer 基于 OpenSearch/JVM，不要为了 RAG 再引入 Elasticsearch。

---

## 1. 配置

```powershell
Copy-Item .env.example .env
```

至少修改：

```dotenv
SOC_QUEUE_MODE=redis
REDIS_URL=redis://127.0.0.1:6379/0

WAZUH_MODE=indexer
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=...

DIFY_MODE=api
DIFY_API_BASE=http://127.0.0.1/v1
DIFY_API_KEY=<YOUR_API_KEY>

KNOWLEDGE_MODE=dify          # 或 local
DIFY_DATASET_ID=...
DIFY_DATASET_API_KEY=...

TOOL_API_TOKEN=...           # Dify 调 tools 的 Bearer token
APPROVAL_API_TOKEN=...       # Dify 调 approval 的 Bearer token
BRIDGE_TOKEN=...             # Wazuh 调 bridge 的 token

APPROVAL_BASE_URL=http://127.0.0.1:8002
APPROVAL_PUBLIC_URL=https://soc.example.com
APPROVAL_EXPOSE_LINKS=false
```

不要提交 `.env`。生产环境用 Docker secret、systemd `EnvironmentFile` 权限 600，或云厂商密钥管理。

> **Docker 网络注意**：容器里的 `127.0.0.1` 是容器自身。Docker 部署时，`WAZUH_INDEXER_URL`、`DIFY_API_BASE` 要填宿主机内网 IP（或 Docker Desktop 的 `host.docker.internal`）；`REDIS_URL` 已由 `deploy/docker-compose.yml` 固定为 `redis://redis:6379/0`，不要改成 `127.0.0.1`。

---

## 2. 启动 Redis

### Docker

```bash
docker run -d --name soc-redis \
  -p 127.0.0.1:6379:6379 \
  -v soc-redis-data:/data \
  redis:7-alpine \
  redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy noeviction
```

### 本机

```bash
sudo apt install redis-server
sudo systemctl enable --now redis-server
```

验证：

```bash
redis-cli ping
# PONG
redis-cli XINFO GROUPS wazuh:alerts
# 第一次消费后才有 group；没有 group 是正常的
```

> 本项目 Redis 是 **Stream 队列**，必须 `noeviction`。Dify 的缓存 Redis 是另一个实例，可以 `allkeys-lru`，不要混用。

---

## 3. 启动 tools / approval / bridge

### 3.1 直接运行（开发）

```powershell
python -m soc_agent serve tools --host 127.0.0.1 --port 8001
python -m soc_agent serve approval --host 127.0.0.1 --port 8002
python -m soc_agent serve bridge --host 127.0.0.1 --port 8000
```

另开一个终端：

```powershell
python -m soc_agent consume
```

### 3.2 健康检查

```bash
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8002/health
curl http://127.0.0.1:8000/health
```

### 3.3 工具服务鉴权

如果设置了 `TOOL_API_TOKEN`：

```bash
curl -X POST http://127.0.0.1:8001/tools/search_attack_knowledge \
  -H "Authorization: Bearer $TOOL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"T1110","top_k":3}'
```

没有 token 或 token 错误返回 401；参数不符合 Schema 返回 422：

```json
{
  "ok": false,
  "error": {
    "code": "INVALID_ARGUMENTS",
    "message": "工具参数不符合 JSON Schema",
    "details": []
  }
}
```

---

## 4. Dify 配置（关键）

### 4.1 安装插件

在 Dify → 插件市场安装：

- `langgenius/agent`（Agent Strategies）
- `langgenius/deepseek`（DeepSeek 模型）

工作流 DSL 里固定了：

```yaml
langgenius/agent:0.0.50@bf104068...
langgenius/deepseek:0.0.25@32f56796...
```

如果你的工作区版本不同，Dify 导入时会提示安装/升级；也可以先改 `dify/l1-triage.workflow.yml` 顶部的依赖版本。**不要删掉 dependencies**，否则 Agent 节点引用的插件没有声明。

### 4.2 导入工作流

1. Dify → 工作室 → 导入 DSL → 选择 `dify/l1-triage.workflow.yml`；
2. 打开“L1 分诊 Agent”节点；
3. 模型选择 DeepSeek，模型 ID 选择当前插件提供的聊天模型：
   - DSL 默认写的是 `deepseek-flash`（与 `langgenius/deepseek:0.0.25` 的模型列表一致）；
   - 如果你的插件版本只显示其他聊天模型（如 `deepseek-chat` / `deepseek-v4-flash`），在 UI 里改选，或改 YAML 后重新导入；
4. 工具列表此时是空的，继续下一步手动绑定。

### 4.3 创建两个自定义工具

Dify → 工具 → 自定义 → 创建自定义工具 → 导入 OpenAPI：

| 文件 | 工具名 | 说明 |
| --- | --- | --- |
| `dify/tools/fetch_wazuh_alerts.openapi.yaml` | `fetch_wazuh_alerts` | 查询最近 15 分钟 Wazuh 告警 |
| `dify/tools/search_attack_knowledge.openapi.yaml` | `search_attack_knowledge` | ATT&CK/IOC 检索 |

每个工具的认证方式：

```text
类型：API Key / Bearer
Header：Authorization
Value：Bearer <TOOL_API_TOKEN>
```

Server URL：

- Dify 在 Docker Desktop（Windows/macOS）：`http://host.docker.internal:8001`
- Dify 在 Linux Docker：`http://172.17.0.1:8001`（或宿主内网 IP）
- Dify 和 tools 在同一个 compose 网络：`http://tools:8001`

导入后在工具调试页分别测试一次，确认返回 `ok: true`。

### 4.4 手动绑定工具到 Agent

打开 Agent 节点 → 工具 → 添加工具 → 勾选：

- `fetch_wazuh_alerts`
- `search_attack_knowledge`

为什么不能自动带过来：Dify 自定义工具的 `provider_id` 是工作区级 ID，不能跨工作区移植。DSL 里 `tools: []` 是故意的，不是漏写。

同时确认：

- `maximum_iterations: 3`；
- Agent 指令里“最多 3 次工具调用”没有被改掉；
- 输出仍然是 JSON，不要改成 Markdown。

### 4.5 发布并取 API Key

1. 右上角“发布”；
2. 访问 API → 创建 API Key（`<YOUR_API_KEY>`）；
3. 写入 `.env`：

```dotenv
DIFY_MODE=api
DIFY_API_BASE=http://<dify-host>/v1
DIFY_API_KEY=<YOUR_API_KEY>
```

Dify 官方 compose 默认通过 nginx 暴露 80 端口，所以 API base 常见是 `http://127.0.0.1/v1`；如果你直接访问 api 容器，则是 `http://127.0.0.1:5001/v1`。

### 4.6 冒烟测试

在 Dify 工作流“运行”里填：

```json
{
  "alert_json": "{\"id\":\"wazuh-1001\",\"rule\":{\"level\":12,\"description\":\"sshd: brute force\",\"mitre\":{\"id\":[\"T1110\"]}},\"agent\":{\"name\":\"web-01\"},\"data\":{\"srcip\":\"203.0.113.45\"},\"full_log\":\"Failed password for root\"}",
  "trace_id": "trc_smoke_0001"
}
```

预期：

- 输出 `verdict=escalate`；
- `recommended_actions` 含 `block_ip`，且 `destructive=true`；
- 如果审批服务可达，返回 `approval_id`；
- 如果审批服务不可达，工作流仍应输出裁决（HTTP 节点 `continue`）。

---

## 5. 知识库

### 方案 A：本地 BM25（默认，零额外服务）

```dotenv
KNOWLEDGE_MODE=local
```

使用 `data/attack_techniques.json` + `data/iocs.csv`。适合演示和 4C4G 小机器。

### 方案 B：Dify Dataset Retrieve

1. Dify → 知识库 → 创建知识库；
2. 上传 `dify/knowledge/attack_techniques.md`、`dify/knowledge/iocs.md`；
3. 等待索引完成；
4. 在知识库 URL 里取 dataset id；
5. 创建 Dataset API Key（不是应用 API Key）；
6. 配置：

```dotenv
KNOWLEDGE_MODE=dify
DIFY_DATASET_ID=...
DIFY_DATASET_API_KEY=...
DIFY_RETRIEVAL_METHOD=hybrid_search
```

检索失败时 `CombinedKnowledgeBackend` 会降级本地 BM25，并在结果 `meta` 里标记 backend。这样 Dify 知识库故障不会让 L1 完全失效。

---

## 6. 审批服务

### 6.1 启动

```bash
python -m soc_agent serve approval --host 0.0.0.0 --port 8002
```

生产必须设置：

```dotenv
APPROVAL_API_TOKEN=...
APPROVAL_PUBLIC_URL=https://soc.example.com
APPROVAL_EXPOSE_LINKS=false
```

### 6.2 Dify HTTP 节点

工作流里的“创建人工审批”节点默认：

```yaml
url: http://host.docker.internal:8002/approvals
headers: |
  Content-Type: application/json
  Authorization: Bearer change-me
```

如果你设置了 `APPROVAL_API_TOKEN`，把 `change-me` 改成实际 token，或改成 Dify 环境变量引用。

Linux Docker 把 `host.docker.internal` 改成宿主机 IP；或在 Dify compose 的 api/worker 服务加：

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

### 6.3 通知

邮件：

```dotenv
SMTP_HOST=smtp.example.com
SMTP_PORT=465
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=soc@example.com
SMTP_TO=oncall@example.com
```

钉钉：

```dotenv
DINGTALK_WEBHOOK=https://oapi.dingtalk.com/robot/send?access_token=...
DINGTALK_SECRET=...
```

不配置通知渠道时，审批单仍会创建，链接只写日志（`APPROVAL_EXPOSE_LINKS=true` 时）。

### 6.4 手工测试

```bash
curl -X POST http://127.0.0.1:8002/approvals \
  -H "Authorization: Bearer $APPROVAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "trace_id":"trc_test",
    "alert_id":"wazuh-1001",
    "result_json":"{\"schema_version\":\"1.0\",\"alert_id\":\"wazuh-1001\",\"trace_id\":\"trc_test\",\"verdict\":\"escalate\",\"risk_score\":89,\"confidence\":0.9,\"summary\":\"test\",\"reason\":\"test\",\"evidence\":[],\"mitre_techniques\":[],\"recommended_actions\":[{\"action\":\"escalate_l2\",\"target\":\"wazuh-1001\",\"reason\":\"L2\"},{\"action\":\"block_ip\",\"target\":\"203.0.113.45\",\"destructive\":true,\"requires_approval\":true,\"reason\":\"block\"}],\"tool_calls_used\":2,\"requires_human_approval\":true,\"escalate_to_l2\":true,\"limitations\":[]}"
  }'
```

返回 `approval_id` 和 `preview.approve_url`。打开链接会看到审批页；同一 token 第二次提交返回 400。

---

## 7. Wazuh 集成

### 7.1 安装脚本

在 Wazuh manager 上：

```bash
sudo install -o root -g ossec -m 750 custom-soc-agent.py /var/ossec/integrations/custom-soc-agent.py
sudo install -o root -g ossec -m 640 /dev/null /var/ossec/etc/soc_bridge_token
echo 'your-bridge-token' | sudo tee /var/ossec/etc/soc_bridge_token >/dev/null
sudo chown root:ossec /var/ossec/etc/soc_bridge_token
sudo chmod 640 /var/ossec/etc/soc_bridge_token
```

如果 Wazuh 找不到 `.py` 脚本，把文件名改成无扩展名的 `custom-soc-agent`，并同步改 `<name>`：

```bash
sudo mv /var/ossec/integrations/custom-soc-agent.py /var/ossec/integrations/custom-soc-agent
```

### 7.2 配置 ossec.conf

把 `deploy/wazuh/ossec-integration.xml` 的 `<integration>` 段加入 `/var/ossec/etc/ossec.conf`：

```xml
<integration>
  <name>custom-soc-agent.py</name>
  <hook_url>http://127.0.0.1:8000/ingest/wazuh</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

重启：

```bash
sudo /var/ossec/bin/wazuh-control restart
sudo tail -f /var/ossec/logs/integrations.log
```

### 7.3 手工验证

先确保 bridge 在跑，然后：

```bash
python3 - <<'PY' > /tmp/one_alert.json
import json
print(json.dumps(json.load(open('data/sample_alerts.json'))[0]))
PY
sudo -u ossec /var/ossec/integrations/custom-soc-agent.py \
  http://127.0.0.1:8000/ingest/wazuh < /tmp/one_alert.json
```

bridge 日志应出现 `alert enqueued`，Redis 里应出现消息：

```bash
redis-cli XLEN wazuh:alerts
```

### 7.4 注意

- `custom-soc-agent.py` 只重试 1 次、3 秒超时，不会把 Wazuh 线程拖死；
- 脚本失败退出码仍是 0，避免 integratord 无限重试同一告警；
- 如果 bridge 和 Wazuh 不在同一台机器，把 `hook_url` 改成内网地址，并限制安全组只允许 Wazuh 访问 8000；
- `BRIDGE_TOKEN` 与 token 文件必须一致。

---

## 8. Docker Compose 部署

### 8.1 准备

```powershell
Copy-Item .env.example .env
# 编辑 .env
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml ps
```

服务：

| 服务 | 端口 | 说明 |
| --- | --- | --- |
| `redis` | 127.0.0.1:6379 | Stream，AOF，noeviction |
| `bridge` | 8000 | Wazuh 入口 |
| `tools` | 8001 | Dify 自定义工具 |
| `approval` | 8002 | 审批页/API |
| `consumer` | - | Dify 消费者 |
| `mock-dify` | 127.0.0.1:8003 | 仅 `--profile demo` |

### 8.2 演示 profile

```bash
docker compose -f deploy/docker-compose.yml --profile demo up -d --build
```

mock-dify 只用于验证 HTTP 契约；生产 `DIFY_MODE=api`，不需要它。

### 8.3 日志与停止

```bash
docker compose -f deploy/docker-compose.yml logs -f consumer
docker compose -f deploy/docker-compose.yml down
# 保留 trace 卷；要清空：
# docker compose -f deploy/docker-compose.yml down -v
```

### 8.4 非 root 与数据卷

Dockerfile 使用非 root 用户 `soc`，trace 写在命名卷 `soc_runtime`。镜像内 `data/` 是只读演示数据；运行期数据不会覆盖镜像。

要导出 trace：

```bash
docker compose -f deploy/docker-compose.yml cp consumer:/app/runtime/traces.jsonl ./traces.jsonl
```

---

## 9. Dify 3GB 内存限制

在 Dify 官方 compose 目录：

```bash
docker compose \
  -f docker-compose.yml \
  -f /opt/soc-agent-l1/deploy/dify-memory-3g.override.yml \
  up -d
```

检查：

```bash
docker stats --no-stream
```

预算表见 [architecture.md](architecture.md#8-资源预算4c4g)。如果总内存仍超 3GB：

1. 先把 `api` / `worker` 各降 100MB；
2. 把 `weaviate` 换 pgvector，或降低索引；
3. 降低 Dify 并发/worker 数；
4. 不要把本项目 Redis 和 Dify 缓存 Redis 混用。

---

## 10. systemd 部署（不用 Docker）

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin socagent
sudo mkdir -p /opt/soc-agent-l1
sudo chown -R socagent:socagent /opt/soc-agent-l1
# 把项目放到 /opt/soc-agent-l1，然后：
cd /opt/soc-agent-l1
sudo -u socagent python3.11 -m venv .venv
sudo -u socagent .venv/bin/pip install -r requirements.txt
sudo -u socagent .venv/bin/pip install -e .
```

配置 `/etc/soc-agent-l1.env`（权限 600，owner root）：

```bash
sudo install -m 600 /dev/null /etc/soc-agent-l1.env
sudo editor /etc/soc-agent-l1.env
```

复制 unit：

```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-bridge soc-tools soc-approval soc-consumer
sudo systemctl status soc-bridge
```

查看日志：

```bash
journalctl -u soc-consumer -f
```

> unit 里 `ProtectSystem=strict` + `ReadWritePaths=/opt/soc-agent-l1/data`，确保 `data/` 属于 `socagent`。如果使用外部路径，改 unit。

---

## 11. 冒烟测试清单

按顺序打勾：

- [ ] `redis-cli ping` 返回 PONG；
- [ ] `curl :8001/health`、`:8002/health`、`:8000/health` 都是 200；
- [ ] `python -m soc_agent demo` 5 条裁决符合预期；
- [ ] `python -m soc_agent seed --limit 1` 返回 202，consumer 日志出现 `alert triaged`；
- [ ] Dify 工作流手动运行返回 `verdict=escalate`；
- [ ] Dify Agent 节点里能看到两个工具；
- [ ] Dify 运行后 tools 服务日志有请求；
- [ ] 破坏性裁决创建审批单，非破坏性返回 `not_required`；
- [ ] 审批链接只能成功一次，第二次 400；
- [ ] `python -m soc_agent trace --id trc_...` 能看到工具参数/结果/裁决；
- [ ] 停掉 Dify，consumer 重试后进 DLQ（或按配置重试）；
- [ ] 停掉 approval，Dify 仍输出裁决，consumer 补建审批；
- [ ] `docker stats --no-stream` 总内存不超过机器预算。

---

## 12. 排错

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| tools 返回 401 | Dify 自定义工具 Bearer 与 `TOOL_API_TOKEN` 不一致 | 重新填认证 Header |
| tools 返回 422 | 模型传了 Schema 外字段/非法 IP | 看 `details`；不要放宽 Schema，改 Prompt |
| Dify 导入提示 dependency 缺失 | 插件未安装/版本不同 | 安装 `langgenius/agent`、`langgenius/deepseek`，或改 YAML 依赖 |
| Agent 没有工具可调用 | 自定义工具未绑定 | 打开 Agent 节点手动添加两个工具 |
| Dify 报 unknown model | 插件模型 ID 与 `deepseek-flash` 不一致 | 在 UI 改选当前聊天模型，或改 YAML |
| Dify HTTP 节点 401 | `Authorization` 与 `APPROVAL_API_TOKEN` 不一致 | 改 Header 或环境变量 |
| 审批链接打不开 | `APPROVAL_PUBLIC_URL` 是内网/容器地址 | 改成用户浏览器可达的地址 |
| 审批链接 400 | token 已用过/过期 | 重新发起告警或调整 TTL |
| Wazuh 没有触发 | `<level>` 太高、脚本无执行权限、`<name>` 不匹配 | 看 `integrations.log`；`chmod 750`；确认文件名 |
| Redis 消息堆积 | consumer 没起/Dify 超时 | 看 `consumer` 日志、`XPENDING`、DLQ |
| `XPENDING` 有大量 pending | consumer 崩溃/处理慢 | `XAUTOCLAIM` 会自动接管；检查 `REDIS_CLAIM_IDLE_MS` |
| 内存被 OOM kill | Dify 整栈超 3GB | 用 override 降限额，`docker stats` 实测 |
| `host.docker.internal` 解析失败 | Linux Docker | 加 `extra_hosts` 或用宿主 IP |
| SQLite `database is locked` | 多进程写同一 DB | 单机减少副本；生产换 Postgres |

---

## 13. 安全检查表

- [ ] `.env` 不在版本库，权限 600；
- [ ] `TOOL_API_TOKEN`、`APPROVAL_API_TOKEN`、`BRIDGE_TOKEN` 都已设置且足够随机；
- [ ] Redis 不暴露公网，`requirepass`/ACL；
- [ ] Wazuh token 文件 640，owner root:ossec；
- [ ] `APPROVAL_EXPOSE_LINKS=false`；
- [ ] 审批页仅内网/VPN 访问，或加反向代理认证；
- [ ] Dify 自定义工具只有两个只读 endpoint；
- [ ] 没有把 Wazuh active response / shell 暴露给模型；
- [ ] trace 访问受限，保留天数符合合规；
- [ ] Dify 插件版本固定，升级前回归测试；
- [ ] 破坏性动作仍然只出建议，不自动执行。
