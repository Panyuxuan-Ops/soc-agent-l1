"""向云端 Redis Stream 注入 3 条典型 Wazuh 告警。

两种注入方式：
- 默认：直连 Redis Stream（旁路 Bridge，适合本地/隧道快速注入）；
- `--via-bridge`：POST 到 Bridge `/ingest/wazuh`，观察真实 `202` 与入队行为。

使用场景：
- 云端 Redis 只监听 127.0.0.1，本地先建立 SSH 隧道：
      ssh -N -L 6379:127.0.0.1:6379 deploy@<云端IP>
- 然后在本机运行：
      python scripts/inject_soc_alert.py
- 演示异步解耦时，在服务器上走 Bridge：
      python scripts/inject_soc_alert.py --via-bridge

环境变量：
- REDIS_HOST      默认 127.0.0.1（SSH 隧道本地端）
- REDIS_PORT      默认 6379
- REDIS_PASSWORD  可选；Redis 未设置密码时留空
- REDIS_STREAM    可选；默认 wazuh:alerts
- BRIDGE_URL      可选；默认 http://127.0.0.1:8000
- BRIDGE_TOKEN    可选；Bridge 开启鉴权时必填

只写入队列，不直接调用 Dify。consumer 会按项目现有格式读取
`alert / trace_id / received_at / source` 字段。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

STREAM_KEY = os.getenv("REDIS_STREAM", "wazuh:alerts").strip() or "wazuh:alerts"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6379
DEFAULT_BRIDGE_URL = (
    os.getenv("BRIDGE_URL", "http://127.0.0.1:8000").strip() or "http://127.0.0.1:8000"
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_alerts(run_id: str, timestamp: str) -> list[dict[str, Any]]:
    """构造 3 条可直接被 normalize_alert 解析的 Wazuh JSON。"""

    return [
        {
            # 1. 暴力破解：level 10，外部源 IP 多次失败登录
            "id": f"inject-{run_id}-brute-force",
            "timestamp": timestamp,
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "sshd: brute force trying to get access to the system",
                "groups": ["syslog", "sshd", "authentication_failures"],
                "mitre": {"id": ["T1110"], "technique": ["Brute Force"]},
            },
            "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.11"},
            "manager": {"name": "wazuh-manager"},
            "data": {
                "srcip": "203.0.113.45",
                "srcport": "54321",
                "dstuser": "root",
                "dstport": "22",
            },
            "full_log": (
                "Oct 21 10:00:00 web-01 sshd[1234]: Failed password for root "
                "from 203.0.113.45 port 54321 ssh2"
            ),
            "location": "/var/log/auth.log",
            "decoder": {"name": "sshd"},
        },
        {
            # 2. 误报误触：level 3，健康检查产生的正常访问日志
            "id": f"inject-{run_id}-false-positive",
            "timestamp": timestamp,
            "rule": {
                "id": "31533",
                "level": 3,
                "description": "Web access log",
                "groups": ["web", "accesslog"],
                "mitre": {"id": [], "technique": []},
            },
            "agent": {"id": "002", "name": "web-02", "ip": "10.0.0.12"},
            "manager": {"name": "wazuh-manager"},
            "data": {
                "id": "GET /health",
                "srcip": "10.0.0.50",
                "srcport": "41234",
                "dstport": "80",
            },
            "full_log": (
                '10.0.0.50 - - [21/Oct/2026:10:00:05 +0000] "GET /health HTTP/1.1" '
                '200 2 "-" "kube-probe/1.29"'
            ),
            "location": "/var/log/nginx/access.log",
            "decoder": {"name": "web-accesslog"},
        },
        {
            # 3. 可疑进程执行：level 12，PowerShell 编码命令
            "id": f"inject-{run_id}-suspicious-process",
            "timestamp": timestamp,
            "rule": {
                "id": "100201",
                "level": 12,
                "description": "Suspicious PowerShell encoded command execution",
                "groups": ["windows", "sysmon", "powershell"],
                "mitre": {"id": ["T1059.001"], "technique": ["PowerShell"]},
            },
            "agent": {"id": "003", "name": "win-01", "ip": "10.0.0.13"},
            "manager": {"name": "wazuh-manager"},
            "data": {
                "win": {
                    "eventdata": {
                        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "commandLine": (
                            "powershell.exe -nop -w hidden -enc "
                            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
                        ),
                        "parentImage": r"C:\Windows\System32\cmd.exe",
                        "user": r"CORP\svc_backup",
                    }
                }
            },
            "full_log": (
                "Sysmon EventID 1: Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe, "
                "CommandLine=powershell.exe -nop -w hidden -enc "
                "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
            ),
            "location": "EventChannel: Microsoft-Windows-Sysmon/Operational",
            "decoder": {"name": "windows-sysmon"},
        },
    ]


def _make_redis(redis_module, host: str, port: int, password: str | None):
    """创建同步 Redis 客户端；只用于独立注入脚本，不依赖项目 Settings。"""

    return redis_module.Redis(
        host=host,
        port=port,
        password=password,
        db=0,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        health_check_interval=30,
    )


def _print_alert_summary(index: int, alert: dict[str, Any], trace_id: str) -> None:
    rule = alert.get("rule", {})
    print(
        f"[{index}/3] level={rule.get('level')} "
        f"rule_id={rule.get('id')} "
        f"alert_id={alert.get('id')} "
        f"trace_id={trace_id}"
    )
    print(f"         {rule.get('description', '')}")


def _post_bridge(url: str, alert: dict[str, Any], token: str) -> tuple[int, dict[str, Any]]:
    """通过标准库 POST 到 Bridge；演示环境禁用系统代理，避免 localhost 被代理。"""

    payload = json.dumps(alert, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Bridge-Token"] = token
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read().decode("utf-8", errors="replace")
            return int(getattr(response, "status", 0)), json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return int(exc.code), {"detail": body[:500]}
    except urllib.error.URLError as exc:
        return 0, {"detail": str(exc.reason)}


def _inject_via_bridge(args: argparse.Namespace, alerts: list[dict[str, Any]]) -> int:
    endpoint = args.bridge_url.rstrip("/") + "/ingest/wazuh"
    written = 0
    for index, alert in enumerate(alerts, start=1):
        status, data = _post_bridge(endpoint, alert, args.bridge_token)
        if status != 202:
            print(
                f"[ERROR] Bridge 返回 {status}: {data.get('detail') or data}",
                file=sys.stderr,
            )
            print(
                "        检查 Bridge 是否启动、BRIDGE_TOKEN 是否正确；"
                "健康检查: curl -fsS http://127.0.0.1:8000/health",
                file=sys.stderr,
            )
            return 2
        print(
            f"[{index}/3] HTTP 202 "
            f"trace_id={data.get('trace_id')} "
            f"stream_id={data.get('stream_id')}"
        )
        written += 1

    print()
    print(f"[OK] Bridge 已接收 {written} 条告警（202），consumer 将异步消费。")
    print("[NEXT] 在 Dify 日志查看 run；用 XLEN / XINFO GROUPS 查看 Stream。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="向 Redis Stream 注入 3 条模拟 Wazuh 告警（默认 wazuh:alerts）"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只打印将写入的告警，不连接 Redis/Bridge",
    )
    parser.add_argument(
        "--via-bridge",
        action="store_true",
        help="通过 Bridge POST /ingest/wazuh 注入，观察真实 202",
    )
    parser.add_argument(
        "--bridge-url",
        default=DEFAULT_BRIDGE_URL,
        help=f"Bridge 地址，默认 {DEFAULT_BRIDGE_URL}",
    )
    parser.add_argument(
        "--bridge-token",
        default=os.getenv("BRIDGE_TOKEN", ""),
        help="Bridge Token，默认读取 BRIDGE_TOKEN",
    )
    args = parser.parse_args(argv)

    host = (os.getenv("REDIS_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST)
    port_raw = os.getenv("REDIS_PORT", str(DEFAULT_PORT)).strip() or str(DEFAULT_PORT)
    password = os.getenv("REDIS_PASSWORD", "")
    password = password if password else None

    try:
        port = int(port_raw)
    except ValueError:
        print(f"[ERROR] REDIS_PORT 不是整数: {port_raw!r}", file=sys.stderr)
        return 2

    if not (1 <= port <= 65535):
        print(f"[ERROR] REDIS_PORT 超出范围: {port}", file=sys.stderr)
        return 2

    run_id = uuid.uuid4().hex[:8]
    timestamp = _iso_now()
    alerts = build_alerts(run_id, timestamp)
    trace_ids = [f"trc_inject_{run_id}_{index}" for index in range(1, 4)]

    mode = "Bridge HTTP 202" if args.via_bridge else "Redis Stream 直连（旁路 Bridge）"
    print(f"Mode:   {mode}")
    if args.via_bridge:
        print(f"Bridge: {args.bridge_url.rstrip('/')}/ingest/wazuh")
        print(f"Stream: {STREAM_KEY} (Bridge 写入)")
    else:
        print(f"Redis:  {host}:{port} (db=0)")
        print(f"Stream: {STREAM_KEY}")
    print(f"Batch:  {run_id}")
    print()

    if args.dry_run:
        for index, (alert, trace_id) in enumerate(zip(alerts, trace_ids), start=1):
            _print_alert_summary(index, alert, trace_id)
            print(json.dumps(alert, ensure_ascii=False, indent=2))
            print()
        if args.via_bridge:
            print("[DRY-RUN] 未连接 Bridge，未发送任何告警。")
        else:
            print("[DRY-RUN] 未连接 Redis，未写入任何消息。")
        return 0

    if args.via_bridge:
        return _inject_via_bridge(args, alerts)

    try:
        import redis
    except ImportError:
        print(
            "[ERROR] 缺少 redis 依赖。请先执行: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2

    client = _make_redis(redis, host, port, password)
    try:
        client.ping()
    except redis.exceptions.AuthenticationError:
        print(
            "[ERROR] Redis 认证失败。检查 REDIS_PASSWORD，"
            "以及 SSH 隧道是否连接到正确的云端 Redis。",
            file=sys.stderr,
        )
        client.close()
        return 2
    except redis.exceptions.ConnectionError as exc:
        print(
            f"[ERROR] 无法连接 Redis {host}:{port}: {exc}",
            file=sys.stderr,
        )
        print(
            "        请确认 SSH 隧道已建立："
            "ssh -N -L 6379:127.0.0.1:6379 deploy@<云端IP>",
            file=sys.stderr,
        )
        client.close()
        return 2
    except redis.exceptions.RedisError as exc:
        print(f"[ERROR] Redis PING 失败: {exc}", file=sys.stderr)
        client.close()
        return 2

    written = 0
    try:
        for index, (alert, trace_id) in enumerate(zip(alerts, trace_ids), start=1):
            fields = {
                "alert": json.dumps(alert, ensure_ascii=False),
                "trace_id": trace_id,
                "received_at": _iso_now(),
                "source": "wazuh",
            }
            message_id = client.xadd(
                STREAM_KEY,
                fields,
                maxlen=10_000,
                approximate=True,
            )
            if isinstance(message_id, bytes):
                message_id = message_id.decode("utf-8")
            _print_alert_summary(index, alert, trace_id)
            print(f"         XADD ok, message_id={message_id}")
            written += 1

        stream_length = client.xlen(STREAM_KEY)
        print()
        print(f"[OK] 已写入 {written} 条告警到 Stream {STREAM_KEY!r}")
        print(f"[OK] 当前 Stream 长度: {stream_length}")
        print("[NEXT] 在云端确认 consumer 已消费；或用 redis-cli XLEN 复查。")
        return 0
    except redis.exceptions.ResponseError as exc:
        print(f"[ERROR] Redis 写入失败: {exc}", file=sys.stderr)
        return 2
    except redis.exceptions.RedisError as exc:
        print(f"[ERROR] Redis 操作失败: {exc}", file=sys.stderr)
        return 2
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
