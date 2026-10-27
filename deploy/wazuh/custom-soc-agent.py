#!/usr/bin/env python3
"""Wazuh integratord -> SOC Agent bridge。

Wazuh 通过 stdin 传入一条 JSON 告警；本脚本只做转发，不做任何判断。
设计约束：
- 3 秒超时，最多重试 1 次，绝不阻塞 Wazuh 的告警处理；
- 失败只写 stderr，退出码仍为 0，避免 integratord 反复重试同一告警；
- token 从文件读取，不写进 ossec.conf。

部署：
  install -o root -g ossec -m 750 custom-soc-agent.py /var/ossec/integrations/custom-soc-agent.py
  install -o root -g ossec -m 640 /dev/null /var/ossec/etc/soc_bridge_token
  echo 'your-token' > /var/ossec/etc/soc_bridge_token
  chown root:ossec /var/ossec/etc/soc_bridge_token

ossec.conf:
  <integration>
    <name>custom-soc-agent.py</name>
    <hook_url>http://127.0.0.1:8000/ingest/wazuh</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000/ingest/wazuh"
TOKEN_FILE = "/var/ossec/etc/soc_bridge_token"
TIMEOUT_SECONDS = 3


def _bridge_url() -> str:
    # Wazuh 会把 <hook_url> 作为第一个参数传给自定义集成脚本
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        return sys.argv[1]
    return os.environ.get("SOC_BRIDGE_URL", DEFAULT_URL)


def _token() -> str:
    token = os.environ.get("SOC_BRIDGE_TOKEN", "")
    if token:
        return token
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _post(alert: dict) -> bool:
    payload = json.dumps(alert, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    token = _token()
    if token:
        headers["X-Bridge-Token"] = token
    request = urllib.request.Request(
        _bridge_url(),
        data=payload,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"soc-agent bridge unavailable: {exc}", file=sys.stderr)
        return False


def main() -> int:
    try:
        alert = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"invalid Wazuh alert JSON: {exc}", file=sys.stderr)
        return 0
    if not isinstance(alert, dict):
        print("Wazuh alert must be a JSON object", file=sys.stderr)
        return 0

    # 只重试一次；Wazuh 本身会继续产生新告警，不能让积压拖垮 manager
    for attempt in range(2):
        if _post(alert):
            return 0
        if attempt == 0:
            time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
