"""Function Calling 的严格 JSON Schema。

这些定义同时用于：
1. DeepSeek function calling 的 tools 参数；
2. 导出 ``schemas/tool_*.schema.json`` 供审计；
3. 与 ``dify/tools/*.openapi.yaml`` 的人工核对。
"""

from __future__ import annotations

import json
from typing import Any

from .models import L1Output

FETCH_ALERTS_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "fetch_wazuh_alerts",
        "description": (
            "只读查询最近 15 分钟的 Wazuh 告警，用于判断同一源 IP 是否在短时间内重复触发。"
            "不传 src_ip 时返回最近的高等级告警，用于了解主机整体风险。"
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "default": 5,
                    "description": "返回条数，默认 5，最大 20",
                },
                "min_level": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 16,
                    "description": "最低 Wazuh rule.level；不传则不过滤",
                },
                "src_ip": {
                    "type": "string",
                    "minLength": 2,
                    "maxLength": 64,
                    "description": "源 IP（IPv4 或 IPv6）",
                },
            },
            "required": [],
        },
    },
}

SEARCH_KNOWLEDGE_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "search_attack_knowledge",
        "description": (
            "在 MITRE ATT&CK 技术摘要与 IOC 列表中检索与告警关键词匹配的技术。"
            "用于解释攻击行为、补充检测依据；不要用它查询主机状态。"
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "query": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 500,
                    "description": "告警关键词、规则描述或技术 ID，例如 ssh brute force 或 T1110",
                },
                "top_k": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "default": 3,
                    "description": "返回条数，默认 3",
                },
            },
            "required": ["query"],
        },
    },
}

AGENT_TOOLS = [FETCH_ALERTS_SCHEMA, SEARCH_KNOWLEDGE_SCHEMA]


def output_schema() -> dict[str, Any]:
    return L1Output.model_json_schema()


def output_schema_text() -> str:
    return json.dumps(output_schema(), ensure_ascii=False, indent=2)


def tool_schema_by_name(name: str) -> dict[str, Any]:
    for tool in AGENT_TOOLS:
        if tool["function"]["name"] == name:
            return tool
    raise KeyError(name)
