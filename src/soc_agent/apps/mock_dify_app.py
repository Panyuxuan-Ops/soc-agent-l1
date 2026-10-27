"""本地 Dify 测试替身入口。"""

from __future__ import annotations

from ..config import Settings
from ..mock_dify import create_mock_dify_app

app = create_mock_dify_app(Settings.from_env())
