"""审批服务入口。"""

from __future__ import annotations

from ..approval import create_approval_app
from ..config import Settings

app = create_approval_app(Settings.from_env())
