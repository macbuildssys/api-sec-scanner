"""Report writers. Every writer takes a ScanResult and returns text, except the console one."""

from __future__ import annotations

import json

from ..models import ScanResult
from .html import render_html
from .markdown import render_markdown
from .sarif import render_sarif

FORMATS = {
    "json": ("json", lambda r: json.dumps(r.to_dict(), indent=2)),
    "markdown": ("md", render_markdown),
    "sarif": ("sarif", render_sarif),
    "html": ("html", render_html),
}

def render(result: ScanResult, fmt: str) -> str:
    return FORMATS[fmt][1](result)

def extension(fmt: str) -> str:
    return FORMATS[fmt][0]
