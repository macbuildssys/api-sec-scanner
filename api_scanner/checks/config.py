"""API8 (security misconfiguration) checks that need their own requests.

Header, cookie, stack trace and secret findings come from passive.py, which looks at
every response for free.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from ..context import ScanContext
from ..http import Blocked
from ..models import Confidence
from . import check

_LOCAL = {"localhost", "127.0.0.1", "::1"}
EVIL_ORIGIN = "https://evil.example"

@check("CFG-006", scope="host")
async def cleartext_transport(ctx: ScanContext) -> None:
    if ctx.web:
        return  # website mode reports this itself, once, with better evidence
    parts = urlsplit(ctx.base_url)
    if parts.scheme == "http" and (parts.hostname or "") not in _LOCAL:
        ctx.add("CFG-006", operation=ctx.base_url, confidence=Confidence.CONFIRMED,
                evidence=f"the API base URL is {ctx.base_url} (no TLS)")

def _probe_endpoints(ctx: ScanContext) -> list:
    """A few GET operations, protected ones first, because CORS matters most there."""
    gets = [e for e in ctx.endpoints if e.method == "GET"]
    gets.sort(key=lambda e: (e.secured is not True, "{" in e.path))
    return gets[:3]

@check("CFG-001", scope="host")
async def cors_policy(ctx: ScanContext) -> None:
    for ep in _probe_endpoints(ctx):
        for origin in (EVIL_ORIGIN, "null"):
            try:
                ex = await ctx.send(ep, identity=ctx.identity, headers={"Origin": origin}, label=f"cors {ep.label}")
            except Blocked:
                return
            if ex.status is None:
                continue
            allow = ex.headers.get("access-control-allow-origin", "")
            creds = ex.headers.get("access-control-allow-credentials", "").lower() == "true"
            if allow == origin and creds:
                ctx.add("CFG-001", operation=ep.label, confidence=Confidence.CONFIRMED,
                        evidence=f"Origin: {origin} was reflected in Access-Control-Allow-Origin together with Allow-Credentials: true")
                return

@check("CFG-007", scope="host")
async def trace_method(ctx: ScanContext) -> None:
    marker = secrets.token_hex(6)
    try:
        ex = await ctx.client.request("TRACE", ctx.base_url or "", identity=None, headers={"X-Scanner-Trace": marker}, label="TRACE /")
    except Blocked:
        return
    if ex.ok and marker in ex.text:
        ctx.add("CFG-007", operation="TRACE /", confidence=Confidence.CONFIRMED, evidence="the TRACE response echoed a unique request header")
