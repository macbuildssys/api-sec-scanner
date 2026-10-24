"""Injection checks (OWASP Top 10:2025 A05). Active mode only.

Every finding needs a differential: the signal must appear with the payload and must NOT
appear with a harmless control value. Time based findings must repeat, and a control
payload with a zero second delay must stay fast.
"""

from __future__ import annotations

import re
import statistics
from typing import Any, Optional

from ..context import ScanContext
from ..http import Exchange
from ..models import Confidence, Endpoint
from . import check
from ..passive import ERROR_SIGNATURES

_SQL_SIGNATURES = [(p, n) for p, n in ERROR_SIGNATURES if "SQL" in n or "Oracle" in n or "PostgreSQL" in n or "SQLite" in n or "MySQL" in n]
_FILE_PARAM = re.compile(r"(file|path|name|page|template|doc|download|dir|folder|include|load|view|resource)", re.I)
_PASSWD = re.compile(r"root:[x*!]?:0:0:")
_WININI = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)

SQL_ERROR_PAYLOADS = ["'", '"', "')", "1'\"", "\\"]
TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
]
SSTI_PAYLOADS = ["{{91*91}}", "${91*91}", "<%= 91*91 %>", "#{91*91}", "{{=91*91}}"]
XSS_MARKER = "zx<q>\"'"

def injection_targets(ep: Endpoint, allow_body: bool) -> list:
    """(location, name, baseline value) for each string like input we may fuzz."""
    targets = []
    for p in ep.params:
        if p.location in ("query", "path") and p.schema.get("type") in (None, "string", "integer", "number"):
            targets.append((p.location, p.name, p.example if p.example is not None else "test"))
    if allow_body and isinstance(ep.body_example, dict):
        for key, value in ep.body_example.items():
            if isinstance(value, str):
                targets.append(("body", key, value))
    return targets[:6]

async def _fire(ctx: ScanContext, ep: Endpoint, location: str, name: str, value: Any, label: str = "probe") -> Exchange:
    if location == "query":
        return await ctx.send(ep, identity=ctx.identity, params={name: value}, label=f"{label} {ep.label}")
    if location == "path":
        return await ctx.send(ep, identity=ctx.identity, path_overrides={name: value}, label=f"{label} {ep.label}")
    body = dict(ep.body_example)
    body[name] = value
    return await ctx.send(ep, identity=ctx.identity, body=body, label=f"{label} {ep.label}")

def _pr(ctx: ScanContext, ep: Endpoint) -> dict:
    """Privileges required: low only when the specification says the operation is protected."""
    return {"PR": "L"} if ep.secured else {}

def _sql_signature(text: str) -> Optional[str]:
    for pattern, name in _SQL_SIGNATURES:
        if pattern.search(text):
            return name
    return None

async def _timed(ctx: ScanContext, ep: Endpoint, location: str, name: str, value: Any) -> float:
    ex = await _fire(ctx, ep, location, name, value, label="timing")
    return ex.elapsed if ex.status is not None else 0.0

@check("INJ-001", active=True)
async def sql_injection(ctx: ScanContext, ep: Endpoint) -> None:
    allow_body = ctx.options.allow_mutating and ep.method in ("POST", "PUT", "PATCH")
    if ep.method not in ("GET", "HEAD") and not allow_body:
        return
    for location, name, normal in injection_targets(ep, allow_body):
        control = await _fire(ctx, ep, location, name, normal)
        control_sig = _sql_signature(control.text) if control.status else None
        for payload in SQL_ERROR_PAYLOADS:
            ex = await _fire(ctx, ep, location, name, f"{normal}{payload}")
            sig = _sql_signature(ex.text) if ex.status else None
            if sig and sig != control_sig:
                ctx.add("INJ-001", operation=ep.label, confidence=Confidence.CONFIRMED, overrides=_pr(ctx, ep),
                        evidence=f"{location} '{name}': payload {payload!r} produced a {sig} that the normal value did not")
                return
        # time based, only after the error based tests found nothing
        delay = ctx.options.time_probe_seconds
        base_times = [await _timed(ctx, ep, location, name, normal) for _ in range(2)]
        if not base_times or max(base_times) > delay * 0.6:
            continue  # the endpoint is already slow or broken, timing proves nothing
        for slow, fast in [
            (f"{normal}' AND SLEEP({delay})-- -", f"{normal}' AND SLEEP(0)-- -"),
            (f"{normal}';SELECT pg_sleep({delay})--", f"{normal}';SELECT pg_sleep(0)--"),
            (f"{normal}'; WAITFOR DELAY '0:0:{delay}'--", f"{normal}'; WAITFOR DELAY '0:0:0'--"),
            (f"{normal} AND (SELECT 1 FROM (SELECT SLEEP({delay}))a)", f"{normal} AND (SELECT 1 FROM (SELECT SLEEP(0))a)"),
        ]:
            t1 = await _timed(ctx, ep, location, name, slow)
            if t1 < delay * 0.9:
                continue
            t2 = await _timed(ctx, ep, location, name, slow)
            t3 = await _timed(ctx, ep, location, name, fast)
            if t2 >= delay * 0.9 and t3 < delay * 0.5:
                ctx.add("INJ-002", operation=ep.label, confidence=Confidence.CONFIRMED, overrides=_pr(ctx, ep),
                        evidence=f"{location} '{name}': {slow!r} took {t1:.1f}s and {t2:.1f}s, the zero delay control took {t3:.1f}s (normal {statistics.mean(base_times):.2f}s)")
                return

@check("INJ-003", active=True)
async def command_injection(ctx: ScanContext, ep: Endpoint) -> None:
    allow_body = ctx.options.allow_mutating and ep.method in ("POST", "PUT", "PATCH")
    if ep.method not in ("GET", "HEAD") and not allow_body:
        return
    delay = ctx.options.time_probe_seconds
    for location, name, normal in injection_targets(ep, allow_body):
        base = await _timed(ctx, ep, location, name, normal)
        if base > delay * 0.6:
            continue
        for template in (";sleep {n}", "|sleep {n}", "$(sleep {n})", "`sleep {n}`", "&& sleep {n}"):
            t1 = await _timed(ctx, ep, location, name, f"{normal}{template.format(n=delay)}")
            if t1 < delay * 0.9:
                continue
            t2 = await _timed(ctx, ep, location, name, f"{normal}{template.format(n=delay)}")
            t3 = await _timed(ctx, ep, location, name, f"{normal}{template.format(n=0)}")
            if t2 >= delay * 0.9 and t3 < delay * 0.5:
                ctx.add("INJ-003", operation=ep.label, confidence=Confidence.CONFIRMED, overrides=_pr(ctx, ep),
                        evidence=f"{location} '{name}': {template.format(n=delay)!r} took {t1:.1f}s and {t2:.1f}s, the zero delay control took {t3:.1f}s")
                return

@check("INJ-004", active=True)
async def path_traversal(ctx: ScanContext, ep: Endpoint) -> None:
    if ep.method not in ("GET", "HEAD"):
        return
    for location, name, normal in injection_targets(ep, False):
        if location == "path" or not _FILE_PARAM.search(name):
            continue
        control = await _fire(ctx, ep, location, name, normal)
        if _PASSWD.search(control.text) or _WININI.search(control.text):
            continue
        for payload in TRAVERSAL_PAYLOADS:
            ex = await _fire(ctx, ep, location, name, payload)
            match = _PASSWD.search(ex.text) or _WININI.search(ex.text)
            if ex.status is not None and match:
                ctx.add("INJ-004", operation=ep.label, confidence=Confidence.CONFIRMED, overrides=_pr(ctx, ep),
                        evidence=f"{location} '{name}': {payload!r} returned operating system file content ({match.group(0)[:20]!r})")
                return

@check("INJ-005", active=True)
async def template_injection(ctx: ScanContext, ep: Endpoint) -> None:
    allow_body = ctx.options.allow_mutating and ep.method in ("POST", "PUT", "PATCH")
    if ep.method not in ("GET", "HEAD") and not allow_body:
        return
    for location, name, normal in injection_targets(ep, allow_body):
        control = await _fire(ctx, ep, location, name, normal)
        if "8281" in control.text:
            continue
        for payload in SSTI_PAYLOADS:
            ex = await _fire(ctx, ep, location, name, payload)
            if ex.status is None or "8281" not in ex.text:
                continue
            # A number can show up on a page by chance. A second expression with other numbers must give its own answer too.
            second = payload.replace("91*91", "73*89")
            again = await _fire(ctx, ep, location, name, second)
            if again.status is not None and "6497" in again.text and "6497" not in control.text:
                ctx.add("INJ-005", operation=ep.label, confidence=Confidence.CONFIRMED, overrides=_pr(ctx, ep),
                        evidence=f"{location} '{name}': {payload!r} was evaluated to 8281 and {second!r} to 6497")
                return

@check("INJ-006", active=True)
async def reflected_xss(ctx: ScanContext, ep: Endpoint) -> None:
    if ep.method not in ("GET", "HEAD"):
        return
    for location, name, normal in injection_targets(ep, False):
        ex = await _fire(ctx, ep, location, name, XSS_MARKER)
        if ex.ok and "html" in ex.content_type and XSS_MARKER in ex.text:
            ctx.add("INJ-006", operation=ep.label, confidence=Confidence.CONFIRMED,
                    evidence=f"{location} '{name}': the marker came back unescaped in a {ex.content_type} response")
            return
