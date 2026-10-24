"""Checks that use what public sources know about the target (see osint.py).

OSINT-001 asks the server once for each sensitive address the web archive remembers.
OSINT-005 reads the DNS answers that were collected, so it sends nothing at all.
OSINT-003 and OSINT-004 report a takeover and an open risky port that osint.py already verified.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from ..context import ScanContext, is_trivial_body
from ..http import Blocked
from ..models import Confidence
from ..osint import is_internal_ip
from . import check
from .discovery import FILE_PROBES

MAX_VERIFY = 15
_ARCHIVE_FILE = re.compile(r"\.(zip|tar|tgz|gz|7z|rar|bak|old|orig|sql\.gz)$|~$", re.I)
_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"Rar!", b"7z\xbc\xaf", b"ustar")

def _validate_archive(ex):
    """A backup or archive file: the answer must start like one, because an HTML page with status 200 proves nothing."""
    if "html" in ex.content_type or not ex.body:
        return None
    head = ex.body[:300]
    if any(head.startswith(m) for m in _MAGIC) or b"ustar" in head[250:300]:
        return f"{len(ex.body)} bytes that start like an archive file"
    return None

def _candidates(urls: list) -> list:
    """(url, check id, validator) for archived addresses that look like sensitive files. Root level probes already ran in EXP-*."""
    root_paths = {path for path, _, _ in FILE_PROBES}
    out = []
    for url in urls:
        path = urlsplit(url).path
        if path in root_paths:
            continue
        for known, check_id, validator in FILE_PROBES:
            if path.endswith(known):
                out.append((url, check_id, validator))
                break
        else:
            if _ARCHIVE_FILE.search(path):
                out.append((url, "OSINT-001", _validate_archive))
    return out[:MAX_VERIFY]

@check("OSINT-001", scope="host")
async def archived_sensitive_files(ctx: ScanContext) -> None:
    osint = getattr(ctx, "osint", None)
    if osint is None or not osint.archived:
        return

    async def verify(url: str, check_id: str, validator) -> None:
        if not ctx.client.in_scope(url):
            return
        try:
            ex = await ctx.client.request("GET", url, identity=None, label=f"GET {urlsplit(url).path}")
        except Blocked:
            return
        if not ex.ok or ctx.soft404.matches(ex) or is_trivial_body(ex):
            return
        proof = validator(ex)
        if proof:
            overrides = {"VC": "L"} if check_id == "EXP-003" else None
            ctx.add("OSINT-001", operation=f"GET {urlsplit(url).path}", confidence=Confidence.CONFIRMED, overrides=overrides,
                    evidence=f"{url} is remembered by the web archive and still answers: {proof}")

    await asyncio.gather(*[verify(u, c, v) for u, c, v in _candidates(osint.archived)])

@check("OSINT-005", scope="host")
async def internal_addresses_in_public_dns(ctx: ScanContext) -> None:
    osint = getattr(ctx, "osint", None)
    found = []
    for h in (osint.hosts if osint else []):
        ip = next((ip for ip in h.ips if is_internal_ip(ip)), None)
        if ip:
            found.append(f"{h.name} -> {ip}")
    if found:
        shown = ", ".join(found[:5]) + (f" and {len(found) - 5} more" if len(found) > 5 else "")
        ctx.add("OSINT-005", operation=f"DNS {osint.domain}", confidence=Confidence.CONFIRMED,
                evidence=f"Public DNS answers with private addresses for {len(found)} name(s): {shown}")

@check("OSINT-003", scope="host")
async def subdomain_takeover(ctx: ScanContext) -> None:
    osint = getattr(ctx, "osint", None)
    for name, provider, proof in (osint.takeovers if osint else []):
        ctx.add("OSINT-003", operation=f"DNS {name}", confidence=Confidence.CONFIRMED, evidence=f"{proof}")

@check("OSINT-004", scope="host")
async def risky_open_port(ctx: ScanContext) -> None:
    osint = getattr(ctx, "osint", None)
    for ip, port, service in (osint.open_risky if osint else []):
        ctx.add("OSINT-004", operation=f"TCP {ip}:{port}", confidence=Confidence.CONFIRMED,
                evidence=f"{service} port {port} on {ip} was listed by Shodan InternetDB and accepted a connection from this scanner")
