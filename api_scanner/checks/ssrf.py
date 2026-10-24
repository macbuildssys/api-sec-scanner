"""API7 (server side request forgery) checks.

SSRF is only reported as proven when the target calls back to the scanner's own
listener with a one time token, or returns content from the cloud metadata service.
"""

from __future__ import annotations

import re
from typing import Any

from ..context import ScanContext
from ..models import Confidence, Endpoint
from . import check

_URL_PARAM = re.compile(
    r"(^|_|-)(url|uri|link|callback|webhook|redirect|return_?to|return_?url|next|dest|destination|target|image_?url|avatar_?url|feed|fetch|proxy|endpoint|source|src|domain|host)($|_|-)",
    re.I,
)
_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
_METADATA_MARKERS = ("ami-id", "instance-id", "local-ipv4", "iam/security-credentials", "security-credentials/")

def url_inputs(ep: Endpoint) -> list:
    """(location, name) of every input that looks like it takes a URL."""
    found = []
    for p in ep.params:
        if p.location == "query" and (_URL_PARAM.search(p.name) or p.schema.get("format") in ("uri", "url")):
            found.append(("query", p.name))
    props = (ep.body_schema or {}).get("properties", {}) if isinstance(ep.body_schema, dict) else {}
    for name, schema in props.items():
        if _URL_PARAM.search(name) or (isinstance(schema, dict) and schema.get("format") in ("uri", "url")):
            found.append(("body", name))
    return found

async def _send_with(ctx: ScanContext, ep: Endpoint, location: str, name: str, value: Any):
    if location == "query":
        return await ctx.send(ep, identity=ctx.identity, params={name: value}, label=ep.label)
    body = dict(ep.body_example) if isinstance(ep.body_example, dict) else {}
    body[name] = value
    return await ctx.send(ep, identity=ctx.identity, body=body, label=ep.label)

def _runnable(ctx: ScanContext, ep: Endpoint, location: str) -> bool:
    if location == "body" or ep.method not in ("GET", "HEAD"):
        return ctx.options.allow_mutating
    return True

@check("SSRF-001", active=True)
async def proven_ssrf(ctx: ScanContext, ep: Endpoint) -> None:
    for location, name in url_inputs(ep):
        if not _runnable(ctx, ep, location):
            continue
        if ctx.callback:
            token, url = ctx.callback.new_url()
            await _send_with(ctx, ep, location, name, url)
            hit = await ctx.callback.wait_for(token)
            if hit:
                ctx.add("SSRF-001", operation=ep.label, confidence=Confidence.CONFIRMED,
                        evidence=f"parameter '{name}': the target at {hit['remote']} requested the scanner's callback URL ({hit['ua'] or 'no user agent'})")
        base = await ctx.baseline(ep)
        probe = await _send_with(ctx, ep, location, name, _METADATA_URL)
        if probe.ok and any(m in probe.text for m in _METADATA_MARKERS) and not any(m in base.text for m in _METADATA_MARKERS):
            ctx.add("SSRF-002", operation=ep.label, confidence=Confidence.CONFIRMED,
                    evidence=f"parameter '{name}': the response contained cloud metadata content ({probe.text[:80]!r})")
