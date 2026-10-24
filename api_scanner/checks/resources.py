"""API4 (unrestricted resource consumption) checks."""

from __future__ import annotations

import asyncio
import re
import time
from collections import Counter

from ..context import ScanContext
from ..http import Blocked
from ..models import Confidence, Endpoint
from . import LOGIN_PATH, check
from .objects import _items

_PAGE_PARAM = re.compile(r"^(limit|page_?size|per_?page|size|count|top|max|rows|take|num)$", re.I)
HUGE = 100000
_RATE_HEADERS = ("ratelimit", "x-ratelimit", "x-rate-limit", "retry-after", "ratelimit-limit", "ratelimit-policy")

@check("RES-001")
async def page_size_cap(ctx: ScanContext, ep: Endpoint) -> None:
    if ep.method != "GET":
        return
    page_params = [p for p in ep.params if p.location == "query" and _PAGE_PARAM.match(p.name)]
    if not page_params:
        return
    param = page_params[0]
    base = await ctx.baseline(ep)
    if not base.ok:
        return
    ex = await ctx.send(ep, identity=ctx.identity, params={param.name: HUGE}, label=ep.label)
    if not ex.ok:
        return  # the server rejected the huge value, which is the right behaviour
    count = len(_items(ex.json))
    baseline_count = len(_items(base.json))
    if count > max(baseline_count, 100):
        ctx.add("RES-001", operation=ep.label, confidence=Confidence.CONFIRMED,
                evidence=f"{param.name}={HUGE} returned {count} items ({len(ex.body)} bytes), default returned {baseline_count}")

async def _burst(ctx: ScanContext, ep: Endpoint, count: int) -> tuple:
    async def one():
        return await ctx.send(ep, identity=ctx.identity, paced=False, label=f"burst {ep.label}", observe=False)

    start = time.perf_counter()
    results = await asyncio.gather(*[one() for _ in range(count)], return_exceptions=True)
    elapsed = time.perf_counter() - start
    return [r for r in results if not isinstance(r, Exception)], elapsed

def _throttled(responses: list) -> bool:
    for r in responses:
        if r.status in (429, 503):
            return True
        if any(any(h.startswith(prefix) for h in r.headers) for prefix in _RATE_HEADERS):
            return True
    return False

@check("RES-002", scope="host")
async def throttling(ctx: ScanContext) -> None:
    count = ctx.options.rate_probe
    if count <= 0 or ctx.spec is None or ctx.web:
        return  # a short burst against an unknown or CDN protected site says nothing, so it is not reported
    limit = ctx.client.config.rps
    if limit and limit < 10:
        ctx.note(f"The throttling test sends a burst of {count} requests at once, so it was skipped because --rps {limit:g} asks for a gentle scan.")
        return
    login = [e for e in ctx.endpoints if LOGIN_PATH.search(e.path + "/") and (e.method == "GET" or ctx.options.allow_mutating)]
    general = [e for e in ctx.endpoints if e.method == "GET" and "{" not in e.path and not LOGIN_PATH.search(e.path + "/")]
    targets = []
    if login:
        targets.append(("RES-003", login[0]))
    if general:
        targets.append(("RES-002", general[0]))
    for check_id, ep in targets:
        if check_id == "RES-002":
            first = await ctx.baseline(ep)
            if not first.ok:
                continue  # a redirect or an error page says nothing about how the application throttles
        try:
            responses, elapsed = await _burst(ctx, ep, count)
        except Blocked:
            return
        usable = [r for r in responses if r.status is not None]
        if len(usable) < count * 0.8 or (check_id == "RES-002" and not all(r.ok for r in usable)):
            continue  # too many failures (or, for plain pages, non 2xx answers) to say anything
        if not _throttled(usable):
            codes = Counter(r.status for r in usable)
            ctx.add(check_id, operation=ep.label, confidence=Confidence.CONFIRMED,
                    evidence=f"{len(usable)} requests in {elapsed:.1f}s all answered ({dict(codes)}); no 429 and no rate limit headers")
