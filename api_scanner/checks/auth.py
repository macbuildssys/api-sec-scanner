"""API2 (authentication) and API5 (function level authorization) checks."""

from __future__ import annotations

import re

from ..context import ScanContext, bodies_similar, is_trivial_body
from ..http import Blocked
from ..models import Confidence, Endpoint
from . import ADMIN_PATH, BENIGN_ADMIN_TAIL, SENSITIVE_PATH, check

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
# Operations that are open on purpose: you must be able to reach them to get credentials in the first place.
PUBLIC_BY_DESIGN = re.compile(r"/(login|logout|signin|signout|sign-in|sign-out|register|signup|sign-up|health|healthz|ping|status|version)(/|$)", re.I)

def _usable_body(ex) -> bool:
    """A real answer: success status, a non trivial body, and not an HTML page (login pages)."""
    return ex.ok and ex.status != 204 and not is_trivial_body(ex) and "html" not in ex.content_type

@check("AUTH-001")
async def missing_authentication(ctx: ScanContext, ep: Endpoint) -> None:
    sensitive = bool(SENSITIVE_PATH.search(ep.path + "/")) and not PUBLIC_BY_DESIGN.search(ep.path + "/")
    if ep.secured is not True and not (ep.secured is None and sensitive):
        return  # the spec says it is public, or there is no sign it should be protected
    if ep.method in WRITE_METHODS and not ctx.options.allow_mutating:
        return
    bare = await ctx.send(ep, identity=None, label=ep.label)
    if not _usable_body(bare) or ctx.soft404.matches(bare):
        return
    evidence = bare.evidence()
    overrides = {"VI": "H"} if ep.method in WRITE_METHODS else {}
    if ctx.identity:
        authed = await ctx.baseline(ep)
        if authed.ok and bodies_similar(bare, authed):
            evidence += " | identical to the authenticated answer"
    if ep.secured is True:
        ctx.add("AUTH-001", operation=ep.label, confidence=Confidence.CONFIRMED, evidence=evidence, overrides=overrides,
                detail="the spec requires authentication")
    else:
        ctx.add("AUTH-001", operation=ep.label, confidence=Confidence.CONFIRMED, evidence=evidence, overrides=overrides,
                detail="the spec does not mention authentication")

@check("BFLA-001")
async def admin_functions(ctx: ScanContext, ep: Endpoint) -> None:
    if not ADMIN_PATH.search(ep.path + "/") or BENIGN_ADMIN_TAIL.search(ep.path):
        return
    if ep.method in WRITE_METHODS and not ctx.options.allow_mutating:
        return
    bare = await ctx.send(ep, identity=None)
    if _usable_body(bare) and not ctx.soft404.matches(bare):
        ctx.add("BFLA-001", operation=ep.label, confidence=Confidence.CONFIRMED, evidence=bare.evidence())
        return

@check("BFLA-003", scope="host")
async def unexpected_methods(ctx: ScanContext) -> None:
    """Ask each documented path which methods it allows, with the harmless OPTIONS method."""
    documented: dict = {}
    for ep in ctx.endpoints:
        if ep.documented:
            documented.setdefault((ep.base_url, ep.path), set()).add(ep.method)
    for (base, path), methods in list(documented.items())[:60]:
        sample = next(e for e in ctx.endpoints if e.base_url == base and e.path == path)
        try:
            ex = await ctx.client.request("OPTIONS", sample.url(), identity=ctx.identity, label=f"OPTIONS {path}")
        except Blocked:
            return
        allow = {m.strip().upper() for m in ex.headers.get("allow", "").split(",") if m.strip()}
        extra = (allow & {"PUT", "DELETE", "PATCH", "POST"}) - methods
        if extra and ex.status is not None and ex.status < 400:
            ctx.add("BFLA-003", operation=f"{'/'.join(sorted(extra))} {path}", confidence=Confidence.CONFIRMED,
                    evidence=f"OPTIONS {path} -> Allow: {ex.headers.get('allow')}; the spec defines only {', '.join(sorted(methods))}")
