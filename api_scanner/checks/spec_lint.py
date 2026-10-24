"""Specification review. Needs no network traffic at all."""

from __future__ import annotations

import re

from ..context import ScanContext
from ..models import Confidence
from . import LOGIN_PATH, check

WRITE = ("POST", "PUT", "PATCH", "DELETE")
# Writes that are normally public on purpose, so a missing security requirement is expected.
PUBLIC_BY_DESIGN = re.compile(r"/(register|signup|sign-up|subscribe|contact|webhooks?|callback|ping|health)(/|$)", re.I)

@check("SPEC-002", scope="host")
async def lint_spec(ctx: ScanContext) -> None:
    spec = ctx.spec
    if spec is None:
        return
    schemes = spec.security_schemes()
    for name, scheme in schemes.items():
        if isinstance(scheme, dict) and scheme.get("type") == "apiKey" and scheme.get("in") == "query":
            ctx.add("SPEC-002", operation=f"security scheme {name}", confidence=Confidence.CONFIRMED,
                    evidence=f"scheme '{name}' sends the API key in the query parameter '{scheme.get('name')}'")
    for ep in ctx.endpoints:
        if ep.method in WRITE and ep.secured is False and schemes and not LOGIN_PATH.search(ep.path + "/") and not PUBLIC_BY_DESIGN.search(ep.path + "/"):
            ctx.add("SPEC-003", operation=ep.label, confidence=Confidence.CONFIRMED,
                    evidence=f"{ep.label} declares no security requirement although other operations are protected")
