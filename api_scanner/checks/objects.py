"""API1 (object level) and API3 (property level) authorization checks."""

from __future__ import annotations

import math
import re
from typing import Any, Optional

from ..context import ScanContext, bodies_similar, is_trivial_body
from ..models import Confidence, Endpoint
from . import check

_LIST_KEYS = ("items", "data", "results", "records", "rows", "users", "entries", "content")

def _items(payload: Any) -> list:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in _LIST_KEYS:
            if isinstance(payload.get(key), list):
                return payload[key]
    return []

def _ids(payload: Any) -> set:
    return {str(i["id"]) for i in _items(payload) if isinstance(i, dict) and "id" in i}

def _detail_and_list(ctx: ScanContext) -> list:
    """Pairs of (detail endpoint /things/{id}, list endpoint /things)."""
    lists = {(e.base_url, e.path): e for e in ctx.endpoints if e.method == "GET" and "{" not in e.path}
    pairs = []
    for ep in ctx.endpoints:
        if ep.method != "GET":
            continue
        names = ep.path_param_names()
        if len(names) != 1 or not ep.path.endswith("{" + names[0] + "}"):
            continue
        prefix = ep.path[: ep.path.rindex("/")] or "/"
        pairs.append((ep, lists.get((ep.base_url, prefix))))
    return pairs

@check("BOLA-001", scope="host")
async def cross_user_object_access(ctx: ScanContext) -> None:
    """Prove broken object level authorization with two identities.

    Ownership is learned from the API itself: an id that the list endpoint shows to identity A
    but not to identity B belongs to A. Then identity B asks for it directly."""
    if not (ctx.identity and ctx.identity_b):
        ctx.note("BOLA-001 needs two identities (--token and --token-b). BOLA-001 was skipped.")
        return
    for detail, listing in _detail_and_list(ctx):
        name = detail.path_param_names()[0]
        owned: list = []
        if ctx.options.owned_object_id:
            owned = [ctx.options.owned_object_id]
        elif listing is not None:
            la = await ctx.baseline(listing, ctx.identity)
            lb = await ctx.baseline(listing, ctx.identity_b)
            if la.ok and lb.ok:
                owned = sorted(_ids(la.json) - _ids(lb.json))[:3]
        if not owned:
            continue
        for object_id in owned:
            a_view = await ctx.send(detail, identity=ctx.identity, path_overrides={name: object_id}, label=detail.label)
            b_view = await ctx.send(detail, identity=ctx.identity_b, path_overrides={name: object_id}, label=detail.label)
            if a_view.ok and b_view.ok and not is_trivial_body(a_view) and bodies_similar(a_view, b_view):
                ctx.add("BOLA-001", operation=detail.label, confidence=Confidence.CONFIRMED,
                        evidence=f"object {object_id} belongs to identity '{ctx.identity.name}' (only its list shows it), yet identity '{ctx.identity_b.name}' received it: {b_view.evidence()}")
                break

# BOPLA-001

_SENSITIVE_FIELD = re.compile(
    r"(^|[_\-.])(password|passwd|pwd|pass_?hash|hash|secret|client_?secret|api_?key|access_?token|refresh_?token|private_?key|ssn|social_?security|credit_?card|card_?number|cvv|cvc|iban|totp|otp_?secret|salt)($|[_\-.])",
    re.I,
)
_NOT_A_SECRET_SUFFIX = re.compile(r"(_at|_date|_time|_count|_required|_enabled|_expires?|_policy|_length|_type|_set|_changed|_reset|has_|is_)", re.I)
_HASH_PREFIX = re.compile(r"^\$(2[abxy]|argon2(id|i|d)|pbkdf2[\w\-]*|scrypt|1|5|6|7)\$")
_HEX = re.compile(r"^[0-9a-fA-F]{32,128}$")
_JWT = re.compile(r"^eyJ[\w\-]+\.[\w\-]+\.[\w\-]*$")
_SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_MASKED = re.compile(r"^[*xX•#\-\s]+$|redacted|masked", re.I)
_TOKENISH = re.compile(r"^[A-Za-z0-9_\-+/=.]{20,}$")

def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def _entropy(text: str) -> float:
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())

def _secret_strength(value: Any) -> Optional[str]:
    """Return 'strong' when the value is shaped like a real secret, 'weak' when only the
    field name is suspicious, or None when the value is empty or masked."""
    if value is None or isinstance(value, (bool, dict, list)):
        return None
    text = str(value).strip()
    if not text or _MASKED.search(text):
        return None
    if _HASH_PREFIX.match(text) or _HEX.match(text) or _JWT.match(text) or "PRIVATE KEY" in text:
        return "strong"
    if _SSN.match(text) or _luhn(text.replace(" ", "").replace("-", "")):
        return "strong"
    if _TOKENISH.match(text) and _entropy(text) > 3.5:
        return "strong"
    return "weak" if len(text) >= 4 else None

def _walk(node: Any, path: str = "", depth: int = 0):
    if depth > 6:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            yield here, str(key), value
            yield from _walk(value, here, depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node[:5]):
            yield from _walk(value, f"{path}[{index}]", depth + 1)

@check("BOPLA-001")
async def sensitive_properties(ctx: ScanContext, ep: Endpoint) -> None:
    if ep.method != "GET":
        return
    ex = await ctx.baseline(ep)
    if not ex.ok or ex.json is None:
        return
    strong, weak = [], []
    for field_path, key, value in _walk(ex.json):
        if not _SENSITIVE_FIELD.search(key) or _NOT_A_SECRET_SUFFIX.search(key):
            continue
        strength = _secret_strength(value)
        if strength == "strong":
            strong.append((field_path, value))
        elif strength == "weak":
            weak.append((field_path, value))

    def show(items: list) -> str:
        return ", ".join(f"{p}={_mask(v)}" for p, v in items[:4])

    if strong:
        ctx.add("BOPLA-001", operation=ep.label, confidence=Confidence.CONFIRMED, evidence=f"{ep.label} returns {show(strong)}")

def _mask(value: Any) -> str:
    text = str(value)
    return text[:3] + "***" if len(text) > 3 else "***"

_PRIVILEGED = {"is_admin": True, "isAdmin": True, "role": "admin", "admin": True, "is_staff": True, "verified": True}

@check("BOPLA-002", mutating=True)
async def mass_assignment(ctx: ScanContext, ep: Endpoint) -> None:
    if ep.method not in ("POST", "PUT", "PATCH") or not isinstance(ep.body_example, dict):
        return
    declared = set((ep.body_schema or {}).get("properties", {}) or {})
    extras = {k: v for k, v in _PRIVILEGED.items() if k not in declared}
    if not extras:
        return
    body = dict(ep.body_example)
    body.update(extras)
    ex = await ctx.send(ep, identity=ctx.identity, body=body, label=ep.label)
    if not ex.ok or not isinstance(ex.json, dict):
        return
    reflected = {k: v for k, v in extras.items() if ex.json.get(k) == v or (isinstance(ex.json.get("data"), dict) and ex.json["data"].get(k) == v)}
    if reflected:
        ctx.add("BOPLA-002", operation=ep.label, confidence=Confidence.CONFIRMED,
                evidence=f"undeclared properties {sorted(reflected)} were accepted and echoed back: {ex.evidence(160)}")
