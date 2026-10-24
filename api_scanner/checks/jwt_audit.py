"""JSON Web Token audit.

Static checks read the token the user supplied. Active checks replay modified copies of it
against one protected operation and compare with control requests, so a finding is only
reported when the server really accepts a forged token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

from ..context import ScanContext, bodies_similar, is_trivial_body
from ..http import Blocked, Identity
from ..models import Confidence
from . import check

# Short list of secrets that appear in tutorials, templates and default configs.
COMMON_SECRETS = [
    "secret", "Secret", "SECRET", "secretkey", "secret_key", "secret-key", "mysecret", "my_secret", "mysecretkey",
    "supersecret", "super_secret", "supersecretkey", "topsecret", "jwtsecret", "jwt_secret", "jwt-secret", "jwtsecretkey",
    "jwt", "jwtkey", "key", "private", "password", "Password", "password1", "passw0rd", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "admin", "administrator", "root", "test", "testing", "dev", "development", "prod", "production",
    "changeme", "change_me", "changeit", "default", "token", "tokensecret", "auth", "authkey", "your-256-bit-secret",
    "your-secret", "your_secret", "your-secret-key", "your_jwt_secret", "keyboardcat", "shhhhh", "shhh", "s3cr3t", "s3cret",
    "HS256", "hs256", "hmac", "hmackey", "api", "apikey", "api_key", "app", "appsecret", "app_secret", "flask", "django",
    "express", "node", "spring", "laravel", "rails", "example", "sample", "demo", "foobar", "foo", "bar", "letmein",
    "welcome", "iloveyou", "abc123", "a-string-secret-at-least-256-bits-long", "ThisIsMySecretKey", "0123456789abcdef",
]

_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
LONG_LIVED_SECONDS = 24 * 3600

def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))

def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def parse_jwt(token: str) -> Optional[tuple]:
    """Return (header, payload, signing_input, signature_bytes) or None if not a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2]) if parts[2] else b""
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, f"{parts[0]}.{parts[1]}".encode(), signature

def crack_hmac_secret(token: str) -> Optional[str]:
    parsed = parse_jwt(token)
    if not parsed:
        return None
    header, _, signing_input, signature = parsed
    hasher = _HASHES.get(header.get("alg", ""))
    if not hasher or not signature:
        return None
    for candidate in COMMON_SECRETS:
        if hmac.compare_digest(hmac.new(candidate.encode(), signing_input, hasher).digest(), signature):
            return candidate
    return None

def forge_none(token: str, spelling: str) -> str:
    header, payload, _, _ = parse_jwt(token)
    header = dict(header, alg=spelling)
    return f"{b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}."

def damage_signature(token: str) -> str:
    """Change a character in the MIDDLE of the signature. The last character of a base64
    signature can carry unused bits, so editing it might not change the decoded bytes."""
    head, payload, sig = token.split(".")
    if len(sig) < 8:
        return token
    pos = len(sig) // 2
    replacement = "A" if sig[pos] != "A" else "B"
    return f"{head}.{payload}.{sig[:pos]}{replacement}{sig[pos + 1:]}"

def _static_checks(ctx: ScanContext, identity: Identity, token: str) -> None:
    parsed = parse_jwt(token)
    if not parsed:
        ctx.note(f"Token for '{identity.name}' is opaque (not a JWT), so JWT checks were skipped for it.")
        return
    header, payload, _, _ = parsed
    where = f"token ({identity.name})"
    secret = crack_hmac_secret(token)
    if secret:
        ctx.add("JWT-003", operation=where, confidence=Confidence.CONFIRMED,
                evidence=f"{header.get('alg')} signature verified with a common secret of {len(secret)} characters starting with '{secret[0]}'")
    exp, iat = payload.get("exp"), payload.get("iat")
    if exp is None:
        ctx.add("JWT-004", operation=where, confidence=Confidence.CONFIRMED, evidence="the token has no exp claim")
    elif isinstance(exp, (int, float)):
        start = iat if isinstance(iat, (int, float)) else time.time()
        lifetime = exp - start
        if lifetime > LONG_LIVED_SECONDS:
            ctx.add("JWT-004", operation=where, confidence=Confidence.CONFIRMED,
                    evidence=f"the token lives about {lifetime / 3600:.0f} hours (more than {LONG_LIVED_SECONDS // 3600})")

async def _pick_probe(ctx: ScanContext, identity: Identity) -> Optional[tuple]:
    """Find a GET operation that returns data for this identity and rejects a garbage token."""
    candidates = [e for e in ctx.endpoints if e.method == "GET" and e.secured is not False]
    candidates.sort(key=lambda e: (e.secured is not True, "{" in e.path))
    for ep in candidates[:6]:
        good = await ctx.baseline(ep, identity)
        if not good.ok or is_trivial_body(good):
            continue
        junk = await ctx.send(ep, identity=Identity("junk", {"Authorization": "Bearer not.a.token"}), label="jwt control")
        if junk.ok:
            continue  # this operation does not enforce authentication, so it proves nothing
        return ep, good
    return None

async def _active_checks(ctx: ScanContext, identity: Identity, token: str) -> None:
    probe = await _pick_probe(ctx, identity)
    if not probe:
        ctx.note("JWT forgery tests skipped: no protected GET operation returned data for the supplied token.")
        return
    ep, good = probe
    where = f"{ep.label} via token ({identity.name})"
    scheme = identity.headers.get("Authorization", "Bearer x").split(" ", 1)[0]

    async def replay(forged: str, label: str):
        return await ctx.send(ep, identity=Identity("forged", {"Authorization": f"{scheme} {forged}"}), label=label)

    damaged = await replay(damage_signature(token), "jwt damaged signature")
    if damaged.ok and bodies_similar(damaged, good):
        ctx.add("JWT-002", operation=where, confidence=Confidence.CONFIRMED,
                evidence=f"a token with a damaged signature got the same answer as the genuine token: {damaged.evidence()}")
    for spelling in ("none", "None", "NONE"):
        forged = await replay(forge_none(token, spelling), f"jwt alg {spelling}")
        if forged.ok and bodies_similar(forged, good):
            ctx.add("JWT-001", operation=where, confidence=Confidence.CONFIRMED,
                    evidence=f"alg='{spelling}' without a signature was accepted: {forged.evidence()}")
            break

@check("JWT", scope="host")
async def audit_tokens(ctx: ScanContext) -> None:
    for identity in (ctx.identity, ctx.identity_b):
        if not identity or not identity.token:
            continue
        token = identity.token
        _static_checks(ctx, identity, token)
        if parse_jwt(token):
            try:
                await _active_checks(ctx, identity, token)
            except Blocked:
                return
