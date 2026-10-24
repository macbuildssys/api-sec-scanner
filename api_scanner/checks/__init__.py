"""Check registry.

A check is an async function taking (ctx) for host scope or (ctx, endpoint) for endpoint
scope. Checks only report what they can back with evidence; see Confidence in models.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Awaitable, Callable

REGISTRY: list = []

SENSITIVE_PATH = re.compile(r"/(admin|users?|accounts?|customers?|profiles?|me|orders?|payments?|billing|invoices?|internal|private|settings|secrets?|tokens?|keys?|employees?|members?)(/|$|\.)", re.I)
ADMIN_PATH = re.compile(r"/(admin|administrator|internal|management|manage|superuser|sysadmin|console|actuator|debug|system)(/|$)", re.I)
BENIGN_ADMIN_TAIL = re.compile(r"/(health|healthz|status|ping|ready|readiness|live|liveness|version)/?$", re.I)
LOGIN_PATH = re.compile(r"/(login|signin|sign-in|authenticate|auth|token|oauth/token|password|reset|forgot|otp|verify|2fa|mfa)(/|$)", re.I)

@dataclass
class CheckDef:
    name: str
    scope: str  # "endpoint" or "host"
    func: Callable[..., Awaitable[None]]
    active: bool = False  # sends attack payloads, needs --active
    mutating: bool = False  # needs --allow-mutating

def check(name: str, scope: str = "endpoint", active: bool = False, mutating: bool = False):
    def decorator(func):
        REGISTRY.append(CheckDef(name, scope, func, active, mutating))
        return func

    return decorator

def load_all() -> list:
    """Import every check module so that the decorators register their functions."""
    from . import auth, config, discovery, injection, jwt_audit, objects, osint, resources, spec_lint, ssrf, tls, web  # noqa: F401

    return REGISTRY
