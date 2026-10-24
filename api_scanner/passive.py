"""Passive analysis: inspect every response the scanner already receives.

No extra traffic is sent. Header and cookie issues are collected across all responses and
reported once, with the list of affected operations, instead of once per request.
"""

from __future__ import annotations

import re

from .context import ScanContext
from .http import Exchange
from .models import Confidence

# Stack traces and database errors. Each pattern is specific to avoid matching ordinary text.
ERROR_SIGNATURES = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace"),
    (re.compile(r"\bat [\w$.]+\([\w$]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"\bat [\w.<>]+\(.*?\) in .+?:line \d+"), ".NET stack trace"),
    (re.compile(r"\bat \S+ \((?:/|[A-Za-z]:\\)[^)\n]+:\d+:\d+\)"), "Node.js stack trace"),
    (re.compile(r"goroutine \d+ \[running\]"), "Go stack trace"),
    (re.compile(r"Fatal error: .{0,120} on line \d+"), "PHP fatal error"),
    (re.compile(r"\.rb:\d+:in `"), "Ruby stack trace"),
    (re.compile(r"You have an error in your SQL syntax"), "MySQL error"),
    (re.compile(r"\bORA-\d{5}\b"), "Oracle error"),
    (re.compile(r"unterminated quoted string at or near|syntax error at or near|PG::[A-Z][A-Za-z]+Error|psycopg2\.[A-Za-z.]+Error"), "PostgreSQL error"),
    (re.compile(r"Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server"), "SQL Server error"),
    (re.compile(r"sqlite3\.OperationalError|SQLite3::SQLException|SQLITE_ERROR"), "SQLite error"),
    (re.compile(r"SQLSTATE\[[0-9A-Z]{5}\]"), "SQL driver error"),
]

SECRET_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "Stripe live secret key"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
]
_PLACEHOLDER = re.compile(r"example|sample|dummy|placeholder|xxxx|your[_-]", re.I)
_SESSIONISH = re.compile(r"(sess|sid|auth|token|jwt|login)", re.I)
_JS_READABLE = re.compile(r"(csrf|xsrf)", re.I)  # anti forgery cookies are meant to be read by the page's own script

class PassiveAnalyzer:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self._missing_nosniff: set = set()
        self._missing_hsts: set = set()
        self._cacheable: set = set()
        self._wildcard_cors: set = set()
        self._banners: dict = {}
        self._cookie_issues: dict = {}

    def __call__(self, ex: Exchange) -> None:
        if ex.status is None:
            return
        label = ex.label or f"{ex.method} {ex.url}"
        self._tech(ex)
        self._errors_and_secrets(ex, label)
        self._cookies(ex, label)

    # technology

    def _tech(self, ex: Exchange) -> None:
        server = ex.headers.get("server")
        if server:
            self.ctx.technologies.add(f"server: {server}")
        powered = ex.headers.get("x-powered-by")
        if powered:
            self.ctx.technologies.add(f"x-powered-by: {powered}")
        for cookie_name, tech in (("phpsessid", "PHP"), ("jsessionid", "Java servlet"), ("csrftoken", "Django"), ("laravel_session", "Laravel"), ("connect.sid", "Express")):
            if cookie_name in ex.headers.get("set-cookie", "").lower():
                self.ctx.technologies.add(f"framework hint: {tech}")

    # errors and secrets

    def _errors_and_secrets(self, ex: Exchange, label: str) -> None:
        if not ex.body or ex.content_type in ("image/png", "image/jpeg", "application/octet-stream"):
            return
        text = ex.text
        for pattern, name in ERROR_SIGNATURES:
            match = pattern.search(text)
            if match:
                self.ctx.add("CFG-003", operation=label, confidence=Confidence.CONFIRMED,
                             evidence=f"{ex.method} {_short(ex.url)} -> {ex.status}: {name}: {match.group(0)[:80]!r}")
                break
        client_side = "html" in ex.content_type or "javascript" in ex.content_type
        for pattern, name in SECRET_PATTERNS:
            match = pattern.search(text)
            if match and name == "Google API key" and client_side:
                continue  # browser keys (maps, fonts) are meant to be public
            if match and not _PLACEHOLDER.search(match.group(0)):
                self.ctx.add("CFG-009", operation=label, confidence=Confidence.CONFIRMED,
                             evidence=f"{ex.method} {_short(ex.url)} -> {ex.status}: {name} ({_mask(match.group(0))})")

    # cookies

    def _cookies(self, ex: Exchange, label: str) -> None:
        raw = ex.headers.get("set-cookie", "")
        for line in filter(None, raw.split("\n")):
            name = line.split("=", 1)[0].strip()
            if not _SESSIONISH.search(name) or _JS_READABLE.search(name):
                continue
            lowered = line.lower()
            missing = []
            if ex.url.startswith("https://") and "secure" not in lowered:
                missing.append("Secure")
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if missing:
                self._cookie_issues.setdefault((name, tuple(missing)), label)

    # results

    def finalize(self) -> None:
        for (name, missing), label in self._cookie_issues.items():
            self.ctx.add("CFG-008", operation=label, confidence=Confidence.CONFIRMED, evidence=f"Cookie {name} lacks {', '.join(missing)}")

def _short(url: str, limit: int = 90) -> str:
    return url if len(url) <= limit else url[:limit] + "..."

def _mask(value: str) -> str:
    return value[:4] + "*" * 6 if len(value) > 8 else "*" * len(value)

def attach(ctx: ScanContext) -> PassiveAnalyzer:
    analyzer = PassiveAnalyzer(ctx)
    ctx.client.observers.append(analyzer)
    return analyzer
