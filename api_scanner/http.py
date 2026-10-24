"""HTTP client with safety rails.

Every request in the scanner goes through ScanClient, which enforces:
    * safe methods only, unless the user opted in to mutating requests
    * scope: only hosts the user allowed
    * a hard request budget
    * a request rate limit and a concurrency limit
    * a cap on how many bytes of a response are read
Secrets are redacted before they can reach a report.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import aiohttp
from yarl import URL

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
_SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "api-key", "x-auth-token", "proxy-authorization", "set-cookie"}
_SECRET_QUERY = re.compile(r"(token|key|secret|password|passwd|auth|signature|sig)", re.I)
from . import __version__  # noqa: E402

USER_AGENT = f"api-sec-scanner/{__version__} (+authorized security testing)"

class Blocked(Exception):
    """A request was refused by a safety rule. The check should skip, not fail."""

class BudgetExhausted(Blocked):
    """The configured maximum number of requests has been used."""

@dataclass
class Identity:
    """A set of credentials, sent as headers."""

    name: str
    headers: dict = field(default_factory=dict)

    @property
    def token(self) -> Optional[str]:
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return None

@dataclass
class ClientConfig:
    timeout: float = 15.0
    rps: float = 10.0
    concurrency: int = 5
    max_requests: int = 2000
    max_bytes: int = 1_000_000
    insecure: bool = False
    allow_mutating: bool = False
    allowed_hosts: set = field(default_factory=set)
    extra_headers: dict = field(default_factory=dict)

@dataclass
class Exchange:
    method: str
    url: str
    status: Optional[int] = None
    headers: dict = field(default_factory=dict)  # lower case names
    body: bytes = b""
    elapsed: float = 0.0
    error: Optional[str] = None
    request_headers: dict = field(default_factory=dict)
    request_body: Optional[str] = None
    label: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def json(self) -> Any:
        if not hasattr(self, "_json"):
            try:
                self._json = json.loads(self.body) if self.body.strip()[:1] in (b"{", b"[") else None
            except (ValueError, UnicodeDecodeError):
                self._json = None
        return self._json

    def evidence(self, limit: int = 220) -> str:
        """A short, redacted description safe to put in a report."""
        shown = redact_url(self.url)
        head = f"{self.method} {shown}"
        if self.request_headers.get("Authorization") or self.request_headers.get("authorization"):
            head += " (with credentials)"
        if self.status is None:
            return f"{head} -> no response ({self.error})"
        snippet = self.text[:limit].replace("\r", " ").replace("\n", " ")
        snippet = redact_text(snippet)
        suffix = "..." if len(self.body) > limit else ""
        return f"{head} -> {self.status} in {self.elapsed * 1000:.0f} ms, body: {snippet}{suffix}"

def redact_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return url
    pairs = [(k, "[redacted]" if _SECRET_QUERY.search(k) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, safe="[]"), parts.fragment))

_TEXT_SECRETS = [
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),  # JWT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\$(2[abxy]|argon2\w*|pbkdf2[\w\-]*|scrypt)\$[^\s\"',}]+"),  # password hashes
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),  # long hex: hashes, keys, session ids
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bsk_live_[0-9a-zA-Z]{20,}\b|\bxox[baprs]-[0-9A-Za-z\-]{20,}\b"),
]
# "password": "value" style pairs: keep the key, hide the value
_SECRET_PAIR = re.compile(r"(?i)(\"(?:[\w.\-]*(?:password|passwd|secret|token|api_?key|private_?key|credential)[\w.\-]*)\"\s*:\s*)\"[^\"]*\"")

def redact_text(text: str) -> str:
    """Hide anything shaped like a secret. Reports must never become a second leak."""
    text = _SECRET_PAIR.sub(r'\1"[redacted]"', text)
    for pattern in _TEXT_SECRETS:
        text = pattern.sub("[redacted]", text)
    return text

def redact_headers(headers: dict) -> dict:
    return {k: ("[redacted]" if k.lower() in _SECRET_HEADERS else v) for k, v in headers.items()}

class ScanClient:
    def __init__(self, config: ClientConfig):
        self.config = config
        self.requests_sent = 0
        self._session: Optional[aiohttp.ClientSession] = None
        self._sem = asyncio.Semaphore(max(1, config.concurrency))
        self._pace_lock = asyncio.Lock()
        self._next_slot = 0.0
        self.observers: list = []  # callables taking an Exchange

    def _make_session(self) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(ssl=False if self.config.insecure else None, limit=max(10, self.config.concurrency * 4))
        return aiohttp.ClientSession(
            connector=connector,
            cookie_jar=aiohttp.DummyCookieJar(),  # never leak cookies between identities
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
        )

    async def __aenter__(self) -> "ScanClient":
        self._session = self._make_session()
        return self

    async def disable_tls_verification(self) -> None:
        """Keep scanning a host whose certificate is rejected. The certificate problem itself is reported separately."""
        self.config.insecure = True
        if self._session:
            await self._session.close()
        self._session = self._make_session()

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    def in_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return host in self.config.allowed_hosts

    async def pace(self) -> None:
        """Wait for the next free slot of the requests per second limit (used by the browser too)."""
        await self._pace()

    async def _pace(self) -> None:
        if self.config.rps <= 0:
            return
        interval = 1.0 / self.config.rps
        async with self._pace_lock:
            now = time.monotonic()
            wait = self._next_slot - now
            self._next_slot = max(now, self._next_slot) + interval
        if wait > 0:
            await asyncio.sleep(wait)

    async def request(
        self,
        method: str,
        url: str,
        *,
        identity: Optional[Identity] = None,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        json_body: Any = None,
        raw_body: Optional[str] = None,
        read_only: bool = False,
        paced: bool = True,
        label: str = "",
        timeout: Optional[float] = None,
        observe: bool = True,
    ) -> Exchange:
        """Send one request.

        read_only marks a POST that is known to only read (for example a GraphQL
        introspection query), so it is allowed even without --allow-mutating.
        """
        method = method.upper()
        if not self.in_scope(url):
            raise Blocked(f"out of scope: {urlsplit(url).hostname}")
        if method not in SAFE_METHODS and not read_only and not self.config.allow_mutating:
            raise Blocked(f"{method} refused: mutating requests need --allow-mutating")
        if self.requests_sent >= self.config.max_requests:
            raise BudgetExhausted(f"request budget of {self.config.max_requests} used")
        assert self._session is not None, "use ScanClient as an async context manager"

        merged = {"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.5"}
        merged.update(self.config.extra_headers)
        if identity:
            merged.update(identity.headers)
        for key, value in (headers or {}).items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value

        full_url = url
        if params:
            query = urlencode({k: str(v) for k, v in params.items()}, quote_via=quote, safe="")
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{query}"

        kwargs: dict[str, Any] = {"headers": merged, "allow_redirects": False}
        request_body = None
        if json_body is not None:
            kwargs["json"] = json_body
            request_body = json.dumps(json_body)[:500]
        elif raw_body is not None:
            kwargs["data"] = raw_body
            request_body = raw_body[:500]
        if timeout:
            kwargs["timeout"] = aiohttp.ClientTimeout(total=timeout)

        if paced:
            await self._pace()
        self.requests_sent += 1
        exchange = Exchange(method=method, url=full_url, request_headers=redact_headers(merged), request_body=request_body, label=label)
        start = time.perf_counter()
        async with self._sem:
            try:
                async with self._session.request(method, URL(full_url, encoded=True), **kwargs) as resp:
                    exchange.status = resp.status
                    exchange.headers = {k.lower(): v for k, v in resp.headers.items()}
                    cookies = resp.headers.getall("Set-Cookie", [])
                    if cookies:
                        exchange.headers["set-cookie"] = "\n".join(cookies)
                    buf = bytearray()
                    while len(buf) < self.config.max_bytes:
                        chunk = await resp.content.read(min(65536, self.config.max_bytes - len(buf)))
                        if not chunk:
                            break
                        buf.extend(chunk)
                    exchange.body = bytes(buf)
            except asyncio.TimeoutError:
                exchange.error = "timeout"
            except (aiohttp.ClientError, OSError, ValueError, UnicodeError) as exc:
                exchange.error = f"{type(exc).__name__}: {exc}"[:200]
        exchange.elapsed = time.perf_counter() - start
        if observe:
            for observer in self.observers:
                observer(exchange)
        return exchange
