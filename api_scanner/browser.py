"""Crawling sites that build their pages with JavaScript, using a real browser.

A plain HTTP fetch of a single page application returns an almost empty shell, so the crawler
sees few pages. With --browser the pages are loaded in headless Chrome, Chromium or Edge and the
finished page is read back. The browser is driven through the Chrome DevTools Protocol over a
local websocket, so nothing besides an installed browser is needed.

The scan's safety rules also apply to everything the browser does. Every request is paused and
checked before it leaves:

* hosts outside the scan scope are blocked, except that scripts and style sheets from other sites
  are fetched with plain GET, because the page cannot work without them
* requests that change data (POST, PUT, PATCH, DELETE) are blocked unless --allow-mutating is set
* images, media and fonts are not requested at all
* every request counts against the request budget and the requests per second limit
* credentials are only sent to hosts that are in scope
"""

from __future__ import annotations

import asyncio
import base64
import glob
import json
import os
import re
import shutil
import tempfile
import time
from typing import Callable, Optional
from urllib.parse import urlsplit

import aiohttp

from . import __version__
from .http import SAFE_METHODS, Exchange

BROWSER_NAMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "microsoft-edge-stable", "chrome")
BROWSER_PATTERNS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome",
)
SKIPPED_TYPES = {"Image", "Media", "Font", "Ping", "CSPViolationReport", "Prefetch"}
PAGE_TIMEOUT = 20.0
SETTLE_QUIET = 0.7
SETTLE_MAX = 8.0
MAX_BODIES_PER_PAGE = 12
STATUS_TEXT = "{} {}"

class BrowserError(Exception):
    pass

def find_browser() -> Optional[str]:
    """The path of an installed Chrome, Chromium or Edge, or None. API_SEC_SCANNER_BROWSER overrides the search."""
    chosen = os.environ.get("API_SEC_SCANNER_BROWSER")
    if chosen:
        return shutil.which(chosen) or (chosen if os.access(chosen, os.X_OK) else None)
    for name in BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    patterns = list(BROWSER_PATTERNS)
    shared = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if shared:
        patterns.append(os.path.join(shared, "chromium-*", "chrome-linux*", "chrome"))
    for pattern in patterns:
        for path in sorted(glob.glob(os.path.expanduser(pattern)), reverse=True):
            if os.access(path, os.X_OK):
                return path
    return None

class Chrome:
    """One headless browser process and its DevTools connection."""

    def __init__(self, executable: str, insecure: bool = False):
        self.executable = executable
        self.insecure = insecure
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._http: Optional[aiohttp.ClientSession] = None
        self._ws = None
        self._profile = ""
        self._next_id = 0
        self._pending: dict = {}
        self._handlers: dict = {}
        self._tasks: list = []

    async def __aenter__(self) -> "Chrome":
        try:
            await self.start()
        except BaseException:
            await self.close()
            raise
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def start(self) -> None:
        self._profile = tempfile.mkdtemp(prefix="api-sec-scanner-chrome-")
        args = [
            self.executable, "--headless=new", "--remote-debugging-port=0", f"--user-data-dir={self._profile}",
            "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--disable-dev-shm-usage", "--disable-extensions",
            "--disable-background-networking", "--disable-sync", "--disable-component-update", "--mute-audio", "--hide-scrollbars",
            "--disable-features=Translate,OptimizationHints", "about:blank",
        ]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.append("--no-sandbox")  # Chrome refuses to run as root otherwise
        if self.insecure:
            args.append("--ignore-certificate-errors")
        # A headless browser needs no display. Leaving these set makes it try the desktop's X server and print errors on the terminal.
        env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY")}
        try:
            self._proc = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                                                              stderr=asyncio.subprocess.PIPE, env=env, start_new_session=True)
        except OSError as exc:
            raise BrowserError(f"could not start {self.executable}: {exc}") from exc
        endpoint = await self._wait_for_endpoint()
        self._tasks.append(asyncio.create_task(self._drain_stderr()))
        self._http = aiohttp.ClientSession()
        try:
            self._ws = await self._http.ws_connect(endpoint, max_msg_size=0, heartbeat=None)
        except (aiohttp.ClientError, OSError) as exc:
            raise BrowserError(f"could not connect to the browser: {exc}") from exc
        self._tasks.append(asyncio.create_task(self._read_loop()))

    async def _wait_for_endpoint(self) -> str:
        async def read() -> str:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    raise BrowserError("the browser exited before it was ready")
                match = re.search(rb"DevTools listening on (ws://\S+)", line)
                if match:
                    return match.group(1).decode()

        try:
            return await asyncio.wait_for(read(), 25)
        except asyncio.TimeoutError as exc:
            raise BrowserError("the browser did not start in time") from exc

    async def _drain_stderr(self) -> None:
        try:
            while await self._proc.stderr.read(65536):
                pass
        except (OSError, asyncio.CancelledError):
            pass

    async def _read_loop(self) -> None:
        try:
            async for message in self._ws:
                if message.type != aiohttp.WSMsgType.TEXT:
                    continue
                data = json.loads(message.data)
                if "id" in data:
                    future = self._pending.pop(data["id"], None)
                    if future and not future.done():
                        if "error" in data:
                            future.set_exception(BrowserError(data["error"].get("message", "browser error")))
                        else:
                            future.set_result(data.get("result", {}))
                else:
                    handler = self._handlers.get(data.get("sessionId"))
                    if handler:
                        handler(data.get("method", ""), data.get("params", {}))
        except (aiohttp.ClientError, OSError, ValueError):
            pass
        finally:
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(BrowserError("the browser connection closed"))
            self._pending.clear()

    async def send(self, method: str, params: Optional[dict] = None, session_id: Optional[str] = None, timeout: float = 20.0) -> dict:
        self._next_id += 1
        message_id = self._next_id
        message = {"id": message_id, "method": method, "params": params or {}}
        if session_id:
            message["sessionId"] = session_id
        future = asyncio.get_running_loop().create_future()
        self._pending[message_id] = future
        try:
            await self._ws.send_str(json.dumps(message))
        except (aiohttp.ClientError, OSError, RuntimeError) as exc:
            self._pending.pop(message_id, None)
            raise BrowserError("the browser connection closed") from exc
        try:
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError as exc:
            self._pending.pop(message_id, None)
            raise BrowserError(f"{method} timed out") from exc

    async def close(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except BaseException:
                pass
        self._tasks.clear()
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
        if self._http is not None:
            await self._http.close()
        if self._proc is not None and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), 5)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        if self._profile:
            shutil.rmtree(self._profile, ignore_errors=True)

class Renderer:
    """One browser tab that loads pages under the scan's rules and returns them as Exchange objects."""

    def __init__(self, chrome: Chrome, client, identity, start_url: str, note: Callable[[str], None], same_site: Callable[[str, str], bool]):
        self.chrome = chrome
        self.client = client
        self.identity = identity
        self.start_url = start_url
        self.note = note
        self.same_site = same_site
        self.api_calls: dict = {}
        self.blocked_changes = 0
        self._session = ""
        self._frame = ""
        self._seen_bodies: set = set()
        self._reset()

    def _reset(self) -> None:
        self._loaded = asyncio.Event()
        self._inflight: set = set()
        self._finished: list = []
        self._types: dict = {}
        self._responses: dict = {}
        self._extra: dict = {}
        self._main_request = ""
        self._navigation_error = ""
        self._last_activity = time.monotonic()

    async def start(self) -> None:
        created = await self.chrome.send("Target.createTarget", {"url": "about:blank"})
        attached = await self.chrome.send("Target.attachToTarget", {"targetId": created["targetId"], "flatten": True})
        self._session = attached["sessionId"]
        self.chrome._handlers[self._session] = self._on_event
        await self._send("Page.enable")
        await self._send("Network.enable")
        tree = await self._send("Page.getFrameTree")
        self._frame = tree["frameTree"]["frame"]["id"]
        version = await self.chrome.send("Browser.getVersion")
        await self._send("Network.setUserAgentOverride", {"userAgent": f"{version.get('userAgent', 'Chrome')} api-sec-scanner/{__version__}"})
        await self._send("Fetch.enable", {"patterns": [{"urlPattern": "*"}]})

    async def _send(self, method: str, params: Optional[dict] = None, timeout: float = 20.0) -> dict:
        return await self.chrome.send(method, params, self._session, timeout)

    def _on_event(self, method: str, params: dict) -> None:
        if method == "Fetch.requestPaused":
            asyncio.get_running_loop().create_task(self._paused(params))
        elif method == "Network.requestWillBeSent":
            request = params.get("request", {})
            self._inflight.add(params["requestId"])
            self._types[params["requestId"]] = (params.get("type", ""), request.get("url", ""), request.get("method", "GET"))
            self._last_activity = time.monotonic()
        elif method in ("Network.loadingFinished", "Network.loadingFailed"):
            self._inflight.discard(params["requestId"])
            if method == "Network.loadingFinished":
                self._finished.append(params["requestId"])
            elif params["requestId"] == self._main_request or self._types.get(params["requestId"], ("",))[0] == "Document":
                self._navigation_error = params.get("errorText", "")
            self._last_activity = time.monotonic()
        elif method == "Network.responseReceived":
            self._responses[params["requestId"]] = params
            if params.get("type") == "Document" and params.get("frameId") == self._frame:
                self._main_request = params["requestId"]
        elif method == "Network.responseReceivedExtraInfo":
            self._extra[params["requestId"]] = params
        elif method == "Page.loadEventFired":
            self._loaded.set()

    async def _paused(self, params: dict) -> None:
        request = params["request"]
        try:
            allowed, headers = await self._decide(request["url"], request["method"], params.get("resourceType", ""), request.get("headers", {}))
            if allowed:
                command = {"requestId": params["requestId"]}
                if headers is not None:
                    command["headers"] = [{"name": k, "value": v} for k, v in headers.items()]
                await self._send("Fetch.continueRequest", command)
            else:
                await self._send("Fetch.failRequest", {"requestId": params["requestId"], "errorReason": "BlockedByClient"})
        except BrowserError:
            pass

    async def _decide(self, url: str, method: str, resource_type: str, headers: dict) -> tuple:
        """Return (allowed, headers to send or None). This is the scan's scope, budget and safety policy for the browser."""
        if url.startswith(("data:", "blob:", "about:")):
            return True, None
        client = self.client
        host = (urlsplit(url).hostname or "").lower()
        if resource_type in SKIPPED_TYPES:
            return False, None
        in_scope = client.in_scope(url)
        if not in_scope and resource_type == "Document" and self.same_site(url, self.start_url):
            client.config.allowed_hosts.add(host)
            self.note(f"{host} was added to the scope because the site redirects to it.")
            in_scope = True
        if not in_scope:
            if resource_type in ("Script", "Stylesheet") and method == "GET":
                return self._spend(), None  # other sites' scripts and styles load like they do in any browser, with no credentials
            return False, None
        if method not in SAFE_METHODS and not client.config.allow_mutating:
            self.blocked_changes += 1
            return False, None
        if not self._spend():
            return False, None
        if resource_type in ("XHR", "Fetch"):
            self.api_calls.setdefault((method, url), None)
        await client.pace()
        merged = dict(headers)
        merged.update(client.config.extra_headers)
        if self.identity:
            merged.update(self.identity.headers)
        return True, merged

    def _spend(self) -> bool:
        if self.client.requests_sent >= self.client.config.max_requests:
            return False
        self.client.requests_sent += 1
        return True

    async def fetch(self, url: str) -> Exchange:
        """Load one page, wait until its scripts have finished, and return the finished page."""
        started = time.perf_counter()
        self._reset()
        path = urlsplit(url).path or "/"
        exchange = Exchange(method="GET", url=url, label=f"GET {path}")
        try:
            navigation = await self._send("Page.navigate", {"url": url}, timeout=PAGE_TIMEOUT)
            if navigation.get("errorText"):
                exchange.error = self._error_text(navigation["errorText"])
                return exchange
            try:
                await asyncio.wait_for(self._loaded.wait(), PAGE_TIMEOUT)
            except asyncio.TimeoutError:
                pass
            await self._settle()
            main = self._responses.get(self._main_request)
            if not main:
                exchange.error = self._error_text(self._navigation_error) if self._navigation_error else "no answer"
                return exchange
            response = main["response"]
            exchange.status = response.get("status")
            exchange.headers = self._headers(self._main_request, response)
            exchange.url = (await self._evaluate("location.href")) or response.get("url", url)
            if "html" in response.get("mimeType", ""):
                html = await self._evaluate("document.documentElement.outerHTML") or ""
                exchange.body = ("<!DOCTYPE html>\n" + html).encode("utf-8", errors="replace")
            else:
                exchange.body = await self._body(self._main_request)
            exchange.elapsed = time.perf_counter() - started
            for observer in self.client.observers:
                observer(exchange)
            await self._collect_bodies()
        except BrowserError as exc:
            exchange.error = f"BrowserError: {exc}"
        return exchange

    @staticmethod
    def _error_text(text: str) -> str:
        if text.startswith("net::ERR_CERT") or "SSL" in text:
            return f"CertificateError: {text}"
        return text or "no answer"

    async def _settle(self) -> None:
        deadline = time.monotonic() + SETTLE_MAX
        while time.monotonic() < deadline:
            if not self._inflight and time.monotonic() - self._last_activity >= SETTLE_QUIET:
                return
            await asyncio.sleep(0.1)

    async def _evaluate(self, expression: str) -> str:
        result = await self._send("Runtime.evaluate", {"expression": expression, "returnByValue": True})
        return (result.get("result") or {}).get("value") or ""

    async def _body(self, request_id: str) -> bytes:
        try:
            result = await self._send("Network.getResponseBody", {"requestId": request_id})
        except BrowserError:
            return b""
        raw = result.get("body", "")
        return base64.b64decode(raw) if result.get("base64Encoded") else raw.encode("utf-8", errors="replace")

    def _headers(self, request_id: str, response: dict) -> dict:
        headers = {k.lower(): v for k, v in (response.get("headers") or {}).items()}
        extra = self._extra.get(request_id)
        if extra:
            headers.update({k.lower(): v for k, v in (extra.get("headers") or {}).items()})
        return headers

    async def _collect_bodies(self) -> None:
        """Show the page's own scripts and API answers to the passive checks (secrets, headers, CORS)."""
        taken = 0
        for request_id in list(self._finished):
            kind, url, method = self._types.get(request_id, ("", "", "GET"))
            response = self._responses.get(request_id)
            if kind not in ("Script", "XHR", "Fetch") or not response or not self.client.in_scope(url) or url in self._seen_bodies:
                continue
            status = response["response"].get("status")
            if not (isinstance(status, int) and 200 <= status < 300):
                continue
            if taken >= MAX_BODIES_PER_PAGE:
                break
            self._seen_bodies.add(url)
            taken += 1
            body = (await self._body(request_id))[: self.client.config.max_bytes]
            exchange = Exchange(method=method, url=url, status=status, headers=self._headers(request_id, response["response"]), body=body,
                                label=f"{method} {urlsplit(url).path or '/'}")
            for observer in self.client.observers:
                observer(exchange)
