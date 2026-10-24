"""Helpers that run a scan against an in process test server."""

from __future__ import annotations

import asyncio

from aiohttp.test_utils import TestServer

from api_scanner.context import ScanOptions
from api_scanner.engine import ScanRequest, run_scan
from api_scanner.http import ClientConfig, Identity
from api_scanner.scoring import AssetProfile

from .apps import issue_token

def bearer(name: str, vulnerable: bool) -> Identity:
    return Identity(name, {"Authorization": f"Bearer {issue_token(name, vulnerable)}"})

def scan_app(app, *, vulnerable: bool, tokens: bool = True, two: bool = True, active: bool = False, mutating: bool = False,
             callback: bool = False, profile: AssetProfile | None = None, target_path: str = "", options: dict | None = None,
             client: dict | None = None, request_hook=None):
    """Start the app, scan it, return (result, app)."""

    async def go():
        server = TestServer(app, host="127.0.0.1", access_log=None)
        await server.start_server()
        try:
            base = str(server.make_url("")).rstrip("/")
            opts = dict(active=active, allow_mutating=mutating, rate_probe=40, time_probe_seconds=2, lookup=False)  # no network lookups unless a test asks
            if callback:
                opts.update(callback_host="127.0.0.1", callback_bind="127.0.0.1")
            opts.update(options or {})
            cfg = dict(rps=0, concurrency=5, timeout=10, max_requests=5000)
            cfg.update(client or {})
            req = ScanRequest(
                target=base + target_path,
                identity=bearer("alice", vulnerable) if tokens else None,
                identity_b=bearer("bob", vulnerable) if tokens and two else None,
                options=ScanOptions(**opts),
                client=ClientConfig(**cfg),
                profile=profile or AssetProfile(),
            )
            if request_hook:
                request_hook(req, base)
            return await run_scan(req)
        finally:
            await server.close()

    return asyncio.run(go())

def ids(result, *confidences):
    wanted = {c.value if hasattr(c, "value") else c for c in confidences} if confidences else None
    return {f.check_id for f in result.findings if wanted is None or f.confidence.value in wanted}

class LiveServer:
    """Runs an aiohttp app on its own thread and event loop, so code that calls asyncio.run (the CLI) can reach it."""

    def __init__(self, app):
        import threading

        from aiohttp import web

        self._web = web
        self._app = app
        self._ready = threading.Event()
        self.base = ""
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        runner = self._web.AppRunner(self._app, access_log=None)
        loop.run_until_complete(runner.setup())
        site = self._web.TCPSite(runner, "127.0.0.1", 0)
        loop.run_until_complete(site.start())
        port = site._server.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self._loop = loop
        self._ready.set()
        loop.run_forever()

    def __enter__(self):
        self._thread.start()
        self._ready.wait(5)
        return self

    def __exit__(self, *exc):
        self._loop.call_soon_threadsafe(self._loop.stop)
