"""Out of band callback listener used to PROVE server side request forgery.

The scanner starts a tiny HTTP listener. A URL containing a one time token is sent to a
parameter that looks like it takes a URL. If the target calls the listener back with that
token, the target really fetches attacker supplied URLs. No guessing is involved.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import Optional

from aiohttp import web

class CanaryServer:
    def __init__(self, public_host: str, bind_host: str = "0.0.0.0"):
        # public_host is host or host:port that the TARGET can reach, for example 10.0.0.5:9099
        self.public_host = public_host
        self.bind_host = bind_host
        self.hits: dict = {}
        self._runner: Optional[web.AppRunner] = None
        self.port = 0

    async def start(self) -> None:
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        want_port = 0
        if ":" in self.public_host:
            want_port = int(self.public_host.rsplit(":", 1)[1])
        site = web.TCPSite(self._runner, self.bind_host, want_port)
        await site.start()
        sockets = site._server.sockets  # type: ignore[union-attr]
        self.port = sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    async def _handle(self, request: web.Request) -> web.Response:
        token = request.match_info.get("tail", "").split("/")[0]
        self.hits.setdefault(token, []).append({"remote": request.remote, "path": request.path_qs, "ua": request.headers.get("User-Agent", "")})
        return web.Response(text="ok")

    def new_url(self) -> tuple:
        token = "cb" + secrets.token_hex(8)
        host = self.public_host if ":" in self.public_host else f"{self.public_host}:{self.port}"
        return token, f"http://{host}/{token}"

    async def wait_for(self, token: str, timeout: float = 4.0) -> Optional[dict]:
        end = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end:
            if token in self.hits:
                return self.hits[token][0]
            await asyncio.sleep(0.1)
        return self.hits.get(token, [None])[0]
