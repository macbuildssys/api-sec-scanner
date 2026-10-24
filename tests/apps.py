"""Two versions of the same small API used as the scanner's test oracle.

make_app(vulnerable=True) contains deliberate flaws, one per scanner check.
make_app(vulnerable=False) has the same routes and behaves correctly, so the scanner
must report no weaknesses with a score against it. That pair is what keeps the
scanner honest in both directions: it must find real flaws and must not cry wolf.
"""

from __future__ import annotations

import asyncio
import copy
import re
import secrets
import time
from typing import Optional

import aiohttp
import jwt as pyjwt
from aiohttp import web

VULN_SECRET = "secret"  # a guessable HMAC secret, on purpose
STRONG_SECRET = secrets.token_hex(32)

USERS = {
    1: {"id": 1, "name": "alice", "email": "alice@example.com", "role": "user",
        "password_hash": "$2b$12$KIXQJ0m3w8X0nQ0YkqzJ4eY8c1Zr5vW6mYb1o8e2z9hF3tQd7uA1S"},
    2: {"id": 2, "name": "bob", "email": "bob@example.com", "role": "user",
        "password_hash": "$2b$12$Zm9yQ2Zv0x1c8aYk3u4nGeLw9rT5pXq7sD2fH6jK8mN0bV1cX3zAe"},
    3: {"id": 3, "name": "carol", "email": "carol@example.com", "role": "admin",
        "password_hash": "$2b$12$Q1wE3rT5yU7iO9pA2sD4fOg6hJ8kL0zX2cV4bN6mQ8wE1rT3yU5iA"},
}
ORDERS = {101: 1, 102: 1, 201: 2, 202: 2}  # order id -> owner user id
UIDS = {"alice": 1, "bob": 2, "carol": 3}

def issue_token(name: str, vulnerable: bool, jwt_mode: Optional[str] = None) -> str:
    claims = {"sub": name, "uid": UIDS[name]}
    if not vulnerable:
        claims["exp"] = int(time.time()) + 900
        claims["iat"] = int(time.time())
    secret = VULN_SECRET if vulnerable else STRONG_SECRET
    return pyjwt.encode(claims, secret, algorithm="HS256")

def build_spec(base_url: str) -> dict:
    sec = [{"bearerAuth": []}]
    public: list = []

    def op(security, summary, params=None, body=None, deprecated=False):
        item: dict = {"summary": summary, "security": security, "responses": {"200": {"description": "ok"}}}
        if params:
            item["parameters"] = params
        if body:
            item["requestBody"] = {"content": {"application/json": {"schema": body}}}
        if deprecated:
            item["deprecated"] = True
        return item

    def q(name, schema=None):
        return {"name": name, "in": "query", "schema": schema or {"type": "string"}}

    id_param = {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
    return {
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "2.0"},
        "servers": [{"url": base_url}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}},
        "paths": {
            "/users": {"get": op(sec, "list users")},
            "/users/{id}": {
                "get": op(sec, "get user", [id_param]),
                "patch": op(sec, "update user", [id_param], {"type": "object", "properties": {"name": {"type": "string"}}}),
            },
            "/orders": {"get": op(sec, "my orders")},
            "/orders/{id}": {"get": op(sec, "get order", [id_param])},
            "/me": {"get": op(sec, "current user")},
            "/admin/stats": {"get": op(sec, "admin statistics")},
            "/login": {"post": op(public, "log in", body={"type": "object", "properties": {"username": {"type": "string"}, "password": {"type": "string"}}})},
            "/search": {"get": op(public, "search", [q("q")])},
            "/lookup": {"get": op(public, "blind lookup", [q("q")])},
            "/files": {"get": op(public, "read a file", [q("name")])},
            "/fetch": {"get": op(public, "fetch a url", [q("url", {"type": "string", "format": "uri"})])},
            "/items": {"get": op(public, "list items", [q("limit", {"type": "integer"})])},
            "/render": {"get": op(public, "render a template", [q("template")])},
            "/echo": {"get": op(public, "echo", [q("msg")])},
            "/crash": {"get": op(public, "always fails")},
            "/diag": {"get": op(public, "network diagnostics", [q("host")])},
            "/public/info": {"get": op(public, "public info")},
            "/v2/ping": {"get": op(public, "ping v2")},
            "/legacy/export": {"get": op(public, "old export", deprecated=True)},
        },
    }

def make_app(vulnerable: bool, jwt_mode: Optional[str] = None) -> web.Application:
    mode = jwt_mode or ("no_verify" if vulnerable else "strict")
    secret = VULN_SECRET if vulnerable else STRONG_SECRET
    hits: dict = {}
    users_db = copy.deepcopy(USERS)  # every app instance gets its own data, scans may change it

    def who(request: web.Request) -> Optional[dict]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:]
        try:
            if mode == "no_verify":
                payload = pyjwt.decode(token, options={"verify_signature": False})
            elif mode == "none_alg" and pyjwt.get_unverified_header(token).get("alg", "").lower() == "none":
                payload = pyjwt.decode(token, options={"verify_signature": False})
            else:
                payload = pyjwt.decode(token, secret, algorithms=["HS256"])
        except Exception:
            return None
        return users_db.get(payload.get("uid"))

    def deny(status=401):
        return web.json_response({"error": "unauthorized" if status == 401 else "forbidden"}, status=status)

    @web.middleware
    async def headers_mw(request, handler):
        request.app["seen"].append((request.method, request.path))
        try:
            resp = await handler(request)
        except web.HTTPException as exc:
            resp = web.json_response({"error": exc.reason}, status=exc.status)
        origin = request.headers.get("Origin")
        if vulnerable:
            resp.headers["Server"] = "Apache/2.4.49 (Unix)"
            resp.headers["X-Powered-By"] = "PHP/7.4.3"
            if origin:
                resp.headers["Access-Control-Allow-Origin"] = origin
                resp.headers["Access-Control-Allow-Credentials"] = "true"
        else:
            resp.headers["Server"] = "api"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["X-RateLimit-Limit"] = "1000"
            if origin == "https://app.example":
                resp.headers["Access-Control-Allow-Origin"] = origin
        return resp

    async def users(request):
        me = who(request)
        if not me:
            return deny()
        if vulnerable:
            return web.json_response({"items": list(users_db.values())})
        return web.json_response({"items": [{"id": me["id"], "name": me["name"]}]})

    async def user(request):
        me = who(request)
        if not me:
            return deny()
        raw = request.match_info["id"]
        uid = int(raw) if raw.isdigit() else -1
        target = users_db.get(uid)
        if not target:
            return web.json_response({"error": "not found"}, status=404)
        if request.method == "PATCH":
            body = await request.json()
            if vulnerable:
                target.update(body)
                return web.json_response(target)
            if uid != me["id"]:
                return deny(403)
            if "name" in body:
                target["name"] = str(body["name"])[:50]
            return web.json_response({"id": uid, "name": target["name"]})
        if vulnerable:
            return web.json_response(target)
        if uid != me["id"] and me["role"] != "admin":
            return deny(403)
        return web.json_response({"id": target["id"], "name": target["name"], "email": target["email"]})

    async def orders(request):
        me = who(request)
        if not me:
            return deny()
        return web.json_response({"items": [{"id": oid, "total": 10 * oid} for oid, owner in ORDERS.items() if owner == me["id"]]})

    async def order(request):
        me = who(request)
        if not me:
            return deny()
        raw = request.match_info["id"]
        oid = int(raw) if raw.isdigit() else -1
        if oid not in ORDERS:
            return web.json_response({"error": "not found"}, status=404)
        if not vulnerable and ORDERS[oid] != me["id"]:
            return web.json_response({"error": "not found"}, status=404)
        return web.json_response({"id": oid, "owner": ORDERS[oid], "total": 10 * oid})

    async def me(request):
        user_ = who(request)
        if not user_:
            return deny()
        return web.json_response({"id": user_["id"], "name": user_["name"]})

    async def admin_stats(request):
        user_ = who(request)
        if vulnerable:
            return web.json_response({"users": len(users_db), "revenue": 12345})
        if not user_:
            return deny()
        if user_["role"] != "admin":
            return deny(403)
        return web.json_response({"users": len(users_db), "revenue": 12345})

    login_attempts: list = []

    async def login(request):
        if not vulnerable:
            now = time.time()
            login_attempts[:] = [t for t in login_attempts if now - t < 10]
            login_attempts.append(now)
            if len(login_attempts) > 10:
                return web.json_response({"error": "slow down"}, status=429, headers={"Retry-After": "10"})
        body = await request.json() if request.can_read_body else {}
        name = body.get("username", "")
        user_ = next((u for u in users_db.values() if u["name"] == name), None)
        if not user_:
            return web.json_response({"error": "bad credentials"}, status=401)
        resp = web.json_response({"token": issue_token(name, vulnerable)})
        return resp

    async def search(request):
        qv = request.query.get("q", "")
        if vulnerable and "'" in qv:
            return web.Response(status=500, text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near ''' at line 1")
        return web.json_response({"results": [], "q": qv[:40]})

    async def lookup(request):
        qv = request.query.get("q", "")
        if vulnerable:
            m = re.search(r"SLEEP\((\d+)\)", qv, re.I) or re.search(r"pg_sleep\((\d+)\)", qv, re.I)
            if m and int(m.group(1)) > 0:
                await asyncio.sleep(int(m.group(1)))
        return web.json_response({"results": []})

    async def files(request):
        name = request.query.get("name", "readme.txt")
        if vulnerable:
            if ".." in name or name.startswith("/") or "%2e" in name.lower():
                return web.Response(text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            return web.Response(text="hello")
        if name != "readme.txt":
            return web.json_response({"error": "unknown file"}, status=400)
        return web.Response(text="hello")

    async def fetch(request):
        url = request.query.get("url", "")
        if not vulnerable:
            return web.json_response({"error": "url not allowed"}, status=400)
        if url.startswith("http://169.254.169.254/latest/meta-data/"):
            return web.Response(text="ami-id\ninstance-id\nlocal-ipv4\niam/security-credentials/\n")
        if url.startswith("http"):
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(url, timeout=aiohttp.ClientTimeout(total=3)) as r:
                        return web.json_response({"status": r.status})
            except Exception as exc:  # noqa: BLE001
                return web.json_response({"error": type(exc).__name__}, status=502)
        return web.json_response({"error": "bad url"}, status=400)

    async def items(request):
        try:
            limit = int(request.query.get("limit", "20"))
        except ValueError:
            return web.json_response({"error": "bad limit"}, status=400)
        if not vulnerable:
            limit = min(limit, 100)
        limit = min(limit, 5000)
        return web.json_response({"items": [{"id": i, "name": f"item {i}"} for i in range(limit)]})

    async def render(request):
        t = request.query.get("template", "hi")
        if vulnerable:
            t = re.sub(r"\{\{(\d+)\*(\d+)\}\}", lambda m: str(int(m.group(1)) * int(m.group(2))), t)
        return web.json_response({"rendered": t})

    async def echo(request):
        msg = request.query.get("msg", "")
        if vulnerable:
            return web.Response(text=f"<html><body>You said: {msg}</body></html>", content_type="text/html")
        return web.json_response({"msg": msg})

    async def crash(request):
        if vulnerable:
            return web.Response(status=500, text='Traceback (most recent call last):\n  File "/srv/app/views.py", line 42, in crash\n    return 1 / 0\nZeroDivisionError: division by zero')
        return web.json_response({"error": "request failed", "id": "c0ffee"}, status=400)

    async def diag(request):
        host = request.query.get("host", "localhost")
        if vulnerable:
            m = re.search(r"(;|\||\$\(|`|&&)\s*sleep\s+(\d+)", host)
            if m and int(m.group(2)) > 0:
                await asyncio.sleep(int(m.group(2)))
        return web.json_response({"host": host[:40], "reachable": True})

    async def public_info(request):
        resp = web.json_response({"name": "test api", "version": "2.0"})
        if vulnerable:
            resp.set_cookie("sessionid", "abc123")
        else:
            resp.set_cookie("sessionid", "abc123", secure=True, httponly=True, samesite="Lax")
        return resp

    async def ping(request):
        return web.json_response({"pong": True})

    async def legacy(request):
        return web.json_response({"export": [1, 2, 3]})

    app = web.Application(middlewares=[headers_mw])
    app["hits"] = hits
    app["seen"] = []
    r = app.router
    r.add_get("/users", users)
    r.add_get("/users/{id}", user)
    r.add_patch("/users/{id}", user)
    r.add_get("/orders", orders)
    r.add_get("/orders/{id}", order)
    r.add_get("/me", me)
    r.add_get("/admin/stats", admin_stats)
    r.add_post("/login", login)
    r.add_get("/search", search)
    r.add_get("/lookup", lookup)
    r.add_get("/files", files)
    r.add_get("/fetch", fetch)
    r.add_get("/items", items)
    r.add_get("/render", render)
    r.add_get("/echo", echo)
    r.add_get("/crash", crash)
    r.add_get("/diag", diag)
    r.add_get("/public/info", public_info)
    r.add_get("/v2/ping", ping)
    r.add_get("/legacy/export", legacy)

    async def spec_handler(request):
        return web.json_response(build_spec(f"{request.scheme}://{request.host}"))

    r.add_get("/openapi.json", spec_handler)

    spec_paths = build_spec("http://x")["paths"]

    def options_factory(path):
        documented = {m.upper() for m in spec_paths[path]}

        async def handler(request):
            allow = {"GET", "POST", "PUT", "DELETE"} if vulnerable else documented
            return web.Response(status=204, headers={"Allow": ", ".join(sorted(allow | {"OPTIONS"}))})
        return handler

    for path in spec_paths:
        try:
            r.add_route("OPTIONS", path, options_factory(path))
        except RuntimeError:
            pass

    if vulnerable:
        async def dotenv(request):
            return web.Response(text="DB_PASSWORD=hunter2\nSECRET_KEY=abc123def456\nAWS_REGION=eu-central-1\n")

        async def gitconfig(request):
            return web.Response(text="[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")

        async def actuator_env(request):
            return web.json_response({"activeProfiles": ["prod"], "propertySources": [{"name": "systemEnvironment"}]})

        async def docs(request):
            return web.Response(text="<html><div id='swagger-ui'></div><script>SwaggerUIBundle({})</script></html>", content_type="text/html")

        async def graphql(request):
            return web.json_response({"data": {"__schema": {"queryType": {"name": "Query"}}}})

        async def trace(request):
            return web.Response(text="\n".join(f"{k}: {v}" for k, v in request.headers.items()))

        async def old_ping(request):
            return web.json_response({"pong": True, "old": True})

        r.add_get("/.env", dotenv)
        r.add_get("/.git/config", gitconfig)
        r.add_get("/actuator/env", actuator_env)
        r.add_get("/docs", docs)
        r.add_post("/graphql", graphql)
        r.add_route("TRACE", "/", trace)
        r.add_get("/v1/ping", old_ping)
        r.add_get("/v0/ping", old_ping)
    return app

def make_catchall_app() -> web.Application:
    """A server that answers 200 with the same body for every path, like a single page app."""

    async def everything(request):
        return web.Response(text="DB_PASSWORD=x\nSECRET_KEY=y\nAPI_URL=z\n")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", everything)
    return app
