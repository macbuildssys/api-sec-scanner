"""Two small websites used as the test oracle for website mode: one full of planted flaws and a hardened twin."""

from __future__ import annotations

import json
from html import escape

from aiohttp import web

SOURCE_MAP = {"version": 3, "sources": ["src/app.js", "src/secret.js"], "sourcesContent": ["const a = 1;", "const b = 2;"], "mappings": ""}

def make_site(vulnerable: bool) -> web.Application:
    hits: list = []

    @web.middleware
    async def mw(request, handler):
        hits.append(request.path_qs)
        try:
            resp = await handler(request)
        except web.HTTPException as exc:
            resp = exc
        if vulnerable:
            resp.headers["Server"] = "Apache/2.2.15 (CentOS)"
        else:
            resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'self'"
            resp.headers["X-Frame-Options"] = "SAMEORIGIN"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "same-origin"
        return resp

    async def home(request):
        script = '<script src="/static/app.js"></script>' + ('<script src="https://cdn.example.net/lib.js"></script>' if vulnerable else "")
        login = ('<form method="get" action="/login"><input type="text" name="user"><input type="password" name="pw"></form>'
                 if vulnerable else '<form method="post" action="/login"><input type="text" name="user"><input type="password" name="pw"></form>')
        html = f"""<!doctype html><html><head><title>Shop</title>{script}</head><body>
        <a href="/about">About</a> <a href="/search?q=shoes">Search</a> <a href="/logout">Log out</a> <a href="/go?next=/about">Go</a>
        <form method="get" action="/search"><input type="text" name="q"></form>{login}</body></html>"""
        resp = web.Response(text=html, content_type="text/html")
        resp.set_cookie("sessionid", "abc123") if vulnerable else resp.set_cookie("sessionid", "abc123", secure=False, httponly=True, samesite="Lax")
        return resp

    async def about(request):
        return web.Response(text="<html><head><title>About</title></head><body><a href='/'>Home</a></body></html>", content_type="text/html")

    async def search(request):
        q = request.query.get("q", "")
        shown = q if vulnerable else escape(q)
        return web.Response(text=f"<html><body><h1>Results for {shown}</h1></body></html>", content_type="text/html")

    async def go(request):
        target = request.query.get("next", "/")
        if not vulnerable and (not target.startswith("/") or target.startswith("//")):
            target = "/"
        raise web.HTTPFound(target)

    async def login(request):
        return web.Response(text="<html><body>login</body></html>", content_type="text/html")

    async def logout(request):
        return web.Response(text="bye")

    async def files(request):
        if not vulnerable:
            raise web.HTTPNotFound()
        return web.Response(text="<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1></body></html>", content_type="text/html")

    async def appjs(request):
        suffix = "\n//# sourceMappingURL=app.js.map" if vulnerable else ""
        return web.Response(text="console.log('hi');" + suffix, content_type="application/javascript")

    async def appmap(request):
        if not vulnerable:
            raise web.HTTPNotFound()
        return web.Response(text=json.dumps(SOURCE_MAP), content_type="application/json")

    async def backup(request):
        if not vulnerable:
            raise web.HTTPNotFound()
        return web.Response(text="CREATE TABLE users (id int, email text);\nINSERT INTO users VALUES (1, 'a@b.c');", content_type="text/plain")

    async def sitemap(request):
        base = f"{request.scheme}://{request.host}"
        return web.Response(text=f"<urlset><url><loc>{base}/hidden</loc></url></urlset>", content_type="application/xml")

    async def hidden(request):
        return web.Response(text="<html><head><title>Hidden</title></head><body>hidden</body></html>", content_type="text/html")

    app = web.Application(middlewares=[mw])
    app.add_routes([
        web.get("/", home), web.get("/about", about), web.get("/search", search), web.get("/go", go), web.get("/login", login),
        web.get("/logout", logout), web.get("/files/", files), web.get("/static/app.js", appjs), web.get("/static/app.js.map", appmap),
        web.get("/backup.sql", backup), web.get("/sitemap.xml", sitemap), web.get("/hidden", hidden),
    ])
    app["hits"] = hits
    return app

def make_redirecting_site(target_base: str = "") -> web.Application:
    """/ redirects to /home, and /away redirects to another host."""

    async def root(request):
        raise web.HTTPMovedPermanently("/home")

    async def home(request):
        return web.Response(text="<html><head><title>Home</title></head><body><a href='/x'>x</a></body></html>", content_type="text/html")

    async def away(request):
        raise web.HTTPMovedPermanently(target_base or "http://localhost:9/")

    app = web.Application()
    app.add_routes([web.get("/", root), web.get("/home", home), web.get("/away", away)])
    return app
