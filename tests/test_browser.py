"""Crawling a single page application in a headless browser. Skipped when no browser is installed."""

import pytest
from aiohttp import web

from api_scanner.browser import find_browser

from .helpers import scan_app

pytestmark = pytest.mark.skipif(find_browser() is None, reason="needs Chrome, Chromium or Edge")

SHELL = """<!doctype html><html><head><title>App</title></head><body><div id="app"></div>
<script src="/app.js"></script></body></html>"""

SCRIPT = """
const app = document.getElementById('app');
const pages = {'/': ['/team', '/jobs'], '/team': ['/'], '/jobs': ['/']};
const links = pages[location.pathname] || ['/'];
app.innerHTML = '<h1>' + document.title + '</h1>' + links.map(l => '<a href="' + l + '">' + l + '</a>').join(' ');
fetch('/api/items?page=1').then(r => r.json());
fetch('/api/delete', {method: 'POST', body: '{}'});
new Image().src = '/pixel.png';
"""

def make_spa():
    hits = []

    @web.middleware
    async def log(request, handler):
        hits.append(f"{request.method} {request.path_qs}")
        return await handler(request)

    async def shell(request):
        return web.Response(text=SHELL, content_type="text/html")

    async def script(request):
        return web.Response(text=SCRIPT, content_type="application/javascript")

    async def items(request):
        return web.json_response({"items": []})

    app = web.Application(middlewares=[log])
    app.add_routes([web.get("/", shell), web.get("/team", shell), web.get("/jobs", shell), web.get("/app.js", script),
                    web.get("/api/items", items), web.post("/api/delete", items), web.get("/pixel.png", items)])
    app["hits"] = hits
    return app

def scan_spa(browser):
    app = make_spa()
    result = scan_app(app, vulnerable=False, tokens=False, options={"browser": browser})
    return result, app

def test_no_browser_option_keeps_the_plain_crawl_and_explains():
    result, _ = scan_spa(False)
    assert result.mode["pages_crawled"] == 1
    assert any("builds its pages with JavaScript" in n for n in result.notes)

def test_script_site_is_crawled_in_the_browser_by_itself():
    result, _ = scan_spa(None)
    assert result.mode["pages_crawled"] == 3
    assert any("crawled again in a headless browser" in n for n in result.notes)

def test_browser_crawl_follows_links_made_by_scripts():
    result, app = scan_spa(True)
    assert result.mode["pages_crawled"] == 3
    assert "GET /api/items?page=1" in app["hits"]
    assert any("headless browser" in n for n in result.notes)
    assert not any("builds its pages with JavaScript, so few" in n for n in result.notes)

def test_browser_never_sends_changes_or_loads_images():
    result, app = scan_spa(True)
    assert "POST /api/delete" not in app["hits"]
    assert "GET /pixel.png" not in app["hits"]
    assert any("change data were blocked" in n for n in result.notes)

def test_calls_made_by_scripts_become_endpoints():
    result, _ = scan_spa(True)
    assert any("1 call(s)" in n for n in result.notes)
