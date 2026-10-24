"""Website checks. They run in website mode, on the pages the crawler already fetched.

Most of them only read responses that were received anyway. Only WEB-007
(common folder probes), WEB-008 (script and source map downloads) and WEB-009 (open
redirects, active mode) send extra requests.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlsplit

from ..context import ScanContext
from ..http import Blocked
from ..models import Confidence, Endpoint
from . import check

_SOURCE_MAP = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_REDIRECT_PARAM = re.compile(r"^(url|redirect|redirect_?uri|redirect_?url|return|return_?url|return_?to|next|continue|dest|destination|goto|target|link|out|forward)$", re.I)
_DIRLIST = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /|\[To Parent Directory\]", re.I)
COMMON_DIRS = ["/images/", "/img/", "/uploads/", "/files/", "/backup/", "/backups/", "/static/", "/assets/", "/media/", "/logs/"]
EVIL = "https://evil.example/"

def _html_pages(ctx: ScanContext) -> list:
    return [p for p in ctx.pages if p.is_html and p.status == 200]

def _labels(pages: list, limit: int = 8) -> list:
    out = []
    for p in pages:
        if p.label not in out:
            out.append(p.label)
    return out[:limit]

@check("WEB-004", scope="host")
async def mixed_content(ctx: ScanContext) -> None:
    for page in _html_pages(ctx):
        if not page.url.startswith("https://"):
            continue
        bad = [r for r in page.resources if r.url.startswith("http://")]
        if bad:
            r = bad[0]
            ctx.add("WEB-004", operation=page.label, confidence=Confidence.CONFIRMED, evidence=f"this HTTPS page loads a {r.kind} over HTTP: {r.url[:100]}")

@check("WEB-006", scope="host")
async def cleartext_login(ctx: ScanContext) -> None:
    for page in _html_pages(ctx):
        for form in page.forms:
            if not form.has_password:
                continue
            problems = []
            local = (urlsplit(page.url).hostname or "") in ("localhost", "127.0.0.1", "::1")  # nothing crosses a network
            if page.url.startswith("http://") and not local:
                problems.append("the page is served over HTTP")
            if form.action.startswith("http://") and not local:
                problems.append("the form posts to an HTTP address")
            if form.method == "get":
                problems.append("the form uses GET, so the password ends up in the URL")
            if problems:
                ctx.add("WEB-006", operation=page.label, confidence=Confidence.CONFIRMED, evidence="password form: " + "; ".join(problems))

@check("WEB-007", scope="host")
async def directory_listing(ctx: ScanContext) -> None:
    for page in _html_pages(ctx):
        if _DIRLIST.search(page.body[:3000]):
            ctx.add("WEB-007", operation=page.label, confidence=Confidence.CONFIRMED, evidence=f"{page.url} shows a file listing")
    parts = urlsplit(ctx.base_url)
    origin = f"{parts.scheme}://{parts.netloc}"

    async def probe(path: str) -> None:
        try:
            ex = await ctx.client.request("GET", origin + path, identity=None, headers={"Accept": "text/html,*/*"}, label=f"GET {path}")
        except Blocked:
            return
        if ex.ok and _DIRLIST.search(ex.text[:3000]):
            ctx.add("WEB-007", operation=f"GET {path}", confidence=Confidence.CONFIRMED, evidence=f"{origin}{path} shows a file listing")

    await asyncio.gather(*[probe(p) for p in COMMON_DIRS])

@check("WEB-008", scope="host")
async def source_maps(ctx: ScanContext) -> None:
    scripts: list = []
    for page in _html_pages(ctx):
        for r in page.resources:
            if r.kind == "script" and ctx.client.in_scope(r.url) and r.url not in scripts:
                scripts.append(r.url)
    for url in scripts[:8]:
        try:
            ex = await ctx.client.request("GET", url, identity=None, headers={"Accept": "*/*"}, label=f"GET {urlsplit(url).path}")
        except Blocked:
            return
        if not ex.ok:
            continue
        match = _SOURCE_MAP.search(ex.text[-600:])
        if not match or match.group(1).startswith("data:"):
            continue
        map_url = urljoin(url, match.group(1))
        if not ctx.client.in_scope(map_url):
            continue
        try:
            mp = await ctx.client.request("GET", map_url, identity=None, headers={"Accept": "*/*"}, label=f"GET {urlsplit(map_url).path}")
        except Blocked:
            return
        data = mp.json if mp.ok else None
        if isinstance(data, dict) and data.get("sources") and any(data.get("sourcesContent") or []):
            ctx.add("WEB-008", operation=f"GET {urlsplit(map_url).path}", confidence=Confidence.CONFIRMED,
                    evidence=f"{map_url} contains the original source of {len(data['sources'])} files")
            return

@check("WEB-009", scope="endpoint", active=True)
async def open_redirect(ctx: ScanContext, ep: Endpoint) -> None:
    if ep.method != "GET":
        return
    for p in ep.params:
        if p.location != "query" or not _REDIRECT_PARAM.match(p.name):
            continue
        control = await ctx.send(ep, identity=None, params={p.name: "/"}, label=f"probe {ep.label}")
        for payload in (EVIL, "//evil.example/"):
            ex = await ctx.send(ep, identity=None, params={p.name: payload}, label=f"probe {ep.label}")
            location = ex.headers.get("location", "")
            if ex.status in (301, 302, 303, 307, 308) and (urlsplit(urljoin("https:", location)).hostname or "") == "evil.example" \
                    and "evil.example" not in control.headers.get("location", ""):
                ctx.add("WEB-009", operation=ep.label, confidence=Confidence.CONFIRMED,
                        evidence=f"parameter '{p.name}': {payload} produced a redirect to {location[:80]}")
                return
