"""Website mode: fetch pages, parse the HTML, and turn what was found into endpoints.

Only the standard library parser is used. The crawl stays on hosts the user allowed, never
follows links that look like they change state (logout, delete, unsubscribe), and respects
the request budget and rate limit of the shared client.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit, urlunsplit

from .http import Blocked, Exchange
from .models import Endpoint, Param

HTML_ACCEPT = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.5"}
_SKIP_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|webp|avif|bmp|css|js|mjs|map|woff2?|ttf|eot|otf|mp[34]|webm|avi|mov|zip|gz|tar|rar|7z|pdf|docx?|xlsx?|pptx?|exe|dmg|iso|xml|json|txt)$",
    re.I)
_RISKY_LINK = re.compile(r"(log-?out|sign-?out|delete|remove|unsubscribe|cancel|destroy|reset)", re.I)
_REDIRECTS = (301, 302, 303, 307, 308)
MAX_FORM_ENDPOINTS = 30
MAX_SCRIPT_ENDPOINTS = 20

@dataclass
class Form:
    page: str
    action: str
    method: str
    inputs: list = field(default_factory=list)  # (name, type, value)

    @property
    def has_password(self) -> bool:
        return any(t == "password" for _, t, _ in self.inputs)

@dataclass
class Resource:
    kind: str  # script, style, frame
    url: str
    integrity: bool = False

@dataclass
class Page:
    url: str
    status: int
    headers: dict
    content_type: str
    title: str = ""
    links: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    body: str = ""

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type

    @property
    def label(self) -> str:
        parts = urlsplit(self.url)
        return f"GET {parts.path or '/'}"

class _Parser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links: list = []
        self.forms: list = []
        self.resources: list = []
        self.meta: dict = {}
        self.title = ""
        self._form: Optional[Form] = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(urljoin(self.page_url, a["href"]))
        elif tag == "form":
            self._form = Form(self.page_url, urljoin(self.page_url, a.get("action", "")), a.get("method", "get").lower())
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form.inputs.append((a["name"], a.get("type", "text").lower() if tag == "input" else tag, a.get("value", "")))
        elif tag == "script" and a.get("src"):
            self.resources.append(Resource("script", urljoin(self.page_url, a["src"]), bool(a.get("integrity"))))
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.resources.append(Resource("style", urljoin(self.page_url, a["href"]), bool(a.get("integrity"))))
        elif tag in ("iframe", "frame") and a.get("src"):
            self.resources.append(Resource("frame", urljoin(self.page_url, a["src"]), False))
        elif tag == "meta" and a.get("name"):
            self.meta[a["name"].lower()] = a.get("content", "")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 200:
            self.title += data.strip()

def parse_page(ex: Exchange) -> Page:
    page = Page(url=ex.url, status=ex.status or 0, headers=ex.headers, content_type=ex.content_type)
    if "html" in ex.content_type:
        parser = _Parser(ex.url)
        try:
            parser.feed(ex.text)
        except Exception:  # broken HTML must never stop a scan
            pass
        page.links, page.forms, page.resources, page.meta, page.title = parser.links, parser.forms, parser.resources, parser.meta, parser.title
        page.body = ex.text
    return page

def same_site(a: str, b: str) -> bool:
    """example.com and www.example.com count as one site."""
    strip = lambda h: (h or "").lower().removeprefix("www.")  # noqa: E731
    return strip(urlsplit(a).hostname) == strip(urlsplit(b).hostname)

def _clean(url: str) -> str:
    clean = urldefrag(url)[0]
    parts = urlsplit(clean)
    if parts.scheme and parts.netloc and not parts.path:
        clean = urlunsplit((parts.scheme, parts.netloc, "/", parts.query, ""))  # http://host and http://host/ are one page
    return clean

@dataclass
class CrawlResult:
    pages: list = field(default_factory=list)
    final_url: str = ""
    is_html: bool = False
    skipped_risky: int = 0
    tls_error: bool = False  # the first request failed because the certificate was rejected
    unreachable: str = ""  # the first request got no answer at all (error text)

async def crawl(ctx, start_url: str, max_pages: int = 25, max_depth: int = 2, renderer=None) -> CrawlResult:
    """Breadth first crawl of one site. Returns the pages that answered with 2xx.

    With a renderer (browser.Renderer) pages are loaded in a headless browser, so links created by JavaScript are seen too.
    """
    client = ctx.client
    result = CrawlResult(final_url=start_url)
    seen: set = set()
    queue: deque = deque([(start_url, 0)])
    first = True
    hops = 0
    while queue and len(result.pages) < max_pages:
        url, depth = queue.popleft()
        key = _clean(url)
        if key in seen:
            continue
        seen.add(key)
        try:
            if renderer is not None:
                if client.requests_sent >= client.config.max_requests:
                    raise Blocked(f"request budget of {client.config.max_requests} used")
                ex = await renderer.fetch(key)
            else:
                ex = await client.request("GET", key, identity=ctx.identity, headers=HTML_ACCEPT, label=f"GET {urlsplit(key).path or '/'}")
        except Blocked as exc:
            ctx.note(f"Crawl stopped: {exc}")
            break
        if ex.status is None and first and renderer is None and not re.search(r"CERTIFICATE_VERIFY_FAILED|CertificateError|SSLCertVerificationError", ex.error or ""):
            # Slow or busy sites often answer the second time, so wait a moment and try once more with more patience.
            await asyncio.sleep(2)
            try:
                ex = await client.request("GET", key, identity=ctx.identity, headers=HTML_ACCEPT, label=f"GET {urlsplit(key).path or '/'}",
                                          timeout=max(45.0, 3 * client.config.timeout))
            except Blocked as exc:
                ctx.note(f"Crawl stopped: {exc}")
                break
        if ex.status is None:
            if first:
                if ex.error and re.search(r"CERTIFICATE_VERIFY_FAILED|CertificateError|SSLCertVerificationError", ex.error):
                    result.tls_error = True
                    pass  # the engine reports the certificate and carries on without verifying it
                else:
                    result.unreachable = ex.error or "no answer"
            first = False
            continue
        if ex.status in _REDIRECTS and ex.headers.get("location"):
            target = _clean(urljoin(key, ex.headers["location"]))
            hops += 1
            if hops > 8:
                break
            if client.in_scope(target):
                queue.appendleft((target, depth))
            elif same_site(target, start_url):
                client.config.allowed_hosts.add((urlsplit(target).hostname or "").lower())
                ctx.note(f"{urlsplit(target).hostname} was added to the scope because {key} redirects to it.")
                queue.appendleft((target, depth))
            elif first:
                ctx.note(f"{key} redirects to {target}, which is outside the allowed scope. Scan that address, or add its host with --scope.")
            continue
        if first:
            result.final_url = _clean(ex.url) if renderer is not None else key
            result.is_html = "html" in ex.content_type
            first = False
            if not result.is_html:
                result.pages.append(parse_page(ex))
                break
        if not ex.ok:
            continue
        page = parse_page(ex)
        if not page.is_html:
            continue
        result.pages.append(page)
        if depth >= max_depth:
            continue
        for link in page.links:
            link = _clean(link)
            parts = urlsplit(link)
            if parts.scheme not in ("http", "https") or not client.in_scope(link) or _SKIP_EXT.search(parts.path):
                continue
            if _RISKY_LINK.search(parts.path):
                result.skipped_risky += 1
                continue
            if link not in seen and len(queue) < 200:
                queue.append((link, depth + 1))
    # sitemap: extra pages beyond what the links showed
    if result.is_html and len(result.pages) < max_pages:
        origin = f"{urlsplit(result.final_url).scheme}://{urlsplit(result.final_url).netloc}"
        try:
            sm = await client.request("GET", origin + "/sitemap.xml", identity=None, label="GET /sitemap.xml")
        except Blocked:
            return result
        if sm.ok and "<loc>" in sm.text:
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sm.text)[:20]:
                loc = _clean(loc)
                if loc in seen or not client.in_scope(loc) or _SKIP_EXT.search(urlsplit(loc).path) or _RISKY_LINK.search(loc):
                    continue
                seen.add(loc)
                if len(result.pages) >= max_pages:
                    break
                try:
                    ex = await client.request("GET", loc, identity=ctx.identity, headers=HTML_ACCEPT, label=f"GET {urlsplit(loc).path or '/'}")
                except Blocked:
                    break
                if ex.ok:
                    page = parse_page(ex)
                    if page.is_html:
                        result.pages.append(page)
    return result

def endpoints_from_pages(pages: list, base_url: str, api_calls=()) -> list:
    """The start page, plus every GET address with parameters (links and GET forms) and the GET calls the page scripts made."""
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    root_path = parts.path or "/"
    endpoints = {("GET", root_path): Endpoint(method="GET", path=root_path, base_url=origin, op_id="root", documented=False, summary="start page")}

    def add(path: str, names: dict) -> None:
        if not names or len(endpoints) >= MAX_FORM_ENDPOINTS:
            return
        key = ("GET", path or "/")
        ep = endpoints.get(key)
        if ep is None:
            ep = endpoints[key] = Endpoint(method="GET", path=path or "/", base_url=origin, op_id=f"page{len(endpoints)}", documented=False, summary="discovered page")
        known = {p.name for p in ep.params}
        for name, value in names.items():
            if name not in known:
                ep.params.append(Param(name=name, location="query", schema={"type": "string"}, example=value or "test"))

    for method, call in api_calls:
        cp = urlsplit(call)
        if method != "GET" or cp.netloc != parts.netloc or len(endpoints) >= MAX_FORM_ENDPOINTS + MAX_SCRIPT_ENDPOINTS:
            continue
        key = ("GET", cp.path or "/")
        if key not in endpoints:
            endpoints[key] = Endpoint(method="GET", path=cp.path or "/", base_url=origin, op_id=f"call{len(endpoints)}", documented=False,
                                      summary="called by the page scripts")
        known = {p.name for p in endpoints[key].params}
        for name, value in parse_qsl(cp.query, keep_blank_values=True):
            if name not in known:
                endpoints[key].params.append(Param(name=name, location="query", schema={"type": "string"}, example=value or "test"))
                known.add(name)

    for page in pages:
        pp = urlsplit(page.url)
        if pp.query:
            add(pp.path, dict(parse_qsl(pp.query, keep_blank_values=True)))
        for link in page.links:
            lp = urlsplit(link)
            if lp.query and lp.netloc == parts.netloc:
                add(lp.path, dict(parse_qsl(lp.query, keep_blank_values=True)))
        for form in page.forms:
            fp = urlsplit(form.action)
            if form.method == "get" and fp.netloc == parts.netloc:
                names = {n: v for n, t, v in form.inputs if t not in ("submit", "button", "file", "password", "checkbox", "radio", "image", "reset")}
                add(fp.path or pp.path, names)
    return list(endpoints.values())
