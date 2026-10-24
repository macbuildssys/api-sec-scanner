"""Scan orchestration."""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlsplit

from . import __version__, browser, osint, passive
from .checks import REGISTRY, load_all
from .checks.discovery import find_spec, origin_of
from .context import ScanContext, ScanOptions
from .http import Blocked, ClientConfig, Identity, ScanClient
from .knowledge import standards_summary
from .models import Endpoint, Param, ScanResult
from .oob import CanaryServer
from .scoring import AssetProfile, compute_posture
from . import vulndb
from .spec import SpecError, SpecModel, looks_like_spec, parse_spec_text
from .web import HTML_ACCEPT, crawl, endpoints_from_pages, parse_page, same_site

# Checks that make sense for a plain website (no OpenAPI document).
WEBSITE_FAMILIES = {"CFG", "EXP", "INJ", "WEB", "RES", "SSRF", "TLS", "OSINT"}

@dataclass
class ScanRequest:
    target: str  # a URL, or a path to an OpenAPI file
    spec: Optional[str] = None  # URL or path of the OpenAPI document
    base_url: Optional[str] = None
    identity: Optional[Identity] = None
    identity_b: Optional[Identity] = None
    options: ScanOptions = field(default_factory=ScanOptions)
    client: ClientConfig = field(default_factory=ClientConfig)
    profile: AssetProfile = field(default_factory=AssetProfile)
    extra_scope: list = field(default_factory=list)

ProgressFn = Callable[[int, int, str], None]

def _family(name: str) -> str:
    return name.split("-")[0].upper()

def _check_wanted(options: ScanOptions, name: str) -> bool:
    fam = _family(name)
    if options.only and not any(_family(p) == fam or name.upper().startswith(p.upper()) for p in options.only):
        return False
    return not any(name.upper() == p.upper() for p in options.skip)

def _choose_base(model: SpecModel, target_url: Optional[str], explicit: Optional[str]) -> str:
    """Pick the base URL to test. The user's target wins over whatever the spec claims,
    so a spec that still lists the production host can never redirect a staging scan."""
    if explicit:
        return explicit.rstrip("/")
    listed = model.base_urls()
    if target_url:
        target_host = urlsplit(target_url).netloc
        for url in listed:
            if urlsplit(url).netloc == target_host:
                return url
        return target_url.rstrip("/")
    if listed:
        return listed[0]
    raise SpecError("the specification lists no absolute server URL; pass --base-url")

def _fallback_endpoint(base_url: str) -> Endpoint:
    path = urlsplit(base_url).path or "/"
    origin = origin_of(base_url)
    return Endpoint(method="GET", path=path if path.startswith("/") else "/" + path, base_url=origin, op_id="root",
                    params=[], documented=False, summary="target URL (no specification)")

async def _load_spec_text(ctx: ScanContext, location: str) -> tuple:
    if location.startswith(("http://", "https://")):
        ctx.client.config.allowed_hosts.add((urlsplit(location).hostname or "").lower())
        ex = await ctx.client.request("GET", location, identity=ctx.identity, label="GET spec")
        if not ex.ok:
            raise SpecError(f"could not download the specification ({ex.status or ex.error})")
        return ex.text, location
    with open(location, "r", encoding="utf-8") as fh:
        return fh.read(), None

def _looks_like_script_site(pages: list) -> bool:
    """A start page that loads scripts but links to almost nothing is probably built in the browser."""
    if not pages or len(pages) > 3:
        return False
    first = pages[0]
    scripts = sum(1 for r in first.resources if r.kind == "script")
    return scripts >= 1 and len(first.links) <= 3

async def _add_pages(ctx: ScanContext, urls: list, origin: str, summary: str, tag: str) -> int:
    """Fetch each address once. Those that really answer become pages and endpoints to test."""
    added = 0
    for url in urls:
        parts = urlsplit(url)
        if not ctx.client.in_scope(url):
            continue
        try:
            ex = await ctx.client.request("GET", url, identity=ctx.identity, headers=HTML_ACCEPT, label=f"GET {parts.path or '/'}")
        except Blocked:
            break
        if not ex.ok or ctx.soft404.matches(ex):
            continue
        page = parse_page(ex)
        if page.is_html:
            ctx.pages.append(page)
        params = [Param(name=n, location="query", schema={"type": "string"}, example=v or "test") for n, v in osint.params_of(url).items()]
        ctx.endpoints.append(Endpoint(method="GET", path=parts.path or "/", base_url=origin, op_id=f"{tag}{added}", params=params,
                                      documented=False, summary=summary))
        added += 1
    return added

async def _gather_osint(ctx: ScanContext, spec_loaded: bool) -> None:
    """Ask public sources about the target and check what they said. Addresses that still answer become pages to test."""
    host = (urlsplit(ctx.base_url).hostname or "").lower()
    ids = ("OSINT-001", "OSINT-002", "OSINT-003", "OSINT-004")
    if not osint.is_public_name(host) or not any(ctx.enabled(i) for i in ids):
        return
    try:
        data = await osint.gather(host, netloc=urlsplit(ctx.base_url).netloc.lower())
    except Exception as exc:  # public sources are an extra, so a problem here must never abort the scan
        ctx.note(f"OSINT could not be used ({type(exc).__name__}: {exc}).")
        return
    ctx.osint = data
    for line in osint.describe(data):
        ctx.note(line)
    if ctx.web and not spec_loaded:
        origin = origin_of(ctx.base_url)
        known = {ep.path for ep in ctx.endpoints}
        added = await _add_pages(ctx, osint.extra_pages(data, known, origin=origin), origin, "address found by OSINT", "osint")
        if added:
            ctx.note(f"OSINT: {added} address(es) from the web archive and robots.txt still answer and were added to the pages that are tested.")

async def _scripts_to_endpoints(ctx: ScanContext) -> None:
    """Read the site's own scripts for API paths such as fetch('/api/items'). A path is kept only when the server answers it."""
    origin = origin_of(ctx.base_url)
    host = (urlsplit(origin).hostname or "").lower()
    scripts = []
    for page in ctx.pages:
        for res in page.resources:
            if res.kind == "script" and res.url not in scripts and same_site(res.url, origin):
                scripts.append(res.url)
    known = {ep.path for ep in ctx.endpoints}
    found = []
    for url in scripts[:15]:
        try:
            ex = await ctx.client.request("GET", url, identity=ctx.identity, label=f"GET {urlsplit(url).path}")
        except Blocked:
            break
        if not ex.ok:
            continue
        for path in osint.api_paths_in_script(ex.text, host):
            if path not in known and path not in found:
                found.append(path)
    added = []
    for path in found[:25]:
        url = origin + path
        try:
            ex = await ctx.client.request("GET", url, identity=ctx.identity, label=f"GET {path}")
        except Blocked:
            break
        if ex.status is None or ex.status in (404, 410) or ex.status >= 500 or ctx.soft404.matches(ex) or "html" in ex.content_type:
            continue
        ctx.endpoints.append(Endpoint(method="GET", path=path, base_url=origin, op_id=f"js{len(added)}", params=[], documented=False,
                                      summary="API path found in a script of the site"))
        added.append(path)
    if added:
        ctx.note(f"OSINT: {len(added)} API path(s) found in the site's scripts answer and were added to the tests: {', '.join(added[:5])}.")

async def _crawl_in_browser(ctx: ScanContext, options: ScanOptions, start_url: str, executable: str):
    """Crawl in a headless browser. Returns None when the browser could not be used."""
    try:
        async with browser.Chrome(executable, insecure=ctx.client.config.insecure) as chrome:
            renderer = browser.Renderer(chrome, ctx.client, ctx.identity, start_url, ctx.note, same_site)
            await renderer.start()
            result = await crawl(ctx, start_url, options.max_pages, renderer=renderer)
            if result.unreachable:
                return None
            ctx.rendered = True
            ctx.api_calls = list(renderer.api_calls)
            if renderer.blocked_changes:
                ctx.note(f"{renderer.blocked_changes} request(s) that change data were blocked in the browser: they need --allow-mutating.")
            return result
    except browser.BrowserError as exc:
        ctx.note(f"The browser could not be used ({exc}), so pages were read without running JavaScript.")
        return None

async def _crawl_site(ctx: ScanContext, options: ScanOptions, start_url: str):
    """Crawl with plain requests. A site built with JavaScript is crawled again in a headless browser when one is installed.

    options.browser: True always uses the browser, False never does, None decides by looking at the site.
    """
    ctx.rendered = False
    executable = browser.find_browser() if options.browser is not False else None
    if options.browser and executable is None:
        ctx.note("--browser was given but no Chrome, Chromium or Edge was found, so pages were read without running JavaScript. "
                 "Install one, or set API_SEC_SCANNER_BROWSER to its path.")
    if options.browser and executable:
        result = await _crawl_in_browser(ctx, options, start_url, executable)
        if result is not None:
            return result
    plain = await crawl(ctx, start_url, options.max_pages)
    if options.browser is None and executable and plain.is_html and not plain.unreachable and _looks_like_script_site(plain.pages):
        result = await _crawl_in_browser(ctx, options, start_url, executable)
        if result is not None:
            ctx.note("The site builds its pages with JavaScript, so it was crawled again in a headless browser.")
            return result
    return plain

async def run_scan(req: ScanRequest, progress: Optional[ProgressFn] = None) -> ScanResult:
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()
    load_all()

    raw_target = req.target.strip()
    target_is_file = os.path.isfile(raw_target)
    guessed_scheme = not target_is_file and "://" not in raw_target
    if guessed_scheme:
        raw_target = "https://" + raw_target.lstrip("/")
    target_url = None if target_is_file else raw_target.rstrip("/")
    spec_location = req.spec or (raw_target if target_is_file else None)

    cfg = req.client
    cfg.allowed_hosts = {h.lower() for h in req.extra_scope}
    if target_url:
        cfg.allowed_hosts.add((urlsplit(target_url).hostname or "").lower())
    if req.base_url:
        cfg.allowed_hosts.add((urlsplit(req.base_url).hostname or "").lower())
    cfg.allow_mutating = req.options.allow_mutating

    async with ScanClient(cfg) as client:
        ctx = ScanContext(client, req.options, req.profile, req.identity, req.identity_b)
        analyzer = passive.attach(ctx)

        if guessed_scheme and target_url:
            first = await client.request("GET", target_url, identity=None, label="GET /", observe=False)
            tls_problem = bool(first.error and "ertificate" in first.error)
            if first.status is None and not tls_problem:
                plain = "http://" + target_url.removeprefix("https://")
                again = await client.request("GET", plain, identity=None, label="GET /", observe=False)
                if again.status is None:
                    raise SpecError(f"could not reach {raw_target.removeprefix('https://')}: {first.error or 'no answer'}")
                target_url = plain
                ctx.note("No scheme was given and HTTPS did not answer, so HTTP was used.")
            else:
                ctx.note("No scheme was given, so https:// was used.")

        # 1. specification
        text, source_url = (None, None)
        if spec_location:
            text, source_url = await _load_spec_text(ctx, spec_location)
        elif target_url:
            # The address may itself be the OpenAPI document (for example .../openapi.json).
            direct = await client.request("GET", target_url, identity=ctx.identity, label="GET target", observe=False)
            if direct.ok and looks_like_spec(direct.text):
                text, source_url = direct.text, target_url
                ctx.note("The address you gave is an OpenAPI document, so it was used as the specification.")
                target_url = origin_of(target_url)
        if text is None and target_url and not spec_location:
            await ctx.soft404.learn(client, origin_of(target_url))
            found = await find_spec(ctx, target_url)
            if found:
                source_url, text = found
                ctx.discovered_spec_url = source_url
                ctx.note(f"Found the OpenAPI document at {source_url}.")
        if text is not None:
            model = SpecModel(parse_spec_text(text), source_url=source_url, base_url_override=None)
            ctx.spec = model
            ctx.base_url = _choose_base(model, target_url, req.base_url)
            model.base_url_override = ctx.base_url
            ctx.endpoints = model.endpoints()
            cfg.allowed_hosts.add((urlsplit(ctx.base_url).hostname or "").lower())
            if target_url and urlsplit(ctx.base_url).netloc != urlsplit(target_url).netloc:
                ctx.note("The specification lists a different host than the target. The target was used.")
        else:
            ctx.base_url = target_url or req.base_url or ""
            if not ctx.base_url:
                raise SpecError("nothing to scan: give a URL or an OpenAPI file")
        spec_loaded = text is not None

        # 1b. website mode: crawl when there is no specification (or when asked to)
        crawled = None
        if req.options.web is not False and target_url and (not spec_loaded or req.options.web):
            crawled = await _crawl_site(ctx, req.options, ctx.base_url)
            if crawled.tls_error:
                # Report the certificate (TLS-001 does that) and keep scanning without verifying it.
                ctx.cert_untrusted = True
                await client.disable_tls_verification()
                ctx.note("The certificate was rejected (see the TLS finding). The rest of the scan continued without verifying it.")
                crawled = await _crawl_site(ctx, req.options, ctx.base_url)
            if crawled.unreachable and not spec_loaded:
                hint = (" The site did not answer in time, even on a second try. It may be down, very slow, or blocking your address. "
                        "Try again later, open it in a browser to check, or raise --timeout.") if crawled.unreachable == "timeout" else ""
                raise SpecError(f"could not reach {ctx.base_url}: {crawled.unreachable}.{hint}")
            if crawled.is_html:
                ctx.web = True
                ctx.pages = crawled.pages
            elif req.options.web:
                ctx.note("The target did not answer with an HTML page, so it was treated as an API.")
        if ctx.web and crawled:
            final = crawled.final_url
            if not spec_loaded:
                ctx.base_url = origin_of(final) + (urlsplit(final).path.rstrip("/") if urlsplit(final).path not in ("", "/") else "")
                ctx.endpoints = endpoints_from_pages(ctx.pages, final, ctx.api_calls)
                cfg.allowed_hosts.add((urlsplit(final).hostname or "").lower())
            ctx.note(f"Website mode: {len(ctx.pages)} page(s) crawled (limit {req.options.max_pages}).")
            if ctx.rendered:
                ctx.note(f"Pages were loaded in a headless browser, which also saw {len(ctx.api_calls)} call(s) made by the page scripts.")
            elif _looks_like_script_site(ctx.pages):
                ctx.note("This site builds its pages with JavaScript, so few pages were found. Install Chrome, Chromium or Edge and it will be "
                         "crawled in a headless browser" + (" (remove --no-browser)." if req.options.browser is False else "."))
            if crawled.skipped_risky:
                ctx.note(f"{crawled.skipped_risky} link(s) that look like logout, delete or reset actions were not opened.")
            if any(f.method == "post" for p in ctx.pages for f in p.forms):
                ctx.note("POST forms were found but not submitted: they need --allow-mutating.")
        elif not spec_loaded:
            ctx.endpoints = [_fallback_endpoint(ctx.base_url)]
            ctx.note("No OpenAPI document was found, so only the URL itself and the discovery probes were tested. "
                     "Pass --spec for full coverage.")
        if ctx.web and not spec_loaded and ctx.soft404.samples:
            ctx.soft404.samples.clear()  # learn again on the host the site really lives on
        if not ctx.soft404.samples:
            await ctx.soft404.learn(client, origin_of(ctx.base_url))
        if req.options.osint and req.options.lookup:
            await _gather_osint(ctx, spec_loaded)
        if req.options.osint and ctx.web and not spec_loaded:
            await _scripts_to_endpoints(ctx)
        ctx.endpoints = ctx.endpoints[: req.options.max_endpoints]
        ctx.endpoint_labels = {ep.label for ep in ctx.endpoints}

        # 2. optional callback listener for SSRF proof
        if req.options.callback_host and req.options.active:
            ctx.callback = CanaryServer(req.options.callback_host, req.options.callback_bind)
            await ctx.callback.start()
        elif req.options.callback_host and not req.options.active:
            ctx.note("--callback-host is ignored without --active.")

        # 3. checks
        runnable = []
        website_only = ctx.web and ctx.spec is None
        for check in REGISTRY:
            if not _check_wanted(req.options, check.name):
                continue
            if _family(check.name) == "WEB" and not ctx.web:
                continue
            if website_only and _family(check.name) not in WEBSITE_FAMILIES:
                continue
            if check.active and not req.options.active:
                continue
            if check.mutating and not req.options.allow_mutating:
                continue
            runnable.append(check)
        host_checks = [c for c in runnable if c.scope == "host"]
        endpoint_checks = [c for c in runnable if c.scope == "endpoint"]
        total = len(host_checks) + len(endpoint_checks) * len(ctx.endpoints)
        done = 0

        def tick(label: str) -> None:
            nonlocal done
            done += 1
            if progress:
                progress(done, total, label)

        async def guarded(check, *args) -> None:
            try:
                await check.func(ctx, *args)
            except Blocked as exc:
                ctx.note(f"{check.name} stopped early: {exc}")
            except Exception as exc:  # a broken check must never abort the whole scan
                ctx.check_errors.append(f"{check.name}: {type(exc).__name__}: {exc}")

        try:
            for check in host_checks:
                await guarded(check)
                tick(check.name)
            sem = asyncio.Semaphore(max(1, req.client.concurrency))

            async def run_endpoint(ep: Endpoint) -> None:
                async with sem:
                    for check in endpoint_checks:
                        await guarded(check, ep)
                        tick(f"{check.name} {ep.label}")

            await asyncio.gather(*[run_endpoint(ep) for ep in ctx.endpoints])
        finally:
            if ctx.callback:
                await ctx.callback.stop()

        if ctx.enabled("VULN-001"):
            try:
                await vulndb.lookup(ctx)
            except Exception as exc:  # a lookup problem must never abort the scan
                ctx.note(f"Known vulnerability lookup failed: {type(exc).__name__}: {exc}")

        analyzer.finalize()
        findings = ctx.finalize_findings()

        for line in ctx.check_errors:
            ctx.note(f"A check failed and was skipped: {line}")

        two_ids = bool(req.identity and req.identity_b)
        kind = "website" if website_only else ("hybrid" if ctx.web else "api")
        if not req.options.active:
            ctx.note("Injection, SSRF and path traversal tests were not run. Use --active to include them.")
        elif req.options.callback_host is None and not website_only:
            ctx.note("SSRF can only be proven with a callback. Add --callback-host to test it.")
        if not req.options.allow_mutating and any(e.method in ("POST", "PUT", "PATCH", "DELETE") for e in ctx.endpoints):
            ctx.note("Operations that change data were not tested. They need --allow-mutating, which can modify data.")

        posture = compute_posture(findings)

        result = ScanResult(
            target=ctx.base_url,
            started=started.isoformat(timespec="seconds"),
            duration=time.perf_counter() - clock,
            requests_sent=client.requests_sent,
            mode={
                "active": req.options.active,
                "allow_mutating": req.options.allow_mutating,
                "two_identities": two_ids,
                "authenticated": bool(req.identity),
                "kind": kind,
                "pages_crawled": len(ctx.pages),
                "osint": ctx.osint.summary() if ctx.osint else None,
                "spec": source_url or spec_location,
                "request_budget": cfg.max_requests,
                "rate_limit_rps": cfg.rps,
            },
            endpoints_tested=len(ctx.endpoints),
            findings=findings,
            posture=posture,
            technologies=sorted(ctx.technologies),
            asset_profile=req.profile.to_dict(),
            notes=ctx.notes,
            tool_version=__version__,
            standards=standards_summary(),
        )
        return result
