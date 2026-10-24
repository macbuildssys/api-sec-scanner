"""Website mode: the crawler, the website checks, and the fixes for the first real world runs."""

import asyncio
import shutil
import ssl
import subprocess

import pytest
from aiohttp import web

from api_scanner.context import ScanOptions
from api_scanner.engine import ScanRequest, run_scan
from api_scanner.http import ClientConfig

from .helpers import ids, scan_app
from .site import make_redirecting_site, make_site

def scan_site(app, **kw):
    kw.setdefault("tokens", False)
    return scan_app(app, vulnerable=False, **kw)

@pytest.fixture(scope="module")
def vuln_site():
    app = make_site(True)
    return scan_site(app, active=True), app

@pytest.fixture(scope="module")
def hard_site():
    app = make_site(False)
    return scan_site(app, active=True), app

def test_website_is_detected_and_crawled(vuln_site):
    result, app = vuln_site
    assert result.mode["kind"] == "website"
    assert result.mode["pages_crawled"] >= 4
    assert "/hidden" in app["hits"]  # found through sitemap.xml
    assert any("Website mode" in n for n in result.notes)

def test_planted_website_flaws_are_found(vuln_site):
    result, _ = vuln_site
    confirmed = ids(result, "confirmed")
    assert {"WEB-006", "WEB-007", "WEB-008", "WEB-009", "EXP-006", "INJ-006"} <= confirmed
    assert "CFG-008" in ids(result, "confirmed")  # session cookie without protective flags

def test_crawler_never_opens_logout_links(vuln_site):
    _, app = vuln_site
    assert "/logout" not in app["hits"]

def test_safe_mode_sends_no_payloads_on_a_website():
    app = make_site(True)
    result = scan_site(app)
    assert "INJ-006" not in ids(result)
    assert "WEB-009" not in ids(result)  # open redirect probing is active mode only
    assert not any("zx" in h or "evil.example" in h for h in app["hits"])

def test_hardened_site_has_no_scored_weaknesses(hard_site):
    result, _ = hard_site
    unexpected = [(f.check_id, f.operations[:2], f.evidence[:1]) for f in result.findings]
    assert unexpected == []

def test_redirect_to_same_host_is_followed_and_not_called_unthrottled():
    result = scan_site(make_redirecting_site())
    assert result.mode["kind"] == "website" and result.mode["pages_crawled"] >= 1
    assert "RES-002" not in ids(result)

def test_redirect_to_another_host_stays_out_of_scope():
    result = scan_site(make_redirecting_site("http://localhost:9/"), target_path="/away")
    assert any("outside the allowed scope" in n for n in result.notes)

def test_api_with_spec_is_still_an_api(tmp_path):
    from .apps import make_app
    result = scan_app(make_app(True), vulnerable=True)
    assert result.mode["kind"] == "api"
    assert not any(f.check_id.startswith("WEB-") for f in result.findings)

def test_mode_api_never_crawls():
    app = make_site(True)
    result = scan_site(app, options={"web": False})
    assert result.mode["kind"] == "api"
    assert "/about" not in app["hits"]

def test_request_burst_on_a_website_is_not_reported(hard_site, vuln_site):
    for result, _ in (hard_site, vuln_site):
        assert "RES-002" not in ids(result) and "RES-003" not in ids(result)

def test_site_given_without_a_scheme_is_scanned():
    result = scan_site(make_site(True), request_hook=lambda req, base: setattr(req, "target", base.removeprefix("http://")))
    assert result.mode["kind"] == "website" and "WEB-007" in ids(result)
    assert any("HTTP was used" in n for n in result.notes)

def test_unreachable_target_is_an_error_not_a_clean_report():
    from api_scanner.spec import SpecError
    with pytest.raises(SpecError):
        scan_site(make_site(True), request_hook=lambda req, base: setattr(req, "target", "127.0.0.1:9"))

def test_no_report_mentions_confirmed_or_likely():
    from io import StringIO

    from rich.console import Console

    from api_scanner.report import render
    from api_scanner.report.console import print_report

    result, _ = scan_site(make_site(True), active=True), None
    buf = StringIO()
    print_report(result, Console(file=buf, width=140, force_terminal=False))
    outputs = [buf.getvalue()] + [render(result, f) for f in ("json", "markdown", "sarif", "html")]
    for text in outputs:
        low = text.lower()
        assert "likely" not in low and "confirmed" not in low and "provisional" not in low and "coverage" not in low

@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl is needed to make a test certificate")
def test_tls_certificate_problem_and_mixed_content(tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "2",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)

    async def home(request):
        return web.Response(text='<html><head><title>t</title><script src="http://cdn.example.net/x.js"></script></head><body></body></html>',
                            content_type="text/html")

    async def go(insecure):
        app = web.Application()
        app.add_routes([web.get("/", home)])
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.load_cert_chain(str(crt), str(key))
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=sslctx)
        await site.start()
        try:
            base = f"https://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
            req = ScanRequest(target=base, options=ScanOptions(rate_probe=0),
                              client=ClientConfig(rps=0, insecure=insecure, timeout=10))
            return await run_scan(req)
        finally:
            await runner.cleanup()

    skipped = asyncio.run(go(True))
    assert "WEB-004" in ids(skipped, "confirmed")  # an https page loading a script over http
    assert "TLS-001" not in ids(skipped)  # certificate checks are skipped with --insecure
    assert any("--insecure" in n for n in skipped.notes)
    checked = asyncio.run(go(False))
    assert any("certificate verification failed" in e for f in checked.findings if f.check_id == "TLS-001" for e in f.evidence)
    assert "WEB-004" in ids(checked)  # the scan carried on after the bad certificate
    assert any("continued without verifying" in n for n in checked.notes)

def test_slow_first_answer_is_retried_once():
    calls = {"n": 0}

    async def home(request):
        calls["n"] += 1
        if calls["n"] == 1:
            await asyncio.sleep(2.5)
        return web.Response(text="<html><head><title>Slow</title></head><body>hello</body></html>", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", home)
    result = scan_site(app, client={"timeout": 1})
    assert result.mode["kind"] == "website" and result.requests_sent > 1

def test_anti_forgery_cookies_and_ad_scripts_are_not_flagged():
    async def home(request):
        html = ('<html><head><title>Dictionary</title><script src="https://cdn.cookielaw.org/consent.js"></script>'
                '<script src="https://securepubads.g.doubleclick.net/tag.js"></script></head><body>hi</body></html>')
        resp = web.Response(text=html, content_type="text/html")
        resp.set_cookie("XSRF-TOKEN", "abc")
        return resp

    app = web.Application()
    app.router.add_get("/", home)
    result = scan_site(app)
    assert "CFG-008" not in ids(result) and "WEB-005" not in ids(result)
