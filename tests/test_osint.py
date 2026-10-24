"""OSINT: public sources, live checks of what they report, and the established tools, with the sources played by a local server."""

import stat
from pathlib import Path

from aiohttp import web

from api_scanner import osint

from .helpers import ids, scan_app
from .site import make_site

ENV_FILE = "DB_PASSWORD=hunter2hunter2\nAPI_KEY=abcdef123456\nDEBUG=false\nSECRET_KEY=zzzzzzzzzzzz\n" * 3
SOURCE_PATHS = ("/_crt", "/_cdx", "/_doh", "/_ct", "/_idb")
ZIP_FILE = b"PK\x03\x04" + b"\x00" * 400

def make_osint_site(dmarc=False, crt_ok=True):
    app = make_site(False)

    async def crt(request):
        if not crt_ok:
            raise web.HTTPBadGateway()
        return web.json_response([{"name_value": "dev.0.1\n*.mail.0.1\nold.0.1"}, {"name_value": "other.example.org"}])

    async def cdx(request):
        base = f"http://{request.host}"
        rows = [["original"]] + [[f"{base}{p}"] for p in (
            "/old/.env", "/backup/site.zip", "/gone.sql", "/old/page.php?id=1", "/static/logo.png", "/logout", "/about")]
        rows.append(["http://elsewhere.example/old/.env"])
        return web.json_response(rows)

    async def doh(request):
        name, kind = request.query["name"], request.query["type"]
        answers = {
            ("127.0.0.1", "A"): [{"type": 1, "data": "127.0.0.1"}],
            ("old.0.1", "A"): [{"type": 5, "data": "ghost-user.github.io."}],
            ("127.0.0.1", "MX"): [{"type": 15, "data": "10 mail.test."}],
            ("127.0.0.1", "TXT"): [{"type": 16, "data": '"v=spf1 -all"'}],
        }
        if dmarc:
            answers[("_dmarc.127.0.0.1", "TXT")] = [{"type": 16, "data": '"v=DMARC1; p=reject"'}]
        if (name, kind) in answers:
            return web.json_response({"Status": 0, "Answer": answers[(name, kind)]})
        return web.json_response({"Status": 3 if name.startswith("_dmarc") else 0})

    async def certspotter(request):
        return web.json_response([{"dns_names": ["shop.0.1", "dev.0.1"]}])

    async def idb(request):
        return web.json_response({"ports": [request.app["risky_port"], 80], "vulns": ["CVE-2020-0001"]})

    async def old_env(request):
        return web.Response(text=ENV_FILE, content_type="text/plain")

    async def site_zip(request):
        return web.Response(body=ZIP_FILE, content_type="application/zip")

    async def robots(request):
        return web.Response(text="User-agent: *\nDisallow: /secret-admin/\nDisallow: /*.pdf$\nDisallow: /\n", content_type="text/plain")

    async def old_page(request):
        return web.Response(text="<html><head><title>Old</title></head><body>old</body></html>", content_type="text/html")

    app["risky_port"] = 0
    app.add_routes([web.get("/_crt", crt), web.get("/_cdx", cdx), web.get("/_doh", doh), web.get("/_ct", certspotter),
                    web.get("/_idb/{ip}", idb), web.get("/old/.env", old_env),
                    web.get("/backup/site.zip", site_zip), web.get("/robots.txt", robots), web.get("/secret-admin/", old_page), web.get("/old/page.php", old_page)])
    return app

def scan_with_sources(monkeypatch, lookup=True, options=None, **kw):
    app = make_osint_site(**kw)
    monkeypatch.setattr(osint, "is_public_name", lambda host: True)
    monkeypatch.setattr(osint.shutil, "which", lambda name: None)  # no real tools on this machine may change the result

    def hook(req, base):
        port = int(base.rsplit(":", 1)[1])
        app["risky_port"] = port
        monkeypatch.setitem(osint.RISKY_PORTS, port, "Test database")
        for key, path in (("crtsh", "/_crt"), ("certspotter", "/_ct"), ("archive", "/_cdx"), ("doh", "/_doh"), ("internetdb", "/_idb")):
            monkeypatch.setitem(osint.ENDPOINTS, key, base + path)
        for key in ("hackertarget", "otx", "anubis", "urlscan", "rdap", "doh_backup"):
            monkeypatch.setitem(osint.ENDPOINTS, key, base + "/_down")  # unavailable, as when a source is blocked

    result = scan_app(app, vulnerable=False, tokens=False, options={"lookup": lookup, **(options or {})}, request_hook=hook)
    return result, app

def test_old_sensitive_addresses_that_still_answer_are_reported(monkeypatch):
    result, app = scan_with_sources(monkeypatch)
    found = [f for f in result.findings if f.check_id == "OSINT-001"]
    assert found and found[0].scored and found[0].cvss_score >= 7
    text = " ".join(found[0].evidence)
    assert "/old/.env" in text and "/backup/site.zip" in text and "gone.sql" not in text and "elsewhere" not in text
    assert "hunter2" not in text

def test_archived_pages_are_tested_and_subdomains_are_only_listed(monkeypatch):
    result, app = scan_with_sources(monkeypatch)
    assert any(h.startswith("/old/page.php?id=") for h in app["hits"])
    assert "/logout" not in app["hits"] and "/static/logo.png" not in app["hits"]
    assert any("4 subdomain(s)" in n and "not scanned" in n for n in result.notes)
    assert result.mode["osint"]["subdomains"] == ["dev.0.1", "mail.0.1", "old.0.1", "shop.0.1"]

def test_private_addresses_in_public_dns_are_reported(monkeypatch):
    real_resolve = osint._resolve

    async def resolve(session, name):
        host = await real_resolve(session, name)
        if name == "dev.0.1":
            host.ips, host.resolves = ["10.12.1.19"], True
        return host

    monkeypatch.setattr(osint, "_resolve", resolve)
    result, _ = scan_with_sources(monkeypatch)
    finding = next(f for f in result.findings if f.check_id == "OSINT-005")
    assert finding.scored and "dev.0.1 -> 10.12.1.19" in " ".join(finding.evidence) and finding.severity.label == "Low"

def test_no_private_addresses_means_no_finding(monkeypatch):
    result, _ = scan_with_sources(monkeypatch)
    assert "OSINT-005" not in ids(result)

def test_mail_records_are_collected_but_not_a_scan_finding(monkeypatch):
    result, _ = scan_with_sources(monkeypatch)
    assert "OSINT-002" not in ids(result) and result.mode["osint"]["mail"]["dmarc"] is False

def test_a_source_that_fails_is_left_out_and_the_scan_goes_on(monkeypatch):
    result, _ = scan_with_sources(monkeypatch, crt_ok=False)
    assert any("crt.sh" in n and "did not answer" in n for n in result.notes) and sum("did not answer" in n for n in result.notes) == 1
    assert result.mode["osint"]["subdomains"] == ["dev.0.1", "shop.0.1"]  # Cert Spotter still answered
    assert "OSINT-001" in ids(result)

def test_offline_sends_nothing_to_public_sources(monkeypatch):
    result, app = scan_with_sources(monkeypatch, lookup=False)
    assert not any(h.startswith(SOURCE_PATHS) for h in app["hits"])
    assert not any(f.check_id.startswith("OSINT") for f in result.findings)
    assert result.mode["osint"] is None

def test_no_osint_option_asks_nobody(monkeypatch):
    result, app = scan_with_sources(monkeypatch, options={"osint": False})
    assert not any(h.startswith(SOURCE_PATHS) for h in app["hits"]) and result.mode["osint"] is None

def test_local_and_internal_names_are_never_sent_to_public_sources():
    for host in ("127.0.0.1", "localhost", "intranet", "printer.local", "10.0.0.5", "::1", "api.corp"):
        assert not osint.is_public_name(host)
    assert osint.is_public_name("www.example.com")

def test_registrable_domain_and_shared_platforms():
    assert osint.registrable("dictionary.cambridge.org") == ("cambridge.org", False)
    assert osint.registrable("www.bbc.co.uk") == ("bbc.co.uk", False)
    assert osint.registrable("macbuildssys.github.io") == ("macbuildssys.github.io", True)
    assert osint.registrable("a.b.macbuildssys.github.io") == ("macbuildssys.github.io", True)

def test_extra_pages_prefer_addresses_with_parameters_and_skip_static_and_risky():
    data = osint.Osint(archived=["https://x.test/a.png", "https://x.test/logout", "https://x.test/news", "https://x.test/s?q=1",
                                 "https://x.test/known", "https://x.test/p.php", "https://x.test/files.zip"])
    pages = osint.extra_pages(data, {"/known"})
    assert pages == ["https://x.test/s?q=1", "https://x.test/news", "https://x.test/p.php"]
    assert osint.params_of(pages[0]) == {"q": "1"}

def test_a_second_source_fills_in_when_the_first_is_down(monkeypatch):
    result, _ = scan_with_sources(monkeypatch, crt_ok=False)
    assert result.mode["osint"]["sources"]["Cert Spotter"] == 2 and "crt.sh" not in result.mode["osint"]["sources"]

def test_robots_txt_paths_are_leads_and_wildcards_are_not(monkeypatch):
    result, app = scan_with_sources(monkeypatch)
    assert result.mode["osint"]["robots_paths"] == ["/secret-admin/"]
    assert "/secret-admin/" in app["hits"]

def test_open_risky_port_is_reported_only_after_a_connection_succeeds(monkeypatch):
    result, _ = scan_with_sources(monkeypatch)
    finding = next(f for f in result.findings if f.check_id == "OSINT-004")
    assert finding.scored and "Test database" in " ".join(finding.evidence) and "accepted a connection" in " ".join(finding.evidence)
    assert result.mode["osint"]["open_risky_ports"][0][2] == "Test database"

def test_port_that_the_database_lists_but_refuses_is_not_reported(monkeypatch):
    app_holder = {}
    real = osint._connects

    async def refuse(ip, port):
        return False

    monkeypatch.setattr(osint, "_connects", refuse)
    result, _ = scan_with_sources(monkeypatch)
    assert "OSINT-004" not in ids(result)
    assert result.mode["osint"]["open_ports"]["127.0.0.1"]
    monkeypatch.setattr(osint, "_connects", real)
    assert app_holder == {}

def test_subdomain_pointing_to_an_unclaimed_service_is_reported(monkeypatch):
    async def probe(session, name):
        return {"status": 404, "server": "GitHub.com", "title": "", "location": "", "body": "<p>There isn't a GitHub Pages site here.</p>"} \
            if name == "old.0.1" else {}

    monkeypatch.setattr(osint, "_probe", probe)
    result, _ = scan_with_sources(monkeypatch)
    finding = next(f for f in result.findings if f.check_id == "OSINT-003")
    assert finding.scored and "GitHub Pages" in " ".join(finding.evidence) and "old.0.1" in " ".join(finding.evidence)
    assert any("T1584.001" in a for a in finding.attack)

def test_subdomain_pointing_to_a_service_that_still_serves_content_is_not_reported(monkeypatch):
    real_resolve = osint._resolve

    async def resolve(session, name):
        host = await real_resolve(session, name)
        if name == "old.0.1":
            host.ips, host.resolves = ["192.0.2.1"], True
        return host

    monkeypatch.setattr(osint, "_resolve", resolve)
    async def probe(session, name):
        return {"status": 200, "server": "GitHub.com", "title": "Hello", "location": "", "body": "<p>Welcome to my site</p>"} if name == "old.0.1" else {}

    monkeypatch.setattr(osint, "_probe", probe)
    result, _ = scan_with_sources(monkeypatch)
    assert "OSINT-003" not in ids(result)

def test_takeover_fingerprints_need_the_provider_in_the_cname():
    assert osint._takeover_match("ghost-user.github.io")[1] == "GitHub Pages"
    assert osint._takeover_match("example.cloudflare.net") is None

def test_installed_tools_add_names_and_addresses(monkeypatch, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "subfinder").write_text("#!/bin/sh\necho hidden.0.1\necho mail.0.1\necho unrelated.example.org\n")
    (bin_dir / "gau").write_text("#!/bin/sh\necho http://127.0.0.1/from-gau.php?x=1\n")
    for f in bin_dir.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    app = make_osint_site()
    monkeypatch.setattr(osint, "is_public_name", lambda host: True)
    monkeypatch.setenv("PATH", str(bin_dir) + ":" + __import__("os").environ["PATH"])
    data = __import__("asyncio").run(osint.gather("127.0.0.1", probe=False))
    assert "hidden.0.1" in data.subdomains and "unrelated.example.org" not in data.subdomains
    assert data.tools_used == ["subfinder", "gau"]
    assert "http://127.0.0.1/from-gau.php?x=1" in data.archived
    assert app is not None

def test_a_missing_tool_is_simply_not_used(monkeypatch):
    monkeypatch.setattr(osint.shutil, "which", lambda name: None)
    data = __import__("asyncio").run(osint.gather("example.invalid.test", probe=False))
    assert data.tools_used == []

def test_api_paths_in_scripts():
    text = "fetch('/api/items?limit=5'); x.get(`/api/users/${id}`); const u='https://shop.test/v2/orders'; load('/static/a.js'); a(\"/graphql\")"
    assert osint.api_paths_in_script(text, "shop.test") == ["/api/items", "/graphql", "/v2/orders"]
    assert osint.api_paths_in_script("'/api/x'", "shop.test") == ["/api/x"]

def test_script_paths_that_answer_become_endpoints_and_those_that_do_not_are_dropped():
    from .helpers import scan_app as run

    hits = []

    @web.middleware
    async def mw(request, handler):
        hits.append(request.path_qs)
        return await handler(request)

    async def home(request):
        return web.Response(text='<html><head><title>x</title><script src="/app.js"></script></head><body><a href="/about">a</a></body></html>',
                            content_type="text/html")

    async def script(request):
        return web.Response(text="fetch('/api/items'); fetch('/api/ghost'); fetch('/api/orders')", content_type="application/javascript")

    async def items(request):
        return web.json_response([{"id": 1}])

    app = web.Application(middlewares=[mw])
    app.add_routes([web.get("/", home), web.get("/app.js", script), web.get("/api/items", items), web.get("/api/orders", items),
                    web.get("/about", home)])
    result = run(app, vulnerable=False, tokens=False, options={"lookup": False, "osint": True, "browser": False})
    assert any("found in a script" in n or "found in the site's scripts" in n for n in result.notes)
    assert "/api/items" in hits and "/api/orders" in hits

def test_console_lists_only_other_hosts_that_answer_200_and_no_notes():
    import io

    from rich.console import Console

    from api_scanner.report.console import print_report

    info = {"domain": "example.com", "hosts": [
        {"name": "example.com", "ips": ["192.0.2.1"], "cname": "", "resolves": True, "status": 200, "title": "Home", "server": "", "location": "", "sources": []},
        {"name": "ok.example.com", "ips": ["192.0.2.2"], "cname": "", "resolves": True, "status": 200, "title": "Blog", "server": "", "location": "", "sources": []},
        {"name": "moved.example.com", "ips": ["192.0.2.3"], "cname": "", "resolves": True, "status": 301, "title": "", "server": "", "location": "", "sources": []},
        {"name": "dead.example.com", "ips": [], "cname": "", "resolves": False, "status": None, "title": "", "server": "", "location": "", "sources": []}]}
    from .helpers import scan_app

    result = scan_app(make_site(False), vulnerable=False, tokens=False)
    result.mode["osint"] = info
    result.target = "https://example.com"
    result.notes.append("A NOTE LINE")
    buf = io.StringIO()
    print_report(result, Console(file=buf, width=140))
    out = buf.getvalue()
    assert "ok.example.com" in out and "moved.example.com" not in out and "dead.example.com" not in out and "A NOTE LINE" not in out
