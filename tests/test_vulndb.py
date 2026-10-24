"""Known vulnerability lookup, tested against local stand ins for OSV.dev and NVD (the real ones are never contacted)."""

import io
import json

import pytest
from aiohttp import web
from rich.console import Console

from api_scanner import vulndb
from api_scanner.report.console import print_report
from api_scanner.scoring import score_published

from .helpers import LiveServer, scan_app
from .site import make_site

JQUERY_ADVISORY = {
    "id": "GHSA-gxr4-xjj5-5px2", "aliases": ["CVE-2020-11022"], "summary": "Cross-site scripting in jQuery",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
    "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-gxr4-xjj5-5px2"}],
}
JETTY_ADVISORY = {
    "id": "GHSA-abcd-efgh-ijkl", "aliases": ["CVE-2024-0001"], "summary": "Jetty request smuggling",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
}
NO_VECTOR = {"id": "GHSA-none-none-none", "aliases": [], "summary": "No score published"}

def nvd_item(cve, vector, score, key="cvssMetricV31"):
    return {"cve": {"id": cve, "descriptions": [{"lang": "en", "value": f"{cve} description"}],
                    "metrics": {key: [{"cvssData": {"vectorString": vector, "baseScore": score}}]}}}

def make_databases():
    seen = []

    async def osv(request):
        body = await request.json()
        seen.append(("osv", body))
        package = body["package"]["name"]
        vulns = {"jquery": [JQUERY_ADVISORY, NO_VECTOR], "org.eclipse.jetty:jetty-server": [JETTY_ADVISORY]}.get(package, [])
        return web.json_response({"vulns": vulns})

    async def nvd(request):
        seen.append(("nvd", request.query_string))
        if "nginx:1.18.0" in request.query_string:
            return web.json_response({"vulnerabilities": [
                nvd_item("CVE-2021-23017", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
                nvd_item("CVE-2019-0001", "AV:N/AC:L/Au:N/C:P/I:N/A:N", 5.0, key="cvssMetricV2"),
                {"cve": {"id": "CVE-2000-0000", "descriptions": [], "metrics": {}}},
            ]})
        return web.json_response({"vulnerabilities": []})

    app = web.Application()
    app.router.add_post("/v1/query", osv)
    app.router.add_get("/rest/json/cves/2.0", nvd)
    return app, seen

def make_target():
    async def home(request):
        html = '<html><head><title>Shop</title><script src="/static/jquery-1.12.4.min.js"></script></head><body><a href="/about">About</a></body></html>'
        return web.Response(text=html, content_type="text/html", headers={"Server": "nginx/1.18.0 (Ubuntu)"})

    async def about(request):
        return web.Response(text="<html><body>About</body></html>", content_type="text/html", headers={"Server": "nginx/1.18.0 (Ubuntu)"})

    async def js(request):
        return web.Response(text="/* jquery */", content_type="application/javascript")

    app = web.Application()
    app.router.add_get("/", home)
    app.router.add_get("/about", about)
    app.router.add_get("/static/jquery-1.12.4.min.js", js)
    return app

def test_components_are_read_from_headers_and_script_names():
    found = vulndb.components_from_headers({
        "server: Jetty(9.4.53.v20231009)", "server: Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3",
        "x-powered-by: Express", "server: Microsoft-IIS/10.0", "framework hint: PHP"})
    labels = {c.label for c in found}
    assert {"Jetty 9.4.53.v20231009", "Apache httpd 2.4.49", "OpenSSL 1.1.1k", "PHP 7.4.3"} <= labels
    assert not any("IIS" in label or "Express" in label for label in labels)

    class Res:
        def __init__(self, url):
            self.url = url

    class Page:
        label = "GET /"
        resources = [Res("/js/jquery-3.3.1.min.js"), Res("https://cdn.example/ajax/libs/jquery/1.12.4/jquery.min.js"),
                     Res("https://x/bootstrap@4.1.0/dist/js/bootstrap.min.js"), Res("/js/jquery.min.js?ver=3.5.1"), Res("/js/app.js")]

    libs = {c.label for c in vulndb.components_from_pages([Page()])}
    assert libs == {"jQuery 3.3.1", "jQuery 1.12.4", "Bootstrap 4.1.0"}

def test_published_scores_are_read_for_cvss_4_3_and_2():
    assert score_published("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")[0] == 9.8
    assert score_published("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")[2] == "4.0"
    assert score_published("AV:N/AC:L/Au:N/C:P/I:P/A:P")[0] == 7.5

def test_parsers_skip_records_without_a_published_score():
    osv = vulndb.parse_osv({"vulns": [JQUERY_ADVISORY, NO_VECTOR]})
    assert [a.cve for a in osv] == ["CVE-2020-11022"] and osv[0].score == 6.1
    nvd = vulndb.parse_nvd({"vulnerabilities": [nvd_item("CVE-1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), {"cve": {"id": "CVE-2"}}]})
    assert [a.cve for a in nvd] == ["CVE-1"]

@pytest.fixture()
def databases(monkeypatch):
    app, seen = make_databases()
    with LiveServer(app) as live:
        monkeypatch.setattr(vulndb, "OSV_URL", live.base + "/v1/query")
        monkeypatch.setattr(vulndb, "NVD_URL", live.base + "/rest/json/cves/2.0")
        yield seen

def test_announced_versions_get_the_published_cvss(databases):
    result = scan_app(make_target(), vulnerable=False, tokens=False, options={"lookup": True})
    vulns = {f.title: f for f in result.findings if f.check_id == "VULN-001"}
    nginx = vulns["Known vulnerabilities in nginx 1.18.0"]
    assert nginx.cvss_score == 8.1 and nginx.cvss_version == "3.1" and nginx.severity.label == "High"
    assert any("CVE-2021-23017" in e for e in nginx.evidence) and any("CVE-2019-0001" in e for e in nginx.evidence)
    jquery = vulns["Known vulnerabilities in jQuery 1.12.4"]
    assert jquery.cvss_score == 6.1 and jquery.severity.label == "Medium" and "GHSA-gxr4-xjj5-5px2" in " ".join(jquery.evidence)
    assert result.posture.total >= 2 and result.posture.rating.label == "High"
    data = json.loads(json.dumps(result.to_dict()))
    assert any(f["cvss"]["version"] == "3.1" for f in data["findings"])

def test_only_product_and_version_leave_the_machine(databases):
    scan_app(make_target(), vulnerable=False, tokens=False, options={"lookup": True})
    assert databases
    for kind, payload in databases:
        text = json.dumps(payload) if kind == "osv" else payload
        assert "127.0.0.1" not in text and "about" not in text

def test_offline_makes_no_lookup_and_says_so(databases):
    result = scan_app(make_target(), vulnerable=False, tokens=False, options={"lookup": False})
    assert not databases
    assert not any(f.check_id == "VULN-001" for f in result.findings)
    assert any("--offline" in n for n in result.notes)

def test_unreachable_database_is_reported_and_the_scan_goes_on(monkeypatch):
    monkeypatch.setattr(vulndb, "OSV_URL", "http://127.0.0.1:9/v1/query")
    monkeypatch.setattr(vulndb, "NVD_URL", "http://127.0.0.1:9/rest/json/cves/2.0")
    result = scan_app(make_target(), vulnerable=False, tokens=False, options={"lookup": True})
    assert result.requests_sent > 0
    assert not any(f.check_id == "VULN-001" for f in result.findings)
    assert any("lookup is incomplete" in n for n in result.notes)

def test_evidence_reads_as_separate_sentences():
    from api_scanner.report.text import sentence

    assert sentence("a script from cdn.example.net is loaded without an integrity hash") == "A script from cdn.example.net is loaded without an integrity hash."
    assert sentence("X-Content-Type-Options: nosniff is missing") == "X-Content-Type-Options: nosniff is missing."
    assert sentence("Cookie JSESSIONID lacks SameSite") == "Cookie JSESSIONID lacks SameSite."
    assert sentence("http://x.test/ answered 200.") == "http://x.test/ answered 200."

def test_nothing_is_reported_without_a_cvss_score():
    result = scan_app(make_site(True), vulnerable=True, tokens=False)
    assert result.findings and all(f.scored for f in result.findings)
    assert sum(result.posture.by_severity.values()) == result.posture.total == len(result.findings)
    buf = io.StringIO()
    print_report(result, Console(file=buf, width=200, force_terminal=False), verbose=False)
    out = buf.getvalue().lower()
    assert "advice" not in out and "┃ cvss " in out
