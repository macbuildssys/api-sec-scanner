"""End to end scans against the vulnerable app, the hardened twin and edge case servers."""

import json

import pytest

from api_scanner.models import Severity
from api_scanner.report import render
from api_scanner.scoring import AssetProfile

from .apps import make_app, make_catchall_app
from .helpers import ids, scan_app

CONFIRMED_SAFE_MODE = {
    "AUTH-001", "BFLA-001", "BOLA-001", "BOPLA-001", "CFG-001", "CFG-003", "CFG-007", "EXP-001", "EXP-002", "EXP-003", "EXP-005",
    "JWT-001", "JWT-002", "JWT-003", "RES-001", "BFLA-003", "CFG-008", "INV-001", "JWT-004", "RES-002",
}
CONFIRMED_ACTIVE = {"INJ-001", "INJ-002", "INJ-003", "INJ-004", "INJ-005", "INJ-006", "SSRF-001", "SSRF-002"}

@pytest.fixture(scope="module")
def vulnerable_safe():
    return scan_app(make_app(True), vulnerable=True)

@pytest.fixture(scope="module")
def vulnerable_full():
    return scan_app(make_app(True), vulnerable=True, active=True, mutating=True, callback=True)

@pytest.fixture(scope="module")
def hardened_full():
    return scan_app(make_app(False), vulnerable=False, active=True, mutating=True, callback=True)

def test_safe_mode_finds_planted_flaws_with_proof(vulnerable_safe):
    assert CONFIRMED_SAFE_MODE <= ids(vulnerable_safe, "confirmed")

def test_safe_mode_sends_no_attack_payloads_and_no_state_changes():
    app = make_app(True)
    scan_app(app, vulnerable=True)
    methods = {m for m, _ in app["seen"]}
    assert methods <= {"GET", "HEAD", "OPTIONS", "TRACE", "POST"}  # POST only for the read only GraphQL introspection
    posts = [p for m, p in app["seen"] if m == "POST"]
    assert set(posts) <= {"/graphql", "/api/graphql", "/v1/graphql", "/query"}  # the introspection probes
    assert not any("'" in p or "sleep" in p.lower() for _, p in app["seen"])

def test_active_mode_proves_injection_and_ssrf(vulnerable_full):
    assert CONFIRMED_ACTIVE <= ids(vulnerable_full, "confirmed")
    assert "BOPLA-002" in ids(vulnerable_full, "confirmed")
    assert "RES-003" in ids(vulnerable_full, "confirmed")

def test_hardened_app_has_no_scored_weaknesses(hardened_full):
    unexpected = [(f.check_id, f.operations[:2], f.evidence[:1]) for f in hardened_full.findings]
    assert unexpected == []
    assert hardened_full.posture.rating == Severity.INFO
    assert hardened_full.posture.exposure_index == 0.0

def test_severity_ordering_and_priorities(vulnerable_full):
    sev = [f.severity for f in vulnerable_full.findings]
    assert sev == sorted(sev, reverse=True)
    by_id = {f.check_id: f for f in vulnerable_full.findings}
    assert by_id["EXP-001"].severity == Severity.CRITICAL and by_id["EXP-001"].priority.value == "Act"
    assert by_id["BFLA-001"].priority.value == "Act"
    # public injection point needs no login, so the privilege requirement stays at None
    assert "PR:N" in by_id["INJ-003"].cvss_vector
    # a protected operation scores lower because it needs a login first
    assert by_id["BOLA-001"].cvss_score < by_id["INJ-001"].cvss_score
    for f in vulnerable_full.findings:
        assert f.cwe and f.operations
        assert f.cvss_vector.startswith("CVSS:4.0/") and f.cvss_score is not None

def test_findings_map_to_owasp_cwe_and_attack(vulnerable_full):
    by_id = {f.check_id: f for f in vulnerable_full.findings}
    bola = by_id["BOLA-001"]
    assert bola.owasp_api == "API1:2023" and bola.owasp_web == "A01:2025"
    assert any(c.startswith("CWE-639") for c in bola.cwe)
    assert any(a.startswith("T1190 Exploit Public-Facing Application") for a in bola.attack)
    assert by_id["INJ-001"].owasp_api is None and by_id["INJ-001"].owasp_web == "A05:2025"
    assert any(a.startswith("T1552.001") for a in by_id["EXP-001"].attack)

def test_secrets_never_reach_the_report(vulnerable_full):
    dump = json.dumps(vulnerable_full.to_dict())
    assert "Bearer eyJ" not in dump
    assert "hunter2" not in dump  # values from the exposed .env file are not copied
    assert "$2b$12$KIXQ" not in dump  # password hashes are masked

def test_profile_changes_scores_not_findings(vulnerable_safe):
    public = AssetProfile(name="catalog", data_classes=["public"], availability="low", mission_impact="low", defined=True)
    lowered = scan_app(make_app(True), vulnerable=True, profile=public)
    assert ids(lowered) == ids(vulnerable_safe)
    old = {f.check_id: f.cvss_score for f in vulnerable_safe.findings if f.cvss_score}
    new = {f.check_id: f.cvss_score for f in lowered.findings if f.cvss_score}
    assert all(new[k] <= old[k] for k in new) and any(new[k] < old[k] for k in new)

def test_jwt_modes_are_told_apart():
    only_none = scan_app(make_app(True, jwt_mode="none_alg"), vulnerable=True)
    assert "JWT-001" in ids(only_none, "confirmed") and "JWT-002" not in ids(only_none)
    strict = scan_app(make_app(True, jwt_mode="strict"), vulnerable=True)
    assert not ({"JWT-001", "JWT-002"} & ids(strict))
    assert "JWT-003" in ids(strict, "confirmed")  # still signed with a guessable secret

def test_without_two_identities_bola_is_not_claimed_and_the_report_says_so():
    result = scan_app(make_app(True), vulnerable=True, two=False)
    assert "BOLA-001" not in ids(result)
    assert any("two identities" in n for n in result.notes)

def test_without_a_token_protected_operations_are_still_tested():
    result = scan_app(make_app(True), vulnerable=True, tokens=False)
    assert "AUTH-001" in ids(result, "confirmed")

def test_catch_all_server_does_not_create_false_exposure_findings():
    result = scan_app(make_catchall_app(), vulnerable=False, tokens=False)
    assert not any(f.check_id.startswith("EXP") for f in result.findings)
    assert any("No OpenAPI document" in n for n in result.notes)

def test_only_and_skip_filters():
    only = scan_app(make_app(True), vulnerable=True, options={"only": ["EXP"]})
    assert {i[:3] for i in ids(only)} == {"EXP"}
    skipped = scan_app(make_app(True), vulnerable=True, options={"skip": ["EXP", "JWT"]})
    assert not any(i.startswith(("EXP", "JWT")) for i in ids(skipped))

def test_request_budget_is_enforced():
    app = make_app(True)
    result = scan_app(app, vulnerable=True, client={"max_requests": 25})
    assert result.requests_sent <= 25
    assert len(app["seen"]) <= 25

def test_out_of_scope_hosts_are_never_contacted():
    app = make_app(True)

    def point_spec_elsewhere(req, base):
        req.base_url = None

    result = scan_app(app, vulnerable=True, request_hook=point_spec_elsewhere)
    assert result.requests_sent > 0  # sanity
    from api_scanner.http import Blocked, ClientConfig, ScanClient
    import asyncio

    async def probe():
        async with ScanClient(ClientConfig(allowed_hosts={"127.0.0.1"})) as c:
            with pytest.raises(Blocked):
                await c.request("GET", "http://example.org/")
            with pytest.raises(Blocked):
                await c.request("DELETE", "http://127.0.0.1:9/x")  # mutating needs the opt in

    asyncio.run(probe())

def test_all_report_formats_render(vulnerable_full):
    for fmt in ("json", "markdown", "sarif", "html"):
        text = render(vulnerable_full, fmt)
        assert len(text) > 500
    sarif = json.loads(render(vulnerable_full, "sarif"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= rule_ids
    assert any(r["properties"].get("security-severity") for r in run["results"])
    data = json.loads(render(vulnerable_full, "json"))
    assert data["standards"]["MITRE ATT&CK"].startswith("Enterprise v20")
    assert data["posture"]["rating"] == "Critical"
    md = render(vulnerable_full, "markdown")
    assert "## Weaknesses" in md

def test_html_report_escapes_content_from_the_target(vulnerable_full):
    vulnerable_full.findings[0].evidence.append("<script>alert(1)</script>")
    html = render(vulnerable_full, "html")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

def test_address_that_is_itself_the_openapi_document_is_used_as_the_spec():
    app = make_app(True)
    plain = scan_app(app, vulnerable=True)
    direct = scan_app(make_app(True), vulnerable=True, target_path="/openapi.json")
    assert direct.mode["kind"] == "api"
    assert direct.endpoints_tested == plain.endpoints_tested
    assert not any("No OpenAPI document was found" in n for n in direct.notes)
    assert any("is an OpenAPI document" in n for n in direct.notes)
    assert ids(plain) == ids(direct)

def test_spec_is_found_next_to_the_address_that_was_given():
    from aiohttp import web

    parent = web.Application()
    parent.add_subapp("/api/v3/", make_app(True))
    result = scan_app(parent, vulnerable=True, tokens=False, target_path="/api/v3")
    assert any("Found the OpenAPI document at" in n and "/api/v3/openapi.json" in n for n in result.notes)

def test_login_and_logout_operations_are_not_reported_as_missing_authentication():
    from aiohttp import web

    spec = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
        "/user/login": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/user/logout": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/user/profile": {"get": {"responses": {"200": {"description": "ok"}}}}}}

    async def spec_h(request):
        return web.json_response(spec)

    async def ok(request):
        return web.json_response({"message": "hello there, this is a real answer"})

    app = web.Application()
    app.router.add_get("/openapi.json", spec_h)
    for path in ("/user/login", "/user/logout", "/user/profile"):
        app.router.add_get(path, ok)
    result = scan_app(app, vulnerable=False, tokens=False, options={"only": ["AUTH-001"]})
    auth = [f for f in result.findings if f.check_id == "AUTH-001"]
    assert auth and all("login" not in op and "logout" not in op for op in auth[0].operations)
    assert any("profile" in op for op in auth[0].operations)

def test_throttling_burst_is_skipped_when_a_gentle_rate_was_asked_for():
    result = scan_app(make_app(True), vulnerable=True, tokens=False, options={"only": ["RES-002"]}, client={"rps": 5})
    assert not any(f.check_id in ("RES-002", "RES-003") for f in result.findings)
    assert any("--rps" in n and "skipped" in n for n in result.notes)

def test_a_number_that_appears_by_chance_is_not_template_injection():
    from aiohttp import web

    async def games(request):
        # shows 8281 whenever the parameter is not the plain default, but never evaluates anything
        return web.Response(text="<html><title>g</title><a href=\"/?trk=a\">x</a>" + ("items: 8281" if request.query.get("trk", "test") not in ("test", "a", "1") else "items: 1") + "</html>",
                            content_type="text/html")

    app = web.Application()
    app.add_routes([web.get("/", games)])
    result = scan_app(app, vulnerable=False, tokens=False, active=True, options={"browser": False})
    assert "INJ-005" not in ids(result)
