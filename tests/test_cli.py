import json

from click.testing import CliRunner

from api_scanner.cli import main

from .apps import issue_token, make_app
from .helpers import LiveServer

def run(args, **kw):
    return CliRunner().invoke(main, args, catch_exceptions=False, **kw)

def test_checks_and_explain_commands():
    out = run(["checks"]).output
    assert "BOLA-001" in out and "INJ-003" in out
    text = run(["explain", "JWT-003"]).output
    assert "CWE-1391" in text and "ATT&CK" in text and "CVSS 4.0 base" in text
    assert run(["explain", "NOPE-1"], ).exit_code != 0

def test_scan_writes_every_format_and_exit_codes(tmp_path):
    with LiveServer(make_app(True)) as server:
        token_a, token_b = issue_token("alice", True), issue_token("bob", True)
        common = ["scan", server.base, "--token", token_a, "--token-b", token_b, "--rps", "0", "-q"]
        out = tmp_path / "report"
        result = run(common + ["-f", "json", "-f", "sarif", "-f", "html", "-f", "markdown", "-o", str(out)])
        assert result.exit_code == 0, result.output  # --fail-on defaults to none
        for ext in ("json", "sarif", "html", "md"):
            assert (tmp_path / f"report.{ext}").stat().st_size > 500
        data = json.loads((tmp_path / "report.json").read_text())
        assert data["posture"]["rating"] == "Critical"
        assert token_a not in (tmp_path / "report.json").read_text()

        failing = run(common + ["--fail-on", "high"])
        assert failing.exit_code == 1
        assert "Rating:" in failing.output and "Weaknesses found" in failing.output

        single = tmp_path / "just.json"
        assert run(common + ["-f", "json", "-o", str(single)]).exit_code == 0 and single.exists()

def test_legacy_invocation_without_subcommand_still_works():
    with LiveServer(make_app(False)) as server:
        result = run([server.base, "--rps", "0", "-q", "--only", "EXP"])
        assert result.exit_code == 0
        assert "RATING: INFO" in result.output.upper()

def test_hardened_api_passes_a_ci_gate():
    with LiveServer(make_app(False)) as server:
        token = issue_token("alice", False)
        result = run(["scan", server.base, "--token", token, "--rps", "0", "-q", "--fail-on", "low"])
        assert result.exit_code == 0, result.output

def test_active_mode_needs_explicit_confirmation_without_a_terminal():
    with LiveServer(make_app(False)) as server:
        result = CliRunner().invoke(main, ["scan", server.base, "--active", "-q"])
        assert result.exit_code != 0 and "--yes" in result.output

def test_unreachable_spec_gives_a_clear_error(tmp_path):
    bad = tmp_path / "x.yaml"
    bad.write_text("hello: world\n")
    result = run(["scan", str(bad)])
    assert result.exit_code == 2 and "Cannot scan" in result.output

def test_no_arguments_without_a_terminal_shows_help():
    from click.testing import CliRunner
    from api_scanner.cli import main
    result = CliRunner().invoke(main, [])
    assert result.exit_code == 0
    assert "Commands:" in result.output and "interactive" in result.output

def test_banner_is_the_original_welcome_message():
    from api_scanner.cli import WELCOME_MESSAGE
    assert "Detect vulnerabilities in REST APIs and websites" in WELCOME_MESSAGE

def test_guided_prompt_refuses_options_typed_into_the_address(monkeypatch):
    from api_scanner import cli

    called = {}
    monkeypatch.setattr(cli.scan, "main", lambda args, prog_name: called.update(args=args))
    typed = "https://example.org/api --spec https://example.org/openapi.json --rps 2\nhttps://example.org/api\n\nn\n1\nn\n"
    result = CliRunner().invoke(cli.main, ["interactive"], input=typed)
    assert "Enter only the address here" in result.output
    assert called["args"][0] == "https://example.org/api"

def test_reports_default_to_downloads_with_the_date_in_the_name(tmp_path, monkeypatch):
    import re
    from datetime import datetime

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    with LiveServer(make_app(False)) as server:
        args = ["scan", server.base, "--rps", "0", "-q", "--only", "EXP", "-f", "html", "--offline"]
        assert run(args).exit_code == 0
        today = datetime.now().strftime("%d-%m-%Y")
        first = tmp_path / "Downloads" / f"report-{today}.html"
        assert first.stat().st_size > 500 and re.fullmatch(r"report-\d\d-\d\d-\d{4}\.html", first.name)
        assert run(args).exit_code == 0  # same day again: the first report is kept
        assert (tmp_path / "Downloads" / f"report-{today}-2.html").exists() and first.exists()
