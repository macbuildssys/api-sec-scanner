"""Command line interface."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from . import __version__
from .context import ScanOptions
from .engine import ScanRequest, run_scan
from .http import ClientConfig, Identity
from .knowledge import CATALOG, attack_label, cwe_label
from .models import Severity
from .report import FORMATS, extension, render
from .report.console import print_report
from .scoring import AssetProfile, score_vector
from .spec import SpecError

NOTICE = "Only scan APIs you own or have written permission to test."

WELCOME_MESSAGE = r"""
__        __   _                            _
\ \      / /__| | ___ ___  _ __ ___   ___  | |
 \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | |
  \ V  V /  __/ | (_| (_) | | | | | |  __/ |_|
   \_/\_/ \___|_|\___\___/|_| |_| |_|\___| (_)
   Detect vulnerabilities in REST APIs and websites
"""

_banner_shown = False
_notice_shown = False

def show_banner(force: bool = False) -> None:
    """Welcome panel on stderr, so piped reports stay clean. Only on a real terminal, once per run."""
    global _banner_shown
    if _banner_shown or (not force and not sys.stderr.isatty()):
        return
    _banner_shown = True
    console = Console(stderr=True)
    console.print(Panel(Align.center(Text(WELCOME_MESSAGE, style="bold blue")), title="[bold blue]REST API and Websites[/bold blue]",
                        subtitle=f"v{__version__}", border_style="blue"))

class DefaultGroup(click.Group):
    """Lets `api-sec-scanner https://host` work like `api-sec-scanner scan https://host`."""

    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["scan"] + list(args)
        elif not args:
            args = ["interactive"] if (sys.stdin.isatty() and sys.stdout.isatty()) else ["--help"]
        return super().parse_args(ctx, args)

def _parse_headers(items) -> dict:
    headers = {}
    for item in items:
        if ":" not in item:
            raise click.BadParameter(f"header must look like 'Name: value', got {item!r}")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers

def _identity(name: str, token: Optional[str], headers: dict) -> Optional[Identity]:
    merged = dict(headers)
    if token:
        merged["Authorization"] = token if token.lower().startswith(("bearer ", "basic ")) else f"Bearer {token}"
    return Identity(name, merged) if merged else None

@click.group(cls=DefaultGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="api-sec-scanner")
def main():
    """Evidence based API security scanner.

    \b
    Scans APIs and websites. Scores findings with CVSS 4.0, maps them to the OWASP API Security
    Top 10 (2023), OWASP Top 10 (2025), CWE and MITRE ATT&CK, and only reports what it saw in a
    response. Run `api-sec-scanner scan --help` for the options.
    """

@main.command()
@click.argument("target", required=False)
@click.option("--mode", type=click.Choice(["auto", "api", "website"]), default="auto", show_default=True,
              help="auto: use the OpenAPI document if there is one, otherwise crawl the site. api: never crawl. website: always crawl.")
@click.option("--max-pages", default=25, show_default=True, help="Most pages to fetch in website mode.")
@click.option("--browser/--no-browser", default=None,
              help="Load pages in a headless Chrome, Chromium or Edge. Default: used by itself when the site is built with JavaScript and one is installed.")
@click.option("--spec", help="OpenAPI document (URL or file). Found automatically when possible.")
@click.option("--base-url", help="Override the server URL from the specification.")
@click.option("--token", envvar="API_SCANNER_TOKEN", help="Bearer token for the main identity (or set API_SCANNER_TOKEN).")
@click.option("--token-b", envvar="API_SCANNER_TOKEN_B", help="Bearer token for a SECOND user, same privilege. Enables proven BOLA tests.")
@click.option("--header", "-H", "headers", multiple=True, help="Header for the main identity, for example 'X-API-Key: abc'. Repeatable.")
@click.option("--header-b", "headers_b", multiple=True, help="Header for the second identity. Repeatable.")
@click.option("--owned-id", help="An object id that belongs to the main identity (improves BOLA proof).")
@click.option("--active", is_flag=True, help="Send attack payloads: injection, SSRF, traversal. Read only methods.")
@click.option("--allow-mutating", is_flag=True, help="Also send POST, PUT, PATCH, DELETE. May create or change data.")
@click.option("--callback-host", help="host[:port] the TARGET can reach, to prove SSRF with a callback. Needs --active.")
@click.option("--callback-bind", default="0.0.0.0", show_default=True, help="Address the callback listener binds to.")
@click.option("--profile", "profile_path", type=click.Path(exists=True, dir_okay=False), help="Asset profile YAML (data classes, availability, mission impact).")
@click.option("--rps", default=10.0, show_default=True, help="Maximum requests per second.")
@click.option("--concurrency", default=5, show_default=True, help="Parallel requests.")
@click.option("--max-requests", default=2000, show_default=True, help="Hard stop after this many requests.")
@click.option("--timeout", default=15.0, show_default=True, help="Seconds per request.")
@click.option("--rate-probe", default=40, show_default=True, help="Burst size for the throttling test. 0 disables it.")
@click.option("--osint/--no-osint", default=True, show_default=True,
              help="Ask public sources (certificate logs, the web archive, DNS) about the target. Only the site name is sent.")
@click.option("--offline", is_flag=True, help="Do not look up announced software versions in the public advisory databases (OSV.dev and NVD).")
@click.option("--insecure", is_flag=True, help="Do not verify TLS certificates.")
@click.option("--scope", "extra_scope", multiple=True, help="Additional host that may be contacted. Repeatable.")
@click.option("--only", multiple=True, help="Run only checks whose id starts with this, e.g. BOLA or INJ-001. Repeatable.")
@click.option("--skip", multiple=True, help="Skip checks with this id. Repeatable.")
@click.option("--format", "-f", "formats", multiple=True, type=click.Choice(["console"] + list(FORMATS)), help="Report format. Repeatable. Default: console.")
@click.option("--output", "-o", type=click.Path(), help="Where to write non console reports. With several formats the extension is added. Default: your Downloads folder, as report-DD-MM-YYYY.")
@click.option("--fail-on", type=click.Choice(["none", "low", "medium", "high", "critical"]), default="none", show_default=True,
              help="Exit with code 1 when a weakness is at least this severe.")
@click.option("--yes", "-y", is_flag=True, help="Confirm you are authorized (needed for --active and --allow-mutating without a terminal).")
@click.option("--quiet", "-q", is_flag=True, help="No progress bar.")
@click.option("--verbose", "-v", is_flag=True, help="Show CVSS vectors and tracebacks.")
def scan(target, mode, max_pages, browser, spec, base_url, token, token_b, headers, headers_b, owned_id, active, allow_mutating, callback_host, callback_bind,
         profile_path, rps, concurrency, max_requests, timeout, rate_probe, osint, offline, insecure, extra_scope, only, skip, formats, output,
         fail_on, yes, quiet, verbose):
    """Scan an API or a website. TARGET is a URL (https://api.example.com or https://www.example.com) or an OpenAPI file."""
    console = Console(stderr=False)
    show_banner()
    if not target:
        if not sys.stdin.isatty():
            raise click.UsageError("give a URL or an OpenAPI file to scan")
        target = click.prompt("API URL or OpenAPI file")
    global _notice_shown
    if not _notice_shown:
        console.print(f"[dim]{NOTICE}[/dim]")
        _notice_shown = True

    if (active or allow_mutating) and not yes:
        if not sys.stdin.isatty():
            raise click.UsageError("--active and --allow-mutating need --yes when there is no terminal")
        what = "attack payloads" + (" and state changing requests" if allow_mutating else "")
        if not click.confirm(f"This will send {what} to {target}. Do you have permission to test it?", default=False):
            raise click.Abort()

    try:
        profile = AssetProfile.load(profile_path)
    except (ValueError, OSError) as exc:
        raise click.UsageError(str(exc))

    request = ScanRequest(
        target=target,
        spec=spec,
        base_url=base_url,
        identity=_identity("user-a", token, _parse_headers(headers)),
        identity_b=_identity("user-b", token_b, _parse_headers(headers_b)),
        options=ScanOptions(active=active, allow_mutating=allow_mutating, callback_host=callback_host, callback_bind=callback_bind,
                            rate_probe=rate_probe, only=list(only), skip=list(skip), owned_object_id=owned_id,
                            web={"auto": None, "api": False, "website": True}[mode], max_pages=max_pages, browser=browser, lookup=not offline, osint=osint and not offline),
        client=ClientConfig(timeout=timeout, rps=rps, concurrency=concurrency, max_requests=max_requests, insecure=insecure),
        profile=profile,
        extra_scope=list(extra_scope),
    )

    show_progress = not quiet and sys.stderr.isatty()
    try:
        if show_progress:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), transient=True, console=Console(stderr=True)) as bar:
                task = bar.add_task("Scanning", total=None)

                def on_progress(done: int, total: int, label: str) -> None:
                    bar.update(task, total=total, completed=done, description=f"Scanning {label[:48]}")

                result = asyncio.run(run_scan(request, on_progress))
        else:
            result = asyncio.run(run_scan(request))
    except SpecError as exc:
        console.print(f"[red]Cannot scan: {exc}[/red]")
        sys.exit(2)
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as exc:  # unexpected: show a short message, full traceback with -v
        console.print(f"[red]Scan failed: {type(exc).__name__}: {exc}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(2)

    formats = list(formats) or ["console"]
    files = [f for f in formats if f != "console"]
    if "console" in formats:
        print_report(result, console, verbose)
    if files and not output:
        output = str(default_report_base(files))
    for fmt in files:
        path = _report_path(output, fmt, len(files))
        path.write_text(render(result, fmt), encoding="utf-8")
        console.print(f"[green]Wrote {fmt} report to {path}[/green]")

    sys.exit(_exit_code(result, fail_on))

def downloads_folder() -> Path:
    """The user's Downloads folder (from the desktop settings when available), created if missing."""
    home = Path.home()
    folder = home / "Downloads"
    exe = shutil.which("xdg-user-dir")
    if exe:
        try:
            found = subprocess.run([exe, "DOWNLOAD"], capture_output=True, text=True, timeout=5).stdout.strip()
            if found and Path(found) != home:
                folder = Path(found)
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        folder.mkdir(parents=True, exist_ok=True)
        return folder
    except OSError:
        return Path.cwd()

def default_report_base(formats) -> Path:
    """Downloads/report-DD-MM-YYYY, with -2, -3 and so on when a report of that day already exists."""
    folder = downloads_folder()
    stem = f"report-{datetime.now().strftime('%d-%m-%Y')}"
    number = 1
    while True:
        name = stem if number == 1 else f"{stem}-{number}"
        if not any((folder / f"{name}.{extension(fmt)}").exists() for fmt in formats):
            return folder / name
        number += 1

def _report_path(output: str, fmt: str, count: int) -> Path:
    """One format and a name with an extension: use it as is. Otherwise add the extension."""
    base = Path(output)
    if count == 1 and base.suffix:
        return base
    return base.with_name(f"{base.stem if base.suffix else base.name}.{extension(fmt)}")

def _exit_code(result, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity.parse(fail_on)
    return 1 if any(f.severity >= threshold for f in result.findings) else 0

@main.command()
def interactive():
    """Guided scan: asks a few questions, then runs the scan."""
    show_banner(force=True)
    console = Console()
    global _notice_shown
    console.print(f"[dim]{NOTICE}[/dim]\n")
    _notice_shown = True
    while True:
        target = click.prompt("API URL, website URL or OpenAPI file").strip()
        if " " not in target:
            break
        console.print("[yellow]Enter only the address here. Options such as --spec or --rps go on the command line, "
                      "for example: scan https://example.com --spec https://example.com/openapi.json[/yellow]")
    argv = [target]
    spec = click.prompt("OpenAPI document URL or file (press Enter to find it automatically)", default="", show_default=False).strip()
    if spec:
        argv += ["--spec", spec]
    if click.confirm("Do you have a token (JWT or API token) for a normal user?", default=False):
        argv += ["--token", click.prompt("Token", hide_input=True)]
        if click.confirm("Do you have a token for a SECOND user of the same level? (proves object access flaws)", default=False):
            argv += ["--token-b", click.prompt("Second token", hide_input=True)]
    console.print("\nScan type:\n  1. Safe scan: read requests only, no attack payloads (recommended)\n"
                  "  2. Active scan: also sends injection, SSRF and traversal payloads (read requests only)")
    if click.prompt("Select option", type=click.Choice(["1", "2"]), default="1") == "2":
        if not click.confirm(f"This sends attack payloads to {target}. Do you have permission to test it?", default=False):
            raise click.Abort()
        argv += ["--active", "--yes"]
    if click.confirm("Also save an HTML report?", default=False):
        argv += ["-f", "console", "-f", "html"]  # saved in Downloads as report-DD-MM-YYYY.html
    console.print()
    scan.main(args=argv, prog_name="api-sec-scanner")

@main.command()
def checks():
    """List every check with its CVSS 4.0 base score and standards mapping."""
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    for column in ("ID", "Base CVSS", "OWASP API", "OWASP 2025", "Title"):
        table.add_column(column)
    for spec in CATALOG.values():
        score = f"{score_vector(spec.vector)[0]}" if spec.vector else "published"
        table.add_row(spec.id, score, spec.owasp_api or "n/a", spec.owasp_web or "n/a", spec.title)
    console.print(table)

@main.command()
@click.argument("check_id")
def explain(check_id):
    """Explain a check: what it proves, standards mapping, and how to fix it."""
    spec = CATALOG.get(check_id.upper())
    if not spec:
        raise click.UsageError(f"unknown check {check_id}. Run `api-sec-scanner checks` for the list.")
    console = Console()
    console.print(f"[bold]{spec.id}[/bold]  {spec.title}\n")
    console.print(spec.description + "\n")
    if spec.vector:
        score, severity = score_vector(spec.vector)
        console.print(f"CVSS 4.0 base: {score} ({severity.label})\n{spec.vector}\n")
    console.print(f"OWASP API Top 10 2023: {spec.owasp_api or 'n/a'}\nOWASP Top 10 2025: {spec.owasp_web or 'n/a'}")
    for c in spec.cwe:
        console.print(f"  {cwe_label(c)}")
    for t in spec.attack:
        console.print(f"  ATT&CK {attack_label(t)}")
    console.print(f"\n[green]Fix:[/green] {spec.remediation}")
    for ref in spec.references:
        console.print(f"[dim]{ref}[/dim]")

if __name__ == "__main__":
    main()
