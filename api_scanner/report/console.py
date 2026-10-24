"""Terminal report built with rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Priority, ScanResult, Severity
from .text import sentence

_COLOR = {Severity.CRITICAL: "bold bright_red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}
_PRIORITY_COLOR = {Priority.ACT: "bold bright_red", Priority.ATTEND: "red", Priority.TRACK_PLUS: "yellow", Priority.TRACK: "dim"}

def _ops(f, limit: int = 2) -> str:
    shown = ", ".join(f.operations[:limit])
    more = len(f.operations) - limit
    return shown + (f" +{more} more" if more > 0 else "")

def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"

def print_report(r: ScanResult, console: Console, verbose: bool = False) -> None:
    p = r.posture
    kind = r.mode.get("kind")
    header = Text()
    header.append(f"{r.target}\n", style="bold")
    mode = "active scan (attack payloads sent)" if r.mode["active"] else "safe scan (read requests only)"
    if r.mode["allow_mutating"]:
        mode += ", changing data allowed"
    if kind == "website":
        unit = f"{_count(r.mode.get('pages_crawled', 0), 'page', 'pages')} crawled, {_count(r.endpoints_tested, 'address', 'addresses')} tested"
    else:
        unit = _count(r.endpoints_tested, "operation", "operations")
    header.append(f"{'Website' if kind == 'website' else 'API'}: {unit}, {_count(r.requests_sent, 'request', 'requests')}, {r.duration:.1f}s, {mode}\n", style="dim")
    header.append("Standards: " + ", ".join(f"{k} {v}" for k, v in r.standards.items() if k != "Decision model"), style="dim")
    console.print(Panel(header, title="REST API and Websites", border_style="blue"))

    verdict = Text()
    verdict.append("Rating: ", style="bold")
    verdict.append(p.rating.label.upper(), style=_COLOR[p.rating])
    verdict.append(f"   Weaknesses found: {p.total}", style="bold")
    verdict.append(f"   Exposure index: {p.exposure_index}/100", style="bold")
    verdict.append("\n" + p.statement)
    console.print(Panel(verdict, title="Result", border_style=_COLOR[p.rating].split()[-1]))

    weaknesses = [f for f in r.findings if f.scored]
    if weaknesses:
        table = Table(show_header=True, header_style="bold magenta", expand=True)
        for column, width in (("Severity", 9), ("CVSS", 6), ("Priority", 8), ("Check", 9)):
            table.add_column(column, width=width, no_wrap=True)
        table.add_column("Weakness", ratio=2)
        table.add_column("Where", ratio=1)
        table.add_column("OWASP", width=7, no_wrap=True)
        for f in weaknesses:
            table.add_row(
                Text(f.severity.label, style=_COLOR[f.severity]), f"{f.cvss_score}",
                Text(f.priority.value, style=_PRIORITY_COLOR[f.priority]), f.check_id, f.title, _ops(f), (f.owasp_api or f.owasp_web or "").split(":")[0],
            )
        console.print(table)
        for f in weaknesses:
            body = Text()
            body.append(f.description + "\n", style="")
            body.append(f"\nCVSS {f.cvss_version} score: {f.cvss_score}\n", style="bold")
            if f.evidence:
                body.append("\nEvidence\n", style="bold")
                for e in f.evidence:
                    body.append(f"  \u2022 {sentence(e)}\n", style="dim")
            body.append("\nMapping\n", style="bold")
            labels = [f"OWASP API 2023: {f.owasp_api}" if f.owasp_api else "", f"OWASP Top 10 2025: {f.owasp_web}" if f.owasp_web else ""]
            body.append("  " + "   ".join(x for x in labels if x) + "\n")
            body.append("  " + "; ".join(f.cwe) + "\n")
            for a in f.attack:
                body.append(f"  ATT&CK {a}\n")
            body.append(f"\nFix: {f.remediation}", style="green")
            if f.cvss_vector and verbose:
                body.append(f"\n{f.cvss_vector}", style="dim")
            console.print(Panel(body, title=f"{f.check_id}  {f.title}  [{f.severity.label}, {f.priority.value}]", border_style=_COLOR[f.severity].split()[-1]))
    else:
        console.print("[green]No weaknesses found.[/green]")
    info = r.mode.get("osint")
    live = [h for h in (info or {}).get("hosts", []) if h["status"] == 200 and h["name"] != r.target.split("//")[-1].split("/")[0].split(":")[0]]
    if live:
        table = Table(title=f"Other hosts of {info['domain']} that answer 200 (not scanned)", header_style="bold magenta", expand=True)
        table.add_column("Host", overflow="fold")
        table.add_column("Address", no_wrap=True)
        table.add_column("What answers", overflow="fold")
        for h in live[:15]:
            table.add_row(h["name"], (h["ips"] or [""])[0], (h["title"] or h["server"])[:50])
        console.print(table)
        if len(live) > 15:
            console.print(f"[dim]{len(live) - 15} more are in the JSON, HTML and Markdown reports.[/dim]")
