from __future__ import annotations

from ..models import Finding, ScanResult
from .osint import HOST_COLUMNS, facts, host_rows
from .text import sentence

def _ops(f: Finding, limit: int = 6) -> str:
    shown = ", ".join(f"`{o}`" for o in f.operations[:limit])
    more = len(f.operations) - limit
    return shown + (f" and {more} more" if more > 0 else "")

def _finding(f: Finding) -> str:
    lines = [f"### {f.check_id}: {f.title}", ""]
    meta = [f"Severity: **{f.severity.label}**", f"Priority: **{f.priority.value}**"]
    if f.cvss_score is not None:
        meta.insert(1, f"CVSS {f.cvss_version}: **{f.cvss_score}**")
    lines.append(" | ".join(meta))
    lines.append("")
    if f.cvss_vector:
        lines.append(f"Vector: `{f.cvss_vector}`")
        lines.append("")
    lines.append(f"Where: {_ops(f)}")
    lines.append("")
    mapping = []
    if f.owasp_api:
        mapping.append(f"OWASP API Top 10 2023: {f.owasp_api}")
    if f.owasp_web:
        mapping.append(f"OWASP Top 10 2025: {f.owasp_web}")
    if f.cwe:
        mapping.append("CWE: " + "; ".join(f.cwe))
    if f.attack:
        mapping.append("MITRE ATT&CK: " + "; ".join(f.attack))
    for m in mapping:
        lines.append(f"* {m}")
    lines.append("")
    lines.append(f.description)
    lines.append("")
    if f.evidence:
        lines.append("Evidence:")
        lines.append("")
        for e in f.evidence:
            lines.append(f"* `{sentence(e)}`")
        lines.append("")
    lines.append(f"Fix: {f.remediation}")
    lines.append("")
    return "\n".join(lines)

def render_markdown(r: ScanResult) -> str:
    p = r.posture
    out = [f"# Security scan: {r.target}", ""]
    if r.mode.get("kind") == "website":
        size = f"{r.mode.get('pages_crawled', 0)} pages crawled, {r.endpoints_tested} addresses tested"
    else:
        size = f"{r.endpoints_tested} operations"
    out.append(f"Scanned {r.started} by api-sec-scanner {r.tool_version} in {r.duration:.1f}s, {r.requests_sent} requests, {size}.")
    out.append("")
    out.append("Standards: " + ", ".join(f"{k} {v}" for k, v in r.standards.items()))
    out.append("")
    out.append("## Result")
    out.append("")
    out.append(f"* Rating (worst weakness): **{p.rating.label}**")
    out.append(f"* Weaknesses found: **{p.total}**")
    out.append(f"* Exposure index: **{p.exposure_index}** out of 100 (a trend aid, not a probability)")
    out.append("")
    out.append(p.statement)
    out.append("")
    weaknesses = [f for f in r.findings if f.scored]
    out.append("## Weaknesses")
    out.append("")
    if not weaknesses:
        out.append("None found.")
        out.append("")
    for f in weaknesses:
        out.append(_finding(f))
    info = r.mode.get("osint")
    if info:
        out.append("## OSINT")
        out.append("")
        rows = host_rows(info)
        if len(rows) > 1:
            out.append("| " + " | ".join(HOST_COLUMNS) + " |")
            out.append("|" + " --- |" * len(HOST_COLUMNS))
            for row in rows:
                out.append("| " + " | ".join(c.replace("|", "/") for c in row) + " |")
            out.append("")
        for line in facts(info):
            out.append(f"* {line}")
        out.append("")
    if r.notes:
        out.append("## Notes")
        out.append("")
        for n in r.notes:
            out.append(f"* {n}")
        out.append("")
    return "\n".join(out)
