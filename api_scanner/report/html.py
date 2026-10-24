"""Self contained HTML report. Everything that came from the target is escaped."""

from __future__ import annotations

from html import escape

from ..models import Severity, ScanResult
from .osint import HOST_COLUMNS, facts, host_rows
from .text import sentence

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5b6570;--line:#dfe3e8;
--crit:#b3112b;--high:#d9480f;--med:#b7791f;--low:#2b6cb0;--info:#5b6570;--ok:#2f855a}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--text:#e6e9ed;--muted:#9aa5b1;--line:#2a313a;
--crit:#ff6b81;--high:#ff9f68;--med:#f2c75c;--low:#74b3ff;--info:#9aa5b1;--ok:#68d391}}
table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border:1px solid var(--line);padding:4px 8px;text-align:left;font-size:13px;word-break:break-word}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.big{font-size:28px;font-weight:700}.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.Critical{color:var(--crit)}.High{color:var(--high)}.Medium{color:var(--med)}.Low{color:var(--low)}.Info{color:var(--info)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0}
summary{cursor:pointer;padding:12px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.body{padding:0 16px 16px}code,pre{font:13px ui-monospace,monospace;background:var(--bg);border-radius:6px}
pre{padding:8px 10px;overflow:auto;white-space:pre-wrap;word-break:break-word;margin:6px 0}
code{padding:1px 5px;word-break:break-all}ul{padding-left:20px}
"""

def _badge(sev: Severity) -> str:
    return f'<span class="pill {sev.label}">{sev.label}</span>'

def _finding(f) -> str:
    score = f"CVSS {f.cvss_version} {f.cvss_score}"
    maps = []
    if f.owasp_api:
        maps.append(f"OWASP {escape(f.owasp_api)}")
    if f.owasp_web:
        maps.append(f"OWASP {escape(f.owasp_web)}")
    maps += [escape(c) for c in f.cwe]
    ops = ", ".join(f"<code>{escape(o)}</code>" for o in f.operations[:8])
    evidence = "".join(f"<pre>{escape(sentence(e))}</pre>" for e in f.evidence)
    attack = "".join(f"<li>{escape(a)}</li>" for a in f.attack)
    vector = f"<p class='muted'>Vector <code>{escape(f.cvss_vector)}</code></p>" if f.cvss_vector else ""
    return (
        f"<details><summary>{_badge(f.severity)}<strong>{escape(f.check_id)}</strong> {escape(f.title)}"
        f"<span class='muted'>{escape(score)} / {escape(f.priority.value)}</span></summary>"
        f"<div class='body'><p>{escape(f.description)}</p>{vector}<p>Where: {ops}</p>"
        f"<p class='muted'>{' / '.join(maps)}</p>"
        f"{'<p>MITRE ATT&amp;CK</p><ul>' + attack + '</ul>' if attack else ''}"
        f"{'<p>Evidence</p>' + evidence if evidence else ''}"
        f"<p><strong>Fix.</strong> {escape(f.remediation)}</p></div></details>"
    )

def _osint_section(r: ScanResult) -> str:
    info = r.mode.get("osint")
    if not info:
        return ""
    rows = host_rows(info)
    table = ""
    if len(rows) > 1:
        head = "".join(f"<th>{escape(c)}</th>" for c in HOST_COLUMNS)
        body = "".join("<tr>" + "".join(f"<td>{escape(c)}</td>" for c in row) + "</tr>" for row in rows)
        table = f"<table><tr>{head}</tr>{body}</table>"
    return "<h2>OSINT</h2>" + table + "<ul>" + "".join(f"<li>{escape(x)}</li>" for x in facts(info)) + "</ul>"

def render_html(r: ScanResult) -> str:
    p = r.posture
    cards = "".join(
        f'<div class="card"><div class="big {label}">{count}</div><div class="muted">{label}</div></div>'
        for label, count in p.by_severity.items()
    )
    notes = "".join(f"<li>{escape(n)}</li>" for n in r.notes)
    standards = ", ".join(f"{k} {v}" for k, v in r.standards.items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Security report</title><style>{_CSS}</style></head><body><main>
<h1>Security report</h1>
<div class="muted">{escape(r.target)} / {escape(r.started)} / {r.requests_sent} requests / {(str(r.mode.get("pages_crawled", 0)) + " pages crawled, " + str(r.endpoints_tested) + " addresses tested") if r.mode.get("kind") == "website" else (str(r.endpoints_tested) + " operations")}</div>
<div class="card"><div class="grid">
<div><div class="muted">Rating</div><div class="big {p.rating.label}">{p.rating.label}</div></div>
<div><div class="muted">Exposure index</div><div class="big">{p.exposure_index}</div></div>
<div><div class="muted">Weaknesses found</div><div class="big">{p.total}</div></div></div>
<p>{escape(p.statement)}</p></div>
<div class="grid">{cards}</div>
<h2>Weaknesses</h2>{''.join(_finding(f) for f in r.findings if f.scored) or '<p class="muted">None found.</p>'}
{_osint_section(r)}
{'<h2>Notes</h2><ul>' + notes + '</ul>' if notes else ''}
<p class="muted">Standards: {escape(standards)}. Tool version {escape(r.tool_version)}.</p>
</main></body></html>"""
