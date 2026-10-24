"""SARIF 2.1.0 output, for GitHub code scanning and other CI dashboards."""

from __future__ import annotations

import json

from ..knowledge import CATALOG
from ..models import Severity, ScanResult

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}

def render_sarif(r: ScanResult) -> str:
    rules = []
    used = {f.check_id for f in r.findings}
    for check_id in sorted(used):
        spec = CATALOG[check_id]
        tags = list(spec.cwe) + list(spec.attack) + [t for t in (spec.owasp_api, spec.owasp_web) if t]
        rule = {
            "id": spec.id,
            "name": spec.title,
            "shortDescription": {"text": spec.title},
            "fullDescription": {"text": spec.description},
            "help": {"text": spec.remediation},
            "helpUri": spec.references[0] if spec.references else "https://owasp.org/API-Security/",
            "properties": {"tags": ["security"] + tags},
        }
        rules.append(rule)
    results = []
    artifact = r.mode.get("spec") or r.target
    for f in r.findings:
        props = {
            "priority": f.priority.value,
            "cvss_version": f.cvss_version if f.cvss_vector else None,
            "cvss_vector": f.cvss_vector,
            "owasp_api_2023": f.owasp_api,
            "owasp_top10_2025": f.owasp_web,
        }
        if f.cvss_score is not None:
            props["security-severity"] = f"{f.cvss_score:.1f}"
        message = f"{f.title}. {f.description}"
        if f.evidence:
            message += " Evidence: " + f.evidence[0]
        results.append({
            "ruleId": f.check_id,
            "level": "note" if f.cvss_score is None else _LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": artifact}, "region": {"startLine": 1}},
                "logicalLocations": [{"name": op, "kind": "member"} for op in f.operations[:10]],
            }],
            "properties": props,
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "api-sec-scanner", "version": r.tool_version, "informationUri": "https://github.com/macbuildssys/api-sec-scanner", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
