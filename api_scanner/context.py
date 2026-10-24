"""Shared state for one scan: options, identities, baselines, and the finding collector."""

from __future__ import annotations

import difflib
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Optional

from .http import Blocked, Exchange, Identity, ScanClient
from .knowledge import CATALOG, attack_label, cwe_label
from .models import Confidence, Endpoint, Finding, Severity
from .scoring import AssetProfile, decide, override_metrics, score_vector, with_environment

MAX_EVIDENCE_LINES = 6
MAX_OPERATIONS_LISTED = 40

@dataclass
class ScanOptions:
    active: bool = False  # send attack payloads (injection, SSRF) on safe methods
    allow_mutating: bool = False  # allow POST, PUT, PATCH, DELETE
    callback_host: Optional[str] = None  # host[:port] the TARGET can reach, for SSRF proof
    callback_bind: str = "0.0.0.0"
    rate_probe: int = 40  # burst size for the throttling test
    max_endpoints: int = 500
    only: list = field(default_factory=list)  # check id prefixes to run
    skip: list = field(default_factory=list)  # check id prefixes to skip
    time_probe_seconds: int = 3
    owned_object_id: Optional[str] = None  # an object id owned by the primary identity (for BOLA-001)
    web: Optional[bool] = None  # True: crawl as a website, False: treat as an API only, None: decide automatically
    max_pages: int = 25  # pages to fetch in website mode
    osint: bool = True  # ask public sources (certificate logs, web archive, DNS) about the target. --offline turns it off
    browser: Optional[bool] = None  # True: always use a headless browser to crawl, False: never, None: only when the site is built with JavaScript
    lookup: bool = True  # ask public advisory databases about announced software versions

class Soft404:
    """Learns what the target returns for pages that do not exist, so that 'catch all'
    servers (single page apps, custom 200 error pages) are not mistaken for real hits."""

    def __init__(self) -> None:
        self.samples: list = []

    @staticmethod
    def _sig(ex: Exchange) -> tuple:
        digest = hashlib.sha1(ex.body[:2000]).hexdigest()
        return (ex.status, ex.content_type, len(ex.body), digest)

    async def learn(self, client: ScanClient, base_url: str) -> None:
        for suffix in (secrets.token_hex(8), secrets.token_hex(8) + ".json", ".git/" + secrets.token_hex(4)):
            try:
                ex = await client.request("GET", f"{base_url.rstrip('/')}/{suffix}", identity=None, observe=False)
            except Blocked:
                return
            if ex.status is not None:
                self.samples.append(self._sig(ex))

    def matches(self, ex: Exchange) -> bool:
        """True if this response looks like the site's generic 'not found' page."""
        if ex.status is None:
            return True
        if not self.samples:
            return False
        sig = self._sig(ex)
        for status, ctype, length, digest in self.samples:
            if sig[0] != status or sig[1] != ctype:
                continue
            if sig[3] == digest or abs(sig[2] - length) <= max(40, int(0.05 * length)):
                return True
        return False

def is_trivial_body(ex: Exchange) -> bool:
    text = ex.text.strip()
    return text in ("", "{}", "[]", "null", '""', "0")

def bodies_similar(a: Exchange, b: Exchange, threshold: float = 0.9) -> bool:
    """True when two responses carry essentially the same content."""
    if a.status is None or b.status is None or a.status != b.status:
        return False
    if a.body == b.body:
        return True
    ja, jb = a.json, b.json
    if ja is not None and jb is not None:
        return _strip_volatile(ja) == _strip_volatile(jb)
    ta, tb = a.text[:3000], b.text[:3000]
    return difflib.SequenceMatcher(None, ta, tb).quick_ratio() >= threshold and difflib.SequenceMatcher(None, ta, tb).ratio() >= threshold

_VOLATILE = {"timestamp", "time", "date", "now", "request_id", "requestid", "trace_id", "traceid", "nonce", "iat", "exp", "server_time", "uptime"}

def _strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_volatile(v) for k, v in value.items() if k.lower() not in _VOLATILE}
    if isinstance(value, list):
        return [_strip_volatile(v) for v in value]
    return value

class ScanContext:
    def __init__(self, client: ScanClient, options: ScanOptions, profile: AssetProfile,
                 identity: Optional[Identity] = None, identity_b: Optional[Identity] = None):
        self.client = client
        self.options = options
        self.profile = profile
        self.identity = identity
        self.identity_b = identity_b
        self.soft404 = Soft404()
        self.endpoints: list = []
        self.spec = None
        self.base_url = ""
        self.technologies: set = set()
        self.notes: list = []
        self.callback = None  # CanaryServer, set by the engine
        self.discovered_spec_url: Optional[str] = None
        self.endpoint_labels: set = set()  # labels of documented operations, used by passive analysis
        self.web = False  # website mode is on
        self.cert_untrusted = False  # the site certificate was rejected, so verification was switched off
        self.pages: list = []  # crawled pages (web.Page)
        self.osint = None  # osint.Osint, filled in when the public sources were asked
        self.api_calls: list = []  # (method, url) calls the page scripts made, seen by the browser
        self._baselines: dict = {}
        self._findings: dict = {}
        self.check_errors: list = []

    # baselines

    async def baseline(self, ep: Endpoint, identity: Optional[Identity] = "primary") -> Exchange:
        who = self.identity if identity == "primary" else identity
        key = (ep.label, ep.base_url, who.name if who else None)
        if key not in self._baselines:
            self._baselines[key] = await self.send(ep, identity=who, label=ep.label)
        return self._baselines[key]

    async def send(self, ep: Endpoint, *, identity: Optional[Identity], params: Optional[dict] = None,
                   path_overrides: Optional[dict] = None, headers: Optional[dict] = None,
                   body: Any = "default", label: str = "", **kw) -> Exchange:
        """Send the endpoint's request with example values, optionally modified."""
        query = dict(ep.query_defaults())
        if params:
            query.update(params)
        json_body = ep.body_example if body == "default" else body
        send_body = json_body if (ep.method in ("POST", "PUT", "PATCH") and json_body is not None and (ep.body_content_type or "").endswith("json")) else None
        ex = await self.client.request(
            ep.method, ep.url(path_overrides), identity=identity, params=query or None,
            json_body=send_body, headers=headers, label=label or ep.label, **kw,
        )
        return ex

    # findings

    def enabled(self, check_id: str) -> bool:
        if self.options.only and not any(check_id.startswith(p.upper()) for p in self.options.only):
            return False
        return not any(check_id.startswith(p.upper()) for p in self.options.skip)

    def add(self, check_id: str, *, operation: str, confidence: Confidence, evidence: str,
            overrides: Optional[dict] = None, detail: str = "") -> None:
        """Record a finding, merging with earlier ones of the same kind."""
        if not self.enabled(check_id):
            return
        spec = CATALOG[check_id]
        key = (check_id, confidence)
        existing = self._findings.get(key)
        vector = spec.vector
        if vector and overrides:
            vector = override_metrics(vector, **overrides)
        if existing is None:
            existing = Finding(
                check_id=check_id,
                title=spec.title,
                confidence=confidence,
                severity=Severity.INFO,
                owasp_api=spec.owasp_api,
                owasp_web=spec.owasp_web,
                cwe=[cwe_label(c) for c in spec.cwe],
                attack=[attack_label(t) for t in spec.attack],
                description=spec.description,
                remediation=spec.remediation,
                references=list(spec.references),
            )
            self._findings[key] = existing
        if operation not in existing.operations:
            existing.operations.append(operation)
        if evidence and evidence not in existing.evidence and len(existing.evidence) < MAX_EVIDENCE_LINES:
            existing.evidence.append(evidence if not detail else f"{evidence} ({detail})")
        if vector:
            # keep the worst vector seen across the affected operations
            score, _ = score_vector(vector)
            if existing.cvss_score is None or score > existing.cvss_score:
                existing.cvss_vector, existing.cvss_score = vector, score

    def add_known_vulnerabilities(self, component: str, where: str, advisories: list) -> None:
        """Record published advisories for one component version as a single weakness.
        The score is the highest one published, with the version of CVSS it was published in."""
        from .scoring import score_published

        spec = CATALOG["VULN-001"]
        ranked = sorted(advisories, key=lambda a: -a.score)
        top = ranked[0]
        _, severity, version = score_published(top.vector)
        def short(text: str) -> str:
            text = " ".join(text.replace("*", "").split())
            return text if len(text) <= 90 else text[:87].rstrip() + "..."

        evidence = [f"{a.label} CVSS {a.score}: {short(a.summary)}" for a in ranked[:4]]
        if len(ranked) > 4:
            evidence.append(f"{len(ranked)} published advisories in total, from {', '.join(sorted({a.source for a in ranked}))}")
        refs = [a.url for a in ranked[:3] if a.url]
        self._findings[("VULN-001", component)] = Finding(
            check_id="VULN-001", title=f"Known vulnerabilities in {component}", confidence=Confidence.CONFIRMED,
            severity=severity, cvss_vector=top.vector, cvss_score=top.score, cvss_version=version,
            owasp_api=spec.owasp_api, owasp_web=spec.owasp_web, cwe=[cwe_label(c) for c in spec.cwe],
            attack=[attack_label(t) for t in spec.attack], operations=[where],
            description=(f"{component} is announced by the target, and public advisories list that version as affected. "
                         f"The score is the highest published one: {top.label}. Servers sometimes carry vendor fixes "
                         "without changing the version number, so check the vendor's own notes."),
            evidence=evidence, remediation=spec.remediation, references=refs + list(spec.references),
        )

    def finalize_findings(self) -> list:
        """Apply the asset profile, set severities and priorities, sort."""
        out = []
        for finding in self._findings.values():
            if finding.cvss_vector and finding.cvss_version != "4.0":
                pass  # a score published by an advisory database is kept as published
            elif finding.cvss_vector:
                vector = with_environment(finding.cvss_vector, self.profile)
                score, severity = score_vector(vector)
                finding.cvss_vector, finding.cvss_score, finding.severity = vector, score, severity
            finding.priority = decide(finding, self.profile)
            if len(finding.operations) > MAX_OPERATIONS_LISTED:
                extra = len(finding.operations) - MAX_OPERATIONS_LISTED
                finding.operations = finding.operations[:MAX_OPERATIONS_LISTED] + [f"... and {extra} more"]
            out.append(finding)
        out.sort(key=lambda f: (-f.severity, -f.priority.rank, f.confidence != Confidence.CONFIRMED, f.check_id))
        return out

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

def json_fingerprint(value: Any) -> str:
    return hashlib.sha1(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
