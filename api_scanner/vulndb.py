"""Known vulnerabilities for the software a target announces.

The scanner reads product names and versions from what the target already shows
(the Server header, X-Powered-By, script file names) and asks free public advisory
databases, none of which needs an API key:

  OSV.dev   Open Source Vulnerabilities. It collects GitHub Security Advisories (GHSA),
            language ecosystems, and others. Used for libraries and Jetty.
  NVD       The US National Vulnerability Database. Used for server software such as
            nginx, Apache httpd, PHP and OpenSSL, which OSV does not index by product.

Only the product name and version are sent, never the address that is being scanned.
The CVSS score and vector are the ones the database publishes. Turn the lookup off with
--offline. Debian's security tracker is not used because it lists distribution urgency
rather than CVSS scores and needs the exact Debian package version, which a website
never reveals.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

import aiohttp

from . import __version__
from .scoring import score_published

OSV_URL = os.environ.get("API_SEC_SCANNER_OSV_URL", "https://api.osv.dev/v1/query")
NVD_URL = os.environ.get("API_SEC_SCANNER_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
MAX_COMPONENTS = 8
MAX_NVD_LOOKUPS = 3  # NVD allows 5 requests per 30 seconds without a key
TIMEOUT = 20

@dataclass(frozen=True)
class Component:
    label: str  # shown to the user, for example "nginx 1.18.0"
    version: str
    where: str  # where the target announced it
    source: str  # "osv" or "nvd"
    package: str = ""  # OSV package name
    ecosystem: str = ""  # OSV ecosystem
    vendor: str = ""  # NVD CPE vendor
    product: str = ""  # NVD CPE product

@dataclass
class Advisory:
    id: str
    cve: str
    summary: str
    score: float
    vector: str
    url: str
    source: str

    @property
    def label(self) -> str:
        return self.cve if self.cve and self.cve == self.id else (f"{self.cve} ({self.id})" if self.cve else self.id)

# Software announced in Server and X-Powered-By headers.
SERVER_PRODUCTS = {
    "jetty": dict(source="osv", package="org.eclipse.jetty:jetty-server", ecosystem="Maven", name="Jetty"),
    "nginx": dict(source="nvd", vendor="f5", product="nginx", name="nginx"),
    "apache": dict(source="nvd", vendor="apache", product="http_server", name="Apache httpd"),
    "apache tomcat": dict(source="nvd", vendor="apache", product="tomcat", name="Apache Tomcat"),
    "tomcat": dict(source="nvd", vendor="apache", product="tomcat", name="Apache Tomcat"),
    "openssl": dict(source="nvd", vendor="openssl", product="openssl", name="OpenSSL"),
    "php": dict(source="nvd", vendor="php", product="php", name="PHP"),
    "lighttpd": dict(source="nvd", vendor="lighttpd", product="lighttpd", name="lighttpd"),
    "openresty": dict(source="nvd", vendor="openresty", product="openresty", name="OpenResty"),
}
_PRODUCT_VERSION = re.compile(r"([A-Za-z][A-Za-z0-9_.\- ]*?)\s*[/(]\s*(\d+(?:\.\d+){1,3}[A-Za-z0-9_.\-]*)")

# JavaScript and CSS libraries recognised from file names such as jquery-3.3.1.min.js.
SCRIPT_LIBS = {
    "jquery": ("jquery", "jQuery"),
    "bootstrap": ("bootstrap", "Bootstrap"),
    "angular": ("angular", "AngularJS"),
    "lodash": ("lodash", "lodash"),
    "moment": ("moment", "Moment.js"),
    "underscore": ("underscore", "Underscore.js"),
    "handlebars": ("handlebars", "Handlebars"),
}
_LIB_VERSION = re.compile(r"(?:^|[/_.\-@])(jquery|bootstrap|angular|lodash|moment|underscore|handlebars)(?:\.js)?[-@/.](\d+\.\d+(?:\.\d+)?)(?![\d])", re.I)

def components_from_headers(technologies) -> list:
    out = []
    for entry in sorted(technologies):
        if ": " not in entry or entry.startswith("framework hint"):
            continue
        header, value = entry.split(": ", 1)
        for match in _PRODUCT_VERSION.finditer(value):
            name, version = match.group(1).strip().lower(), match.group(2).rstrip(".")
            info = SERVER_PRODUCTS.get(name)
            if not info:
                continue
            fields = {k: v for k, v in info.items() if k != "name"}
            out.append(Component(label=f"{info['name']} {version}", version=version,
                                 where=f"{header.title()} header", **fields))
    return out

def components_from_pages(pages) -> list:
    out = []
    for page in pages:
        for res in page.resources:
            match = _LIB_VERSION.search(res.url.split("?", 1)[0])
            if not match:
                continue
            package, name = SCRIPT_LIBS[match.group(1).lower()]
            version = match.group(2)
            out.append(Component(label=f"{name} {version}", version=version, where=page.label, source="osv",
                                 package=package, ecosystem="npm"))
    return out

def find_components(ctx) -> list:
    seen, out = set(), []
    for comp in components_from_headers(ctx.technologies) + components_from_pages(ctx.pages):
        key = (comp.label, comp.source)
        if key not in seen:
            seen.add(key)
            out.append(comp)
    return out[:MAX_COMPONENTS]

# Reading the answers

def _best_vector(entries: list) -> Optional[str]:
    """Pick the newest CVSS vector from OSV severity entries (CVSS 4.0, then 3.x, then 2.0)."""
    order = {"CVSS_V4": 0, "CVSS_V3": 1, "CVSS_V2": 2}
    usable = [e for e in entries if isinstance(e, dict) and e.get("type") in order and e.get("score")]
    usable.sort(key=lambda e: order[e["type"]])
    return usable[0]["score"] if usable else None

def parse_osv(payload: dict) -> list:
    out = []
    for vuln in payload.get("vulns") or []:
        vector = _best_vector(vuln.get("severity") or [])
        if not vector:
            continue
        try:
            score, _, _ = score_published(vector)
        except Exception:
            continue
        vid = vuln.get("id", "")
        cve = next((a for a in vuln.get("aliases") or [] if a.startswith("CVE-")), vid if vid.startswith("CVE-") else "")
        url = next((r.get("url", "") for r in vuln.get("references") or [] if r.get("type") == "ADVISORY"), "") or f"https://osv.dev/vulnerability/{quote(vid)}"
        summary = vuln.get("summary") or (vuln.get("details") or "").split("\n", 1)[0]
        out.append(Advisory(vid, cve, summary or vid, score, vector, url, "OSV.dev (GHSA and others)" if vid.startswith("GHSA") else "OSV.dev"))
    return out

def parse_nvd(payload: dict) -> list:
    out = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        metrics = cve.get("metrics") or {}
        data = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                data = (metrics[key][0] or {}).get("cvssData")
                break
        if not data or not data.get("vectorString"):
            continue
        vector = data["vectorString"]
        try:
            score = float(data.get("baseScore"))
            score_published(vector)
        except Exception:
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
        cid = cve.get("id", "")
        out.append(Advisory(cid, cid, desc, score, vector, f"https://nvd.nist.gov/vuln/detail/{cid}", "NVD"))
    return out

# Asking the databases

async def _osv(session: aiohttp.ClientSession, comp: Component) -> list:
    body = {"package": {"name": comp.package, "ecosystem": comp.ecosystem}, "version": comp.version}
    found = []
    for _ in range(3):  # follow at most three pages
        async with session.post(OSV_URL, json=body) as resp:
            if resp.status != 200:
                raise RuntimeError(f"OSV.dev answered {resp.status}")
            payload = await resp.json(content_type=None)
        found += parse_osv(payload)
        token = payload.get("next_page_token")
        if not token:
            break
        body["page_token"] = token
    return found

async def _nvd(session: aiohttp.ClientSession, comp: Component) -> list:
    cpe = f"cpe:2.3:a:{comp.vendor}:{comp.product}:{comp.version}:*:*:*:*:*:*:*"
    url = f"{NVD_URL}?cpeName={quote(cpe, safe=':*')}&isVulnerable&resultsPerPage=2000"
    async with session.get(url) as resp:
        if resp.status != 200:
            raise RuntimeError(f"NVD answered {resp.status}")
        payload = await resp.json(content_type=None)
    return parse_nvd(payload)

def _dedupe(advisories: list) -> list:
    """One entry per CVE. A GHSA record and an NVD record for the same CVE count once."""
    best: dict = {}
    for adv in advisories:
        key = adv.cve or adv.id
        if key not in best or (adv.source.startswith("OSV") and not best[key].source.startswith("OSV")):
            best[key] = adv
    return list(best.values())

async def lookup(ctx) -> None:
    """Find components, ask the databases, and add one weakness per vulnerable component."""
    components = find_components(ctx)
    if not components:
        return
    if not ctx.options.lookup:
        ctx.note(f"{len(components)} announced component version(s) were not checked against public advisories (--offline).")
        return
    failures: set = set()
    clean = 0
    nvd_used = 0
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    headers = {"User-Agent": f"api-sec-scanner/{__version__}", "Accept": "application/json"}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers, trust_env=True) as session:
        for comp in components:
            if comp.source == "nvd":
                if nvd_used >= MAX_NVD_LOOKUPS:
                    failures.add("more than 3 server products were announced, so the rest were not checked")
                    continue
                nvd_used += 1
            try:
                advisories = _dedupe(await (_nvd(session, comp) if comp.source == "nvd" else _osv(session, comp)))
            except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError, ValueError) as exc:
                failures.add(f"{'NVD' if comp.source == 'nvd' else 'OSV.dev'} could not be used ({type(exc).__name__}: {exc})".replace(": )", ")"))
                continue
            if advisories:
                ctx.add_known_vulnerabilities(comp.label, comp.where, advisories)
            else:
                clean += 1
    for failure in sorted(failures):
        ctx.note(f"Known vulnerability lookup is incomplete: {failure}.")
    if clean:
        ctx.note(f"{clean} announced component version(s) have no scored public advisories in OSV.dev or NVD.")
