"""OSINT: what public sources know about the target, checked against reality.

A list of names from a database proves nothing, so this module does two things with it. It asks
many free sources at once, so that one slow or blocked source does not leave the result empty,
and it then checks every name itself: does it resolve, does it answer, what does it run, is it
pointing at a service nobody owns any more, which ports does its address really accept.

Sources that need no account or API key (only the site name is sent, never a payload):

  Certificate logs   crt.sh and Cert Spotter. Every public TLS certificate is logged.
  Passive DNS        AlienVault OTX, HackerTarget, Anubis, urlscan.io.
  Web archive        web.archive.org and AlienVault OTX keep the addresses a site served in the past.
  DNS over HTTPS     Cloudflare, with Google as the second choice. A, CNAME, MX and TXT records.
  RDAP               Registrar, creation and expiry dates, name servers.
  Shodan InternetDB  Open ports and technologies seen on an address.

Established OSINT tools are used as well when they are installed, because they query far more
sources than any built in list can (many of them with the API keys you configured in them):

  subfinder   ProjectDiscovery's passive subdomain finder.
  gau         GetAllUrls, addresses from the web archive, Common Crawl, OTX and urlscan.
  waybackurls Addresses from the web archive (used when gau is not installed).

The results feed the scan: live hosts and old addresses become pages to test, sensitive files
are fetched once to see if they still answer, an unclaimed service behind a subdomain, a risky
open port and a mail domain without DMARC are reported. Hosts other than the target are listed
and checked lightly (one request to the front page) but never scanned. Use --offline or
--no-osint to turn all of this off.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import parse_qsl, urlsplit

import aiohttp

from . import __version__

ENDPOINTS = {
    "crtsh": os.environ.get("API_SEC_SCANNER_CRT_URL", "https://crt.sh/"),
    "certspotter": "https://api.certspotter.com/v1/issuances",
    "hackertarget": "https://api.hackertarget.com/hostsearch/",
    "otx": "https://otx.alienvault.com/api/v1/indicators/domain",
    "anubis": "https://jldc.me/anubis/subdomains",
    "urlscan": "https://urlscan.io/api/v1/search/",
    "archive": os.environ.get("API_SEC_SCANNER_ARCHIVE_URL", "https://web.archive.org/cdx/search/cdx"),
    "doh": os.environ.get("API_SEC_SCANNER_DOH_URL", "https://cloudflare-dns.com/dns-query"),
    "doh_backup": "https://dns.google/resolve",
    "rdap": "https://rdap.org/domain",
    "internetdb": "https://internetdb.shodan.io",
}
TIMEOUT = 25
PROBE_TIMEOUT = 8
TOOL_TIMEOUT = 90
MAX_SUBDOMAINS = 400
MAX_RESOLVE = 120
MAX_PROBE = 40
MAX_ARCHIVED = 3000
MAX_BYTES = 6_000_000
MAX_EXTRA_PAGES = 20

# Sites that share one domain between many owners. Their parent domain is not the target's.
SHARED_PLATFORMS = (
    "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "azurewebsites.net",
    "cloudfront.net", "amazonaws.com", "appspot.com", "firebaseapp.com", "web.app", "onrender.com", "fly.dev", "blogspot.com",
    "wordpress.com", "wixsite.com", "readthedocs.io", "surge.sh", "glitch.me", "repl.co", "ngrok.io", "ngrok-free.app",
)
_SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "go", "gob", "nic"}
_STATIC = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|avif|bmp|css|js|mjs|map|woff2?|ttf|eot|otf|mp[34]|webm|avi|mov|pdf|docx?|xlsx?|pptx?|rss|atom)$", re.I)
_RISKY = re.compile(r"(log-?out|sign-?out|delete|remove|unsubscribe|cancel|destroy|reset)", re.I)
_PAGE_EXT = re.compile(r"\.(php\d?|aspx?|jsp|cgi|pl|do|action|html?)$", re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HOSTNAME = re.compile(r"[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+")

# Services that are reachable from the internet by accident far too often.
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "Windows RPC", 139: "NetBIOS", 445: "SMB", 1433: "Microsoft SQL Server", 1521: "Oracle database",
    2375: "Docker API", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

# (CNAME suffixes, text the provider shows for a name nobody has claimed, provider). A hit on both is a real takeover risk.
TAKEOVER = (
    (("github.io",), r"There isn't a GitHub Pages site here", "GitHub Pages"),
    (("herokuapp.com", "herokudns.com"), r"No such app|no-such-app", "Heroku"),
    (("s3.amazonaws.com", ".s3-website"), r"NoSuchBucket|The specified bucket does not exist", "Amazon S3"),
    (("azurewebsites.net",), r"Web Site not found|Web app not found", "Azure App Service"),
    (("fastly.net",), r"Fastly error: unknown domain", "Fastly"),
    (("pantheonsite.io",), r"The gods are wise, but do not know of the site which you seek", "Pantheon"),
    (("netlify.app", "netlify.com"), r"Not Found - Request ID", "Netlify"),
    (("surge.sh",), r"project not found", "Surge"),
    (("readme.io",), r"Project doesnt exist", "Readme"),
    (("helpscoutdocs.com",), r"No settings were found for this company", "Help Scout"),
    (("zendesk.com",), r"Help Center Closed", "Zendesk"),
    (("ghost.io",), r"Failed to resolve DNS path for this host|Site unavailable", "Ghost"),
    (("myshopify.com",), r"Sorry, this shop is currently unavailable", "Shopify"),
    (("bitbucket.io",), r"Repository not found", "Bitbucket"),
)

_API_PATH = re.compile(r"""["'`](/(?:api|rest|graphql|gql|v\d+|ajax|services?|internal|public|json|rpc)(?:/[A-Za-z0-9_\-.~%]+)*/?)(?:\?[^"'`\s]{0,200})?["'`]""")
_API_ABSOLUTE = re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+(?::\d+)?)(/(?:api|rest|graphql|v\d+)(?:/[A-Za-z0-9_\-.~%]+)*/?)["'`]""")

@dataclass
class Host:
    name: str
    ips: list = field(default_factory=list)
    cname: str = ""
    resolves: Optional[bool] = None
    status: Optional[int] = None
    title: str = ""
    server: str = ""
    location: str = ""
    sources: list = field(default_factory=list)

@dataclass
class Osint:
    domain: str = ""
    shared: bool = False
    subdomains: list = field(default_factory=list)
    hosts: list = field(default_factory=list)  # Host objects that were resolved
    archived: list = field(default_factory=list)  # addresses of this host that archives saw answering
    robots: list = field(default_factory=list)  # paths robots.txt asks crawlers to stay out of
    security_txt: Optional[bool] = None
    mail: Optional[dict] = None  # {"domain", "mx", "spf", "dmarc"} or None when it could not be checked or there is no mail
    registration: dict = field(default_factory=dict)
    ports: dict = field(default_factory=dict)  # ip -> ports InternetDB has seen open
    open_risky: list = field(default_factory=list)  # (ip, port, service) confirmed with a connection
    cves: dict = field(default_factory=dict)  # ip -> CVE ids InternetDB lists (informational only, they are guesses from banners)
    takeovers: list = field(default_factory=list)  # (name, provider, evidence)
    sources_used: dict = field(default_factory=dict)  # source -> how many names or addresses it gave
    tools_used: list = field(default_factory=list)
    failures: list = field(default_factory=list)

    @property
    def live_hosts(self) -> list:
        return [h for h in self.hosts if h.status is not None]

    def summary(self) -> dict:
        return {
            "domain": self.domain, "subdomains": self.subdomains, "hosts": [asdict(h) for h in self.hosts],
            "archived_addresses": len(self.archived), "robots_paths": self.robots, "security_txt": self.security_txt, "mail": self.mail,
            "registration": self.registration, "open_ports": self.ports, "open_risky_ports": [list(x) for x in self.open_risky],
            "takeovers": [list(x) for x in self.takeovers], "sources": self.sources_used, "tools": self.tools_used, "unavailable": self.failures,
        }

def is_public_name(host: str) -> bool:
    """True for a name that can exist on the public internet (not an IP address, localhost or an internal name)."""
    host = (host or "").lower().strip(".")
    if not host or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not host.endswith((".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".test", ".invalid", ".example"))

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]

def is_internal_ip(ip: str) -> bool:
    """True for an address of a private network (RFC 1918, carrier grade NAT or unique local IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _INTERNAL)

def registrable(host: str) -> tuple:
    """The domain that the site's owner registered, and whether it sits on a shared platform.

    This is a close guess without the public suffix list: a short country code after co, com, org and
    similar words keeps three labels (example.co.uk), everything else keeps two (example.com).
    """
    host = host.lower().strip(".")
    for platform in SHARED_PLATFORMS:
        if host == platform:
            return host, True
        if host.endswith("." + platform):
            owner = host[: -len(platform) - 1].split(".")[-1]
            return f"{owner}.{platform}", True
    labels = host.split(".")
    keep = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL else 2
    return ".".join(labels[-keep:]), False

def _chain(host: str, domain: str) -> list:
    """host, then each parent name, down to the registered domain."""
    labels = host.split(".")
    out = []
    for i in range(len(labels)):
        name = ".".join(labels[i:])
        out.append(name)
        if name == domain:
            break
    return out or [host]

def _clean_names(names, domain: str) -> set:
    out = set()
    for name in names:
        name = str(name).strip().lower().removeprefix("*.").strip(".")
        if name.endswith("." + domain) and _HOSTNAME.fullmatch(name):
            out.add(name)
    return out

async def _get(session: aiohttp.ClientSession, url: str, params: Optional[dict] = None, headers: Optional[dict] = None, as_json: bool = True):
    async with session.get(url, params=params, headers=headers) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        raw = await resp.content.read(MAX_BYTES)
    return json.loads(raw) if as_json else raw.decode("utf-8", errors="replace")

# Subdomain sources. Each returns the names it knows, or raises when it cannot be used.

async def _src_crtsh(session, domain):
    data = await _get(session, ENDPOINTS["crtsh"], {"q": f"%.{domain}", "output": "json"})
    return [n for entry in data for n in str(entry.get("name_value", "")).splitlines()]

async def _src_certspotter(session, domain):
    data = await _get(session, ENDPOINTS["certspotter"], {"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
    return [n for entry in data for n in entry.get("dns_names", [])]

async def _src_hackertarget(session, domain):
    text = await _get(session, ENDPOINTS["hackertarget"], {"q": domain}, as_json=False)
    if text.lower().startswith("error") or "API count exceeded" in text:
        raise RuntimeError(text.strip()[:60])
    return [line.split(",")[0] for line in text.splitlines()]

async def _src_otx(session, domain):
    data = await _get(session, f"{ENDPOINTS['otx']}/{domain}/passive_dns")
    return [r.get("hostname", "") for r in data.get("passive_dns", [])]

async def _src_anubis(session, domain):
    return await _get(session, f"{ENDPOINTS['anubis']}/{domain}")

async def _src_urlscan(session, domain):
    data = await _get(session, ENDPOINTS["urlscan"], {"q": f"domain:{domain}", "size": "100"})
    return [r.get("page", {}).get("domain", "") for r in data.get("results", [])]

SUBDOMAIN_SOURCES = {
    "crt.sh": _src_crtsh, "Cert Spotter": _src_certspotter, "HackerTarget": _src_hackertarget, "AlienVault OTX": _src_otx,
    "Anubis": _src_anubis, "urlscan.io": _src_urlscan,
}

# Address sources

def _norm_url(url: str, host: str) -> Optional[str]:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or (parts.hostname or "").lower() != host.split(":")[0]:
        return None
    netloc = parts.netloc.lower().removesuffix(":80" if parts.scheme == "http" else ":443")
    return f"{parts.scheme}://{netloc}{parts.path}" + (f"?{parts.query}" if parts.query else "")

async def _urls_archive(session, host):
    data = await _get(session, ENDPOINTS["archive"], {"url": f"{host}/*", "output": "json", "fl": "original", "collapse": "urlkey",
                                                      "filter": "statuscode:200", "limit": str(MAX_ARCHIVED)})
    rows = data[1:] if data and data[0] == ["original"] else data
    return [row[0] for row in rows if isinstance(row, list) and row]

async def _urls_otx(session, host):
    data = await _get(session, f"{ENDPOINTS['otx']}/{host}/url_list", {"limit": "500", "page": "1"})
    return [r.get("url", "") for r in data.get("url_list", [])]

URL_SOURCES = {"Web Archive": _urls_archive, "AlienVault OTX urls": _urls_otx}

# DNS

async def _doh(session, name: str, kind: str) -> Optional[dict]:
    """The DNS answer as JSON, from Cloudflare or else Google, or None when neither could be reached."""
    for key in ("doh", "doh_backup"):
        try:
            return await _get(session, ENDPOINTS[key], {"name": name, "type": kind}, {"Accept": "application/dns-json"})
        except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError, ValueError):
            continue
    return None

async def _dns(session, name: str, kind: str) -> Optional[list]:
    """The answer strings, an empty list when the name has no such record, or None when the question failed."""
    data = await _doh(session, name, kind)
    if data is None:
        return None
    if data.get("Status") == 3:
        return []
    if data.get("Status") != 0:
        return None
    wanted = {"MX": 15, "TXT": 16}[kind]
    return [str(a.get("data", "")) for a in data.get("Answer", []) if a.get("type") == wanted]

async def _resolve(session, name: str) -> Host:
    host = Host(name=name)
    data = await _doh(session, name, "A")
    if data is None:
        return host
    answers = data.get("Answer", []) or []
    host.ips = [a["data"] for a in answers if a.get("type") == 1 and a.get("data")]
    cnames = [a["data"].rstrip(".").lower() for a in answers if a.get("type") == 5 and a.get("data")]
    host.cname = cnames[-1] if cnames else ""
    if not host.ips:
        aaaa = await _doh(session, name, "AAAA")
        if aaaa:
            host.ips = [a["data"] for a in aaaa.get("Answer", []) or [] if a.get("type") == 28 and a.get("data")]
    host.resolves = bool(host.ips)
    return host

async def _mail(session, host: str, domain: str) -> Optional[dict]:
    """Does this domain handle mail, and does it say who may send mail in its name?"""
    mail_domain, mx = None, []
    for name in _chain(host, domain):
        answers = await _dns(session, name, "MX")
        if answers is None:
            raise RuntimeError("the DNS lookup failed")
        real = [a for a in answers if a.strip() not in ("0 .", "0")]
        if real:
            mail_domain, mx = name, real
            break
    if not mail_domain:
        return None  # no mail is handled here, so there is nothing to spoof
    spf_records = await _dns(session, mail_domain, "TXT")
    spf = any("v=spf1" in r.lower() for r in (spf_records or []))
    dmarc = False
    for name in _chain(mail_domain, domain):
        records = await _dns(session, f"_dmarc.{name}", "TXT")
        if records is None:
            raise RuntimeError("the DNS lookup failed")
        if any("v=dmarc1" in r.lower().replace(" ", "") for r in records):
            dmarc = True
            break
    return {"domain": mail_domain, "mx": [m.split()[-1].rstrip(".") for m in mx][:3], "spf": spf, "dmarc": dmarc}

async def _rdap(session, domain: str) -> dict:
    data = await _get(session, f"{ENDPOINTS['rdap']}/{domain}")
    out = {}
    for event in data.get("events", []):
        action, date = event.get("eventAction", ""), str(event.get("eventDate", ""))[:10]
        if action == "registration":
            out["created"] = date
        elif action == "expiration":
            out["expires"] = date
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    out["registrar"] = item[3]
    out["nameservers"] = sorted({n.get("ldhName", "").lower() for n in data.get("nameservers", []) if n.get("ldhName")})
    return {k: v for k, v in out.items() if v}

async def _internetdb(session, ip: str) -> dict:
    try:
        return await _get(session, f"{ENDPOINTS['internetdb']}/{ip}")
    except RuntimeError as exc:
        if "404" in str(exc):
            return {}  # not known to the database
        raise

async def _probe(session, name: str) -> dict:
    """One request to the front page of a host, to see what answers there."""
    for scheme in ("https", "http"):
        try:
            async with session.get(f"{scheme}://{name}/", allow_redirects=False, ssl=False, timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT)) as resp:
                body = (await resp.content.read(65536)).decode("utf-8", errors="replace")
                match = _TITLE.search(body)
                title = " ".join(match.group(1).split())[:80] if match else ""
                return {"status": resp.status, "server": resp.headers.get("Server", "")[:60], "title": title, "body": body,
                        "location": resp.headers.get("Location", "")[:120]}
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
            continue
    return {}

async def _fetch_text(session, host: str, path: str, limit: int = 200_000) -> Optional[tuple]:
    """(status, content type, text) of one small file on the target, over HTTPS or else HTTP."""
    for scheme in ("https", "http"):
        try:
            async with session.get(f"{scheme}://{host}{path}", ssl=False, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT)) as resp:
                text = (await resp.content.read(limit)).decode("utf-8", errors="replace")
                return resp.status, resp.headers.get("Content-Type", ""), text
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
            continue
    return None

async def _connects(ip: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), 4)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True

async def _run_tool(command: list) -> Optional[list]:
    """Run an installed OSINT tool and return its output lines, or None when it is missing or fails."""
    if not shutil.which(command[0]):
        return None
    try:
        proc = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), TOOL_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return None
    return out.decode("utf-8", errors="replace").splitlines()[:50000]

def _takeover_match(cname: str):
    for suffixes, fingerprint, provider in TAKEOVER:
        if any(cname.endswith(s) or s in cname for s in suffixes):
            return fingerprint, provider
    return None

def parse_robots(text: str) -> list:
    """Paths that robots.txt asks crawlers to avoid. They are what the owner would rather not see listed, so they are good leads."""
    out = []
    for line in text.splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if key.strip().lower() in ("disallow", "allow") and value.startswith("/") and value != "/" and not any(c in value for c in "*$"):
            if value not in out:
                out.append(value)
    return out[:40]

async def gather(host: str, probe: bool = True, tools: bool = True, netloc: str = "") -> Osint:
    """Ask the public sources about one site, then check what they said. A source that does not answer is skipped and named."""
    domain, shared = registrable(host)
    result = Osint(domain=domain, shared=shared)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    headers = {"User-Agent": f"api-sec-scanner/{__version__} (+authorized security testing)", "Accept": "application/json"}
    names: dict = {}  # hostname -> sources that saw it
    urls: dict = {}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers, trust_env=True) as session:
        jobs = {} if shared and host == domain else {("sub", n): f(session, domain) for n, f in SUBDOMAIN_SOURCES.items()}
        jobs.update({("url", n): f(session, host) for n, f in URL_SOURCES.items()})
        jobs[("rdap", "RDAP")] = _rdap(session, domain)
        if not shared:
            jobs[("mail", "DNS")] = _mail(session, host, domain)
        if tools:
            jobs[("tool", "subfinder")] = _run_tool(["subfinder", "-d", domain, "-silent", "-all"])
            jobs[("tool", "gau")] = _run_tool(["gau", "--subs", host]) if shutil.which("gau") else _run_tool(["waybackurls", host])
        outcomes = await asyncio.gather(*jobs.values(), return_exceptions=True)
        for (kind, name), outcome in zip(jobs.keys(), outcomes):
            if isinstance(outcome, asyncio.CancelledError):
                raise outcome
            if isinstance(outcome, BaseException) or (kind == "tool" and outcome is None):
                if kind != "tool":
                    result.failures.append(name)
                continue
            if kind == "sub":
                found = _clean_names(outcome, domain)
                result.sources_used[name] = len(found)
                for n in found:
                    names.setdefault(n, []).append(name)
            elif kind == "url":
                found = [u for u in (_norm_url(x, host) for x in outcome) if u]
                result.sources_used[name] = len(found)
                for u in found:
                    urls.setdefault(u, name)
            elif kind == "rdap":
                result.registration = outcome
            elif kind == "mail":
                result.mail = outcome
            elif kind == "tool":
                result.tools_used.append(name)
                if name == "subfinder":
                    found = _clean_names(outcome, domain)
                    result.sources_used["subfinder"] = len(found)
                    for n in found:
                        names.setdefault(n, []).append("subfinder")
                else:
                    found = [u for u in (_norm_url(x, host) for x in outcome) if u]
                    result.sources_used[name] = len(found)
                    for u in found:
                        urls.setdefault(u, name)
        result.subdomains = sorted(names)[:MAX_SUBDOMAINS]
        result.archived = list(urls)[:MAX_ARCHIVED]
        if probe:
            await _inspect(session, result, host, names, netloc or host)
    return result

async def _inspect(session, result: Osint, host: str, names: dict, netloc: str) -> None:
    """Resolve and probe the names, read robots.txt, and check the target's ports."""
    sem = asyncio.Semaphore(10)
    ordered = [host] + [n for n in result.subdomains if n != host][:MAX_RESOLVE]

    async def resolve(name):
        async with sem:
            h = await _resolve(session, name)
            h.sources = names.get(name, [])
            return h

    hosts = [h for h in await asyncio.gather(*[resolve(n) for n in ordered]) if h.resolves is not None]
    bodies: dict = {}

    async def probe_one(h):
        async with sem:
            got = await _probe(session, netloc if h.name == host else h.name)
            if got:
                h.status, h.server, h.title, h.location = got["status"], got["server"], got["title"], got["location"]
                bodies[h.name] = got["body"]

    await asyncio.gather(*[probe_one(h) for h in [h for h in hosts if h.resolves][:MAX_PROBE]])
    result.hosts = hosts

    for h in hosts:
        matched = _takeover_match(h.cname) if h.cname else None
        if not matched:
            continue
        fingerprint, provider = matched
        if bodies.get(h.name) and re.search(fingerprint, bodies[h.name], re.I):
            result.takeovers.append((h.name, provider, f"{h.name} points to {h.cname} ({provider}) and its front page says nobody owns it"))
        elif h.resolves is False:
            result.takeovers.append((h.name, provider, f"{h.name} points to {h.cname} ({provider}), which no longer resolves"))

    robots = await _fetch_text(session, netloc, "/robots.txt")
    if robots and robots[0] == 200 and "html" not in robots[1]:
        result.robots = parse_robots(robots[2])
    security = await _fetch_text(session, netloc, "/.well-known/security.txt", 20_000)
    if security is not None:
        result.security_txt = security[0] == 200 and "contact:" in security[2].lower()

    target = next((h for h in hosts if h.name == host), None)
    ips = [ip for ip in (target.ips if target else []) if ":" not in ip][:3]
    if ips and not result.shared:
        infos = await asyncio.gather(*[_internetdb(session, ip) for ip in ips], return_exceptions=True)
        for ip, info in zip(ips, infos):
            if isinstance(info, BaseException) or not info:
                continue
            result.ports[ip] = sorted(info.get("ports", []))
            if info.get("vulns"):
                result.cves[ip] = sorted(info["vulns"])[:20]
            for port in result.ports[ip]:
                if port in RISKY_PORTS and await _connects(ip, port):
                    result.open_risky.append((ip, port, RISKY_PORTS[port]))

def extra_pages(osint: Osint, known_paths: set, limit: int = MAX_EXTRA_PAGES, origin: str = "") -> list:
    """Remembered addresses worth testing as pages: those that take parameters first, then plain pages, then robots.txt paths."""
    with_params, plain = [], []
    candidates = list(osint.archived) + [origin + p for p in osint.robots if origin]
    for url in candidates:
        parts = urlsplit(url)
        path = parts.path or "/"
        if _STATIC.search(path) or _RISKY.search(path) or path in known_paths:
            continue
        if parts.query:
            with_params.append(url)
        elif _PAGE_EXT.search(path) or "." not in path.rsplit("/", 1)[-1]:
            plain.append(url)
    chosen, seen = [], set()
    for url in with_params + plain:
        key = urlsplit(url).path
        if key in seen:
            continue
        seen.add(key)
        chosen.append(url)
        if len(chosen) >= limit:
            break
    return chosen

def params_of(url: str) -> dict:
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))

def api_paths_in_script(text: str, host: str) -> list:
    """Paths that look like API calls inside a script, for example fetch('/api/items')."""
    found = []
    for match in _API_PATH.finditer(text):
        path = match.group(1)
        if "${" not in path and path not in found:
            found.append(path)
    for match in _API_ABSOLUTE.finditer(text):
        if (urlsplit(match.group(1)).hostname or "").lower() == host.split(":")[0] and match.group(2) not in found:
            found.append(match.group(2))
    return found[:60]

def describe(osint: Osint) -> list:
    """One or two plain sentences for the report notes."""
    notes = []
    answering = [h for h in osint.hosts[1:] if h.status is not None] if osint.hosts else []
    if osint.subdomains:
        notes.append(f"OSINT found {len(osint.subdomains)} subdomain(s) of {osint.domain}, {len(answering)} of them answer on the web. "
                     "They were not scanned. Scan one on its own with: api-sec-scanner scan https://HOST")
    if not osint.sources_used and not osint.live_hosts:
        notes.append("OSINT: no source returned anything. Check your internet connection, or install subfinder for more sources.")
    elif osint.failures:
        notes.append(f"OSINT sources that did not answer: {', '.join(osint.failures)}.")
    return notes
