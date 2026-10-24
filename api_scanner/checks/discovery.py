"""Discovery of exposed files, debug interfaces, documentation and old API versions.

A path counts as found only when the CONTENT matches what that file should look like.
A bare 200 status proves nothing on servers that answer 200 for every unknown path.
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional
from urllib.parse import urlsplit

from ..context import ScanContext, is_trivial_body
from ..http import Blocked, Exchange
from ..models import Confidence
from ..spec import looks_like_spec
from . import check

SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml", "/swagger.json", "/swagger.yaml", "/v3/api-docs", "/v2/api-docs",
    "/api-docs", "/api/openapi.json", "/api/swagger.json", "/api/v1/openapi.json", "/docs/openapi.json",
    "/swagger/v1/swagger.json", "/.well-known/openapi.json", "/api/docs/openapi.json",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
_INTROSPECTION = {"query": "{__schema{queryType{name}}}"}

_ENV_LINE = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S")

def _validate_env(ex: Exchange) -> Optional[str]:
    if "html" in ex.content_type:
        return None
    keys = [m.group(0).split("=")[0].strip() for m in _ENV_LINE.finditer(ex.text)]
    if len(keys) >= 2:
        return f"{len(keys)} KEY=value lines, keys: {', '.join(keys[:5])}"
    return None

def _validate_gitconfig(ex: Exchange) -> Optional[str]:
    return "contains [core] and repositoryformatversion" if "[core]" in ex.text and "repositoryformatversion" in ex.text else None

def _validate_githead(ex: Exchange) -> Optional[str]:
    return "starts with 'ref: refs/'" if ex.text.startswith("ref: refs/") else None

def _validate_json_keys(*keys: str):
    def validator(ex: Exchange) -> Optional[str]:
        data = ex.json
        if isinstance(data, dict) and any(k in data for k in keys):
            return f"JSON containing {', '.join(k for k in keys if k in data)}"
        return None
    return validator

def _validate_contains(*needles: str):
    def validator(ex: Exchange) -> Optional[str]:
        for needle in needles:
            if needle in ex.text:
                return f"page contains '{needle}'"
        return None
    return validator

def _validate_heapdump(ex: Exchange) -> Optional[str]:
    if ex.text.startswith("JAVA PROFILE") or "octet-stream" in ex.content_type:
        return "binary heap dump"
    return None

def _validate_prometheus(ex: Exchange) -> Optional[str]:
    return "Prometheus metrics" if ex.text.lstrip().startswith("# HELP") or "\n# TYPE " in ex.text else None

def _validate_dsstore(ex: Exchange) -> Optional[str]:
    return "macOS .DS_Store file" if ex.body.startswith(b"\x00\x00\x00\x01Bud1") else None

def _validate_svn(ex: Exchange) -> Optional[str]:
    return "Subversion metadata" if re.match(r"^\d+\s*\n", ex.text) and "dir" in ex.text[:200] else None

def _validate_sql_dump(ex: Exchange) -> Optional[str]:
    if "html" in ex.content_type:
        return None
    return "SQL dump (CREATE TABLE / INSERT INTO)" if re.search(r"(?i)\bCREATE TABLE\b|\bINSERT INTO\b", ex.text[:20000]) else None

def _validate_php_config(ex: Exchange) -> Optional[str]:
    return "PHP configuration with database credentials" if "DB_PASSWORD" in ex.text or "DB_USER" in ex.text else None

def _validate_htpasswd(ex: Exchange) -> Optional[str]:
    if "html" in ex.content_type:
        return None
    return "password hash file" if re.search(r"(?m)^[\w.\-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$6\$)", ex.text) else None

def _validate_webinf(ex: Exchange) -> Optional[str]:
    return "Java web.xml deployment descriptor" if "<web-app" in ex.text else None

def _validate_npmrc(ex: Exchange) -> Optional[str]:
    return "npm credentials (_authToken)" if "_authToken" in ex.text and "html" not in ex.content_type else None

# (path, check id, validator)
FILE_PROBES = [
    ("/.env", "EXP-001", _validate_env), ("/.env.local", "EXP-001", _validate_env), ("/.env.production", "EXP-001", _validate_env),
    ("/.env.dev", "EXP-001", _validate_env), ("/.env.backup", "EXP-001", _validate_env), ("/config/.env", "EXP-001", _validate_env),
    ("/.DS_Store", "EXP-006", _validate_dsstore), ("/.svn/entries", "EXP-002", _validate_svn),
    ("/.htpasswd", "EXP-006", _validate_htpasswd), ("/.npmrc", "EXP-006", _validate_npmrc),
    ("/WEB-INF/web.xml", "EXP-006", _validate_webinf),
    ("/wp-config.php.bak", "EXP-006", _validate_php_config), ("/wp-config.php.old", "EXP-006", _validate_php_config),
    ("/wp-config.php~", "EXP-006", _validate_php_config), ("/config.php.bak", "EXP-006", _validate_php_config),
    ("/backup.sql", "EXP-006", _validate_sql_dump), ("/dump.sql", "EXP-006", _validate_sql_dump),
    ("/database.sql", "EXP-006", _validate_sql_dump), ("/db.sql", "EXP-006", _validate_sql_dump),
    ("/.git/config", "EXP-002", _validate_gitconfig), ("/.git/HEAD", "EXP-002", _validate_githead),
    ("/actuator/env", "EXP-003", _validate_json_keys("propertySources", "activeProfiles")),
    ("/env", "EXP-003", _validate_json_keys("propertySources", "activeProfiles")),
    ("/actuator/heapdump", "EXP-003", _validate_heapdump),
    ("/actuator/mappings", "EXP-003", _validate_json_keys("contexts", "dispatcherServlets")),
    ("/actuator/configprops", "EXP-003", _validate_json_keys("contexts", "beans")),
    ("/actuator/beans", "EXP-003", _validate_json_keys("contexts", "beans")),
    ("/actuator/httptrace", "EXP-003", _validate_json_keys("traces", "exchanges")),
    ("/actuator/threaddump", "EXP-003", _validate_json_keys("threads")),
    ("/debug/pprof/", "EXP-003", _validate_contains("Types of profiles available")),
    ("/debug/vars", "EXP-003", _validate_json_keys("memstats", "cmdline")),
    ("/metrics", "EXP-003", _validate_prometheus),
    ("/phpinfo.php", "EXP-003", _validate_contains("phpinfo()", "PHP Version")),
    ("/info.php", "EXP-003", _validate_contains("phpinfo()", "PHP Version")),
    ("/server-status", "EXP-003", _validate_contains("Apache Server Status")),
    ("/console", "EXP-003", _validate_contains("Werkzeug", "Interactive Console")),
    ("/_profiler", "EXP-003", _validate_contains("Symfony Profiler")),
]

def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"

async def find_spec(ctx: ScanContext, origin: str) -> Optional[tuple]:
    """Look for an OpenAPI document. Returns (url, text) or None."""
    prefix = urlsplit(origin).path.rstrip("/")
    root = f"{urlsplit(origin).scheme}://{urlsplit(origin).netloc}"
    # Look next to the address that was given (for example /api/v3/openapi.json) and then at the site root.
    candidates = [(root, prefix + p) for p in SPEC_PATHS] if prefix else []
    candidates += [(root, p) for p in SPEC_PATHS]
    for origin, path in candidates:
        try:
            # Ask without credentials first. Credentials are only sent if the server demands them.
            ex = await ctx.client.request("GET", origin + path, identity=None, label=f"GET {path}")
            if ex.status in (401, 403) and ctx.identity:
                ex = await ctx.client.request("GET", origin + path, identity=ctx.identity, label=f"GET {path}")
        except Blocked:
            return None
        if ex.ok and not ctx.soft404.matches(ex) and looks_like_spec(ex.text):
            return origin + path, ex.text
    return None

@check("EXP", scope="host")
async def exposures(ctx: ScanContext) -> None:
    origin = origin_of(ctx.base_url)

    async def probe(path: str, check_id: str, validator) -> None:
        try:
            ex = await ctx.client.request("GET", origin + path, identity=None, label=f"GET {path}")
        except Blocked:
            return
        if not ex.ok or ctx.soft404.matches(ex) or is_trivial_body(ex):
            return
        proof = validator(ex)
        if proof:
            ctx.add(check_id, operation=f"GET {path}", confidence=Confidence.CONFIRMED, evidence=f"{origin}{path} is public: {proof}")

    await asyncio.gather(*[probe(p, c, v) for p, c, v in FILE_PROBES])

    # GraphQL introspection. The query only reads, so it is allowed even without --allow-mutating.
    for path in GRAPHQL_PATHS:
        try:
            ex = await ctx.client.request("POST", origin + path, identity=ctx.identity, json_body=_INTROSPECTION, read_only=True, label=f"POST {path}")
        except Blocked:
            break
        data = ex.json
        if ex.ok and isinstance(data, dict) and isinstance(data.get("data"), dict) and "__schema" in data["data"]:
            ctx.add("EXP-005", operation=f"POST {path}", confidence=Confidence.CONFIRMED, evidence=f"{origin}{path} answered an introspection query")

_VERSION = re.compile(r"/v(\d+)(?=/|$)")

@check("INV-001", scope="host")
async def inventory(ctx: ScanContext) -> None:
    """Probe lower API versions than the documented ones, and flag deprecated operations that still work."""
    seen: set = set()
    for ep in ctx.endpoints:
        if ep.method != "GET" or "{" in ep.path:
            continue
        full_path = urlsplit(ep.base_url).path + ep.path
        match = _VERSION.search(full_path)
        if not match or int(match.group(1)) < 2:
            continue
        current = int(match.group(1))
        for older in range(current - 1, -1, -1):
            candidate = full_path[: match.start()] + f"/v{older}" + full_path[match.end():]
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                ex = await ctx.client.request("GET", origin_of(ep.base_url) + candidate, identity=ctx.identity, label=f"GET {candidate}")
            except Blocked:
                return
            if ex.ok and not is_trivial_body(ex) and not ctx.soft404.matches(ex):
                ctx.add("INV-001", operation=f"GET {candidate}", confidence=Confidence.CONFIRMED,
                        evidence=f"{candidate} answers although the documented version is v{current}")
        if len(seen) > 12:
            break
