"""Transport security: certificate, protocol versions, weak cipher suites.

These checks open plain TLS connections and stop after the server's first answer. They run for any
HTTPS target, API or website. The plain HTTP and redirect checks only run in website mode.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from urllib.parse import urlsplit

from .. import tlsprobe
from ..context import ScanContext
from ..http import Blocked
from ..models import Confidence
from . import check

LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

def _inspect_certificate(host: str, port: int, timeout: float) -> dict:
    out: dict = {}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                out["version"] = tls.version()
                cert = tls.getpeercert()
                if cert and cert.get("notAfter"):
                    out["days_left"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
    except ssl.SSLCertVerificationError as exc:
        out["verify_error"] = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        out["unreachable"] = str(exc)[:120]
    return out

async def _probe(ctx: ScanContext, host: str, port: int) -> tlsprobe.TlsReport:
    """Probe once per scan and share the answer between the TLS checks."""
    cached = getattr(ctx, "_tls_report", None)
    if cached is None:
        cached = await asyncio.to_thread(tlsprobe.probe, host, port)
        ctx._tls_report = cached
    return cached

def _target(ctx: ScanContext) -> tuple:
    parts = urlsplit(ctx.base_url)
    if parts.scheme != "https":
        return "", 0
    return parts.hostname or "", parts.port or 443

@check("TLS-001", scope="host")
async def transport_security(ctx: ScanContext) -> None:
    parts = urlsplit(ctx.base_url)
    host = parts.hostname or ""
    if parts.scheme == "http" and ctx.web and host not in LOCAL_HOSTS:
        ctx.add("CFG-006", operation="GET /", confidence=Confidence.CONFIRMED, evidence=f"the site is served over plain HTTP ({ctx.base_url})")
        return
    host, port = _target(ctx)
    if not host:
        return
    where = f"TLS {host}"
    if not ctx.client.config.insecure or ctx.cert_untrusted:
        info = await asyncio.to_thread(_inspect_certificate, host, port, 8.0)
        if "verify_error" in info:
            ctx.add("TLS-001", operation=where, confidence=Confidence.CONFIRMED, evidence=f"certificate verification failed: {info['verify_error']}")
    else:
        ctx.note("TLS certificate checks were skipped because of --insecure.")
    report = await _probe(ctx, host, port)
    obsolete = report.obsolete
    if obsolete:
        ctx.add("TLS-001", operation=where, confidence=Confidence.CONFIRMED, evidence="the server accepts obsolete " + " and ".join(obsolete))
        if not (report.versions.get("TLSv1.2") or report.versions.get("TLSv1.3")):
            ctx.add("TLS-001", operation=where, confidence=Confidence.CONFIRMED, evidence="the server offers neither TLS 1.2 nor TLS 1.3")
    if ctx.web and parts.port in (None, 443):
        try:
            ex = await ctx.client.request("GET", f"http://{host}/", identity=None, headers={"Accept": "text/html,*/*"}, label=f"GET http://{host}/")
        except Blocked:
            return
        location = ex.headers.get("location", "")
        if ex.ok or (ex.status in (301, 302, 303, 307, 308) and not location.lower().startswith("https://")):
            ctx.add("CFG-006", operation=f"GET http://{host}/", confidence=Confidence.CONFIRMED,
                    evidence=f"http://{host}/ answered {ex.status} instead of redirecting to HTTPS")

@check("TLS-002", scope="host")
async def weak_ciphers(ctx: ScanContext) -> None:
    host, port = _target(ctx)
    if not host:
        return
    report = await _probe(ctx, host, port)
    for label, (severity, names) in report.weak.items():
        overrides = {"critical": {"VI": "H"}, "moderate": {"VC": "L"}}.get(severity, {})
        ctx.add("TLS-002", operation=f"TLS {host}", confidence=Confidence.CONFIRMED, overrides=overrides,
                evidence=f"the server accepts {label} cipher suites, for example {names[0]}")
