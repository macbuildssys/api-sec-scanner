"""TLS probing: the hand built ClientHello, the weak cipher checks."""

import asyncio
import shutil
import socket
import ssl
import struct
import subprocess
import threading

import pytest
from aiohttp import web

from api_scanner import tlsprobe
from api_scanner.context import ScanOptions
from api_scanner.engine import ScanRequest, run_scan
from api_scanner.http import ClientConfig

needs_openssl = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl is needed to make a test certificate")

def offered_suites(hello: bytes) -> tuple:
    """Read the client version and cipher suites out of a ClientHello record."""
    body = hello[5 + 4:]
    version = struct.unpack(">H", body[:2])[0]
    session_len = body[34]
    pos = 35 + session_len
    count = struct.unpack(">H", body[pos:pos + 2])[0]
    suites = [struct.unpack(">H", body[pos + 2 + i:pos + 4 + i])[0] for i in range(0, count, 2)]
    return version, suites

def server_hello(version: int, suite: int) -> bytes:
    body = struct.pack(">H", version) + b"\x00" * 32 + b"\x00" + struct.pack(">H", suite) + b"\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack(">H", version) + struct.pack(">H", len(handshake)) + handshake

class FakeTlsServer:
    """Answers ClientHellos like a badly configured server: it picks any offered suite it allows, at any version it allows."""

    def __init__(self, allowed_suites, allowed_versions):
        self.allowed_suites, self.allowed_versions = set(allowed_suites), set(allowed_versions)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3)
                try:
                    data = conn.recv(4096)
                    version, suites = offered_suites(data)
                    pick = next((s for s in suites if s in self.allowed_suites), None)
                    if version in self.allowed_versions and pick is not None:
                        conn.sendall(server_hello(version, pick))
                    else:
                        conn.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
                except (OSError, struct.error, IndexError):
                    pass

    def close(self):
        self.sock.close()

def test_client_hello_offers_exactly_the_suites_asked_for():
    hello = tlsprobe.build_client_hello("example.org", tlsprobe.TLS11, [0x0005, 0x000A])
    assert hello[0] == 22 and hello[5] == 1
    assert offered_suites(hello) == (tlsprobe.TLS11, [0x0005, 0x000A])
    assert b"example.org" in hello
    assert b"example.org" not in tlsprobe.build_client_hello("127.0.0.1", tlsprobe.TLS12, [0x002F])

def test_server_hello_is_read_and_alerts_are_not():
    assert tlsprobe.parse_server_hello(server_hello(tlsprobe.TLS10, 0x0005)) == (tlsprobe.TLS10, 0x0005)
    assert tlsprobe.parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x28") is None
    assert tlsprobe.parse_server_hello(b"") is None

def test_weak_server_is_caught_even_though_local_openssl_cannot_speak_rc4_or_3des():
    server = FakeTlsServer({0x0005, 0x000A, 0x002F, 0xC013}, {tlsprobe.TLS10, tlsprobe.TLS11, tlsprobe.TLS12})
    try:
        report = tlsprobe.probe("127.0.0.1", server.port, timeout=3)
    finally:
        server.close()
    assert report.obsolete == ["TLSv1.0", "TLSv1.1"]
    assert set(report.weak) == {"RC4", "3DES (Sweet32)"}
    assert report.weak["RC4"] == ("severe", ["RC4-SHA"]) and report.weak["3DES (Sweet32)"][0] == "moderate"

def test_modern_server_has_nothing_to_report():
    server = FakeTlsServer({0xC02F, 0xC030, 0xCCA8}, {tlsprobe.TLS12})
    try:
        report = tlsprobe.probe("127.0.0.1", server.port, timeout=3)
    finally:
        server.close()
    assert report.obsolete == [] and report.weak == {}

def make_certificate(tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "30",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
    return key, crt

def scan_https(tmp_path, ciphers: str):
    key, crt = make_certificate(tmp_path)

    async def home(request):
        return web.json_response({"hello": "world"})

    async def go():
        app = web.Application()
        app.add_routes([web.get("/", home)])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(crt), str(key))
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(ciphers)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
        await site.start()
        try:
            base = f"https://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
            request = ScanRequest(target=base, options=ScanOptions(rate_probe=0, lookup=False),
                                  client=ClientConfig(rps=0, insecure=True, timeout=10))
            return await run_scan(request)
        finally:
            await runner.cleanup()

    return asyncio.run(go())

@needs_openssl
def test_real_openssl_server_with_only_forward_secret_suites_is_clean(tmp_path):
    result = scan_https(tmp_path, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384")
    assert not {"TLS-001", "TLS-002"} & {f.check_id for f in result.findings}

def test_weak_cipher_findings_are_scored_by_how_bad_the_suite_is():
    from api_scanner.context import ScanContext, ScanOptions
    from api_scanner.http import ClientConfig, ScanClient
    from api_scanner.models import Confidence
    from api_scanner.scoring import AssetProfile

    async def run():
        async with ScanClient(ClientConfig()) as client:
            scores = {}
            for severity in ("critical", "severe", "moderate"):
                ctx = ScanContext(client, ScanOptions(), AssetProfile())
                overrides = {"critical": {"VI": "H"}, "moderate": {"VC": "L"}}.get(severity, {})
                ctx.add("TLS-002", operation="TLS x", confidence=Confidence.CONFIRMED, overrides=overrides, evidence="e")
                scores[severity] = ctx.finalize_findings()[0].severity.label
            return scores

    assert asyncio.run(run()) == {"critical": "High", "severe": "Medium", "moderate": "Low"}
