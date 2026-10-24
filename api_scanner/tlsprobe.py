"""TLS probing with hand built ClientHello messages.

Python's ssl module follows the local OpenSSL build, which no longer offers RC4, 3DES, DES or
export ciphers and often refuses TLS 1.0 and 1.1. A scanner must still ask a server about them,
so this module sends its own ClientHello that offers only the cipher suites being tested and reads
which suite the server picks in its ServerHello. The handshake is never completed: no certificate
is checked, no data is sent, and the connection is closed right after the answer.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Optional

SSL3, TLS10, TLS11, TLS12, TLS13 = 0x0300, 0x0301, 0x0302, 0x0303, 0x0304
VERSION_NAMES = {SSL3: "SSLv3", TLS10: "TLSv1.0", TLS11: "TLSv1.1", TLS12: "TLSv1.2", TLS13: "TLSv1.3"}

# Cipher suite numbers from the IANA registry, grouped by the weakness being tested.
SUITES = {
    0x0001: "NULL-MD5", 0x0002: "NULL-SHA", 0x003B: "NULL-SHA256", 0xC001: "ECDH-ECDSA-NULL-SHA", 0xC006: "ECDHE-ECDSA-NULL-SHA",
    0xC00B: "ECDH-RSA-NULL-SHA", 0xC010: "ECDHE-RSA-NULL-SHA",
    0x0018: "ADH-RC4-MD5", 0x001A: "ADH-DES-CBC-SHA", 0x001B: "ADH-DES-CBC3-SHA", 0x0034: "ADH-AES128-SHA", 0x003A: "ADH-AES256-SHA",
    0x006C: "ADH-AES128-SHA256", 0x006D: "ADH-AES256-SHA256", 0x00A6: "ADH-AES128-GCM-SHA256", 0x00A7: "ADH-AES256-GCM-SHA384",
    0xC015: "AECDH-NULL-SHA", 0xC016: "AECDH-RC4-SHA", 0xC017: "AECDH-DES-CBC3-SHA", 0xC018: "AECDH-AES128-SHA", 0xC019: "AECDH-AES256-SHA",
    0x0003: "EXP-RC4-MD5", 0x0006: "EXP-RC2-CBC-MD5", 0x0008: "EXP-DES-CBC-SHA", 0x000B: "EXP-DH-DSS-DES-CBC-SHA",
    0x000E: "EXP-DH-RSA-DES-CBC-SHA", 0x0011: "EXP-EDH-DSS-DES-CBC-SHA", 0x0014: "EXP-EDH-RSA-DES-CBC-SHA",
    0x0017: "EXP-ADH-RC4-MD5", 0x0019: "EXP-ADH-DES-CBC-SHA",
    0x0004: "RC4-MD5", 0x0005: "RC4-SHA", 0x0066: "DHE-DSS-RC4-SHA", 0xC002: "ECDH-ECDSA-RC4-SHA", 0xC007: "ECDHE-ECDSA-RC4-SHA",
    0xC00C: "ECDH-RSA-RC4-SHA", 0xC011: "ECDHE-RSA-RC4-SHA",
    0x0009: "DES-CBC-SHA", 0x0012: "EDH-DSS-DES-CBC-SHA", 0x0015: "EDH-RSA-DES-CBC-SHA",
    0x000A: "DES-CBC3-SHA", 0x0013: "EDH-DSS-DES-CBC3-SHA", 0x0016: "EDH-RSA-DES-CBC3-SHA", 0xC003: "ECDH-ECDSA-DES-CBC3-SHA",
    0xC008: "ECDHE-ECDSA-DES-CBC3-SHA", 0xC00D: "ECDH-RSA-DES-CBC3-SHA", 0xC012: "ECDHE-RSA-DES-CBC3-SHA",
    0x002F: "AES128-SHA", 0x0035: "AES256-SHA", 0x003C: "AES128-SHA256", 0x003D: "AES256-SHA256", 0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384", 0x0041: "CAMELLIA128-SHA", 0x0084: "CAMELLIA256-SHA",
    0xC009: "ECDHE-ECDSA-AES128-SHA", 0xC00A: "ECDHE-ECDSA-AES256-SHA", 0xC013: "ECDHE-RSA-AES128-SHA", 0xC014: "ECDHE-RSA-AES256-SHA",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256", 0xC030: "ECDHE-RSA-AES256-GCM-SHA384", 0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305", 0x009E: "DHE-RSA-AES128-GCM-SHA256", 0x009F: "DHE-RSA-AES256-GCM-SHA384",
}

# Each group: label, severity class ("critical", "severe" or "moderate"), cipher suite numbers.
WEAK_GROUPS = [
    ("no encryption (NULL)", "critical", [0x0001, 0x0002, 0x003B, 0xC001, 0xC006, 0xC00B, 0xC010]),
    ("no server authentication (anonymous)", "critical",
     [0x0018, 0x001A, 0x001B, 0x0034, 0x003A, 0x006C, 0x006D, 0x00A6, 0x00A7, 0xC015, 0xC016, 0xC017, 0xC018, 0xC019]),
    ("export grade", "severe", [0x0003, 0x0006, 0x0008, 0x000B, 0x000E, 0x0011, 0x0014, 0x0017, 0x0019]),
    ("RC4", "severe", [0x0004, 0x0005, 0x0066, 0xC002, 0xC007, 0xC00C, 0xC011]),
    ("single DES", "moderate", [0x0009, 0x0012, 0x0015]),
    ("3DES (Sweet32)", "moderate", [0x000A, 0x0013, 0x0016, 0xC003, 0xC008, 0xC00D, 0xC012]),
]
LEGACY_PROBE_SUITES = [0xC014, 0xC013, 0xC00A, 0xC009, 0x0035, 0x002F, 0x000A]
MODERN_SUITES = [0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9, 0x009E, 0x009F, 0xC013, 0xC014, 0x002F, 0x0035]
_SIGNATURE_ALGORITHMS = (0x0601, 0x0501, 0x0401, 0x0201, 0x0603, 0x0503, 0x0403, 0x0203, 0x0804, 0x0805, 0x0806)

def build_client_hello(host: str, version: int, suites: list) -> bytes:
    """A ClientHello that offers exactly these cipher suites at this protocol version (TLS 1.2 or older)."""
    body = struct.pack(">H", version) + os.urandom(32) + b"\x00"
    body += struct.pack(">H", 2 * len(suites)) + b"".join(struct.pack(">H", s) for s in suites)
    body += b"\x01\x00"
    ext = b""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip and host:
        name = host.encode("idna")
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        listing = struct.pack(">H", len(entry)) + entry
        ext += struct.pack(">HH", 0x0000, len(listing)) + listing
    groups = b"".join(struct.pack(">H", g) for g in (0x001D, 0x0017, 0x0018, 0x0019))
    ext += struct.pack(">HH", 0x000A, 2 + len(groups)) + struct.pack(">H", len(groups)) + groups
    ext += struct.pack(">HH", 0x000B, 2) + b"\x01\x00"
    sigs = b"".join(struct.pack(">H", s) for s in _SIGNATURE_ALGORITHMS)
    ext += struct.pack(">HH", 0x000D, 2 + len(sigs)) + struct.pack(">H", len(sigs)) + sigs
    body += struct.pack(">H", len(ext)) + ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack(">H", TLS10) + struct.pack(">H", len(handshake)) + handshake

def parse_server_hello(data: bytes) -> Optional[tuple]:
    """Return (protocol version, cipher suite number) from the first record, or None for an alert or anything else."""
    if len(data) < 5 or data[0] != 22:
        return None
    payload = data[5:]
    if len(payload) < 40 or payload[0] != 2:
        return None
    version = struct.unpack(">H", payload[4:6])[0]
    session_len = payload[6 + 32]
    offset = 6 + 32 + 1 + session_len
    if len(payload) < offset + 2:
        return None
    return version, struct.unpack(">H", payload[offset:offset + 2])[0]

def _read_first_record(sock: socket.socket) -> bytes:
    data = b""
    while len(data) < 5:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk
    need = 5 + struct.unpack(">H", data[3:5])[0]
    while len(data) < min(need, 5 + 80):  # the start of the ServerHello is all that is needed
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def offer(host: str, port: int, version: int, suites: list, timeout: float = 6.0) -> Optional[tuple]:
    """Offer only these suites. Returns (version, suite number) if the server picks one, else None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(build_client_hello(host, version, suites))
            return parse_server_hello(_read_first_record(sock))
    except (OSError, struct.error, ValueError):
        return None

def accepts_protocol(host: str, port: int, version: int, timeout: float = 6.0) -> bool:
    """True when the server completes a handshake negotiation at exactly this protocol version."""
    if version in (TLS12, TLS13):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2 if version == TLS12 else ssl.TLSVersion.TLSv1_3
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=None if _is_ip(host) else host):
                    return True
        except (OSError, ssl.SSLError, ValueError):
            return False
    answer = offer(host, port, version, LEGACY_PROBE_SUITES, timeout)
    return bool(answer) and answer[0] == version

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

@dataclass
class TlsReport:
    versions: dict = field(default_factory=dict)  # protocol name -> True when accepted
    weak: dict = field(default_factory=dict)  # group label -> (severity class, [suite names accepted])

    @property
    def obsolete(self) -> list:
        return [name for name in ("SSLv3", "TLSv1.0", "TLSv1.1") if self.versions.get(name)]

def probe(host: str, port: int, timeout: float = 6.0) -> TlsReport:
    """Ask the server about protocol versions, weak cipher suites."""
    report = TlsReport()
    jobs = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for version in (TLS10, TLS11, TLS12, TLS13):
            jobs[pool.submit(accepts_protocol, host, port, version, timeout)] = ("version", version)
        for label, severity, suites in WEAK_GROUPS:
            jobs[pool.submit(offer, host, port, TLS12, suites, timeout)] = ("weak", (label, severity))
        for future, (kind, info) in jobs.items():
            result = future.result()
            if kind == "version":
                report.versions[VERSION_NAMES[info]] = bool(result)
            elif kind == "weak" and result:
                report.weak[info[0]] = (info[1], [SUITES.get(result[1], f"0x{result[1]:04X}")])
    return report
