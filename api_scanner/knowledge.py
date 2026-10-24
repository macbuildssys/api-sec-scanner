"""Standards knowledge base.

Everything the scanner knows about OWASP, CWE, MITRE ATT&CK and the CVSS 4.0 base
vector of each check lives here, so the check code only has to say WHAT it observed.

Standards covered:
    OWASP API Security Top 10, 2023 edition (still the current API edition)
    OWASP Top 10, 2025 edition (used for injection and other web classes)
    CWE identifiers (names verified against the official MITRE list)
    MITRE ATT&CK Enterprise v20 (technique names loaded from data/attack_subset.json)
    CVSS v4.0 (vectors scored with the reference tables, see scoring.py)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Optional

OWASP_API_2023 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

OWASP_WEB_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-215": "Insertion of Sensitive Information Into Debugging Code",
    "CWE-285": "Improper Authorization",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-295": "Improper Certificate Validation",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-672": "Operation on a Resource after Expiration or Release",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-324": "Use of a Key Past its Expiration Date",
    "CWE-346": "Origin Validation Error",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-359": "Exposure of Private Personal Information to an Unauthorized Actor",
    "CWE-489": "Active Debug Code",
    "CWE-353": "Missing Support for Integrity Check",
    "CWE-523": "Unprotected Transport of Credentials",
    "CWE-524": "Use of Cache Containing Sensitive Information",
    "CWE-540": "Inclusion of Sensitive Information in Source Code",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
    "CWE-552": "Files or Directories Accessible to External Parties",
    "CWE-598": "Use of GET Request Method With Sensitive Query Strings",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
    "CWE-749": "Exposed Dangerous Method or Function",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-799": "Improper Control of Interaction Frequency",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1295": "Debug Messages Revealing Unnecessary Information",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
    "CWE-1391": "Use of Weak Credentials",
}

@dataclass(frozen=True)
class CheckSpec:
    """Static facts about one check. The vector is the CVSS 4.0 BASE vector for the
    typical case. Checks may override single metrics when the evidence says so."""

    id: str
    title: str
    owasp_api: Optional[str]
    owasp_web: Optional[str]
    cwe: tuple
    attack: tuple
    vector: str  # CVSS base vector. Empty only for known vulnerability entries, which take the score the advisory published
    description: str
    remediation: str
    references: tuple = ()

def _v(av="N", ac="L", at="N", pr="N", ui="N", vc="N", vi="N", va="N", sc="N", si="N", sa="N") -> str:
    return (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/VC:{vc}/VI:{vi}/VA:{va}"
        f"/SC:{sc}/SI:{si}/SA:{sa}"
    )

_API_SEC = "https://owasp.org/API-Security/editions/2023/en/"
_JWT_BCP = "https://www.rfc-editor.org/rfc/rfc8725"
_WEB_REF = "https://cheatsheetseries.owasp.org/cheatsheets/"

_SPECS = [
    # Authentication
    CheckSpec(
        "AUTH-001", "Protected operation answers without credentials",
        "API2:2023", "A07:2025", ("CWE-306", "CWE-862"), ("T1190", "T1078"),
        _v(vc="H"),
        "The operation is documented as requiring authentication, or is clearly sensitive, "
        "yet it returned data to a request that carried no credentials at all.",
        "Enforce authentication in one central place (gateway or middleware) and make it deny by default. "
        "Add a test that calls every operation without a token and expects 401.",
        (_API_SEC + "0xa2-broken-authentication/",),
    ),
    CheckSpec(
        "JWT-001", "JWT signature check can be bypassed with the 'none' algorithm",
        "API2:2023", "A07:2025", ("CWE-347",), ("T1606", "T1550.001"),
        _v(vc="H", vi="H"),
        "The server accepted a token whose header says alg=none and which has no signature. "
        "Anyone can create a token for any user.",
        "Pin the accepted algorithms on the server. Never read the algorithm from the token to choose how to verify it. "
        "Reject 'none' explicitly.",
        (_JWT_BCP,),
    ),
    CheckSpec(
        "JWT-002", "JWT signature is not verified",
        "API2:2023", "A07:2025", ("CWE-347",), ("T1606", "T1550.001"),
        _v(vc="H", vi="H"),
        "A token with a damaged signature was accepted exactly like the genuine one, so the server only decodes "
        "tokens and never checks them.",
        "Use a maintained JWT library in verify mode and fail closed on any verification error.",
        (_JWT_BCP,),
    ),
    CheckSpec(
        "JWT-003", "JWT is signed with a guessable secret",
        "API2:2023", "A04:2025", ("CWE-1391", "CWE-347"), ("T1606", "T1110"),
        _v(at="P", vc="H", vi="H"),
        "The HMAC secret that signs the supplied token was recovered offline from a short list of common values. "
        "An attacker holding any token can mint tokens for any user, including administrators.",
        "Rotate the secret now. Use at least 256 random bits from a secrets manager, or switch to an asymmetric "
        "algorithm such as ES256 or EdDSA with the private key kept on the issuer only.",
        (_JWT_BCP,),
    ),
    CheckSpec(
        "JWT-004", "JWT lives too long or never expires",
        "API2:2023", "A07:2025", ("CWE-613",), ("T1528", "T1550.001"),
        _v(ac="H", at="P", vc="L", vi="L"),
        "A stolen token stays useful for a long time, because it has no expiry or a very long one.",
        "Issue short lived access tokens (minutes), pair them with refresh tokens that can be revoked, and always set exp.",
        (_JWT_BCP,),
    ),
    # Object level
    CheckSpec(
        "BOLA-001", "One user can read another user's object",
        "API1:2023", "A01:2025", ("CWE-639", "CWE-863"), ("T1190", "T1213", "T1119"),
        _v(pr="L", vc="H"),
        "A second, different identity retrieved an object that belongs to the first identity.",
        "Check on the server that the caller owns or may access the specific object, on every request, "
        "using the identity from the token and never an id supplied by the client. Prefer unguessable ids as defence in depth.",
        (_API_SEC + "0xa1-broken-object-level-authorization/",),
    ),
    # Property level
    CheckSpec(
        "BOPLA-001", "Response exposes sensitive properties",
        "API3:2023", "A01:2025", ("CWE-200", "CWE-359"), ("T1213",),
        _v(pr="L", vc="H"),
        "A response contains fields such as password hashes, secrets or card numbers that no client should ever receive.",
        "Return explicit response models (allow lists) instead of whole database rows, and review every field a client does not need.",
        (_API_SEC + "0xa3-broken-object-property-level-authorization/",),
    ),
    CheckSpec(
        "BOPLA-002", "Privileged properties are accepted on write (mass assignment)",
        "API3:2023", "A01:2025", ("CWE-915",), ("T1190",),
        _v(pr="L", vc="L", vi="H"),
        "The operation accepted and echoed properties such as role or is_admin that a normal client must not be able to set.",
        "Bind requests to an explicit input model that lists only the writable fields. Never copy a request body straight onto a database object.",
        (_API_SEC + "0xa3-broken-object-property-level-authorization/",),
    ),
    # Resource consumption
    CheckSpec(
        "RES-001", "No upper limit on page size",
        "API4:2023", "A06:2025", ("CWE-770",), ("T1499.004",),
        _v(at="P", va="L"),
        "A very large limit parameter was honoured and a large result came back. One request can load the database and the network.",
        "Cap page size on the server (for example 100), reject larger values with 400, and set a maximum in the spec.",
        (_API_SEC + "0xa4-unrestricted-resource-consumption/",),
    ),
    CheckSpec(
        "RES-002", "No request throttling observed",
        "API4:2023", "A06:2025", ("CWE-770", "CWE-799"), ("T1499.003",),
        _v(at="P", va="L"),
        "A burst of requests was never slowed down, rejected with 429, or described by rate limit headers.",
        "Apply rate limits per identity, per IP and per operation at the gateway, and return 429 with Retry-After.",
        (_API_SEC + "0xa4-unrestricted-resource-consumption/",),
    ),
    CheckSpec(
        "RES-003", "No throttling on an authentication operation",
        "API4:2023", "A07:2025", ("CWE-307", "CWE-799"), ("T1110.001", "T1110.004"),
        _v(ac="H", at="P", vc="L", vi="L"),
        "A burst of login style requests was never slowed down. Attackers can guess passwords or stuff stolen credentials at full speed.",
        "Throttle by account and by IP, add progressive delays or lockouts, and monitor for credential stuffing.",
        (_API_SEC + "0xa2-broken-authentication/",),
    ),
    # Function level
    CheckSpec(
        "BFLA-001", "Administrative function reachable without authentication",
        "API5:2023", "A01:2025", ("CWE-306", "CWE-285"), ("T1190", "T1078"),
        _v(vc="H", vi="H", va="H"),
        "An operation under an administrative path answered a request that carried no credentials.",
        "Require authentication and an explicit admin role for every administrative route, and put management routes on an internal-only listener.",
        (_API_SEC + "0xa5-broken-function-level-authorization/",),
    ),
    CheckSpec(
        "BFLA-002", "Administrative function reachable with an ordinary token",
        "API5:2023", "A01:2025", ("CWE-285", "CWE-863"), ("T1190", "T1078"),
        _v(pr="L", vc="H", vi="H", va="H"),
        "An operation under an administrative path answered a request made with the supplied token. "
        "This is only a finding if that token belongs to a non-administrator, which is how the scanner assumes it is used.",
        "Authorise by role or permission on every function, deny by default, and test each admin route with a normal user.",
        (_API_SEC + "0xa5-broken-function-level-authorization/",),
    ),
    CheckSpec(
        "BFLA-003", "Undocumented HTTP methods are enabled",
        "API5:2023", "A02:2025", ("CWE-650", "CWE-749"), ("T1190",),
        _v(pr="L", vi="L"),
        "The server advertises methods such as PUT or DELETE for a path where the specification defines none.",
        "Allow only the methods the specification lists. Answer anything else with 405 and an accurate Allow header.",
        (_API_SEC + "0xa5-broken-function-level-authorization/",),
    ),
    # SSRF
    CheckSpec(
        "SSRF-001", "Server fetches attacker supplied URLs (proved by callback)",
        "API7:2023", "A01:2025", ("CWE-918",), ("T1190",),
        _v(pr="L", vc="L", sc="L"),
        "The scanner passed a URL that points to its own listener, and the target called it. "
        "The server can therefore be steered to make requests from inside your network.",
        "Do not fetch user supplied URLs. If you must, use an allow list of hosts, resolve and check the IP, block private "
        "and link local ranges, disable redirects, and run the fetcher in an isolated network segment.",
        (_API_SEC + "0xa7-server-side-request-forgery/",),
    ),
    CheckSpec(
        "SSRF-002", "Cloud metadata service reachable through the API",
        "API7:2023", "A01:2025", ("CWE-918",), ("T1552.005", "T1190"),
        _v(pr="L", vc="H", vi="L", sc="H"),
        "Content from the cloud instance metadata address was returned. Credentials for the cloud account are usually one request away.",
        "Block 169.254.169.254 and fd00:ec2::254 at the egress layer, require IMDSv2 with hop limit 1, and fix the URL fetching code.",
        (_API_SEC + "0xa7-server-side-request-forgery/",),
    ),
    # Configuration
    CheckSpec(
        "CFG-001", "CORS trusts any origin together with credentials",
        "API8:2023", "A02:2025", ("CWE-942", "CWE-346"), ("T1539", "T1190"),
        _v(ui="P", vc="H", vi="L"),
        "The server echoed a hostile Origin and allowed credentials, so any website can read authenticated responses from a victim's browser.",
        "Allow only an explicit list of trusted origins. Never reflect the Origin header, never allow 'null', and avoid credentials unless required.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    CheckSpec(
        "CFG-003", "Error responses leak internals",
        "API8:2023", "A10:2025", ("CWE-209", "CWE-1295"), ("T1592.002", "T1595.002"),
        _v(at="P", vc="L"),
        "A response contained a stack trace, source path or database error message.",
        "Return a generic error body with a correlation id, log the details on the server, and run with debug mode off.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    CheckSpec(
        "VULN-001", "Known vulnerabilities in a component",
        "API8:2023", "A03:2025", ("CWE-1395",), ("T1190",),
        "",  # the score is the one published for the advisory, not a vector of ours
        "A component version announced by the target has published security advisories.",
        "Upgrade to a release that fixes the listed advisories, or apply the vendor's patch, and stop announcing exact versions.",
        ("https://osv.dev/", "https://nvd.nist.gov/"),
    ),
    CheckSpec(
        "CFG-006", "Service is served over plain HTTP",
        "API8:2023", "A04:2025", ("CWE-319",), ("T1557", "T1040"),
        _v(av="A", ac="H", at="P", vc="H", vi="H"),
        "Traffic, including tokens, can be read or changed by anyone on the network path.",
        "Serve only over HTTPS with modern TLS, redirect or refuse HTTP, and send HSTS.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    CheckSpec(
        "CFG-007", "HTTP TRACE is enabled",
        "API8:2023", "A02:2025", ("CWE-749",), ("T1592.002",),
        _v(ac="H", at="P", ui="A", vc="L"),
        "The server reflects whole requests for the TRACE method.",
        "Disable TRACE at the web server or gateway.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    CheckSpec(
        "CFG-008", "Session cookie lacks protective flags",
        "API8:2023", "A07:2025", ("CWE-614", "CWE-1004"), ("T1539",),
        _v(ac="H", at="P", ui="P", vc="L", vi="L"),
        "A cookie that looks like a session identifier is missing Secure, HttpOnly or SameSite.",
        "Set Secure, HttpOnly and SameSite=Lax (or Strict) on every session cookie.",
        ("https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "CFG-009", "Secret credentials appear in a response",
        "API8:2023", "A04:2025", ("CWE-798", "CWE-200"), ("T1552", "T1528"),
        _v(vc="H", vi="H", sc="L", si="L"),
        "A response contains something shaped exactly like a live credential (cloud key, private key or API token).",
        "Revoke and rotate the credential now, remove it from the response, and add secret scanning to your build and logs.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    # Exposure
    CheckSpec(
        "EXP-001", "Environment file is downloadable",
        "API8:2023", "A02:2025", ("CWE-538", "CWE-552"), ("T1552.001", "T1190"),
        _v(vc="H", vi="H", sc="H", si="H"),
        "A file shaped like KEY=value configuration, typically with database passwords and API keys, is served to anyone.",
        "Remove the file from the web root now, rotate every secret in it, and deploy only build artifacts.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    CheckSpec(
        "EXP-002", "Version control metadata is downloadable",
        "API8:2023", "A02:2025", ("CWE-538", "CWE-552"), ("T1552.001", "T1190"),
        _v(vc="H"),
        "The .git directory is served, which lets an attacker rebuild the full source history, including old secrets.",
        "Block dot directories at the web server and deploy build artifacts instead of a checkout.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    CheckSpec(
        "EXP-003", "Debug or management interface is exposed",
        "API8:2023", "A02:2025", ("CWE-215", "CWE-489"), ("T1592.002", "T1552", "T1190"),
        _v(vc="H", vi="L"),
        "A diagnostic endpoint (for example Spring Boot Actuator, pprof, phpinfo or server-status) is reachable and returned real content.",
        "Bind management endpoints to an internal interface or require strong authentication, and disable the ones you do not need.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    CheckSpec(
        "EXP-005", "GraphQL introspection is enabled",
        "API8:2023", "A02:2025", ("CWE-200",), ("T1592.002", "T1595.002"),
        _v(at="P", vc="L"),
        "The full GraphQL schema, including hidden types and fields, can be downloaded by anyone.",
        "Disable introspection in production unless the API is meant to be fully public, and enforce authorisation per field.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    # Websites
    CheckSpec(
        "TLS-001", "TLS certificate or protocol problem",
        None, "A04:2025", ("CWE-295", "CWE-324"), ("T1557",),
        _v(ac="H", at="P", vc="L", vi="L"),
        "The HTTPS connection fails certificate checks (expired, wrong name, untrusted issuer) or still accepts an obsolete TLS version.",
        "Install a valid certificate for the exact host name, renew it before it expires, and allow only TLS 1.2 and 1.3.",
        (_WEB_REF + "Transport_Layer_Security_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "TLS-002", "Server accepts weak TLS cipher suites",
        None, "A04:2025", ("CWE-327", "CWE-326"), ("T1557",),
        _v(av="A", ac="H", at="P", vc="H", vi="L"),
        "The server agrees to cipher suites that offer no or broken protection: no encryption, no server authentication, export grade, RC4, DES or 3DES.",
        "Disable these suites and offer only AEAD suites (AES-GCM or ChaCha20-Poly1305) with ECDHE key exchange, as in the Mozilla intermediate profile.",
        ("https://wiki.mozilla.org/Security/Server_Side_TLS", _WEB_REF + "Transport_Layer_Security_Cheat_Sheet.html"),
    ),
    CheckSpec(
        "WEB-004", "Insecure content is loaded on an HTTPS page",
        None, "A04:2025", ("CWE-319",), ("T1557",),
        _v(ac="H", at="P", ui="P", vc="L", vi="L"),
        "An HTTPS page loads a script, stylesheet or frame over plain HTTP. Anyone on the network path can replace it and run code in the page.",
        "Load every resource over HTTPS, and add the upgrade-insecure-requests CSP directive while you fix the old links.",
        (_WEB_REF + "Transport_Layer_Security_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "WEB-006", "Login form sends the password without encryption",
        None, "A04:2025", ("CWE-523", "CWE-319"), ("T1557", "T1040"),
        _v(av="A", vc="H"),
        "A form with a password field is served over HTTP, posts to an HTTP address, or uses GET so the password lands in the URL.",
        "Serve the page and post the form over HTTPS only, always use POST for passwords, and redirect all HTTP traffic to HTTPS.",
        (_WEB_REF + "Authentication_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "WEB-007", "Directory listing is enabled",
        None, "A02:2025", ("CWE-548",), ("T1083",),
        _v(at="P", vc="L"),
        "The server shows a browsable list of files for a folder instead of a page. It often reveals backups and internal files.",
        "Turn off automatic indexes (for example Options -Indexes in Apache, autoindex off in nginx) and keep private files out of the web root.",
        (_WEB_REF + "Securing_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "WEB-008", "JavaScript source maps are public",
        None, "A02:2025", ("CWE-540",), ("T1592.002",),
        _v(at="P", vc="L"),
        "A source map that includes the original source code is downloadable, which exposes internal logic, comments and sometimes secrets.",
        "Do not publish .map files to production, or serve them only to authenticated developers.",
        ("https://developer.mozilla.org/docs/Web/HTTP/Headers/SourceMap",),
    ),
    CheckSpec(
        "WEB-009", "Open redirect",
        None, "A01:2025", ("CWE-601",), ("T1566.002",),
        _v(ui="A", sc="L", si="L"),
        "A parameter sends visitors to any address you give it. Attackers use this to make phishing links look like they belong to your site.",
        "Redirect only to relative paths or to an allowlist of known destinations, and never to a raw user supplied URL.",
        (_WEB_REF + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "EXP-006", "Backup, dump or leftover file is downloadable",
        None, "A02:2025", ("CWE-538", "CWE-552"), ("T1552.001", "T1190"),
        _v(vc="H"),
        "A backup, database dump, password file or editor leftover is served, and its content matches what such a file contains.",
        "Delete the file from the web root, rotate any secret it contained, and keep backups outside the document root.",
        (_WEB_REF + "Securing_Cheat_Sheet.html",),
    ),
    # Inventory
    CheckSpec(
        "INV-001", "Older API version is still reachable",
        "API9:2023", "A06:2025", ("CWE-1104",), ("T1190",),
        _v(at="P", vc="L", vi="L"),
        "A lower version of the API than the documented one answered. Old versions usually miss newer security fixes.",
        "Retire old versions on a published schedule, and keep an inventory of every live version and host.",
        (_API_SEC + "0xa9-improper-inventory-management/",),
    ),
    # Injection
    CheckSpec(
        "INJ-001", "SQL injection (database error triggered)",
        None, "A05:2025", ("CWE-89",), ("T1190",),
        _v(vc="H", vi="H", va="H"),
        "A single quote in an input made the database report a syntax error that did not appear for normal input.",
        "Use parameterised queries or a safe ORM API everywhere. Never build SQL by concatenating input.",
        ("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "INJ-002", "SQL injection (time delay reproduced)",
        None, "A05:2025", ("CWE-89",), ("T1190",),
        _v(vc="H", vi="H", va="H"),
        "An injected sleep command delayed the response twice, while an identical command with zero delay did not.",
        "Use parameterised queries or a safe ORM API everywhere. Never build SQL by concatenating input.",
        ("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "INJ-003", "OS command injection (time delay reproduced)",
        None, "A05:2025", ("CWE-78",), ("T1190", "T1059"),
        _v(vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
        "An injected sleep command delayed the response twice, while an identical command with zero delay did not.",
        "Do not pass input to a shell. Use library calls, or an argument array with a strict allow list.",
        ("https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "INJ-004", "Path traversal reads files outside the intended folder",
        None, "A01:2025", ("CWE-22",), ("T1190", "T1552.001"),
        _v(vc="H"),
        "A parameter containing ../ sequences returned the contents of an operating system file.",
        "Resolve the final path and check that it stays inside the allowed folder, or map ids to files instead of accepting names.",
        ("https://owasp.org/www-community/attacks/Path_Traversal",),
    ),
    CheckSpec(
        "INJ-005", "Server side template injection",
        None, "A05:2025", ("CWE-1336",), ("T1190", "T1059"),
        _v(vc="H", vi="H", va="H"),
        "A template expression sent as input was evaluated by the server (the product of two numbers came back).",
        "Never render user input as a template. Pass it as data to a fixed template, and use a sandboxed engine.",
        ("https://portswigger.net/web-security/server-side-template-injection",),
    ),
    CheckSpec(
        "INJ-006", "Reflected cross site scripting in an HTML response",
        None, "A05:2025", ("CWE-79",), ("T1190",),
        _v(ui="A", vc="L", vi="L", sc="L", si="L"),
        "Input was returned unescaped inside an HTML response.",
        "Encode output for its context, return JSON with the correct content type, and set a strict Content-Security-Policy.",
        ("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",),
    ),
    # Specification review (no traffic needed)
    CheckSpec(
        "SPEC-002", "API key is expected in the query string",
        "API2:2023", "A04:2025", ("CWE-598",), ("T1528",),
        _v(ac="H", at="P", vc="L"),
        "Query strings end up in logs, browser history and referrer headers, which leaks the key.",
        "Send keys in a header such as Authorization or X-API-Key.",
        (_API_SEC + "0xa2-broken-authentication/",),
    ),
    CheckSpec(
        "SPEC-003", "Write operation declared without any security requirement",
        "API2:2023", "A01:2025", ("CWE-306",), ("T1190",),
        _v(vc="L", vi="H"),
        "The specification gives a state changing operation no security requirement. Either the spec is wrong or the operation is open to everyone.",
        "Add a security requirement to the operation, or confirm in writing that it is meant to be public.",
        (_API_SEC + "0xa2-broken-authentication/",),
    ),
    # OSINT
    CheckSpec(
        "OSINT-001", "Old address from the web archive still serves a sensitive file",
        "API8:2023", "A02:2025", ("CWE-538", "CWE-552"), ("T1552.001", "T1190"),
        _v(vc="H"),
        "A public web archive remembers an address that served a sensitive file (an environment file, a backup, a database dump, "
        "repository metadata). The same address still returns that content today, so anyone who looks in the archive can download it.",
        "Remove the file from the server, rotate every secret that was ever in it, and block dot files and backup extensions at the web server.",
        (_API_SEC + "0xa8-security-misconfiguration/",),
    ),
    CheckSpec(
        "OSINT-002", "Mail domain has no DMARC policy",
        None, "A02:2025", ("CWE-290",), ("T1684.002",),
        _v(at="P", ui="P", vi="L", si="L"),
        "The domain receives mail (it has MX records) but publishes no DMARC record, so receiving servers have no instruction to reject "
        "mail that falsely claims to come from it. Criminals can send convincing phishing mail in the organisation's name.",
        "Publish SPF and DKIM for every sender, then add a DMARC record, starting with p=none to collect reports and moving to p=quarantine or p=reject.",
        ("https://www.rfc-editor.org/rfc/rfc7489",),
    ),
    CheckSpec(
        "OSINT-003", "Subdomain points to a service that nobody has claimed",
        None, "A02:2025", ("CWE-672",), ("T1584.001", "T1190"),
        _v(ui="P", vc="L", vi="L", sc="L", si="L"),
        "A subdomain still points (by a CNAME record) to a hosting service, and that service reports that no one owns the name. "
        "Anyone can register it with the provider and then publish pages, scripts or login forms under the organisation's own domain.",
        "Delete the DNS record, or claim the resource again at the provider.",
        ("https://github.com/EdOverflow/can-i-take-over-xyz",),
    ),
    CheckSpec(
        "OSINT-004", "Database or remote access port is open to the internet",
        None, "A02:2025", ("CWE-668",), ("T1133", "T1190"),
        _v(at="P", vc="L", vi="L", va="L"),
        "A public source lists a service that is normally kept private (a database, cache, remote desktop or file sharing port) on the "
        "address of this site, and a connection to that port from here was accepted.",
        "Close the port in the firewall, or restrict it to the addresses that need it.",
        ("https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",),
    ),
    CheckSpec(
        "OSINT-005", "Public DNS reveals internal network addresses",
        None, "A02:2025", ("CWE-200",), ("T1590.005",),
        _v(at="P", ui="P", vc="L"),
        "Hostnames of this organisation are published in public DNS but point to private network addresses (10.x.x.x, 172.16 to 31.x.x, 192.168.x.x). "
        "That tells outsiders the names of internal systems and how the internal network is laid out.",
        "Move internal names to a private DNS zone that is not served on the internet.",
        ("https://www.rfc-editor.org/rfc/rfc1918",),
    ),
]

CATALOG: dict[str, CheckSpec] = {s.id: s for s in _SPECS}

@lru_cache(maxsize=1)
def attack_data() -> dict:
    with resources.files("api_scanner.data").joinpath("attack_subset.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)

def used_attack_ids() -> list:
    ids = set()
    for spec in CATALOG.values():
        ids.update(spec.attack)
    return sorted(ids)

def attack_label(technique_id: str) -> str:
    entry = attack_data()["techniques"].get(technique_id)
    return f"{technique_id} {entry['name']}" if entry else technique_id

def attack_tactics(technique_id: str) -> list:
    entry = attack_data()["techniques"].get(technique_id)
    return entry["tactics"] if entry else []

def cwe_label(cwe_id: str) -> str:
    name = CWE_NAMES.get(cwe_id)
    return f"{cwe_id} {name}" if name else cwe_id

def standards_summary() -> dict:
    data = attack_data()
    return {
        "OWASP API Security Top 10": "2023",
        "OWASP Top 10": "2025",
        "MITRE ATT&CK": f"Enterprise v{data['attack_version']} ({data['released']})",
        "CVSS": "scores from the scanner (v4.0) and from advisory databases",
        "Decision model": "SSVC style (Act, Attend, Track*, Track)",
    }
