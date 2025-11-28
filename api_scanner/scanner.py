import asyncio
import time
import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import aiohttp
import requests
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from datetime import datetime
from .discoverer import APIDiscoverer
from .models import (
    RiskLevel, HTTPMethod, AuthType, CVSSScore, TechnologyInfo,
    Vulnerability, DiscoveryResult, ScanResult
)
from .jwt import JWTAnalyzer
from .analyzer import OpenAPIAnalyzer
from .detector import TechnologyDetector

class AdvancedVulnerabilityScanner:
    """Advanced vulnerability scanning with comprehensive OWASP API Top 10 coverage"""

    def __init__(self):
        self.owasp_categories = {
            "API1:2023": "Broken Object Level Authorization",
            "API2:2023": "Broken Authentication",
            "API3:2023": "Broken Object Property Level Authorization",
            "API4:2023": "Unrestricted Resource Consumption",
            "API5:2023": "Broken Function Level Authorization",
            "API6:2023": "Unrestricted Access to Sensitive Business Flows",
            "API7:2023": "Server Side Request Forgery",
            "API8:2023": "Security Misconfiguration",
            "API9:2023": "Improper Inventory Management",
            "API10:2023": "Unsafe Consumption of APIs"
        }

    def scan_broken_object_authorization(self, url: str, method: str, response_content: str, status_code: int) -> List[Vulnerability]:
        """API1:2023 - Broken Object Level Authorization"""
        vulnerabilities = []
        operation = f"{method} {urlparse(url).path}"
        # Check for direct object references in URLs
        if re.search(r'/\d+(?:/|$)', url) and status_code == 200:
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="L", ui="N",
                vc="H", vi="H", va="H", sc="N", si="N", sa="N",
                e="P", cr="H"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API1:2023",
                vulnerability_type="Broken Object Level Authorization",
                description="Potential direct object reference without proper authorization checks",
                evidence=f"Endpoint accepts ID parameter without auth validation",
                remediation="Implement proper object-level authorization checks"
            ))
        # Check for user/ID enumeration
        if any(keyword in response_content.lower() for keyword in ['user_id', 'userid', 'account_id', 'customer_id']):
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="L", ui="N",
                vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                e="U", cr="M"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API1:2023",
                vulnerability_type="Object Enumeration",
                description="Response contains user/object identifiers that may enable enumeration",
                evidence="User/object IDs found in response",
                remediation="Avoid exposing internal object identifiers"
            ))
        return vulnerabilities

    def scan_broken_authentication(self, headers: Dict[str, str], operation: str, status_code: int) -> List[Vulnerability]:
        """API2:2023 - Broken Authentication"""
        vulnerabilities = []
        # Check for missing authentication
        auth_headers = ['authorization', 'x-api-key', 'api-key', 'x-auth-token']
        has_auth = any(h.lower() in [header.lower() for header in headers.keys()] for h in auth_headers)
        if status_code == 200 and not has_auth and any(sensitive in operation.lower() for sensitive in ['user', 'admin', 'account', 'profile']):
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="H", vi="H", va="H", sc="N", si="N", sa="N",
                e="A", cr="H"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API2:2023",
                vulnerability_type="Missing Authentication",
                description="Sensitive endpoint accessible without authentication",
                evidence="No authentication headers required for sensitive operation",
                remediation="Implement proper authentication mechanisms"
            ))
        # Check for weak session management
        session_cookies = ['sessionid', 'jsessionid', 'phpsessid', 'session']
        set_cookie = headers.get('set-cookie', '').lower()
        for cookie in session_cookies:
            if cookie in set_cookie and 'secure' not in set_cookie:
                score = CVSSScore.calculate(
                    av="N", ac="L", at="N", pr="N", ui="N",
                    vc="H", vi="H", va="L", sc="N", si="N", sa="N",
                    e="P", cr="H"
                )
                vulnerabilities.append(Vulnerability(
                    operation=operation,
                    risk_level=score.severity,
                    cvss_score=score,
                    owasp_category="API2:2023",
                    vulnerability_type="Insecure Session Cookie",
                    description="Session cookie lacks Secure flag",
                    evidence=f"Cookie {cookie} missing Secure flag",
                    remediation="Set Secure flag on all session cookies"
                ))
        return vulnerabilities

    def scan_broken_property_authorization(self, response_content: str, operation: str) -> List[Vulnerability]:
        """API3:2023 - Broken Object Property Level Authorization"""
        vulnerabilities = []
        try:
            if response_content.strip().startswith('{'):
                import json
                data = json.loads(response_content)
                # Check for excessive data exposure
                sensitive_fields = ['password', 'secret', 'token', 'key', 'ssn', 'credit_card', 'api_key', 'private']
                admin_fields = ['is_admin', 'admin', 'role', 'permissions', 'privileges']
                def find_sensitive_fields(obj, path="", found_fields=None):
                    if found_fields is None:
                        found_fields = []
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            current_path = f"{path}.{key}" if path else key
                            if any(sensitive.lower() in key.lower() for sensitive in sensitive_fields):
                                found_fields.append((current_path, "sensitive"))
                            elif any(admin.lower() in key.lower() for admin in admin_fields):
                                found_fields.append((current_path, "admin"))
                            find_sensitive_fields(value, current_path, found_fields)
                    elif isinstance(obj, list):
                        for i, item in enumerate(obj):
                            find_sensitive_fields(item, f"{path}[{i}]", found_fields)
                    return found_fields
                found = find_sensitive_fields(data)
                for field_path, field_type in found:
                    if field_type == "sensitive":
                        score = CVSSScore.calculate(
                            av="N", ac="L", at="N", pr="L", ui="N",
                            vc="H", vi="H", va="L", sc="N", si="N", sa="N",
                            e="P", cr="H"
                        )
                        vulnerabilities.append(Vulnerability(
                            operation=operation,
                            risk_level=score.severity,
                            cvss_score=score,
                            owasp_category="API3:2023",
                            vulnerability_type="Sensitive Data Exposure",
                            description="API response exposes sensitive user data",
                            evidence=f"Sensitive field exposed: {field_path}",
                            remediation="Filter sensitive data from API responses"
                        ))
                    elif field_type == "admin":
                        score = CVSSScore.calculate(
                            av="N", ac="L", at="N", pr="L", ui="N",
                            vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                            e="U", cr="M"
                        )
                        vulnerabilities.append(Vulnerability(
                            operation=operation,
                            risk_level=score.severity,
                            cvss_score=score,
                            owasp_category="API3:2023",
                            vulnerability_type="Admin Data Exposure",
                            description="API response exposes administrative information",
                            evidence=f"Admin field exposed: {field_path}",
                            remediation="Restrict admin fields to authorized users only"
                        ))
        except json.JSONDecodeError:
            pass
        return vulnerabilities

    def scan_resource_consumption(self, headers: Dict[str, str], operation: str, response_time: float) -> List[Vulnerability]:
        """API4:2023 - Unrestricted Resource Consumption"""
        vulnerabilities = []
        # Check for rate limiting headers
        rate_limit_headers = [
            'x-ratelimit-limit', 'x-rate-limit-limit', 'ratelimit-limit',
            'x-ratelimit-remaining', 'x-rate-limit-remaining', 'retry-after'
        ]
        has_rate_limiting = any(header.lower() in [h.lower() for h in headers.keys()] for header in rate_limit_headers)
        if not has_rate_limiting:
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                e="U", cr="M"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API4:2023",
                vulnerability_type="Missing Rate Limiting",
                description="API endpoint lacks rate limiting protection",
                evidence="No rate limiting headers detected",
                remediation="Implement rate limiting to prevent abuse"
            ))
        # Check for slow response times (potential DoS vulnerability)
        if response_time > 5.0:
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                e="U", cr="L"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API4:2023",
                vulnerability_type="Slow Response Time",
                description="Endpoint has slow response time, potential DoS vector",
                evidence=f"Response time: {response_time:.2f}s",
                remediation="Optimize endpoint performance and add timeouts"
            ))
        return vulnerabilities

    def scan_function_level_authorization(self, url: str, method: str, status_code: int) -> List[Vulnerability]:
        """API5:2023 - Broken Function Level Authorization"""
        vulnerabilities = []
        operation = f"{method} {urlparse(url).path}"
        # Check for admin endpoints without proper authorization
        admin_patterns = ['/admin', '/management', '/config', '/settings', '/debug']
        if any(pattern in url.lower() for pattern in admin_patterns) and status_code == 200:
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="H", ui="N",
                vc="H", vi="H", va="H", sc="H", si="H", sa="H",
                e="A", cr="H"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API5:2023",
                vulnerability_type="Admin Function Without Authorization",
                description="Administrative function accessible without proper authorization",
                evidence=f"Admin endpoint {url} returned 200 OK",
                remediation="Implement proper function-level authorization checks"
            ))
        # Check for dangerous HTTP methods
        if method in ['DELETE', 'PUT', 'PATCH'] and status_code != 405:
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="L", ui="N",
                vc="H", vi="H", va="H", sc="N", si="N", sa="N",
                e="P", cr="H"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API5:2023",
                vulnerability_type="Dangerous HTTP Method Allowed",
                description=f"Potentially destructive HTTP method {method} is allowed",
                evidence=f"{method} method did not return 405 Method Not Allowed",
                remediation="Restrict HTTP methods to only those required"
            ))
        return vulnerabilities

    def scan_ssrf_vulnerabilities(self, response_content: str, operation: str) -> List[Vulnerability]:
        """API7:2023 - Server Side Request Forgery with deduplication"""
        vulnerabilities = []
        seen_ssrf_indicators = set()  # Track reported SSRF indicators

        ssrf_indicators = [
            'localhost', '127.0.0.1', '0.0.0.0', '192.168.', '10.', '172.',
            'file://', 'ftp://', 'dict://', 'gopher://', 'ldap://'
        ]
        for indicator in ssrf_indicators:
            if indicator in response_content.lower() and indicator not in seen_ssrf_indicators:
                seen_ssrf_indicators.add(indicator)
                score = CVSSScore.calculate(
                    av="N", ac="L", at="N", pr="L", ui="N",
                    vc="H", vi="H", va="H", sc="H", si="H", sa="H",
                    e="P", cr="H"
                )
                vulnerabilities.append(Vulnerability(
                    operation=operation,
                    risk_level=score.severity,
                    cvss_score=score,
                    owasp_category="API7:2023",
                    vulnerability_type="Potential SSRF Vulnerability",
                    description="Response contains internal/local network references",
                    evidence=f"Found indicator: {indicator}",
                    remediation="Validate and sanitize all URL inputs"
                ))
        return vulnerabilities

    def scan_security_headers(self, headers: Dict[str, str], operation: str) -> List[Vulnerability]:
        """API8:2023 - Security Misconfiguration"""
        vulnerabilities = []
        security_checks = [
            ("x-frame-options", "X-Frame-Options Header is missing", RiskLevel.MEDIUM),
            ("x-content-type-options", "X-Content-Type-Options Header is missing", RiskLevel.LOW),
            ("strict-transport-security", "HSTS Header is missing", RiskLevel.LOW),
            ("content-security-policy", "CSP Header is not set", RiskLevel.LOW),
            ("x-xss-protection", "X-XSS-Protection Header is missing", RiskLevel.LOW),
            ("referrer-policy", "Referrer-Policy Header is missing", RiskLevel.LOW)
        ]
        for header, description, risk_level in security_checks:
            if header not in [h.lower() for h in headers.keys()]:
                score = CVSSScore.calculate(
                    av="N", ac="L", at="N", pr="N", ui="N",
                    vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                    e="U", cr="L"
                )
                vulnerabilities.append(Vulnerability(
                    operation=operation,
                    risk_level=score.severity,
                    cvss_score=score,
                    owasp_category="API8:2023",
                    vulnerability_type="Security Misconfiguration",
                    description=description,
                    remediation=f"Add {header} header with appropriate value"
                ))
        # CORS checks
        cors_origin = headers.get('access-control-allow-origin', '')
        if cors_origin == '*':
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="H", vi="H", va="L", sc="N", si="N", sa="N",
                e="P", cr="H"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API8:2023",
                vulnerability_type="Overly Permissive CORS",
                description="CORS policy allows all origins (*)",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Restrict CORS to specific trusted domains"
            ))
        elif not any(cors_header.lower().startswith('access-control-') for cors_header in headers.keys()):
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                e="U", cr="M"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API8:2023",
                vulnerability_type="Security Misconfiguration",
                description="CORS Headers are missing",
                remediation="Configure proper CORS headers"
            ))
        # CSP frame-ancestors check
        csp_header = headers.get('content-security-policy', '')
        if csp_header and 'frame-ancestors' not in csp_header.lower():
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                e="U", cr="M"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API8:2023",
                vulnerability_type="Security Misconfiguration",
                description="CSP frame-ancestors policy is not set",
                remediation="Add frame-ancestors directive to CSP header"
            ))
        return vulnerabilities

    def scan_information_disclosure(self, content: str, headers: Dict[str, str], operation: str) -> List[Vulnerability]:
        """Enhanced information disclosure detection"""
        vulnerabilities = []
        # Check for error information disclosure
        error_patterns = [
            (r"Traceback \(most recent call last\)", "Python Stack Trace", RiskLevel.MEDIUM),
            (r"Exception in thread", "Java Exception", RiskLevel.MEDIUM),
            (r"Fatal error:", "PHP Fatal Error", RiskLevel.MEDIUM),
            (r"Microsoft.*Exception", ".NET Exception", RiskLevel.MEDIUM),
            (r"ORA-\d{5}", "Oracle Error", RiskLevel.HIGH),
            (r"MySQL.*Error", "MySQL Error", RiskLevel.HIGH),
            (r"PostgreSQL.*ERROR", "PostgreSQL Error", RiskLevel.HIGH)
        ]
        for pattern, vuln_type, risk_level in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score = CVSSScore.calculate(
                    av="N", ac="L", at="N", pr="N", ui="N",
                    vc="H", vi="H", va="L", sc="N", si="N", sa="N",
                    e="P", cr="H"
                )
                vulnerabilities.append(Vulnerability(
                    operation=operation,
                    risk_level=score.severity,
                    cvss_score=score,
                    owasp_category="API3:2023",
                    vulnerability_type="Information Disclosure",
                    description=f"{vuln_type} exposed in response",
                    evidence=f"Pattern matched: {pattern}",
                    remediation="Implement proper error handling"
                ))
        # Check for server information disclosure
        server_header = headers.get('server', '')
        if server_header and any(tech in server_header.lower() for tech in ['apache', 'nginx', 'iis', 'tomcat']):
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                e="U", cr="L"
            )
            vulnerabilities.append(Vulnerability(
                operation=operation,
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API8:2023",
                vulnerability_type="Server Information Disclosure",
                description="Server header reveals technology stack",
                evidence=f"Server: {server_header}",
                remediation="Remove or obfuscate server version information"
            ))
        return vulnerabilities

    def scan_injection_vulnerabilities(self, content: str, operation: str) -> List[Vulnerability]:
        """Comprehensive injection vulnerability detection with deduplication"""
        vulnerabilities = []
        seen_vuln_types = set()  # Track reported vulnerability types

        # SQL Injection patterns
        sql_patterns = [
            (r"SQL syntax.*error", "SQL Syntax Error", RiskLevel.CRITICAL),
            (r"mysql_fetch", "MySQL Error", RiskLevel.HIGH),
            (r"ORA-\d{5}", "Oracle Error", RiskLevel.HIGH),
            (r"PostgreSQL.*ERROR", "PostgreSQL Error", RiskLevel.HIGH),
            (r"Microsoft.*ODBC", "ODBC Error", RiskLevel.HIGH),
            (r"SQLite.*error", "SQLite Error", RiskLevel.HIGH)
        ]
        for pattern, vuln_type, risk_level in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE) and vuln_type not in seen_vuln_types:
                seen_vuln_types.add(vuln_type)
                score = CVSSScore.calculate(
                    av="N", ac="L", at="N", pr="L", ui="N",
                    vc="H", vi="H", va="H", sc="H", si="H", sa="H",
                    e="A", cr="H"
                )
                vulnerabilities.append(Vulnerability(
                    operation=operation,
                    risk_level=score.severity,
                    cvss_score=score,
                    owasp_category="API8:2023",
                    vulnerability_type="SQL Injection",
                    description=f"Potential SQL injection - {vuln_type}",
                    evidence=f"Pattern matched: {pattern}",
                    remediation="Use parameterized queries and input validation"
                ))

        # XSS patterns
        xss_patterns = [
            (r"<script[^>]*>.*?</script>", "Script Tag Reflected", RiskLevel.MEDIUM),
            (r"javascript:", "JavaScript Protocol", RiskLevel.MEDIUM),
            (r"on\w+\s*=", "Event Handler", RiskLevel.MEDIUM)
        ]
        for pattern, vuln_type, risk_level in xss_patterns:
            if re.search(pattern, content, re.IGNORECASE) and vuln_type not in seen_vuln_types:
                seen_vuln_types.add(vuln_type)
                score = CVSSScore.calculate(
                    av="N", ac="L", at="N", pr="N", ui="R",
                    vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                    e="P", cr="M"
                )
                vulnerabilities.append(Vulnerability(
                    operation=operation,
                    risk_level=score.severity,
                    cvss_score=score,
                    owasp_category="API8:2023",
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    description=f"Potential XSS - {vuln_type}",
                    evidence=f"Pattern matched: {pattern}",
                    remediation="Sanitize and encode user input"
                ))

        # Command injection patterns
        cmd_patterns = [
            (r"sh:\s*\d+:", "Shell Command Error", RiskLevel.HIGH),
            (r"command not found", "Command Execution", RiskLevel.HIGH),
            (r"Permission denied", "File System Access", RiskLevel.MEDIUM)
        ]
        for pattern, vuln_type, risk_level in cmd_patterns:
            if re.search(pattern, content, re.IGNORECASE) and vuln_type not in seen_vuln_types:
                seen_vuln_types.add(vuln_type)
                score = CVSSScore.calculate(
                    av="N", ac="L", at="N", pr="L", ui="N",
                    vc="H", vi="H", va="H", sc="N", si="N", sa="N",
                    e="P", cr="H"
                )
                vulnerabilities.append(Vulnerability(
                    operation=operation,
                    risk_level=score.severity,
                    cvss_score=score,
                    owasp_category="API8:2023",
                    vulnerability_type="Command Injection",
                    description=f"Potential command injection - {vuln_type}",
                    evidence=f"Pattern matched: {pattern}",
                    remediation="Validate and sanitize all user inputs"
                ))

        return vulnerabilities

    async def scan_endpoint(self, session: aiohttp.ClientSession, method: str, url: str,
                          jwt_token: Optional[str] = None) -> List[Vulnerability]:
        """Comprehensive endpoint vulnerability scan"""
        vulnerabilities = []
        operation = f"{method} {urlparse(url).path}"
        # Prepare headers
        headers = {}
        if jwt_token:
            headers['Authorization'] = f'Bearer {jwt_token}'
            # Analyze JWT vulnerabilities
            vulnerabilities.extend(JWTAnalyzer.analyze_jwt_vulnerabilities(jwt_token))
        try:
            # Test various payloads for comprehensive testing
            test_payloads = [
                "",  # Normal request
                "' OR '1'='1 --",  # SQL injection
                "<script>alert('xss')</script>",  # XSS
                "../../../../etc/passwd",  # Path traversal
                "{{7*7}}",  # Template injection
                "../../../windows/system32/drivers/etc/hosts",  # Windows path traversal
                "http://localhost:8080/admin",  # SSRF test
                "; cat /etc/passwd #",  # Command injection
            ]
            start_time = time.time()
            for i, payload in enumerate(test_payloads):
                test_params = {"test": payload} if payload else {}
                test_data = {"data": payload} if payload and method in ['POST', 'PUT', 'PATCH'] else None
                async with session.request(method, url, params=test_params, json=test_data, headers=headers) as response:
                    content = await response.text()
                    response_headers = dict(response.headers)
                    response_time = time.time() - start_time
                    # Run all vulnerability scans (only once for normal request)
                    if i == 0:  # First iteration (normal request)
                        vulnerabilities.extend(
                            self.scan_broken_object_authorization(url, method, content, response.status)
                        )
                        vulnerabilities.extend(
                            self.scan_broken_authentication(response_headers, operation, response.status)
                        )
                        vulnerabilities.extend(
                            self.scan_broken_property_authorization(content, operation)
                        )
                        vulnerabilities.extend(
                            self.scan_resource_consumption(response_headers, operation, response_time)
                        )
                        vulnerabilities.extend(
                            self.scan_function_level_authorization(url, method, response.status)
                        )
                        vulnerabilities.extend(
                            self.scan_security_headers(response_headers, operation)
                        )
                        vulnerabilities.extend(
                            self.scan_information_disclosure(content, response_headers, operation)
                        )
                    # Test for SSRF and injection on all payloads
                    vulnerabilities.extend(
                        self.scan_ssrf_vulnerabilities(content, operation)
                    )
                    vulnerabilities.extend(
                        self.scan_injection_vulnerabilities(content, operation)
                    )
        except Exception:
            pass

        # Deduplicate vulnerabilities
        unique_vulnerabilities = []
        seen_vuln_keys = set()
        for vuln in vulnerabilities:
            vuln_key = (vuln.operation, vuln.vulnerability_type, vuln.evidence)
            if vuln_key not in seen_vuln_keys:
                seen_vuln_keys.add(vuln_key)
                unique_vulnerabilities.append(vuln)

        return unique_vulnerabilities

class AdvancedAPIScanner:
    """Main advanced API scanner orchestrator"""

    def __init__(self):
        self.discoverer = APIDiscoverer()
        self.scanner = AdvancedVulnerabilityScanner()
        self.openapi_analyzer = OpenAPIAnalyzer()

    async def discover_api(self, base_url: str) -> DiscoveryResult:
        """Perform API discovery"""
        return await self.discoverer.discover(base_url)

    async def scan_curl(self, url: str, method: str = "GET", headers: Dict[str, str] = None,
                       jwt_token: Optional[str] = None) -> ScanResult:
        """Scan using curl-like approach"""
        start_time = time.time()
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            ) as progress:
                scan_task = progress.add_task(f"Scanning {url}...", total=1)
                vulnerabilities = await self.scanner.scan_endpoint(session, method, url, jwt_token)
                progress.update(scan_task, advance=1)
        try:
            response = requests.get(url, timeout=10)
            tech_info = TechnologyDetector.detect_from_response(response.text, dict(response.headers))
        except:
            tech_info = TechnologyInfo()
        end_time = time.time()

        # Generate advice based on risk levels and CVSS scores
        risk_counts = {}
        for vuln in vulnerabilities:
            if vuln.cvss_score.score > 0.0:
                risk_counts[vuln.risk_level] = risk_counts.get(vuln.risk_level, 0) + 1
        if risk_counts.get(RiskLevel.CRITICAL, 0) > 0:
            advice = "Critical vulnerabilities found! Immediate action required."
        elif risk_counts.get(RiskLevel.HIGH, 0) > 0:
            advice = "High-risk vulnerabilities detected. Prompt remediation advised."
        elif risk_counts.get(RiskLevel.MEDIUM, 0) > 0:
            advice = "There are some medium-risk issues. It's advised to take a look."
        elif risk_counts.get(RiskLevel.LOW, 0) > 0:
            advice = "Low-risk issues found. Consider addressing when convenient."
        else:
            advice = "No significant vulnerabilities detected. Good security posture!"

        return ScanResult(
            target_url=url,
            scan_method="curl",
            scan_timestamp=datetime.now().isoformat(),
            technologies=tech_info,
            vulnerabilities=vulnerabilities,
            total_operations=1,
            scan_duration=end_time - start_time,
            advice=advice
        )

    async def scan_openapi(self, openapi_spec_path: str, jwt_token: Optional[str] = None) -> ScanResult:
        """Scan using OpenAPI specification"""
        start_time = time.time()
        # Parse OpenAPI spec
        spec = self.openapi_analyzer.parse_openapi(openapi_spec_path)
        if not spec:
            raise ValueError("Failed to parse OpenAPI specification")
        endpoints = self.openapi_analyzer.extract_endpoints(spec)
        all_vulnerabilities = []
        # Scan all endpoints
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
            ) as progress:
                scan_task = progress.add_task("Scanning operations...", total=len(endpoints))
                for method, url, operation_id in endpoints:
                    progress.update(scan_task, description=f"Scanning {method} {operation_id}")
                    vulnerabilities = await self.scanner.scan_endpoint(session, method, url, jwt_token)
                    all_vulnerabilities.extend(vulnerabilities)
                    progress.advance(scan_task)

        # Deduplicate vulnerabilities
        unique_vulnerabilities = []
        seen_vuln_keys = set()
        for vuln in all_vulnerabilities:
            vuln_key = (vuln.operation, vuln.vulnerability_type, vuln.evidence)
            if vuln_key not in seen_vuln_keys:
                seen_vuln_keys.add(vuln_key)
                unique_vulnerabilities.append(vuln)

        # Detect technology from base URL
        base_url = ""
        if "servers" in spec and spec["servers"]:
            base_url = spec["servers"][0].get("url", "")
        tech_info = TechnologyInfo()
        if base_url:
            try:
                response = requests.get(base_url, timeout=10)
                tech_info = TechnologyDetector.detect_from_response(response.text, dict(response.headers))
            except:
                pass
        end_time = time.time()

        # Generate advice
        risk_counts = {}
        for vuln in unique_vulnerabilities:
            if vuln.cvss_score.score > 0.0:
                risk_counts[vuln.risk_level] = risk_counts.get(vuln.risk_level, 0) + 1
        if risk_counts.get(RiskLevel.CRITICAL, 0) > 0:
            advice = "Critical vulnerabilities found! Immediate action required."
        elif risk_counts.get(RiskLevel.HIGH, 0) > 0:
            advice = "High-risk vulnerabilities detected. Prompt remediation advised."
        elif risk_counts.get(RiskLevel.MEDIUM, 0) > 0:
            advice = "There are some medium-risk issues. It's advised to take a look."
        elif risk_counts.get(RiskLevel.LOW, 0) > 0:
            advice = "Low-risk issues found. Consider addressing when convenient."
        else:
            advice = "No significant vulnerabilities detected. Good security posture!"

        return ScanResult(
            target_url=base_url or openapi_spec_path,
            scan_method="openapi",
            scan_timestamp=datetime.now().isoformat(),
            technologies=tech_info,
            vulnerabilities=unique_vulnerabilities,
            total_operations=len(endpoints),
            scan_duration=end_time - start_time,
            advice=advice
        )
