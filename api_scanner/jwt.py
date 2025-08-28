from typing import Dict, Any, List, Optional
from .models import Vulnerability, CVSSScore, RiskLevel

class JWTAnalyzer:
    """JWT token analysis and vulnerability detection"""
    @staticmethod
    def decode_jwt(token: str) -> Dict[str, Any]:
        """Decode JWT token without verification"""
        try:
            import jwt as jwt_lib
        except ImportError:
            return {}
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            # Decode without verification to analyze
            decoded = jwt_lib.decode(token, options={"verify_signature": False})
            header = jwt_lib.get_unverified_header(token)
            return {
                "header": header,
                "payload": decoded,
                "raw_token": token
            }
        except Exception:
            return {}

    @staticmethod
    def analyze_jwt_vulnerabilities(token: str) -> List[Vulnerability]:
        """Analyze JWT for vulnerabilities"""
        vulnerabilities = []
        jwt_data = JWTAnalyzer.decode_jwt(token)
        if not jwt_data:
            return vulnerabilities
        header = jwt_data.get("header", {})
        payload = jwt_data.get("payload", {})
        # Check for 'none' algorithm
        if header.get("alg") == "none":
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="H", vi="H", va="H", sc="N", si="N", sa="N",
                e="A", cr="H"
            )
            score.score = min(score.score, 10.0)
            if score.score == 0.0:
                score.severity = RiskLevel.NONE
            elif score.score < 4.0:
                score.severity = RiskLevel.LOW
            elif score.score < 7.0:
                score.severity = RiskLevel.MEDIUM
            elif score.score < 9.0:
                score.severity = RiskLevel.HIGH
            else:
                score.severity = RiskLevel.CRITICAL
            vulnerabilities.append(Vulnerability(
                operation="JWT Analysis",
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API2:2023",
                vulnerability_type="JWT None Algorithm",
                description="JWT uses 'none' algorithm allowing signature bypass",
                evidence=f"Algorithm: {header.get('alg')}",
                remediation="Use proper signing algorithms (RS256, HS256, etc.)"
            ))
        # Check for weak algorithms
        weak_algs = ["HS256"]  # Consider HS256 potentially weak in some contexts
        if header.get("alg") in weak_algs:
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="L", vi="L", va="L", sc="N", si="N", sa="N",
                e="P", cr="M"
            )
            score.score = min(score.score, 10.0)
            if score.score == 0.0:
                score.severity = RiskLevel.NONE
            elif score.score < 4.0:
                score.severity = RiskLevel.LOW
            elif score.score < 7.0:
                score.severity = RiskLevel.MEDIUM
            elif score.score < 9.0:
                score.severity = RiskLevel.HIGH
            else:
                score.severity = RiskLevel.CRITICAL
            vulnerabilities.append(Vulnerability(
                operation="JWT Analysis",
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API2:2023",
                vulnerability_type="JWT Weak Algorithm",
                description="JWT uses potentially weak signing algorithm",
                evidence=f"Algorithm: {header.get('alg')}",
                remediation="Consider using RS256 or ES256 for better security"
            ))
        # Check token expiration
        if "exp" not in payload:
            score = CVSSScore.calculate(
                av="N", ac="L", at="N", pr="N", ui="N",
                vc="H", vi="H", va="L", sc="N", si="N", sa="N",
                e="P", cr="H"
            )
            score.score = min(score.score, 10.0)
            if score.score == 0.0:
                score.severity = RiskLevel.NONE
            elif score.score < 4.0:
                score.severity = RiskLevel.LOW
            elif score.score < 7.0:
                score.severity = RiskLevel.MEDIUM
            elif score.score < 9.0:
                score.severity = RiskLevel.HIGH
            else:
                score.severity = RiskLevel.CRITICAL
            vulnerabilities.append(Vulnerability(
                operation="JWT Analysis",
                risk_level=score.severity,
                cvss_score=score,
                owasp_category="API2:2023",
                vulnerability_type="JWT Missing Expiration",
                description="JWT token lacks expiration claim",
                evidence="No 'exp' claim found",
                remediation="Add expiration time to JWT tokens"
            ))
        # Check for sensitive data in payload
        sensitive_fields = ['password', 'secret', 'key', 'ssn', 'credit_card']
        for field in sensitive_fields:
            if field in str(payload).lower():
                score = CVSSScore.calculate(
                    av="N", ac="L", at="N", pr="N", ui="N",
                    vc="H", vi="H", va="L", sc="N", si="N", sa="N",
                    e="P", cr="H"
                )
                score.score = min(score.score, 10.0)
                if score.score == 0.0:
                    score.severity = RiskLevel.NONE
                elif score.score < 4.0:
                    score.severity = RiskLevel.LOW
                elif score.score < 7.0:
                    score.severity = RiskLevel.MEDIUM
                elif score.score < 9.0:
                    score.severity = RiskLevel.HIGH
                else:
                    score.severity = RiskLevel.CRITICAL
                vulnerabilities.append(Vulnerability(
                    operation="JWT Analysis",
                    risk_level=score.severity,
                    cvss_score=score,
                    owasp_category="API3:2023",
                    vulnerability_type="JWT Sensitive Data Exposure",
                    description="JWT payload contains sensitive information",
                    evidence=f"Sensitive field detected: {field}",
                    remediation="Remove sensitive data from JWT payload"
                ))
        return vulnerabilities
