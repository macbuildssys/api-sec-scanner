from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Union
from datetime import datetime

class RiskLevel(Enum):
    """Risk/Severity levels with CVSS 4.0 alignment"""
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    INFO = "Info"

class HTTPMethod(Enum):
    """HTTP Methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"

class AuthType(Enum):
    """API Authentication types"""
    NONE = "none"
    JWT_BEARER = "jwt_bearer"
    API_KEY_HEADER = "api_key_header"
    API_KEY_QUERY = "api_key_query"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"

@dataclass
class CVSSScore:
    """CVSS 4.0 Score representation with Base, Temporal, and Environmental support"""
    score: float
    vector: str
    severity: RiskLevel

    @classmethod
    def calculate(
        cls,
        # Base Metrics
        av: str,  # Attack Vector: N, A, L, P
        ac: str,  # Attack Complexity: L, H
        at: str,  # Attack Requirements: N, P
        pr: str,  # Privileges Required: N, L, H
        ui: str,  # User Interaction: N, R
        vc: str,  # Vulnerable System Confidentiality: H, L, N
        vi: str,  # Vulnerable System Integrity: H, L, N
        va: str,  # Vulnerable System Availability: H, L, N
        sc: str,  # Subsequent System Confidentiality: H, L, N
        si: str,  # Subsequent System Integrity: H, L, N
        sa: str,  # Subsequent System Availability: H, L, N
        # Temporal Metrics (default: Not Defined)
        e: str = "X",  # Exploit Maturity: X, U, P, A
        # Environmental Metrics (default: Not Defined)
        cr: str = "X",  # Confidentiality Requirement: X, L, M, H
        ir: str = "X",  # Integrity Requirement: X, L, M, H
        ar: str = "X",  # Availability Requirement: X, L, M, H
        mav: str = "X",  # Modified Attack Vector: X, N, A, L, P
        mac: str = "X",  # Modified Attack Complexity: X, L, H
        mat: str = "X",  # Modified Attack Requirements: X, N, P
        mpr: str = "X",  # Modified Privileges Required: X, N, L, H
        mui: str = "X",  # Modified User Interaction: X, N, R
        mvc: str = "X",  # Modified Vulnerable System Confidentiality: X, H, L, N
        mvi: str = "X",  # Modified Vulnerable System Integrity: X, H, L, N
        mva: str = "X",  # Modified Vulnerable System Availability: X, H, L, N
        msc: str = "X",  # Modified Subsequent System Confidentiality: X, H, L, N
        msi: str = "X",  # Modified Subsequent System Integrity: X, H, L, N
        msa: str = "X",  # Modified Subsequent System Availability: X, H, L, N
    ) -> "CVSSScore":
        """
         Base Score Calculation
         Exploitability Coefficients
        """
        av_coeff = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.22}
        ac_coeff = {"L": 0.77, "H": 0.44}
        at_coeff = {"N": 0.85, "P": 0.90}
        pr_coeff = {"N": 0.85, "L": 0.62, "H": 0.27}
        ui_coeff = {"N": 0.85, "R": 0.62}
        # Impact Coefficients (scaled from 0-1 to 0-5.2)
        impact_coeff = {"H": 1.0, "L": 0.5, "N": 0.0}
        # Calculate Exploitability
        exploitability = 8.22 * av_coeff[av] * ac_coeff[ac] * pr_coeff[pr] * ui_coeff[ui] * at_coeff[at]
        # Calculate Vulnerable System Impact (VSI)
        vsi = 1 - ((1 - impact_coeff[vc]) * (1 - impact_coeff[vi]) * (1 - impact_coeff[va]))
        ssi = 1 - ((1 - impact_coeff[sc]) * (1 - impact_coeff[si]) * (1 - impact_coeff[sa]))
        if ssi <= 0:
            impact = 6.42 * vsi
        else:
            impact = 7.52 * (vsi + ssi) - 7.22 * vsi * ssi
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif impact >= 10:
            base_score = 10.0
        else:
            base_score = min(10.0, 1.08 * (impact + exploitability))
        # Exploit Maturity Coefficients
        e_coeff = {"X": 1.0, "U": 0.91, "P": 0.94, "A": 0.97}
        temporal_score = base_score * e_coeff[e]
        # Confidentiality, Integrity, Availability Requirements
        cr_coeff = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
        ir_coeff = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
        ar_coeff = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
        mav = mav if mav != "X" else av
        mac = mac if mac != "X" else ac
        mat = mat if mat != "X" else at
        mpr = mpr if mpr != "X" else pr
        mui = mui if mui != "X" else ui
        mvc = mvc if mvc != "X" else vc
        mvi = mvi if mvi != "X" else vi
        mva = mva if mva != "X" else va
        msc = msc if msc != "X" else sc
        msi = msi if msi != "X" else si
        msa = msa if msa != "X" else sa
        modified_exploitability = 8.22 * av_coeff[mav] * ac_coeff[mac] * pr_coeff[mpr] * ui_coeff[mui] * at_coeff[mat]
        mvsi = 1 - ((1 - impact_coeff[mvc]) * (1 - impact_coeff[mvi]) * (1 - impact_coeff[mva]))
        mssi = 1 - ((1 - impact_coeff[msc]) * (1 - impact_coeff[msi]) * (1 - impact_coeff[msa]))
        if mssi <= 0:
            modified_impact = 6.42 * mvsi
        else:
            modified_impact = 7.52 * (mvsi + mssi) - 7.22 * mvsi * mssi
        if modified_impact <= 0:
            modified_base = 0.0
        elif modified_impact >= 10:
            modified_base = 10.0
        else:
            modified_base = min(10.0, 1.08 * (modified_impact + modified_exploitability))
        environmental_score = (
            modified_base *
            cr_coeff[cr] *
            ir_coeff[ir] *
            ar_coeff[ar] *
            e_coeff[e]
        )
        final_score = environmental_score if cr != "X" or ir != "X" or ar != "X" else temporal_score if e != "X" else base_score
        final_score = round(min(max(final_score, 0.0), 10.0), 1)  # Ensure score is between 0.0 and 10.0
        # Determine Severity based on final score
        if final_score == 0.0:
            severity = RiskLevel.NONE
        elif final_score < 4.0:
            severity = RiskLevel.LOW
        elif final_score < 7.0:
            severity = RiskLevel.MEDIUM
        elif final_score < 9.0:
            severity = RiskLevel.HIGH
        else:
            severity = RiskLevel.CRITICAL
        # Build Vector String
        vector = (
            f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
            f"/E:{e}"
            f"/CR:{cr}/IR:{ir}/AR:{ar}"
            f"/MAV:{mav}/MAC:{mac}/MAT:{mat}/MPR:{mpr}/MUI:{mui}"
            f"/MVC:{mvc}/MVI:{mvi}/MVA:{mva}/MSC:{msc}/MSI:{msi}/MSA:{msa}"
        )
        return cls(score=final_score, vector=vector, severity=severity)

@dataclass
class TechnologyInfo:
    """Detected technology information"""
    framework: Optional[str] = None
    language: Optional[str] = None
    server: Optional[str] = None
    version: Optional[str] = None

@dataclass
class Vulnerability:
    """Enhanced vulnerability representation"""
    operation: str
    risk_level: RiskLevel
    cvss_score: CVSSScore
    owasp_category: str
    vulnerability_type: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cve_references: List[str] = None

@dataclass
class DiscoveryResult:
    """API discovery results"""
    openapi_urls: List[str]
    graphql_urls: List[str]
    well_known_urls: List[str]
    exposed_files: List[str]
    technologies: TechnologyInfo

@dataclass
class ScanResult:
    """Complete scan results"""
    target_url: str
    scan_method: str  # "curl" or "openapi"
    scan_timestamp: str
    technologies: TechnologyInfo
    vulnerabilities: List[Vulnerability]
    total_operations: int
    scan_duration: float
    advice: str
