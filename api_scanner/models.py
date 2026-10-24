"""Core data types shared by every part of the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Optional
from urllib.parse import quote

class Severity(IntEnum):
    """Severity band. Bands follow the official CVSS 4.0 qualitative scale."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        # CVSS 4.0: 0.0 None, 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical
        if score <= 0.0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL

    @property
    def label(self) -> str:
        return self.name.title()

    @classmethod
    def parse(cls, text: str) -> "Severity":
        return cls[text.strip().upper()]

class Confidence(str, Enum):
    """Internal only, never shown to the user. Every reported finding is something the scanner observed.

    CONFIRMED  A weakness that gets a CVSS score.
    """

    CONFIRMED = "confirmed"

class Priority(str, Enum):
    """Decision outcome, modelled on the CISA SSVC vocabulary."""

    ACT = "Act"
    ATTEND = "Attend"
    TRACK_PLUS = "Track*"
    TRACK = "Track"

    @property
    def rank(self) -> int:
        return {"Act": 3, "Attend": 2, "Track*": 1, "Track": 0}[self.value]

@dataclass
class Param:
    name: str
    location: str  # path, query, header, cookie
    required: bool = False
    schema: dict[str, Any] = field(default_factory=dict)
    example: Any = None

@dataclass
class Endpoint:
    method: str
    path: str  # path template, for example /users/{id}
    base_url: str
    op_id: str = ""
    params: list[Param] = field(default_factory=list)
    body_schema: Optional[dict[str, Any]] = None
    body_example: Any = None
    body_content_type: Optional[str] = None
    secured: Optional[bool] = None  # None means the spec did not say
    security_schemes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False
    documented: bool = True
    summary: str = ""

    @property
    def label(self) -> str:
        return f"{self.method} {self.path}"

    def path_param_names(self) -> list[str]:
        return [p.name for p in self.params if p.location == "path"]

    def url(self, overrides: Optional[dict[str, Any]] = None) -> str:
        """Build the full URL, filling path parameters with examples or overrides."""
        overrides = overrides or {}
        path = self.path
        for p in self.params:
            if p.location != "path":
                continue
            value = overrides.get(p.name, p.example)
            if value is None:
                value = "1"
            path = path.replace("{" + p.name + "}", quote(str(value), safe=""))
        # Any template variable the spec forgot to declare gets a neutral value.
        while "{" in path and "}" in path:
            start, end = path.index("{"), path.index("}")
            path = path[:start] + "1" + path[end + 1:]
        return self.base_url.rstrip("/") + "/" + path.lstrip("/") if path else self.base_url

    def query_defaults(self) -> dict[str, Any]:
        """Example values for required query parameters."""
        return {
            p.name: p.example
            for p in self.params
            if p.location == "query" and p.required and p.example is not None
        }

@dataclass
class Finding:
    check_id: str
    title: str
    confidence: Confidence
    severity: Severity
    cvss_vector: str = ""
    cvss_score: Optional[float] = None
    cvss_version: str = "4.0"  # 4.0 for the scanner's own checks, the published version for known vulnerabilities
    owasp_api: Optional[str] = None
    owasp_web: Optional[str] = None
    cwe: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    priority: Priority = Priority.TRACK
    operations: list[str] = field(default_factory=list)
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (self.check_id, self.title)

    @property
    def scored(self) -> bool:
        """True for a weakness with a CVSS score."""
        return self.cvss_score is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.label,
            "cvss": {"version": self.cvss_version, "score": self.cvss_score, "vector": self.cvss_vector}
            if self.cvss_vector
            else None,
            "priority": self.priority.value,
            "owasp_api_2023": self.owasp_api,
            "owasp_top10_2025": self.owasp_web,
            "cwe": self.cwe,
            "mitre_attack": self.attack,
            "operations": self.operations,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }

@dataclass
class Posture:
    """Overall rating of the scanned API."""

    rating: Severity  # worst scored finding
    exposure_index: float  # 0 to 100, for trending, not a probability
    total: int  # scored weaknesses only
    by_severity: dict[str, int]  # scored weaknesses only
    statement: str

@dataclass
class ScanResult:
    target: str
    started: str
    duration: float
    requests_sent: int
    mode: dict[str, Any]
    endpoints_tested: int
    findings: list[Finding]
    posture: Posture
    technologies: list[str]
    asset_profile: dict[str, Any]
    notes: list[str] = field(default_factory=list)
    tool_version: str = ""
    standards: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "api-sec-scanner", "version": self.tool_version},
            "standards": self.standards,
            "target": self.target,
            "started": self.started,
            "duration_seconds": round(self.duration, 2),
            "requests_sent": self.requests_sent,
            "mode": self.mode,
            "endpoints_tested": self.endpoints_tested,
            "technologies": self.technologies,
            "asset_profile": self.asset_profile,
            "posture": {
                "rating": self.posture.rating.label,
                "exposure_index": self.posture.exposure_index,
                "total": self.posture.total,
                "by_severity": self.posture.by_severity,
                "statement": self.posture.statement,
            },
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
        }
