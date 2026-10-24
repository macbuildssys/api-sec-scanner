"""Quantitative risk scoring.

Why this replaces qualitative methods such as DREAD
---------------------------------------------------
DREAD asks a person to guess five numbers (damage, reproducibility, exploitability,
affected users, discoverability). Two people give different answers, and the
discoverability factor even rewards security through obscurity. Microsoft dropped it.

This module uses three layers instead, each one reproducible from evidence:

1. CVSS v4.0 base score. The vector is fixed per kind of weakness (see knowledge.py)
   and scored with the official reference tables (macrovectors), not a home made formula.
2. Environmental metrics. A short asset profile (data classes, availability need) sets
   the Confidentiality, Integrity and Availability Requirements, so the same flaw
   scores higher on a payments API than on a public weather API. This is how CVSS 4.0
   itself says to express "how critical is this asset".
3. A decision outcome in the style of CISA SSVC (Act, Attend, Track*, Track) that
   combines what the scanner proved (exploitation evidence), whether the flaw can be
   automated by anyone, the technical impact and the mission impact.

The overall rating of an API is the worst CONFIRMED finding, never an average,
because one open door matters more than ten closed ones.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import yaml
from cvss import CVSS2, CVSS3, CVSS4

from .models import Finding, Posture, Priority, Severity

_CONFIDENTIAL_CLASSES = {"pii", "financial", "health", "credentials", "secret"}
_INTEGRITY_CLASSES = {"financial", "health", "credentials", "secret"}

@dataclass
class AssetProfile:
    """What the scanned API is worth. All fields are optional."""

    name: str = "unnamed API"
    exposure: str = "internet"  # internet or internal
    data_classes: list = field(default_factory=list)  # public, internal, pii, financial, health, credentials, secret
    availability: str = "normal"  # low, normal or critical
    mission_impact: str = "medium"  # low, medium or high
    defined: bool = False  # True when the user supplied a profile

    @classmethod
    def load(cls, path: Optional[str]) -> "AssetProfile":
        if not path:
            return cls()
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        profile = cls(
            name=str(raw.get("name", "unnamed API")),
            exposure=str(raw.get("exposure", "internet")).lower(),
            data_classes=[str(x).lower() for x in raw.get("data_classes", [])],
            availability=str(raw.get("availability", "normal")).lower(),
            mission_impact=str(raw.get("mission_impact", "medium")).lower(),
            defined=True,
        )
        profile.validate()
        return profile

    def validate(self) -> None:
        if self.exposure not in ("internet", "internal"):
            raise ValueError("asset profile: exposure must be 'internet' or 'internal'")
        if self.availability not in ("low", "normal", "critical"):
            raise ValueError("asset profile: availability must be low, normal or critical")
        if self.mission_impact not in ("low", "medium", "high"):
            raise ValueError("asset profile: mission_impact must be low, medium or high")
        known = {"public", "internal"} | _CONFIDENTIAL_CLASSES
        unknown = set(self.data_classes) - known
        if unknown:
            raise ValueError(f"asset profile: unknown data_classes {sorted(unknown)}; allowed {sorted(known)}")

    def requirements(self) -> dict:
        """CVSS 4.0 environmental security requirements (CR, IR, AR)."""
        if not self.defined:
            return {}
        classes = set(self.data_classes)
        if classes & _CONFIDENTIAL_CLASSES:
            cr = "H"
        elif "internal" in classes:
            cr = "M"
        elif classes:
            cr = "L"
        else:
            cr = "M"
        if classes & _INTEGRITY_CLASSES:
            ir = "H"
        elif classes & {"pii", "internal"}:
            ir = "M"
        elif classes:
            ir = "L"
        else:
            ir = "M"
        ar = {"critical": "H", "normal": "M", "low": "L"}[self.availability]
        return {"CR": cr, "IR": ir, "AR": ar}

    def to_dict(self) -> dict:
        return asdict(self)

def override_metrics(vector: str, **metrics: str) -> str:
    """Return the vector with some base metrics replaced, e.g. override_metrics(v, PR="L")."""
    parts = vector.split("/")
    out = []
    wanted = {k.upper(): v for k, v in metrics.items()}
    for part in parts:
        key = part.split(":", 1)[0]
        if key in wanted:
            out.append(f"{key}:{wanted[key]}")
        else:
            out.append(part)
    return "/".join(out)

def score_vector(vector: str) -> tuple:
    """Score a CVSS 4.0 vector. Returns (score, Severity)."""
    cvss = CVSS4(vector)
    score = float(cvss.base_score)
    return score, Severity.from_cvss(score)

def score_published(vector: str) -> tuple:
    """Score a vector published by an advisory database (CVSS 4.0, 3.x or 2.0).
    Returns (score, Severity, version)."""
    if vector.startswith("CVSS:4.0"):
        cvss, version = CVSS4(vector), "4.0"
    elif vector.startswith("CVSS:3"):
        cvss, version = CVSS3(vector), vector.split("/", 1)[0].split(":")[1]
    else:
        cvss, version = CVSS2(vector), "2.0"
    score = float(cvss.base_score)
    return score, Severity.from_cvss(score), version

def with_environment(vector: str, profile: AssetProfile) -> str:
    """Append the environmental requirement metrics to a base vector."""
    req = profile.requirements()
    if not req:
        return vector
    return f"{vector}/CR:{req['CR']}/IR:{req['IR']}/AR:{req['AR']}"

def _metrics(vector: str) -> dict:
    return dict(part.split(":", 1) for part in vector.split("/")[1:])

def is_automatable(vector: str) -> bool:
    """True when anyone on the network can repeat the attack with no setup."""
    m = _metrics(vector)
    return m.get("AV") == "N" and m.get("AC") == "L" and m.get("AT", "N") == "N" and m.get("PR") == "N" and m.get("UI") == "N"

def technical_impact(vector: str) -> str:
    """total, partial or none. Total means the attacker controls the vulnerable system."""
    m = _metrics(vector)
    vuln = [m.get("VC", m.get("C", "N")), m.get("VI", m.get("I", "N")), m.get("VA", m.get("A", "N"))]  # CVSS 3.x names as a fallback
    if vuln.count("H") >= 2 or (vuln[1] == "H" and m.get("PR") == "N"):
        return "total"
    if "H" in vuln or "L" in vuln:
        return "partial"
    return "none"

def decide(finding: Finding, profile: AssetProfile) -> Priority:
    """SSVC style decision. A simplified, documented rule set, not CISA's full trees.

    Inputs: automatable, technical impact (from the vector), severity and mission
    impact (from the asset profile). Every scored finding was observed by the scanner.
    """
    if not finding.cvss_vector or finding.severity <= Severity.LOW:
        return Priority.TRACK
    auto = is_automatable(finding.cvss_vector)
    tech = technical_impact(finding.cvss_vector)
    mission = profile.mission_impact
    if tech == "none":
        return Priority.TRACK
    if (auto and tech == "total") or (tech == "total" and mission == "high"):
        return Priority.ACT
    if auto or tech == "total" or mission == "high":
        return Priority.ATTEND
    return Priority.TRACK_PLUS

def exposure_index(findings: Iterable[Finding]) -> float:
    """0 to 100 index for comparing scans over time.

    Each scored finding contributes p = (score / 10) squared. The index is
    100 * (1 - product of (1 - p)), a noisy OR: more findings and worse findings push
    it up, with diminishing returns, and it never exceeds 100. It is a ranking aid,
    not a probability.
    """
    survive = 1.0
    for f in findings:
        if f.cvss_score is None:
            continue
        survive *= 1.0 - min((f.cvss_score / 10.0) ** 2, 0.999)
    return round(100.0 * (1.0 - survive), 1)

def compute_posture(findings: list) -> Posture:
    scored = [f for f in findings if f.cvss_score is not None]
    worst = max((f.severity for f in scored), default=Severity.INFO)
    by_severity = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for f in scored:
        by_severity[f.severity.label] += 1
    if scored:
        top = sum(1 for f in scored if f.severity == worst)
        statement = f"Rated {worst.label}: {len(scored)} weakness(es) with a score, {top} of them at {worst.label} level."
    else:
        statement = "No weaknesses found by the checks that ran. This is not proof that the target is secure."
    return Posture(rating=worst, exposure_index=exposure_index(findings), total=len(scored), by_severity=by_severity, statement=statement)
