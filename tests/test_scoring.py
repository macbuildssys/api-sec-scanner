import pytest

from api_scanner.knowledge import CATALOG, CWE_NAMES, OWASP_API_2023, OWASP_WEB_2025, attack_data, used_attack_ids
from api_scanner.models import Confidence, Finding, Priority, Severity
from api_scanner.scoring import (
    AssetProfile, compute_posture, decide, exposure_index, is_automatable, override_metrics, score_vector,
    technical_impact, with_environment,
)

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

def test_known_cvss4_reference_scores():
    # Values published by FIRST for these vectors.
    assert score_vector(BASE)[0] == 9.3
    assert score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")[0] == 10.0
    assert score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")[0] == 8.7

@pytest.mark.parametrize("score,band", [(0.0, Severity.INFO), (0.1, Severity.LOW), (3.9, Severity.LOW), (4.0, Severity.MEDIUM),
                                        (6.9, Severity.MEDIUM), (7.0, Severity.HIGH), (8.9, Severity.HIGH), (9.0, Severity.CRITICAL), (10.0, Severity.CRITICAL)])
def test_severity_bands_follow_the_cvss_scale(score, band):
    assert Severity.from_cvss(score) == band

def test_the_old_invalid_user_interaction_value_is_rejected():
    # The previous version used UI:R, which exists in CVSS 3.1 but not in 4.0.
    with pytest.raises(Exception):
        score_vector(BASE.replace("UI:N", "UI:R"))

def test_override_metrics_changes_only_named_metrics():
    out = override_metrics(BASE, PR="L", VA="N")
    assert "PR:L" in out and "VA:N" in out and "VC:H" in out
    assert score_vector(out)[0] < score_vector(BASE)[0]

def test_asset_profile_lowers_score_for_low_value_assets():
    vec = CATALOG["BOLA-001"].vector
    public = AssetProfile(name="weather", data_classes=["public"], availability="low", defined=True)
    bank = AssetProfile(name="bank", data_classes=["financial", "pii"], availability="critical", defined=True)
    assert score_vector(with_environment(vec, public))[0] < score_vector(vec)[0]
    # CVSS 4.0 treats "not defined" as the worst case, so a high value asset equals the base score.
    assert score_vector(with_environment(vec, bank))[0] == score_vector(vec)[0]
    assert with_environment(vec, AssetProfile()) == vec

def test_profile_validation(tmp_path):
    bad = tmp_path / "p.yaml"
    bad.write_text("exposure: moon\n")
    with pytest.raises(ValueError):
        AssetProfile.load(str(bad))
    ok = tmp_path / "ok.yaml"
    ok.write_text("name: pay\nexposure: internet\ndata_classes: [financial]\navailability: critical\nmission_impact: high\n")
    p = AssetProfile.load(str(ok))
    assert p.requirements() == {"CR": "H", "IR": "H", "AR": "H"}

def test_every_catalog_entry_is_valid():
    for spec in CATALOG.values():
        if spec.vector:
            score_vector(spec.vector)  # parses
        assert spec.owasp_api is None or spec.owasp_api in OWASP_API_2023
        assert spec.owasp_web is None or spec.owasp_web in OWASP_WEB_2025
        assert spec.owasp_api or spec.owasp_web, spec.id
        for cwe in spec.cwe:
            assert cwe in CWE_NAMES, (spec.id, cwe)
        assert spec.remediation and spec.description

def test_attack_mapping_exists_in_vendored_release():
    techniques = attack_data()["techniques"]
    assert attack_data()["attack_version"] == "20.0"
    for tid in used_attack_ids():
        assert tid in techniques, tid

def _finding(vector, confidence):
    f = Finding(check_id="X", title="x", confidence=confidence, severity=Severity.INFO, cvss_vector=vector)
    f.cvss_score, f.severity = score_vector(vector)
    return f

def test_automatable_and_technical_impact():
    assert is_automatable(BASE)
    assert not is_automatable(override_metrics(BASE, PR="L"))
    assert technical_impact(BASE) == "total"
    assert technical_impact(CATALOG["BOLA-001"].vector) == "partial"

def test_decision_follows_automation_impact_and_mission():
    high_mission = AssetProfile(mission_impact="high", defined=True)
    default = AssetProfile()
    open_door = _finding(BASE, Confidence.CONFIRMED)
    assert decide(open_door, default) == Priority.ACT
    partial = _finding(CATALOG["BOLA-001"].vector, Confidence.CONFIRMED)
    assert decide(partial, default) == Priority.TRACK_PLUS
    assert decide(partial, high_mission) == Priority.ATTEND
    low = _finding(CATALOG["CFG-007"].vector, Confidence.CONFIRMED)
    assert low.severity <= Severity.LOW and decide(low, high_mission) == Priority.TRACK  # minor issues never jump the queue

def test_posture_is_driven_by_worst_finding_not_average():
    crit = _finding(BASE, Confidence.CONFIRMED)
    lows = [_finding(CATALOG["CFG-007"].vector, Confidence.CONFIRMED) for _ in range(20)]
    assert compute_posture(lows).rating == Severity.LOW
    assert compute_posture(lows + [crit]).rating == Severity.CRITICAL
    assert compute_posture(lows + [crit]).total == 21
    assert "not proof" in compute_posture([]).statement

def test_exposure_index_is_bounded_and_monotonic():
    crit = _finding(BASE, Confidence.CONFIRMED)
    assert exposure_index([]) == 0.0
    one = exposure_index([crit])
    two = exposure_index([crit, _finding(CATALOG["BOLA-001"].vector, Confidence.CONFIRMED)])
    many = exposure_index([crit] * 50)
    assert 0 < one < two <= many <= 100
