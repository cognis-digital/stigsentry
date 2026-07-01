"""STIG -> NIST 800-53 crosswalk + status handling + RMF-mapping-gap behavior.

Covers: known vs unknown STIG IDs, the rule_id fallback, every pass/fail status
spelling, severity propagation, and what happens when a finding has no NIST
mapping at all (the RMF mapping gap).
"""
import json

import pytest

from stigsentry.core import scan, STIG_CONTROLS
from cognis_mil.models import Severity


def _scan(tmp_path, findings):
    p = tmp_path / "f.json"
    p.write_text(json.dumps(findings), encoding="utf-8")
    return scan(str(p), enrich=False)


# --------------------------------------------------------------------------- #
# crosswalk table integrity
# --------------------------------------------------------------------------- #
def test_every_crosswalk_entry_has_required_fields():
    for sid, info in STIG_CONTROLS.items():
        assert sid.startswith("V-"), sid
        assert info["title"]
        assert info["nist"]
        assert isinstance(info["sev"], Severity)
        assert info["cci"].startswith("CCI-")


def test_crosswalk_nist_ids_are_normalizable():
    from stigsentry.feeds import normalize_control_id
    for info in STIG_CONTROLS.values():
        assert normalize_control_id(info["nist"]) != ""


# --------------------------------------------------------------------------- #
# known STIG IDs map through with full provenance
# --------------------------------------------------------------------------- #
def test_known_stig_maps_full_provenance(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-238298", "host": "h1", "status": "fail"}])
    f = next(f for f in r.findings if f.disa_stig == "V-238298")
    assert f.nist_800_53 == "SC-13"
    assert f.cci == "CCI-002450"
    assert f.severity == Severity.VERY_HIGH
    assert f.location == "h1"
    assert "SC-13" in f.remediation


def test_severity_propagates_from_table(tmp_path):
    r = _scan(tmp_path, [
        {"stig_id": "V-242414", "status": "fail"},  # VERY_HIGH
        {"stig_id": "V-238382", "status": "fail"},  # HIGH
    ])
    sev = {f.disa_stig: f.severity for f in r.findings}
    assert sev["V-242414"] == Severity.VERY_HIGH
    assert sev["V-238382"] == Severity.HIGH


# --------------------------------------------------------------------------- #
# unknown STIG IDs (the mapping gap) become tracked LOW findings, never dropped
# --------------------------------------------------------------------------- #
def test_unknown_stig_id_kept_as_low(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-999999", "status": "fail"}])
    f = next(f for f in r.findings if f.id == "SS-UNK-V-999999")
    assert f.severity == Severity.LOW
    assert "Unknown STIG ID" in f.title
    assert f.nist_800_53 == ""  # the mapping gap: no control mapped


def test_unknown_stig_id_has_remediation_hint(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-000001", "status": "fail"}])
    f = next(f for f in r.findings if f.id == "SS-UNK-V-000001")
    assert "STIG_CONTROLS" in f.remediation


def test_empty_stig_id_still_produces_unknown(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "", "status": "fail"}])
    assert any(f.id == "SS-UNK-" for f in r.findings)


# --------------------------------------------------------------------------- #
# rule_id fallback when stig_id absent
# --------------------------------------------------------------------------- #
def test_rule_id_used_when_stig_id_missing(tmp_path):
    r = _scan(tmp_path, [{"rule_id": "V-238298", "status": "fail"}])
    assert "SS-V-238298" in {f.id for f in r.findings}


def test_stig_id_wins_over_rule_id(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-238298", "rule_id": "V-238213", "status": "fail"}])
    assert "SS-V-238298" in {f.id for f in r.findings}
    assert "SS-V-238213" not in {f.id for f in r.findings}


# --------------------------------------------------------------------------- #
# status handling — every pass/non-applicable spelling is dropped
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("status", ["pass", "PASS", "Pass",
                                     "not_a_finding", "NOT_A_FINDING",
                                     "notapplicable", "not_applicable"])
def test_passing_statuses_dropped(tmp_path, status):
    r = _scan(tmp_path, [{"stig_id": "V-238298", "status": status}])
    assert r.total_findings() == 0


@pytest.mark.parametrize("status", ["fail", "FAIL", "open", "error", "unknown", ""])
def test_non_passing_statuses_kept(tmp_path, status):
    r = _scan(tmp_path, [{"stig_id": "V-238298", "status": status}])
    assert r.total_findings() == 1


def test_missing_status_treated_as_open(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-238298"}])
    assert r.total_findings() == 1


# --------------------------------------------------------------------------- #
# composite scoring / risk roll-up
# --------------------------------------------------------------------------- #
def test_very_high_pushes_risk_up(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-238298", "status": "fail"}] * 6)
    r.finalize()
    assert r.composite_score > 0
    assert r.risk_level in ("Moderate", "High", "Very High")


def test_no_findings_is_very_low(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-238211", "status": "pass"}])
    r.finalize()
    assert r.risk_level == "Very Low"
    assert r.composite_score == 0.0


def test_score_caps_at_100(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-238298", "status": "fail"}] * 50)
    r.finalize()
    assert r.composite_score <= 100.0
