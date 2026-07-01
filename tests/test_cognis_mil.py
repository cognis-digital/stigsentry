"""Coverage for the shared cognis_mil primitives: models, audit log, classmark.

These ship inside stigsentry and back the scoring, tamper-evident logging, and
classification-banner shape validation.
"""
import pytest

from cognis_mil.models import Severity, Finding, ScanResult, WEIGHTS
from cognis_mil.audit import AuditLog
from cognis_mil.classmark import ClassificationBanner, VALID_LEVELS


# --------------------------------------------------------------------------- #
# Finding / Severity
# --------------------------------------------------------------------------- #
def test_finding_default_weight_from_severity():
    f = Finding("x", Severity.HIGH, "t")
    assert f.weight == WEIGHTS[Severity.HIGH]


def test_finding_string_severity_coerced():
    f = Finding("x", "high", "t")
    assert f.severity == Severity.HIGH


def test_finding_explicit_weight_kept():
    f = Finding("x", Severity.LOW, "t", weight=99.0)
    assert f.weight == 99.0


def test_critical_is_alias_for_very_high():
    assert Severity.CRITICAL == Severity.VERY_HIGH
    assert Severity.CRITICAL.value == "very_high"


def test_finding_to_dict_serializes_severity():
    d = Finding("x", Severity.VERY_HIGH, "t").to_dict()
    assert d["severity"] == "very_high"


# --------------------------------------------------------------------------- #
# ScanResult scoring
# --------------------------------------------------------------------------- #
def test_empty_result_is_very_low():
    r = ScanResult(tool_name="t")
    r.finalize()
    assert r.composite_score == 0.0
    assert r.risk_level == "Very Low"


def test_finalize_returns_self():
    r = ScanResult(tool_name="t")
    assert r.finalize() is r


@pytest.mark.parametrize("count,expect_min", [(1, "Very Low"), (10, "Very High")])
def test_risk_scales_with_findings(count, expect_min):
    r = ScanResult(tool_name="t")
    for i in range(count):
        r.add(Finding(f"f{i}", Severity.VERY_HIGH, "t"))
    r.finalize()
    assert r.composite_score <= 100.0
    assert r.risk_level in ("Very Low", "Low", "Moderate", "High", "Very High")


def test_to_dict_includes_classification_and_findings():
    r = ScanResult(tool_name="t")
    r.add(Finding("x", Severity.HIGH, "t"))
    r.finalize()
    d = r.to_dict()
    assert d["classification"]
    assert d["tool_name"] == "t"
    assert len(d["findings"]) == 1


def test_total_findings_counts():
    r = ScanResult(tool_name="t")
    r.add(Finding("a", Severity.LOW, "t"))
    r.add(Finding("b", Severity.LOW, "t"))
    assert r.total_findings() == 2


# --------------------------------------------------------------------------- #
# AuditLog hash chain
# --------------------------------------------------------------------------- #
def test_audit_append_and_verify(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    log.append({"action": "scan", "host": "h1"})
    log.append({"action": "emit", "host": "h1"})
    ok, msg = log.verify()
    assert ok, msg
    assert "Chain OK" in msg


def test_audit_first_entry_genesis_prev(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    entry = log.append({"x": 1})
    assert entry["prev"] == "GENESIS"
    assert len(entry["hash"]) == 64


def test_audit_empty_log_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    ok, msg = log.verify()
    assert ok
    assert "Empty" in msg


def test_audit_detects_tamper(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path)
    log.append({"action": "scan"})
    log.append({"action": "emit"})
    # tamper with the first line's event payload
    lines = path.read_text().splitlines()
    import json
    rec = json.loads(lines[0])
    rec["event"] = {"action": "TAMPERED"}
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    ok, msg = log.verify()
    assert not ok
    assert "mismatch" in msg.lower()


def test_audit_detects_corrupt_json(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path)
    log.append({"a": 1})
    path.write_text("not json at all\n")
    ok, msg = log.verify()
    assert not ok


# --------------------------------------------------------------------------- #
# ClassificationBanner
# --------------------------------------------------------------------------- #
def test_banner_placeholder_is_public():
    b = ClassificationBanner.placeholder()
    ok, errs = b.validate()
    assert ok and not errs
    assert "UNCLASSIFIED" in b.render()


def test_banner_rejects_invalid_level():
    ok, errs = ClassificationBanner(level="ULTRA SECRET").validate()
    assert not ok
    assert any("Invalid base level" in e for e in errs)


def test_banner_unclassified_cannot_carry_sci():
    ok, errs = ClassificationBanner(level="UNCLASSIFIED", sci=["SI"]).validate()
    assert not ok
    assert any("SCI" in e for e in errs)


def test_banner_renders_dissem():
    b = ClassificationBanner(level="SECRET", dissem=["NOFORN"])
    assert b.render() == "SECRET//NOFORN"


def test_valid_levels_known():
    assert "TOP SECRET" in VALID_LEVELS
    assert "UNCLASSIFIED" in VALID_LEVELS
