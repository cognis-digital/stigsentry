"""Edge cases for the export surface: POA&M CSV, OSCAL AR, SARIF, Markdown, JSON.

Covers empty results, findings with missing NIST mappings, CSV quoting of
control titles that contain commas, OSCAL determinism + structural completeness,
SARIF severity mapping, and the JSON round-trip.
"""
import csv
import io
import json

import pytest

from stigsentry.core import scan, emit_poam
from cognis_mil.models import ScanResult, Finding, Severity
from cognis_mil.exporters import (
    to_oscal, to_sarif, to_markdown, to_json, to_console,
)


def _scan(tmp_path, findings, **kw):
    p = tmp_path / "f.json"
    p.write_text(json.dumps(findings), encoding="utf-8")
    return scan(str(p), **kw)


# --------------------------------------------------------------------------- #
# POA&M CSV
# --------------------------------------------------------------------------- #
def test_poam_header_present_on_empty_result():
    r = ScanResult(tool_name="stigsentry")
    poam = emit_poam(r)
    assert poam.splitlines()[0].startswith("Control,Control Title,Weakness")
    # only the header row, no weakness rows
    assert len(list(csv.reader(io.StringIO(poam)))) == 1


def test_poam_missing_nist_shows_none(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-999999", "status": "fail"}], enrich=False)
    poam = emit_poam(r)
    rows = list(csv.reader(io.StringIO(poam)))
    # the unknown finding has no NIST control -> "(none)"
    assert any(row[0] == "(none)" for row in rows[1:])


def test_poam_csv_quotes_control_title_with_comma():
    r = ScanResult(tool_name="stigsentry")
    r.add(Finding("x", Severity.HIGH, "weak", nist_800_53="AC-2"))
    r.meta["nist_800_53_controls_resolved"] = {"AC-2": "Account, Management"}
    poam = emit_poam(r)
    rows = list(csv.reader(io.StringIO(poam)))
    # csv.reader must reconstruct the comma-containing title as a single cell
    assert rows[1][1] == "Account, Management"


def test_poam_carries_stig_and_cci_in_comments(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-238298", "status": "fail"}], enrich=False)
    poam = emit_poam(r)
    assert "V-238298" in poam
    assert "CCI-002450" in poam


def test_poam_all_status_open(tmp_path):
    r = _scan(tmp_path, [{"stig_id": "V-238298", "status": "fail"}], enrich=False)
    rows = list(csv.reader(io.StringIO(emit_poam(r))))
    status_idx = rows[0].index("Status")
    assert all(row[status_idx] == "Open" for row in rows[1:])


# --------------------------------------------------------------------------- #
# OSCAL AR
# --------------------------------------------------------------------------- #
def _two():
    r = ScanResult(tool_name="stigsentry")
    r.started_at = 1750000000
    r.add(Finding("SS-V-242418", Severity.VERY_HIGH, "Blank password",
                  nist_800_53="IA-5", disa_stig="V-242418", cci="CCI-000196"))
    r.add(Finding("SS-V-238213", Severity.HIGH, "SSH root",
                  nist_800_53="AC-6(2)", disa_stig="V-238213"))
    r.finalize()
    return r


def test_oscal_empty_result_valid_shape():
    r = ScanResult(tool_name="stigsentry")
    r.started_at = 1750000000
    doc = json.loads(to_oscal(r))
    res = doc["assessment-results"]["results"][0]
    assert res["observations"] == []
    assert res["findings"] == []
    assert doc["assessment-results"]["metadata"]["oscal-version"] == "1.1.2"


def test_oscal_observation_per_finding():
    res = json.loads(to_oscal(_two()))["assessment-results"]["results"][0]
    assert len(res["observations"]) == 2
    assert len(res["findings"]) == 2


def test_oscal_finding_links_to_observation():
    res = json.loads(to_oscal(_two()))["assessment-results"]["results"][0]
    obs_uuids = {o["uuid"] for o in res["observations"]}
    for f in res["findings"]:
        assert f["related-observations"][0]["observation-uuid"] in obs_uuids


def test_oscal_target_status_not_satisfied():
    res = json.loads(to_oscal(_two()))["assessment-results"]["results"][0]
    assert all(f["target"]["status"]["state"] == "not-satisfied" for f in res["findings"])


def test_oscal_deterministic():
    assert to_oscal(_two()) == to_oscal(_two())


def test_oscal_no_zero_uuid():
    assert "00000000-0000-0000-0000-000000000000" not in to_oscal(_two())


def test_oscal_finding_without_nist_targets_id():
    r = ScanResult(tool_name="stigsentry")
    r.started_at = 1750000000
    r.add(Finding("SS-UNK", Severity.LOW, "unknown", nist_800_53=""))
    res = json.loads(to_oscal(r))["assessment-results"]["results"][0]
    # with no NIST control, the target falls back to the finding id
    assert res["findings"][0]["target"]["target-id"] == "SS-UNK"
    assert "implementation-statement-uuid" not in res["findings"][0]


def test_oscal_props_preserve_stig_cci():
    res = json.loads(to_oscal(_two()))["assessment-results"]["results"][0]
    props = {p["name"]: p["value"] for p in res["findings"][0]["props"]}
    assert props["disa-stig"] == "V-242418"
    assert props["cci"] == "CCI-000196"


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #
def test_sarif_severity_mapping():
    r = ScanResult(tool_name="stigsentry")
    r.add(Finding("a", Severity.VERY_HIGH, "vh"))
    r.add(Finding("b", Severity.MODERATE, "mod"))
    r.add(Finding("c", Severity.LOW, "low"))
    run = json.loads(to_sarif(r))["runs"][0]
    levels = {res["ruleId"]: res["level"] for res in run["results"]}
    assert levels["a"] == "error"
    assert levels["b"] == "warning"
    assert levels["c"] == "note"


def test_sarif_empty_result():
    r = ScanResult(tool_name="stigsentry")
    run = json.loads(to_sarif(r))["runs"][0]
    assert run["results"] == []


def test_sarif_schema_url():
    r = ScanResult(tool_name="stigsentry")
    doc = json.loads(to_sarif(r))
    assert doc["version"] == "2.1.0"
    assert "sarif-2.1.0" in doc["$schema"]


# --------------------------------------------------------------------------- #
# Markdown + JSON + console
# --------------------------------------------------------------------------- #
def test_markdown_has_table_header():
    md = to_markdown(_two())
    assert "| Sev | ID | Title | NIST | STIG | ATT&CK |" in md


def test_markdown_carries_classification_banner():
    r = _two()
    r.classification_placeholder = "UNCLASSIFIED//FOR PUBLIC RELEASE"
    md = to_markdown(r)
    assert md.count("UNCLASSIFIED//FOR PUBLIC RELEASE") == 2  # top + bottom


def test_json_roundtrip():
    doc = json.loads(to_json(_two()))
    assert doc["tool_name"] == "stigsentry"
    assert len(doc["findings"]) == 2
    assert doc["findings"][0]["disa_stig"] == "V-242418"


def test_console_renders_findings():
    out = to_console(_two())
    assert "stigsentry" in out
    assert "V-242418" in out or "Blank password" in out
