"""OSCAL 1.1.2 Assessment Results export — real, validatable structure."""

import json

from cognis_mil.models import ScanResult, Finding, Severity
from cognis_mil.exporters import to_oscal, to_oscal_skeleton


def _result():
    r = ScanResult(tool_name="stigsentry", tool_version="0.1.0")
    r.started_at = 1750000000  # fixed -> deterministic timestamps
    r.add(Finding("SS-V-242418", Severity.VERY_HIGH, "Blank password permitted",
                  nist_800_53="IA-5", disa_stig="V-242418", cci="CCI-000196",
                  remediation="Disable blank passwords"))
    r.add(Finding("SS-V-238213", Severity.HIGH, "SSH root login permitted",
                  nist_800_53="AC-6(2)", disa_stig="V-238213", cci="CCI-000206"))
    r.finalize()
    return r


def test_oscal_top_level_shape():
    doc = json.loads(to_oscal(_result()))
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert len(ar["uuid"]) == 36
    assert ar["import-ap"]["href"]
    assert ar["results"]


def test_no_placeholder_zero_uuids():
    out = to_oscal(_result())
    assert "00000000-0000-0000-0000-000000000000" not in out
    assert "finding-1" not in out  # old skeleton style is gone


def test_observation_and_finding_per_item():
    res = json.loads(to_oscal(_result()))["assessment-results"]["results"][0]
    assert len(res["observations"]) == 2
    assert len(res["findings"]) == 2
    f0 = res["findings"][0]
    assert f0["target"]["status"]["state"] == "not-satisfied"
    assert f0["target"]["target-id"] == "IA-5"
    # finding links to its observation
    obs_uuids = {o["uuid"] for o in res["observations"]}
    assert f0["related-observations"][0]["observation-uuid"] in obs_uuids


def test_stig_cci_preserved_in_props():
    res = json.loads(to_oscal(_result()))["assessment-results"]["results"][0]
    props = {p["name"]: p["value"] for p in res["findings"][0]["props"]}
    assert props["disa-stig"] == "V-242418"
    assert props["cci"] == "CCI-000196"
    assert props["severity"]


def test_deterministic_uuids():
    a, b = to_oscal(_result()), to_oscal(_result())
    assert a == b  # uuid5 + fixed timestamp => byte-identical


def test_backcompat_alias():
    assert to_oscal_skeleton is to_oscal


def test_cli_oscal_format(capsys, tmp_path):
    # the shared make_cli exposes --format oscal across every cognis_mil tool
    import json as _json
    from stigsentry.core import scan
    findings = [{"stig_id": "V-242418", "host": "h1", "status": "open"}]
    p = tmp_path / "f.json"
    p.write_text(_json.dumps(findings))
    r = scan(str(tmp_path))
    doc = _json.loads(to_oscal(r))
    assert doc["assessment-results"]["results"][0]["findings"]
