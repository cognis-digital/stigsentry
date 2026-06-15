"""Tests covering hardened error-handling and edge-case paths."""
from __future__ import annotations

import json
import subprocess
import sys
import pytest

from stigsentry.core import (
    StigsentryError,
    emit_poam,
    parse_findings_file,
    scan,
)


# ---------------------------------------------------------------------------
# parse_findings_file
# ---------------------------------------------------------------------------

def test_missing_file_raises(tmp_path):
    """parse_findings_file raises StigsentryError for a non-existent file."""
    with pytest.raises(StigsentryError, match="not found"):
        parse_findings_file(tmp_path / "ghost.json")


def test_malformed_json_raises(tmp_path):
    """parse_findings_file raises StigsentryError for invalid JSON."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    with pytest.raises(StigsentryError, match="Invalid JSON"):
        parse_findings_file(bad)


def test_json_not_a_list_raises(tmp_path):
    """parse_findings_file raises StigsentryError when JSON root is not a list."""
    obj = tmp_path / "obj.json"
    obj.write_text(json.dumps({"stig_id": "V-238298", "status": "fail"}))
    with pytest.raises(StigsentryError, match="expected a JSON array"):
        parse_findings_file(obj)


def test_empty_json_file_returns_empty(tmp_path):
    """Empty JSON file returns an empty list without error."""
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert parse_findings_file(empty) == []


def test_empty_json_array_returns_empty(tmp_path):
    """JSON file containing [] returns an empty list without error."""
    f = tmp_path / "zero.json"
    f.write_text("[]")
    assert parse_findings_file(f) == []


def test_csv_missing_required_column_raises(tmp_path):
    """CSV missing the 'status' column raises StigsentryError."""
    bad_csv = tmp_path / "bad.csv"
    bad_csv.write_text("stig_id,host\nV-238298,web01\n")
    with pytest.raises(StigsentryError, match="missing required columns"):
        parse_findings_file(bad_csv)


# ---------------------------------------------------------------------------
# scan()
# ---------------------------------------------------------------------------

def test_scan_nonexistent_target_raises():
    """scan() raises StigsentryError when the target path does not exist."""
    with pytest.raises(StigsentryError, match="not found"):
        scan("/tmp/definitely_does_not_exist_xyzzy_12345")


def test_scan_empty_directory_returns_zero_findings(tmp_path):
    """scan() on an empty directory produces zero findings without crashing."""
    result = scan(str(tmp_path))
    assert result.total_findings() == 0
    assert result.items_scanned == 0


def test_scan_all_pass_returns_no_findings(tmp_path):
    """Findings with status=pass are not included in results."""
    f = tmp_path / "all_pass.json"
    f.write_text(json.dumps([
        {"stig_id": "V-238298", "host": "h1", "status": "pass"},
        {"stig_id": "V-238213", "host": "h1", "status": "not_a_finding"},
    ]))
    result = scan(str(tmp_path))
    assert result.total_findings() == 0


def test_scan_malformed_json_yields_parse_error_finding(tmp_path):
    """A malformed JSON input file yields a parse-error finding rather than crashing."""
    bad = tmp_path / "corrupt.json"
    bad.write_text("{bad")
    result = scan(str(bad))
    ids = [f.id for f in result.findings]
    assert any("PARSE-ERR" in fid for fid in ids)


def test_scan_finding_missing_stig_id(tmp_path):
    """A finding row without stig_id/rule_id yields a SS-NO-ID finding."""
    f = tmp_path / "noid.json"
    f.write_text(json.dumps([{"host": "h1", "status": "fail"}]))
    result = scan(str(f))
    ids = [finding.id for finding in result.findings]
    assert "SS-NO-ID" in ids


# ---------------------------------------------------------------------------
# emit_poam edge cases
# ---------------------------------------------------------------------------

def test_emit_poam_empty_findings():
    """emit_poam on a result with no findings still produces a valid CSV header."""
    from cognis_mil import ScanResult

    r = ScanResult(tool_name="stigsentry")
    r.finalize()
    poam = emit_poam(r)
    assert "Control,Weakness" in poam
    # Only the header row — no data rows
    lines = [ln for ln in poam.splitlines() if ln.strip()]
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# CLI exit-code contract
# ---------------------------------------------------------------------------

def test_cli_nonexistent_target_exits_2():
    """CLI exits with code 2 when the target path does not exist."""
    result = subprocess.run(
        [sys.executable, "-m", "stigsentry", "/nonexistent/path/xyzzy"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "error" in result.stderr.lower()
