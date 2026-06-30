"""Error-path + edge-case coverage for findings parsing and scanning.

Covers malformed JSON/CSV, missing target paths, wrapper-object JSON shapes,
case-insensitive suffixes, and the strict-vs-lenient scan modes. These are the
real-world inputs a compliance scanner sees (OpenSCAP/SCC exporters, hand-edited
spreadsheets) and must not silently drop or crash on.
"""
import json

import pytest

from stigsentry.core import (
    FindingsParseError,
    parse_findings_file,
    scan,
    emit_poam,
    _coerce_findings,
)


# --------------------------------------------------------------------------- #
# malformed / unreadable inputs
# --------------------------------------------------------------------------- #
def test_malformed_json_raises_not_silent(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(FindingsParseError) as ei:
        parse_findings_file(p)
    assert "invalid JSON" in str(ei.value)
    assert "bad.json" in str(ei.value)


def test_empty_json_file_raises(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    with pytest.raises(FindingsParseError):
        parse_findings_file(p)


def test_truncated_json_array_raises(tmp_path):
    p = tmp_path / "trunc.json"
    p.write_text('[{"stig_id": "V-238298"', encoding="utf-8")
    with pytest.raises(FindingsParseError):
        parse_findings_file(p)


def test_missing_file_raises(tmp_path):
    with pytest.raises(FindingsParseError) as ei:
        parse_findings_file(tmp_path / "does-not-exist.json")
    assert "cannot read" in str(ei.value)


def test_json_scalar_rejected(tmp_path):
    p = tmp_path / "scalar.json"
    p.write_text("42", encoding="utf-8")
    with pytest.raises(FindingsParseError) as ei:
        parse_findings_file(p)
    assert "expected a JSON list or object" in str(ei.value)


def test_json_object_without_findings_key_rejected(tmp_path):
    p = tmp_path / "weird.json"
    p.write_text(json.dumps({"random": "object", "no": "findings"}), encoding="utf-8")
    with pytest.raises(FindingsParseError) as ei:
        parse_findings_file(p)
    assert "no recognized findings list" in str(ei.value)


# --------------------------------------------------------------------------- #
# wrapper-object JSON shapes (the common SCAP/SCC export shapes)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("key", ["findings", "results", "rules", "items", "rule_results"])
def test_wrapper_object_keys_accepted(key):
    data = {key: [{"stig_id": "V-238298", "status": "fail"}]}
    out = _coerce_findings(data, "test")
    assert out == [{"stig_id": "V-238298", "status": "fail"}]


def test_single_finding_object_accepted():
    data = {"stig_id": "V-238298", "status": "fail", "host": "h1"}
    out = _coerce_findings(data, "test")
    assert out == [data]


def test_bare_list_passes_through():
    data = [{"stig_id": "V-238298"}, {"stig_id": "V-238213"}]
    assert _coerce_findings(data, "t") == data


def test_list_drops_non_dict_entries():
    data = [{"stig_id": "V-238298"}, "garbage", 5, None]
    out = _coerce_findings(data, "t")
    assert out == [{"stig_id": "V-238298"}]


def test_dict_shaped_json_scan_does_not_crash(tmp_path):
    p = tmp_path / "obj.json"
    p.write_text(json.dumps({"findings": [{"stig_id": "V-238298", "status": "fail"}]}),
                 encoding="utf-8")
    r = scan(str(p), enrich=False)
    assert "SS-V-238298" in {f.id for f in r.findings}


# --------------------------------------------------------------------------- #
# case-insensitive suffixes
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["x.JSON", "x.Json", "x.json"])
def test_uppercase_json_suffix(tmp_path, name):
    p = tmp_path / name
    p.write_text(json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    assert parse_findings_file(p)[0]["stig_id"] == "V-238298"


@pytest.mark.parametrize("name", ["x.CSV", "x.Csv"])
def test_uppercase_csv_suffix(tmp_path, name):
    p = tmp_path / name
    p.write_text("stig_id,status\nV-238298,fail\n", encoding="utf-8")
    rows = parse_findings_file(p)
    assert rows[0]["stig_id"] == "V-238298"


def test_unknown_suffix_returns_empty(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("hello", encoding="utf-8")
    assert parse_findings_file(p) == []


# --------------------------------------------------------------------------- #
# missing / empty scan targets
# --------------------------------------------------------------------------- #
def test_scan_missing_path_raises():
    with pytest.raises(FileNotFoundError) as ei:
        scan("/no/such/path/exists", enrich=False)
    assert "does not exist" in str(ei.value)


def test_scan_empty_dir_is_clean(tmp_path):
    r = scan(str(tmp_path), enrich=False)
    assert r.items_scanned == 0
    assert r.total_findings() == 0
    assert r.risk_level == "Very Low"


def test_scan_dir_ignores_non_findings_files(tmp_path):
    (tmp_path / "readme.txt").write_text("ignore me", encoding="utf-8")
    (tmp_path / "data.json").write_text(
        json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    r = scan(str(tmp_path), enrich=False)
    # only the .json counts as a scanned item
    assert r.items_scanned == 1


# --------------------------------------------------------------------------- #
# strict vs lenient on a malformed file inside a directory
# --------------------------------------------------------------------------- #
def test_scan_lenient_records_parse_error_finding(tmp_path):
    (tmp_path / "bad.json").write_text("{broken", encoding="utf-8")
    r = scan(str(tmp_path), enrich=False)  # strict defaults to False
    ids = {f.id for f in r.findings}
    assert "SS-PARSE-ERROR" in ids
    pe = next(f for f in r.findings if f.id == "SS-PARSE-ERROR")
    assert pe.severity.value == "moderate"
    assert "invalid JSON" in pe.description


def test_scan_strict_reraises_parse_error(tmp_path):
    (tmp_path / "bad.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(FindingsParseError):
        scan(str(tmp_path), enrich=False, strict=True)


def test_scan_lenient_continues_past_bad_file(tmp_path):
    (tmp_path / "bad.json").write_text("{broken", encoding="utf-8")
    (tmp_path / "good.json").write_text(
        json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    r = scan(str(tmp_path), enrich=False)
    ids = {f.id for f in r.findings}
    assert "SS-PARSE-ERROR" in ids   # the bad file was flagged
    assert "SS-V-238298" in ids      # the good file still scanned


# --------------------------------------------------------------------------- #
# emit_poam write hardening
# --------------------------------------------------------------------------- #
def test_emit_poam_creates_parent_dirs(tmp_path):
    p = tmp_path / "nested" / "deep" / "poam.csv"
    r = scan_findings(tmp_path)
    emit_poam(r, p)
    assert p.exists()
    assert "Control,Control Title,Weakness" in p.read_text(encoding="utf-8")


def test_emit_poam_utf8_roundtrip(tmp_path):
    p = tmp_path / "poam.csv"
    r = scan_findings(tmp_path)
    emit_poam(r, p)
    # explicit utf-8 read works regardless of platform default encoding
    assert "SC-13" in p.read_text(encoding="utf-8")


def scan_findings(tmp_path):
    f = tmp_path / "f.json"
    f.write_text(json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    r = scan(str(f), enrich=False)
    r.finalize()
    return r
