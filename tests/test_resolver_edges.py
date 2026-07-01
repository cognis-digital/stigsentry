"""Edge cases for the offline NIST 800-53 (OSCAL) control resolver + air-gap layer.

Network is hard-blocked (conftest); the trimmed OSCAL fixture is served as the
cache. Covers control-ID normalization edge cases, unmapped controls, an
explicitly-passed catalog (no cache at all), and the datafeeds air-gap snapshot
export/import round-trip.
"""
import json
import tarfile
from pathlib import Path

import pytest

from stigsentry import datafeeds as df
from stigsentry.feeds import (
    ControlResolver,
    normalize_control_id,
    enrich_result,
    relevant_catalog,
    _index_catalog,
)
from cognis_mil.models import ScanResult, Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# normalize_control_id edge cases
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expect", [
    ("AC-6(2)", "ac-6.2"),
    ("IA-2(11)", "ia-2.11"),
    ("AC-7(a)", "ac-7"),          # alpha statement part -> base
    ("SC-13", "sc-13"),
    ("AC-6(2)(a)", "ac-6.2"),     # combined enhancement + statement part
    ("AC-6 (2)", "ac-6.2"),       # tolerate a space before the paren
    ("  ac-3  ", "ac-3"),         # surrounding whitespace
    ("", ""),
    (None, ""),
])
def test_normalize_variants(raw, expect):
    assert normalize_control_id(raw) == expect


# --------------------------------------------------------------------------- #
# resolver: hits, misses, titles
# --------------------------------------------------------------------------- #
def test_resolver_resolves_base_and_enhancement():
    r = ControlResolver(offline=True)
    assert r.title("SC-13") == "Cryptographic Protection"
    assert r.title("AC-6(2)") == "Non-privileged Access for Nonsecurity Functions"


def test_resolver_unmapped_control_returns_none():
    r = ControlResolver(offline=True)
    assert r.resolve("ZZ-99") is None
    assert r.title("ZZ-99") == ""        # title() degrades to empty string


def test_resolver_family_metadata():
    r = ControlResolver(offline=True)
    info = r.resolve("IA-5")
    assert info["family"] == "ia"
    assert info["family_title"] == "Identification and Authentication"


def test_resolver_accepts_explicit_catalog_no_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))  # empty cache
    catalog = json.loads((FIXTURES / "oscal-800-53-rev5-catalog.data").read_text(encoding="utf-8"))
    r = ControlResolver(catalog=catalog)  # offline irrelevant when catalog supplied
    assert r.title("SC-13") == "Cryptographic Protection"


def test_resolver_len_matches_index():
    r = ControlResolver(offline=True)
    catalog = json.loads((FIXTURES / "oscal-800-53-rev5-catalog.data").read_text(encoding="utf-8"))
    assert len(r) == len(_index_catalog(catalog))


def test_index_catalog_handles_bare_catalog_shape():
    # accept both {"catalog": {...}} and a bare {...}
    bare = {"groups": [{"id": "xx", "title": "X Fam",
                        "controls": [{"id": "xx-1", "title": "T"}]}]}
    idx = _index_catalog(bare)
    assert idx["xx-1"]["title"] == "T"


def test_index_catalog_empty_is_empty():
    assert _index_catalog({}) == {}
    assert _index_catalog({"catalog": {"groups": []}}) == {}


# --------------------------------------------------------------------------- #
# enrich_result behavior
# --------------------------------------------------------------------------- #
def _result():
    r = ScanResult(tool_name="stigsentry")
    r.add(Finding("SS-V-238298", Severity.VERY_HIGH, "FIPS off", nist_800_53="SC-13"))
    return r


def test_enrich_weaves_title_into_empty_description():
    r = _result()
    enrich_result(r, offline=True)
    assert "Cryptographic Protection" in r.findings[0].description


def test_enrich_appends_when_description_present():
    r = ScanResult(tool_name="stigsentry")
    r.add(Finding("x", Severity.HIGH, "t", description="pre-existing note", nist_800_53="SC-13"))
    enrich_result(r, offline=True)
    d = r.findings[0].description
    assert d.startswith("pre-existing note")
    assert "Cryptographic Protection" in d


def test_enrich_skips_findings_without_nist():
    r = ScanResult(tool_name="stigsentry")
    r.add(Finding("x", Severity.LOW, "no mapping", nist_800_53=""))
    resolved = enrich_result(r, offline=True)
    assert resolved == {}


def test_enrich_unmapped_control_not_in_resolved():
    r = ScanResult(tool_name="stigsentry")
    r.add(Finding("x", Severity.LOW, "t", nist_800_53="ZZ-99"))
    resolved = enrich_result(r, offline=True)
    assert "ZZ-99" not in resolved


def test_enrich_no_cache_is_noop(monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    r = _result()
    resolved = enrich_result(r, offline=True)
    assert resolved == {}
    assert "unavailable" in r.meta["nist_800_53_catalog"]


def test_enrich_idempotent_description(monkeypatch):
    r = _result()
    enrich_result(r, offline=True)
    first = r.findings[0].description
    enrich_result(r, offline=True)  # second pass must not double-append
    assert r.findings[0].description == first


# --------------------------------------------------------------------------- #
# relevant_catalog filtering
# --------------------------------------------------------------------------- #
def test_relevant_catalog_only_compliance_feed():
    cat = relevant_catalog()
    ids = [f["id"] for f in cat["feeds"]]
    assert ids == ["oscal-800-53-rev5-catalog"]


# --------------------------------------------------------------------------- #
# datafeeds offline / air-gap behavior
# --------------------------------------------------------------------------- #
def test_get_offline_missing_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        df.get("oscal-800-53-rev5-catalog", offline=True)


def test_update_unknown_feed_raises():
    with pytest.raises(KeyError):
        df.update("no-such-feed-id")


def test_cached_age_hours_uncached(monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    assert df.cached_age_hours("oscal-800-53-rev5-catalog") is None


def test_cached_age_hours_present():
    age = df.cached_age_hours("oscal-800-53-rev5-catalog")
    assert age is not None and age >= 0


def test_snapshot_export_import_roundtrip(monkeypatch, tmp_path):
    # export the fixture cache, then import into a fresh empty cache and resolve
    snap = tmp_path / "snap.tar.gz"
    n = df.snapshot_export(str(snap))
    assert n >= 1
    assert snap.exists()

    fresh = tmp_path / "fresh-cache"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(fresh))
    imported = df.snapshot_import(str(snap))
    assert imported >= 1
    # resolver now works entirely from the sneakernet'd snapshot
    r = ControlResolver(offline=True)
    assert r.title("SC-13") == "Cryptographic Protection"


def test_snapshot_export_is_flat(monkeypatch, tmp_path):
    snap = tmp_path / "snap.tar.gz"
    df.snapshot_export(str(snap))
    with tarfile.open(snap, "r:gz") as t:
        names = t.getnames()
    # arcnames must be flat (basename only) so they import into any cache dir
    assert all("/" not in n and "\\" not in n for n in names)


def test_load_catalog_missing_returns_empty(tmp_path):
    missing = tmp_path / "nope.json"
    assert df.load_catalog(str(missing)) == {"feeds": []}
