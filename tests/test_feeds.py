"""Offline tests for the NIST 800-53 rev5 (OSCAL) feed enrichment.

These NEVER hit the network: COGNIS_FEEDS_CACHE is pointed at tests/fixtures/,
which holds a trimmed snapshot of the real NIST OSCAL catalog (only the controls
referenced by stigsentry's STIG crosswalk). Everything is served offline=True.
"""

import json
import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    # serve the trimmed OSCAL fixture as the feed cache; force offline everywhere
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURES))
    yield


def test_fixture_present():
    assert (FIXTURES / "oscal-800-53-rev5-catalog.data").exists()
    assert (FIXTURES / "oscal-800-53-rev5-catalog.meta.json").exists()


def test_relevant_catalog_filtered():
    from stigsentry import feeds
    ids = [f["id"] for f in feeds.list_feeds()]
    assert ids == ["oscal-800-53-rev5-catalog"]  # compliance feed only


def test_normalize_control_id():
    from stigsentry.feeds import normalize_control_id
    assert normalize_control_id("AC-6(2)") == "ac-6.2"
    assert normalize_control_id("IA-2(11)") == "ia-2.11"
    assert normalize_control_id("AC-7(a)") == "ac-7"   # alpha part -> base control
    assert normalize_control_id("SC-13") == "sc-13"
    assert normalize_control_id("") == ""


def test_resolver_offline_resolves_real_titles():
    from stigsentry.feeds import ControlResolver
    r = ControlResolver(offline=True)
    assert len(r) >= 8
    assert r.title("SC-13") == "Cryptographic Protection"
    assert r.title("AC-6(2)") == "Non-privileged Access for Nonsecurity Functions"
    assert r.title("IA-5") == "Authenticator Management"
    assert r.title("AC-7(a)") == "Unsuccessful Logon Attempts"
    assert r.resolve("SC-13")["family_title"] == "System and Communications Protection"


def test_resolver_offline_missing_cache_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))  # empty cache
    from stigsentry.feeds import ControlResolver
    with pytest.raises(FileNotFoundError):
        ControlResolver(offline=True)


def test_enrich_result_offline():
    from cognis_mil.models import ScanResult, Finding, Severity
    from stigsentry.feeds import enrich_result
    r = ScanResult(tool_name="stigsentry", tool_version="0.1.0")
    r.add(Finding("SS-V-238298", Severity.VERY_HIGH, "FIPS 140 mode disabled",
                  nist_800_53="SC-13", disa_stig="V-238298", cci="CCI-002450"))
    r.add(Finding("SS-V-238213", Severity.HIGH, "SSH root login permitted",
                  nist_800_53="AC-6(2)", disa_stig="V-238213"))
    resolved = enrich_result(r, offline=True)
    assert resolved["SC-13"] == "Cryptographic Protection"
    assert resolved["AC-6(2)"] == "Non-privileged Access for Nonsecurity Functions"
    # the resolved title is woven into the finding description
    assert "Cryptographic Protection" in r.findings[0].description
    assert r.meta["nist_800_53_catalog"] == "NIST SP 800-53 rev5 (OSCAL)"


def test_enrich_result_no_cache_is_noop(monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    from cognis_mil.models import ScanResult, Finding, Severity
    from stigsentry.feeds import enrich_result
    r = ScanResult(tool_name="stigsentry")
    r.add(Finding("SS-V-238298", Severity.VERY_HIGH, "FIPS 140 mode disabled",
                  nist_800_53="SC-13"))
    resolved = enrich_result(r, offline=True)
    assert resolved == {}
    assert "unavailable" in r.meta["nist_800_53_catalog"]


def test_scan_enriches_and_poam_carries_real_titles(tmp_path):
    from stigsentry.core import scan, emit_poam
    findings = [
        {"stig_id": "V-238298", "host": "h1", "status": "open"},   # SC-13
        {"stig_id": "V-238213", "host": "h2", "status": "open"},   # AC-6(2)
    ]
    p = tmp_path / "f.json"
    p.write_text(json.dumps(findings))
    r = scan(str(tmp_path), offline=True)
    titles = r.meta.get("nist_800_53_controls_resolved", {})
    assert titles.get("SC-13") == "Cryptographic Protection"
    poam = emit_poam(r)
    assert "Control Title" in poam              # new column header
    assert "Cryptographic Protection" in poam   # real OSCAL title in the POAM


def test_feeds_cli_list_offline(capsys):
    from stigsentry.cli import _feeds_cli
    rc = _feeds_cli(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "oscal-800-53-rev5-catalog" in out


def test_feeds_cli_get_offline(capsys):
    from stigsentry.cli import _feeds_cli
    rc = _feeds_cli(["get", "oscal-800-53-rev5-catalog", "--offline"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "catalog" in out


def test_feeds_cli_rejects_unrelated_feed(capsys):
    from stigsentry.cli import _feeds_cli
    rc = _feeds_cli(["get", "cisa-kev", "--offline"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not a stigsentry feed" in err
