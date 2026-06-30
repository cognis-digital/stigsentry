"""Smoke + behavior tests for the audience demo scenarios.

These run offline (conftest points COGNIS_FEEDS_CACHE at the bundled OSCAL
snapshot and hard-blocks network), so they double as the demos' regression net.
"""
import csv
import importlib
import io
import json
import sys
from pathlib import Path

import pytest

DEMOS = Path(__file__).resolve().parent.parent / "demos"
sys.path.insert(0, str(DEMOS))

SCENARIOS = [
    "01_sysadmin_scan",
    "02_isso_poam",
    "03_auditor_oscal",
    "04_ato_risk_brief",
    "05_airgap_pipeline",
    "06_malformed_input_handling",
    "07_wrapper_json_shapes",
    "08_rmf_mapping_gap",
    "09_control_id_normalization",
    "10_snapshot_sneakernet",
    "11_ci_gate_exit_codes",
    "12_audit_trail",
    "13_classification_banner",
    "14_severity_rollup",
    "15_csv_tsv_ingest",
    "16_multi_format_export",
    "17_poam_to_grc",
    "18_oscal_diff",
    "19_per_host_triage",
    "20_end_to_end_pipeline",
]


@pytest.mark.parametrize("name", SCENARIOS)
def test_demo_runs_and_narrates(name, capsys):
    mod = importlib.import_module(name)
    mod.main()
    out = capsys.readouterr().out
    assert len(out.splitlines()) > 5  # narrated output, not silent


def test_run_all_exit_zero():
    import run_all
    run_all.main()  # raises if any scenario blows up


def test_enclave_scan_shape():
    from _common import scan_enclave
    r = scan_enclave()
    ids = {f.id for f in r.findings}
    # open findings present, passing rows dropped, unknown STIG handled
    assert "SS-V-238298" in ids        # very-high fail (FIPS)
    assert "SS-V-242414" in ids        # k8s no-auth fail
    # V-238211 is a PASS on web02 but a FAIL on k8s-api01: only the fail carries
    # through, and only on the k8s host (the passing web02 row is dropped).
    hosts_238211 = {f.location for f in r.findings if f.disa_stig == "V-238211"}
    assert hosts_238211 == {"k8s-api01.enclave.mil"}
    assert "SS-UNK-V-999999" in ids    # unknown STIG ID kept as a low finding
    assert r.total_findings() == 9
    assert r.risk_level == "Very High"


def test_enclave_poam_has_real_control_titles():
    from _common import scan_enclave, emit_poam
    r = scan_enclave()
    poam = emit_poam(r)
    rows = list(csv.reader(io.StringIO(poam)))
    header = rows[0]
    assert header[:2] == ["Control", "Control Title"]
    # the real OSCAL title for SC-13 must appear (resolved offline)
    flat = "\n".join(",".join(row) for row in rows)
    assert "Cryptographic Protection" in flat
    assert "Authenticator Management" in flat


def test_enclave_oscal_deterministic_and_complete():
    from _common import scan_enclave, to_oscal
    r = scan_enclave()
    a, b = to_oscal(r), to_oscal(r)
    assert a == b  # deterministic uuid5 export
    res = json.loads(a)["assessment-results"]["results"][0]
    assert len(res["observations"]) == r.total_findings()
    assert len(res["findings"]) == r.total_findings()
    assert all(f["target"]["status"]["state"] == "not-satisfied" for f in res["findings"])


def test_enclave_offline_resolver_loaded():
    from stigsentry.feeds import ControlResolver
    resolver = ControlResolver(offline=True)
    assert len(resolver) > 0
    assert resolver.title("SC-13") == "Cryptographic Protection"
