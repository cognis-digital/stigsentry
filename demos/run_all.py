"""Run every stigsentry demo scenario end to end, fully offline.

    python demos/run_all.py

Each scenario re-scans the bundled sample enclave (no live host, no network) and
prints narrated output, so they double as smoke tests. Exits 0 on success.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 72)
    print("  All stigsentry demo scenarios completed (offline, exit 0).")
    print("=" * 72)


if __name__ == "__main__":
    main()
