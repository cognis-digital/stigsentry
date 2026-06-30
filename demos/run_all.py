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
