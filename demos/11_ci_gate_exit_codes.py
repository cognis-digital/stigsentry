"""Scenario 11 - CI gate semantics: --fail-on thresholds and exit codes.

Audience: the pipeline engineer wiring stigsentry into a build gate. ``--fail-on``
sets the severity at/above which the scan returns a non-zero exit. This demo
simulates the gate logic for a clean run, a moderate-only run, and a very-high
run across each threshold, printing the build decision (PASS / BLOCK) for each —
the same matrix you'd reason about when choosing your gate strictness.
"""
import json
import tempfile
from pathlib import Path

from _common import rule
from stigsentry.core import scan
from cognis_mil.models import Severity, WEIGHTS

THRESHOLDS = {
    "very_high": [Severity.VERY_HIGH],
    "high": [Severity.VERY_HIGH, Severity.HIGH],
    "moderate": [Severity.VERY_HIGH, Severity.HIGH, Severity.MODERATE],
}

RUNS = {
    "clean (all pass)": [{"stig_id": "V-238211", "status": "pass"}],
    "moderate only": [{"stig_id": "V-238382", "status": "fail"}],     # HIGH actually
    "very-high present": [{"stig_id": "V-238298", "status": "fail"}],  # VERY_HIGH
}


def _gate(findings, level):
    block = THRESHOLDS[level]
    return any(f.severity in block for f in findings)


def main() -> None:
    rule("CI GATE  -  --fail-on threshold matrix (exit 0 = PASS, 1 = BLOCK)")
    work = Path(tempfile.mkdtemp(prefix="ss-demo11-"))

    print(f"\n  {'run':<22} " + " ".join(f"{t:>10}" for t in THRESHOLDS))
    print("  " + "-" * 56)
    for label, payload in RUNS.items():
        (work / "f.json").write_text(json.dumps(payload), encoding="utf-8")
        r = scan(str(work), offline=True)
        cells = []
        for level in THRESHOLDS:
            cells.append("BLOCK" if _gate(r.findings, level) else "pass")
        print(f"  {label:<22} " + " ".join(f"{c:>10}" for c in cells))

    print("\nPick the strictness your enclave's risk posture demands; the gate is")
    print("just `stigsentry <dir> --fail-on <level>` returning a build-breaking exit.")


if __name__ == "__main__":
    main()
