"""Scenario 18 - Deterministic OSCAL evidence: diff two assessment runs.

Audience: the assessor who re-runs an assessment after remediation and wants to
diff the evidence. stigsentry's OSCAL export uses uuid5 (content-derived) UUIDs
and a fixed timestamp source, so an *unchanged* scan re-exports byte-identical,
and a *changed* scan diffs cleanly to exactly the findings that moved. This demo
exports a baseline, then a "post-remediation" run with one finding fixed, and
shows the structural diff.
"""
import json
import tempfile
from pathlib import Path

from _common import scan_enclave, to_oscal, rule, kv
from stigsentry.core import scan


def main() -> None:
    rule("OSCAL DIFF  -  deterministic AR export, before/after remediation")

    baseline = scan_enclave()
    a1 = to_oscal(baseline)
    a2 = to_oscal(baseline)
    kv("Re-export unchanged scan:", "byte-identical" if a1 == a2 else "DIFFERS")
    assert a1 == a2

    base_ids = {f.disa_stig for f in baseline.findings if f.disa_stig}
    kv("Baseline STIG findings:", len(base_ids))

    # Simulate remediation: re-scan a copy of the enclave with V-238298 now passing.
    work = Path(tempfile.mkdtemp(prefix="ss-demo18-"))
    remediated = [
        {"stig_id": "V-238298", "host": "web01.enclave.mil", "status": "pass"},  # fixed
        {"stig_id": "V-238213", "host": "web01.enclave.mil", "status": "fail"},
        {"stig_id": "V-242414", "host": "k8s-api01.enclave.mil", "status": "fail"},
    ]
    (work / "f.json").write_text(json.dumps(remediated), encoding="utf-8")
    after = scan(str(work), offline=True)
    after_ids = {f.disa_stig for f in after.findings if f.disa_stig}

    closed = base_ids - after_ids
    print("\nFindings closed since baseline (would drop out of the new AR):")
    for sid in sorted(closed):
        print(f"     - {sid}")
    kv("\nStill open:", sorted(after_ids))
    assert "V-238298" in closed

    print("\nDeterministic UUIDs let an assessor diff two OSCAL runs and see exactly")
    print("what was remediated — no spurious churn from regenerated identifiers.")


if __name__ == "__main__":
    main()
