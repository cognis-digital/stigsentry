"""Scenario 8 - The RMF mapping gap: STIG IDs with no 800-53 control yet.

Audience: the RMF/eMASS engineer maintaining the crosswalk. New or
org-specific STIG IDs may not be in the bundled DISA->800-53 table. stigsentry
never drops an unmapped finding — it keeps it as a tracked LOW finding flagged
"Unknown STIG ID" with a remediation hint to extend the crosswalk. This demo
shows a mapped and an unmapped finding side by side and how the gap surfaces in
the POA&M (control column reads "(none)").
"""
import csv
import io
import json
import tempfile
from pathlib import Path

from _common import rule, kv
from stigsentry.core import scan, emit_poam


def main() -> None:
    rule("RMF GAP  -  unmapped STIG IDs are tracked, not silently dropped")
    work = Path(tempfile.mkdtemp(prefix="ss-demo8-"))
    (work / "f.json").write_text(json.dumps([
        {"stig_id": "V-238298", "host": "h1", "status": "fail"},   # mapped -> SC-13
        {"stig_id": "V-000777", "host": "h1", "status": "fail"},   # NOT in the crosswalk
    ]), encoding="utf-8")

    result = scan(str(work), offline=True)
    print("\nFindings:")
    for f in result.findings:
        mapped = f.nist_800_53 or "(no 800-53 mapping)"
        print(f"     [{f.severity.value.upper():<10}] {f.disa_stig or f.id:<12} -> {mapped}")
        if f.id.startswith("SS-UNK-"):
            print(f"        fix: {f.remediation}")

    unmapped = [f for f in result.findings if f.id.startswith("SS-UNK-")]
    kv("\nMapping gaps found:", len(unmapped))

    poam = emit_poam(result)
    rows = list(csv.reader(io.StringIO(poam)))
    print("\nIn the POA&M, the gap shows as a '(none)' control row to triage:")
    for row in rows[1:]:
        print(f"     control={row[0]:<8} weakness={row[2][:40]}")

    print("\nClose the gap by adding the STIG ID to STIG_CONTROLS; nothing is lost meanwhile.")


if __name__ == "__main__":
    main()
