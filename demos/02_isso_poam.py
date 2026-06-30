"""Scenario 2 - ISSO / ISSM.

Audience: the Information System Security Officer/Manager who owns the POA&M. A
STIG finding maps to a NIST 800-53 control ID like `AC-6(2)` — opaque on a
spreadsheet. stigsentry resolves each ID to its **official** control title from
the authoritative NIST SP 800-53 rev5 OSCAL catalog (served offline from the
bundled snapshot), then emits an eMASS-ready POA&M CSV with a real Control Title
column. This is the artifact you upload to eMASS / Xacta / RSA Archer.
"""
from _common import scan_enclave, emit_poam, rule, kv


def main() -> None:
    rule("ISSO / ISSM  -  STIG findings -> eMASS-ready POA&M")
    result = scan_enclave()

    resolved = result.meta.get("nist_800_53_controls_resolved", {})
    kv("NIST catalog:", result.meta.get("nist_800_53_catalog", "(offline, no cache)"))
    kv("Controls resolved:", f"{len(resolved)} (real OSCAL rev5 titles)")

    print("\nNIST 800-53 control titles resolved from the real catalog:")
    for cid, title in sorted(resolved.items()):
        print(f"     {cid:<10} {title}")

    import csv
    import io

    poam = emit_poam(result)
    rows = list(csv.reader(io.StringIO(poam)))
    print(f"\neMASS POA&M ({len(rows) - 1} weakness rows, header included):\n")
    # parse the real CSV (commas inside titles are quoted) and show 4 columns
    for cells in rows:
        print("   " + " | ".join(c[:34] for c in cells[:4]))

    print("\nEach row carries the control, its official title, severity and the")
    print("STIG/CCI provenance — drop it straight into eMASS as the POA&M of record.")


if __name__ == "__main__":
    main()
