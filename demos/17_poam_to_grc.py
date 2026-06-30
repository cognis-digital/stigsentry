"""Scenario 17 - POA&M column walkthrough for the eMASS / Xacta / Archer import.

Audience: the ISSM mapping stigsentry's POA&M CSV onto the GRC tool's import
template. This demo emits the POA&M for the bundled enclave and explains each
column — which are auto-filled from the scan (Control, Control Title, Weakness,
Severity, Status, provenance Comments) and which are operator TBD fields (SCD,
POC, Resources Required) you complete before upload.
"""
import csv
import io

from _common import scan_enclave, emit_poam, rule, kv


COLUMN_NOTES = {
    "Control": "NIST 800-53 control id (auto)",
    "Control Title": "official OSCAL rev5 title (auto, resolved offline)",
    "Weakness": "the STIG finding title (auto)",
    "Severity": "NIST 800-30 severity band (auto)",
    "SCD": "Scheduled Completion Date — operator TBD",
    "POC": "Point of Contact — operator TBD",
    "Status": "Open (auto)",
    "Resources Required": "operator TBD",
    "Comments": "STIG id + CCI provenance (auto)",
}


def main() -> None:
    rule("POA&M  -  column-by-column for the GRC import")
    result = scan_enclave()
    poam = emit_poam(result)
    rows = list(csv.reader(io.StringIO(poam)))
    header = rows[0]

    kv("Weakness rows:", len(rows) - 1)
    print("\nColumns:")
    for col in header:
        print(f"     {col:<20} {COLUMN_NOTES.get(col, '')}")

    print("\nFirst two weakness rows (Control / Title / Severity / Comments):")
    ci = {c: header.index(c) for c in ("Control", "Control Title", "Severity", "Comments")}
    for row in rows[1:3]:
        print(f"     {row[ci['Control']]:<9} {row[ci['Control Title']][:34]:<34} "
              f"{row[ci['Severity']]:<10} {row[ci['Comments']][:30]}")

    print("\nFill the TBD operator fields, then upload as the POA&M of record.")


if __name__ == "__main__":
    main()
