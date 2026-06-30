"""Scenario 15 - CSV / TSV ingest and the case-insensitive suffix handling.

Audience: the operator whose SCC/STIG Viewer export is a spreadsheet, possibly
with an upper-cased extension (``.CSV``) or tab-separated. stigsentry reads
``.csv``/``.tsv`` (and any letter-case of them) with the same ``stig_id, host,
status`` columns as the JSON path. This demo writes a CSV, an uppercase-suffix
CSV, and a TSV, and confirms all three ingest identically.
"""
import tempfile
from pathlib import Path

from _common import rule, kv
from stigsentry.core import scan


def main() -> None:
    rule("CSV / TSV  -  spreadsheet exports ingest like JSON (any suffix case)")
    work = Path(tempfile.mkdtemp(prefix="ss-demo15-"))

    rows = "stig_id,host,status\nV-238298,h1,fail\nV-238211,h2,pass\n"
    (work / "a.csv").write_text(rows, encoding="utf-8")
    (work / "b.CSV").write_text(rows, encoding="utf-8")  # upper-case suffix
    (work / "c.tsv").write_text(rows.replace(",", "\t"), encoding="utf-8")

    for name in ("a.csv", "b.CSV", "c.tsv"):
        r = scan(str(work / name), offline=True)
        ids = sorted(f.id for f in r.findings)
        kv(f"{name}:", f"{r.total_findings()} open -> {ids}")
        # the passing V-238211 row is dropped; only the V-238298 fail carries
        assert ids == ["SS-V-238298"], (name, ids)

    print("\nUpper-case suffixes and tab delimiters are handled — no pre-conversion.")


if __name__ == "__main__":
    main()
