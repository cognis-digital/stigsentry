"""Scenario 7 - Ingesting real exporter shapes (OpenSCAP / SCC / hand-rolled).

Audience: integrators wiring stigsentry behind whatever produced the findings.
Different scanners nest the findings list under different keys — ``findings``,
``results``, ``rule_results``, ``items`` — or emit a bare list, or a single
object. This demo feeds every one of those shapes through the same scan path and
shows they all resolve to the same findings, so you don't have to pre-massage the
exporter output.
"""
import json
import tempfile
from pathlib import Path

from _common import rule, kv
from stigsentry.core import scan


SHAPES = {
    "bare list": [{"stig_id": "V-238298", "status": "fail"}],
    "{'findings': [...]}": {"findings": [{"stig_id": "V-238298", "status": "fail"}]},
    "{'results': [...]}": {"results": [{"stig_id": "V-238298", "status": "fail"}]},
    "{'rule_results': [...]}": {"rule_results": [{"stig_id": "V-238298", "status": "fail"}]},
    "single object": {"stig_id": "V-238298", "status": "fail"},
}


def main() -> None:
    rule("INTEGRATION  -  every common JSON exporter shape ingests the same")
    work = Path(tempfile.mkdtemp(prefix="ss-demo7-"))

    for label, payload in SHAPES.items():
        f = work / "f.json"
        f.write_text(json.dumps(payload), encoding="utf-8")
        r = scan(str(f), offline=True)
        ids = sorted(f.id for f in r.findings)
        kv(f"{label}:", f"{r.total_findings()} finding(s) -> {ids}")
        assert ids == ["SS-V-238298"], (label, ids)

    print("\nAll shapes normalize to the same finding — no exporter-specific glue.")


if __name__ == "__main__":
    main()
