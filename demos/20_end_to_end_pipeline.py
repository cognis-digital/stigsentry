"""Scenario 20 - End-to-end: raw SCAP -> enriched scan -> POA&M + OSCAL -> audit log.

Audience: anyone who wants the whole stigsentry pipeline in one screen. This
demo runs the full chain on the bundled enclave, fully offline:
  1. scan raw SCAP/SCC results, drop passing rows
  2. enrich each NIST control with its official OSCAL rev5 title
  3. emit the eMASS POA&M CSV
  4. emit the OSCAL 1.1.2 Assessment Results
  5. record each step in a tamper-evident audit log and verify the chain
"""
import csv
import io
import json
import tempfile
from pathlib import Path

from _common import scan_enclave, emit_poam, to_oscal, rule, kv
from cognis_mil.audit import AuditLog


def main() -> None:
    rule("END-TO-END  -  scan -> enrich -> POA&M + OSCAL -> verified audit log")
    log = AuditLog(Path(tempfile.mkdtemp(prefix="ss-demo20-")) / "run.log")

    # 1 + 2: scan + offline OSCAL title enrichment
    result = scan_enclave()
    resolved = result.meta.get("nist_800_53_controls_resolved", {})
    log.append({"step": "scan", "items": result.items_scanned,
                "findings": result.total_findings()})
    kv("1. Scanned:", f"{result.items_scanned} file(s), {result.total_findings()} open findings")
    kv("2. Enriched:", f"{len(resolved)} NIST controls -> official titles")

    # 3: POA&M
    poam = emit_poam(result)
    rows = len(list(csv.reader(io.StringIO(poam)))) - 1
    log.append({"step": "poam", "rows": rows})
    kv("3. POA&M:", f"{rows} weakness rows (eMASS-ready CSV)")

    # 4: OSCAL AR
    oscal = json.loads(to_oscal(result))
    res = oscal["assessment-results"]["results"][0]
    log.append({"step": "oscal", "findings": len(res["findings"])})
    kv("4. OSCAL AR:", f"{len(res['findings'])} findings / {len(res['observations'])} observations")

    # 5: verify the audit chain
    ok, msg = log.verify()
    log.append({"step": "verify", "ok": ok})
    kv("5. Audit chain:", msg)
    assert ok

    kv("\nComposite risk:", f"{result.composite_score}/100 ({result.risk_level})")
    print("Every step ran offline against the bundled snapshot and is recorded in")
    print("a hash-chained log — reproducible and self-attesting end to end.")


if __name__ == "__main__":
    main()
