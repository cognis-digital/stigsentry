"""Scenario 12 - Tamper-evident audit trail for an assessment run.

Audience: the assessor / ISSM who must prove the assessment record wasn't edited
after the fact. cognis_mil ships a hash-chained, append-only audit log: each
entry binds to the previous entry's hash, so any post-hoc edit breaks the chain.
This demo logs a scan + emit, verifies the chain is intact, then tampers one
entry and shows verify() catching it.
"""
import json
import tempfile
from pathlib import Path

from _common import scan_enclave, rule, kv
from cognis_mil.audit import AuditLog


def main() -> None:
    rule("AUDIT TRAIL  -  hash-chained, tamper-evident assessment log")
    log_path = Path(tempfile.mkdtemp(prefix="ss-demo12-")) / "assessment.log"
    log = AuditLog(log_path)

    result = scan_enclave()
    log.append({"action": "scan", "items": result.items_scanned,
                "findings": result.total_findings(), "risk": result.risk_level})
    log.append({"action": "emit_oscal", "tool": "stigsentry"})
    log.append({"action": "emit_poam", "rows": result.total_findings()})

    ok, msg = log.verify()
    kv("Entries logged:", len(log_path.read_text().splitlines()))
    kv("Chain status:", msg)
    assert ok

    # Tamper: rewrite the first entry's event payload.
    lines = log_path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["event"]["findings"] = 0  # pretend the scan found nothing
    lines[0] = json.dumps(rec)
    log_path.write_text("\n".join(lines) + "\n")

    ok2, msg2 = log.verify()
    kv("After tampering:", msg2)
    assert not ok2

    print("\nAny edit to a logged assessment event breaks the hash chain — the")
    print("record is self-attesting without a central server.")


if __name__ == "__main__":
    main()
