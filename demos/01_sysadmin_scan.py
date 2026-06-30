"""Scenario 1 - System administrators.

Audience: the sysadmin / engineer who just ran a SCAP/SCC benchmark and has a pile
of raw STIG pass/fail rows. The question is simple: *what actually failed on my
boxes, how bad is it, and what do I fix first?* stigsentry ingests the bundled
SCAP results, drops the passing rows, and hands back a severity-ranked, per-host
worklist with the remediation note for each open finding.
"""
from _common import scan_enclave, rule, kv
from cognis_mil.models import WEIGHTS


def main() -> None:
    rule("SYSADMIN  -  turn raw SCAP rows into a fix-first worklist")
    result = scan_enclave()

    kv("Result files scanned:", result.items_scanned)
    kv("Open findings:", result.total_findings())
    kv("Composite risk:", f"{result.composite_score}/100 ({result.risk_level})")

    # Group open findings by host, worst-first.
    by_host: dict[str, list] = {}
    for f in result.findings:
        by_host.setdefault(f.location, []).append(f)

    print("\nOpen STIG findings by host (worst severity first):")
    for host in sorted(by_host):
        findings = sorted(by_host[host], key=lambda f: WEIGHTS[f.severity], reverse=True)
        print(f"\n  {host}  ({len(findings)} open)")
        for f in findings:
            print(f"     [{f.severity.value.upper():<10}] {f.disa_stig or '(unknown)':<10} {f.title}")
            print(f"        fix: {f.remediation}")

    print("\nPassing rows were dropped automatically; only open findings carry through.")
    print("Run the same scan in CI with --fail-on high to block a non-compliant build.")


if __name__ == "__main__":
    main()
