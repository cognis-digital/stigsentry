"""Scenario 19 - Per-host triage and a fleet remediation order.

Audience: the ops lead with a fleet of hosts and finite remediation hours. This
demo scans the bundled multi-host enclave, computes each host's worst severity
and a host-level risk weight (sum of finding weights), and prints the hosts in
the order you should work them — worst risk first — so the most exposed box gets
patched first.
"""
from collections import defaultdict

from _common import scan_enclave, rule, kv
from cognis_mil.models import WEIGHTS


def main() -> None:
    rule("TRIAGE  -  rank hosts by aggregate risk, worst-first")
    result = scan_enclave()

    by_host = defaultdict(list)
    for f in result.findings:
        by_host[f.location].append(f)

    ranked = sorted(
        by_host.items(),
        key=lambda kv: (-sum(WEIGHTS[f.severity] for f in kv[1]), kv[0]),
    )

    print("\n  rank  host                          risk   open  worst")
    print("  " + "-" * 58)
    for i, (host, findings) in enumerate(ranked, 1):
        risk = sum(WEIGHTS[f.severity] for f in findings)
        worst = max(findings, key=lambda f: WEIGHTS[f.severity]).severity.value.upper()
        print(f"  {i:>4}  {host:<28} {risk:>6.1f}  {len(findings):>4}  {worst}")

    top = ranked[0][0]
    kv("\nPatch first:", top)
    print("Work the list top-down to retire the most aggregate risk per hour spent.")


if __name__ == "__main__":
    main()
