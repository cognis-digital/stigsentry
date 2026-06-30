"""Scenario 5 - Disconnected / air-gapped enclaves & CI pipelines.

Audience: teams running on disconnected, edge, or air-gapped gear, and the CI
engineers who gate builds on compliance. The whole flow runs with the NIST OSCAL
catalog served from a cached snapshot — no network. This demo shows the offline
control resolver, then the SARIF export that feeds a code-scanning dashboard,
and finally the --fail-on gate logic an air-gapped pipeline runs to block a
non-compliant deployment.
"""
import json

from _common import scan_enclave, to_sarif, rule, kv
from stigsentry.feeds import ControlResolver
from cognis_mil.models import WEIGHTS, Severity


def main() -> None:
    rule("AIR-GAP / CI  -  offline OSCAL resolve + SARIF + fail-on gate")
    result = scan_enclave()

    # The control resolver loaded entirely from the cached snapshot (offline=True).
    resolver = ControlResolver(offline=True)
    kv("OSCAL controls in cache:", len(resolver))
    kv("Resolved offline, no net:", "AC-6(2) -> " + (resolver.title("AC-6(2)") or "(n/a)"))

    sarif = json.loads(to_sarif(result))
    run = sarif["runs"][0]
    levels = {}
    for r in run["results"]:
        levels[r["level"]] = levels.get(r["level"], 0) + 1
    kv("\nSARIF schema:", sarif["$schema"].rsplit("/", 1)[-1])
    kv("SARIF results:", f"{len(run['results'])}  ({dict(sorted(levels.items()))})")

    # CI gate: --fail-on high means exit non-zero if any finding >= HIGH exists.
    threshold = WEIGHTS[Severity.HIGH]
    blocking = [f for f in result.findings if WEIGHTS[f.severity] >= threshold]
    print(f"\nCI gate (--fail-on high): {len(blocking)} finding(s) at/above HIGH")
    for f in blocking[:3]:
        print(f"     would FAIL build: [{f.severity.value.upper()}] {f.disa_stig} {f.title}")
    decision = "BLOCK build (non-zero exit)" if blocking else "PASS"
    kv("\nPipeline decision:", decision)

    print("\nEverything above ran offline against the bundled snapshot — the same")
    print("flow works inside an air-gapped enclave after a one-time sneakernet import.")


if __name__ == "__main__":
    main()
