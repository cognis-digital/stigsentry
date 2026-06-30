"""Scenario 14 - Severity weighting and the composite risk score.

Audience: anyone who needs to understand *how* the headline 0-100 composite risk
is computed. Each severity carries a NIST 800-30-style weight; the composite is
the weighted sum (x1.5, capped at 100) and the risk band falls out of that. This
demo prints the weight table, then shows the composite climbing as findings of
increasing severity are added.
"""
from _common import rule, kv
from cognis_mil.models import ScanResult, Finding, Severity, WEIGHTS


def main() -> None:
    rule("SCORING  -  severity weights -> composite risk band")

    print("\nSeverity weight table (NIST 800-30 style):")
    for sev in (Severity.VERY_HIGH, Severity.HIGH, Severity.MODERATE,
                Severity.LOW, Severity.VERY_LOW):
        kv(f"  {sev.value.upper()}:", WEIGHTS[sev])

    print("\nComposite risk as findings accumulate:")
    r = ScanResult(tool_name="stigsentry")
    ladder = [Severity.VERY_LOW, Severity.LOW, Severity.MODERATE,
              Severity.HIGH, Severity.VERY_HIGH, Severity.VERY_HIGH]
    for i, sev in enumerate(ladder, 1):
        r.add(Finding(f"f{i}", sev, f"finding {i}"))
        r.finalize()
        print(f"     +{sev.value.upper():<10} -> {r.composite_score:>5.1f}/100  ({r.risk_level})")

    print("\nThe composite is the AO's at-a-glance number; the per-family rollup")
    print("(demo 04) and the POA&M (demo 02) back the residual-risk decision.")


if __name__ == "__main__":
    main()
