"""Scenario 4 - ATO / Authorizing Official team.

Audience: the AO and the package team deciding whether to grant / sustain an
Authority To Operate. They don't read raw STIG rows — they need the risk posture
at a glance and a control-family rollup. This demo computes the severity-weighted
composite risk (NIST 800-30 style), rolls findings up by 800-53 control family,
and renders the Markdown briefing block you paste into the risk assessment.
"""
from collections import Counter

from _common import scan_enclave, to_markdown, rule, kv
from cognis_mil.models import Severity


def main() -> None:
    rule("ATO / AUTHORIZING OFFICIAL  -  risk posture + control-family rollup")
    result = scan_enclave()

    kv("Composite risk:", f"{result.composite_score}/100  ({result.risk_level})")
    kv("Total open findings:", result.total_findings())

    sev = Counter(f.severity for f in result.findings)
    print("\nFindings by severity:")
    for s in (Severity.VERY_HIGH, Severity.HIGH, Severity.MODERATE,
              Severity.LOW, Severity.VERY_LOW):
        if sev.get(s):
            print(f"     {s.value.upper():<12} {sev[s]}")

    # Roll findings up to the NIST 800-53 control family (the prefix before '-').
    fam = Counter()
    for f in result.findings:
        if f.nist_800_53:
            fam[f.nist_800_53.split("-")[0].upper()] += 1
    print("\nOpen findings by NIST 800-53 control family:")
    for family, n in fam.most_common():
        print(f"     {family:<4} {n}")

    print("\nAO Markdown briefing block (paste into the risk assessment):\n")
    md = to_markdown(result).splitlines()
    for line in md[:11]:  # header + score block + table head + a few rows
        print("   " + line)
    print("   ...")

    print("\nThe composite score and family rollup are the AO's go/no-go view;")
    print("the full table and POA&M (demo 02) back the residual-risk decision.")


if __name__ == "__main__":
    main()
