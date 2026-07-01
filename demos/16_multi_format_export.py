"""Scenario 16 - One scan, five artifacts (console / JSON / Markdown / SARIF / OSCAL).

Audience: the engineer who needs the *same* assessment in different downstream
formats — a terminal summary, a JSON feed, a Markdown briefing, a SARIF file for
code-scanning, and an OSCAL AR for the GRC platform. This demo runs one scan of
the bundled enclave and emits all five, printing a size + shape line for each so
you can see one source of truth fanning out.
"""
import json

from _common import (
    scan_enclave, to_console, to_json, to_markdown, to_sarif, to_oscal,
    rule, kv,
)


def main() -> None:
    rule("EXPORT  -  one scan -> console / JSON / Markdown / SARIF / OSCAL")
    result = scan_enclave()
    kv("Findings in scan:", result.total_findings())

    console = to_console(result)
    js = to_json(result)
    md = to_markdown(result)
    sarif = to_sarif(result)
    oscal = to_oscal(result)

    print("\nArtifact          bytes   shape check")
    print("-" * 52)
    kv("console", f"{len(console):>6}   {len(console.splitlines())} lines")
    kv("json", f"{len(js):>6}   {len(json.loads(js)['findings'])} findings")
    kv("markdown", f"{len(md):>6}   table + banner")
    n_sarif = len(json.loads(sarif)["runs"][0]["results"])
    kv("sarif", f"{len(sarif):>6}   {n_sarif} SARIF results")
    res = json.loads(oscal)["assessment-results"]["results"][0]
    kv("oscal", f"{len(oscal):>6}   {len(res['findings'])} findings / {len(res['observations'])} obs")

    # sanity: every format reflects the same finding count
    assert len(json.loads(js)["findings"]) == result.total_findings()
    assert n_sarif == result.total_findings()
    assert len(res["findings"]) == result.total_findings()
    print("\nAll five artifacts derive from a single scan — consistent by construction.")


if __name__ == "__main__":
    main()
