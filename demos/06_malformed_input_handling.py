"""Scenario 6 - Robustness: malformed / mixed inputs in a results drop.

Audience: the engineer whose scan directory is a grab-bag of exporter outputs —
some clean, some half-written, some in a wrapper-object shape. A compliance
scanner must never silently swallow a broken file (that would read as a false
"all clear"). This demo drops a deliberately-broken JSON next to a good one and
shows stigsentry flagging the unparseable file as its own finding while still
scanning the rest — and then the strict mode that fails the build instead.
"""
import json
import tempfile
from pathlib import Path

from _common import rule, kv
from stigsentry.core import scan, FindingsParseError


def main() -> None:
    rule("ROBUSTNESS  -  a broken file is flagged, never silently dropped")

    work = Path(tempfile.mkdtemp(prefix="ss-demo6-"))
    (work / "good.json").write_text(json.dumps(
        [{"stig_id": "V-238298", "host": "h1", "status": "fail"}]), encoding="utf-8")
    (work / "wrapper.json").write_text(json.dumps(
        {"findings": [{"stig_id": "V-242418", "host": "h2", "status": "fail"}]}),
        encoding="utf-8")
    (work / "broken.json").write_text("{ this is not valid json", encoding="utf-8")

    kv("Files in results drop:", "good.json, wrapper.json (object shape), broken.json")

    # lenient (default): broken file surfaces as a MODERATE finding, rest scan
    result = scan(str(work), offline=True)
    print("\nLenient scan (default) — broken file becomes a tracked finding:")
    for f in result.findings:
        print(f"     [{f.severity.value.upper():<10}] {f.id:<16} {f.title}")
    assert any(f.id == "SS-PARSE-ERROR" for f in result.findings)
    assert "SS-V-238298" in {f.id for f in result.findings}      # good file scanned
    assert "SS-V-242418" in {f.id for f in result.findings}      # wrapper shape scanned

    # strict: a malformed file fails the build outright
    print("\nStrict scan (CI mode) — a malformed export fails the build:")
    try:
        scan(str(work), offline=True, strict=True)
    except FindingsParseError as exc:
        kv("Raised:", f"FindingsParseError ({str(exc).split(':')[-1].strip()[:40]}...)")

    print("\nNo silent empties: a half-written export can't masquerade as compliant.")


if __name__ == "__main__":
    main()
