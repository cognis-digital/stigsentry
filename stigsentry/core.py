"""stigsentry — DISA STIG + NIST 800-53 evidence mapper, eMASS-import POAM emitter.

Cognis additions only. Pairs with Wazuh / OSSEC / Splunk / Elastic as a
SIEM-agnostic enrichment layer.
"""
from __future__ import annotations
import json, csv, time
from pathlib import Path
from cognis_mil import ScanResult, Finding, Severity

# Sample of the DISA STIG → NIST 800-53 crosswalk (public)
# Real operators load DISA's full SCAP / XCCDF benchmarks.
STIG_CONTROLS = {
    "V-238211": {"title":"Admin account lockout < 3 attempts", "nist":"AC-7(a)", "sev": Severity.HIGH, "cci":"CCI-000044"},
    "V-238213": {"title":"SSH root login permitted",          "nist":"AC-6(2)", "sev": Severity.HIGH, "cci":"CCI-000206"},
    "V-238219": {"title":"PIV/CAC not required",               "nist":"IA-2(11)","sev": Severity.HIGH, "cci":"CCI-000765"},
    "V-238230": {"title":"Unsigned kernel modules",            "nist":"SI-7",    "sev": Severity.HIGH, "cci":"CCI-001749"},
    "V-238298": {"title":"FIPS 140 mode disabled",             "nist":"SC-13",   "sev": Severity.VERY_HIGH, "cci":"CCI-002450"},
    "V-238382": {"title":"World-writable file owned by root",  "nist":"AC-3",    "sev": Severity.HIGH, "cci":"CCI-000213"},
    "V-242414": {"title":"Kubernetes API not requiring auth",  "nist":"IA-2",    "sev": Severity.VERY_HIGH, "cci":"CCI-000764"},
    "V-242418": {"title":"Blank password permitted",           "nist":"IA-5",    "sev": Severity.VERY_HIGH, "cci":"CCI-000196"},
}

class FindingsParseError(ValueError):
    """Raised when a findings file cannot be parsed (malformed JSON/CSV)."""


def _coerce_findings(data, src: str) -> list[dict]:
    """Normalize parsed JSON into a list of finding dicts.

    Accepts a bare list, or a wrapper object that nests the list under a common
    key (``findings`` / ``results`` / ``rules`` / ``items``) — the latter is the
    shape most SCAP/SCC and OpenSCAP exporters emit. Anything else is rejected
    with a clear error rather than crashing downstream on a bad ``.get``.
    """
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("findings", "results", "rules", "items", "rule_results"):
            val = data.get(key)
            if isinstance(val, list):
                return [d for d in val if isinstance(d, dict)]
        # a single finding object, not a wrapper
        if any(k in data for k in ("stig_id", "rule_id", "status")):
            return [data]
        raise FindingsParseError(
            f"{src}: JSON object has no recognized findings list "
            f"(expected a list, or a 'findings'/'results' key)")
    raise FindingsParseError(
        f"{src}: expected a JSON list or object, got {type(data).__name__}")


def parse_findings_file(path: Path) -> list[dict]:
    """Parse a findings file into a list of ``{stig_id, host, status}`` dicts.

    Accepts ``.json`` (a list, or an object nesting the list under
    ``findings``/``results``/…) and ``.csv``/``.tsv`` (header row with the same
    columns). Suffix matching is case-insensitive. Malformed JSON or an
    unreadable file raises :class:`FindingsParseError` with the offending path
    rather than silently returning an empty list (which would mask findings and
    yield a false "all clear" on a compliance scan).
    """
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise FindingsParseError(f"{path}: cannot read file: {exc}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise FindingsParseError(f"{path}: invalid JSON: {exc}") from exc
        return _coerce_findings(data, str(path))
    if suffix in (".csv", ".tsv"):
        try:
            with path.open(encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f, delimiter="\t" if suffix == ".tsv" else ",")
                rows = [dict(r) for r in reader]
        except OSError as exc:
            raise FindingsParseError(f"{path}: cannot read file: {exc}") from exc
        return rows
    return []

def scan(target=".", enrich=True, offline=False, strict=False, **opts):
    """Scan a findings file or a directory of them.

    ``strict=True`` re-raises a :class:`FindingsParseError` from any input file
    instead of recording it as a finding — useful in CI where a malformed export
    should fail the build rather than pass silently.
    """
    r = ScanResult(tool_name="stigsentry", tool_version="0.1.0")
    p = Path(target)
    if not p.exists():
        raise FileNotFoundError(
            f"scan target does not exist: {target!r} "
            f"(pass an existing findings file or a directory of them)")
    if p.is_dir():
        files = sorted(
            f for f in p.iterdir()
            if f.is_file() and f.suffix.lower() in (".json", ".csv", ".tsv"))
    else:
        files = [p]
    r.items_scanned = len(files)
    for f in files:
        if not f.is_file(): continue
        try:
            findings = parse_findings_file(f)
        except FindingsParseError as exc:
            if strict:
                raise
            # surface the parse failure as a finding instead of dropping the file
            r.add(Finding(f"SS-PARSE-ERROR", Severity.MODERATE,
                          f"Unparseable findings file: {f.name}", location=str(f),
                          description=str(exc),
                          remediation="Fix the file format; see error in description"))
            continue
        for finding in findings:
            sid = finding.get("stig_id") or finding.get("rule_id") or ""
            status = (finding.get("status") or "").lower()
            if status in ("pass","not_a_finding","notapplicable","not_applicable"): continue
            info = STIG_CONTROLS.get(sid)
            if not info:
                r.add(Finding(f"SS-UNK-{sid}", Severity.LOW,
                              f"Unknown STIG ID: {sid}", location=str(f),
                              remediation="Add to STIG_CONTROLS table"))
                continue
            r.add(Finding(f"SS-{sid}", info["sev"], info["title"],
                          location=finding.get("host", str(f)),
                          nist_800_53=info["nist"], disa_stig=sid, cci=info["cci"],
                          remediation=f"Remediate per DISA {sid}, evidence to control {info['nist']}"))
    # Real feed enrichment: resolve each NIST 800-53 control ID to its official
    # title from the authoritative OSCAL 800-53 rev5 catalog (cached / offline-safe).
    if enrich:
        try:
            from .feeds import enrich_result
            enrich_result(r, offline=offline)
        except Exception:  # never let an unreachable feed break a scan
            pass
    r.finalize(); return r

def emit_poam(result: ScanResult, out: Path = None) -> str:
    """Emit eMASS-compatible POAM (Plan of Action & Milestones) CSV."""
    # Official NIST 800-53 rev5 control titles, resolved from the real OSCAL
    # catalog by feeds.enrich_result() (empty dict if enrichment didn't run).
    titles = result.meta.get("nist_800_53_controls_resolved", {})
    rows = [["Control","Control Title","Weakness","Severity","SCD","POC","Status","Resources Required","Comments"]]
    for f in result.findings:
        rows.append([
            f.nist_800_53 or "(none)", titles.get(f.nist_800_53, ""), f.title,
            f.severity.value, "TBD", "TBD",
            "Open", "TBD", f"STIG {f.disa_stig} / CCI {f.cci}"
        ])
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(rows)
    text = buf.getvalue()
    if out:
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        # explicit UTF-8 so control titles with non-ASCII survive on Windows (cp1252)
        out.write_text(text, encoding="utf-8")
    return text
