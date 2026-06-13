"""stigsentry — DISA STIG + NIST 800-53 evidence mapper, eMASS-import POAM emitter.

Cognis additions only. Pairs with Wazuh / OSSEC / Splunk / Elastic as a
SIEM-agnostic enrichment layer.
"""
from __future__ import annotations
import json, csv
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

def parse_findings_file(path: Path) -> list[dict]:
    """Accept JSON list of {stig_id, host, status} OR CSV with same cols."""
    if path.suffix == ".json":
        try: return json.loads(path.read_text())
        except: return []
    if path.suffix in (".csv", ".tsv"):
        with path.open() as f:
            reader = csv.DictReader(f, delimiter="\t" if path.suffix == ".tsv" else ",")
            return list(reader)
    return []

def scan(target=".", **opts):
    r = ScanResult(tool_name="stigsentry", tool_version="0.1.0")
    p = Path(target)
    files = list(p.glob("*.json")) + list(p.glob("*.csv")) if p.is_dir() else [p]
    r.items_scanned = len(files)
    for f in files:
        if not f.is_file(): continue
        for finding in parse_findings_file(f):
            sid = finding.get("stig_id") or finding.get("rule_id") or ""
            status = (finding.get("status") or "").lower()
            if status in ("pass","not_a_finding"): continue
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
    r.finalize(); return r

def emit_poam(result: ScanResult, out: Path = None) -> str:
    """Emit eMASS-compatible POAM (Plan of Action & Milestones) CSV."""
    rows = [["Control","Weakness","Severity","SCD","POC","Status","Resources Required","Comments"]]
    for f in result.findings:
        rows.append([
            f.nist_800_53 or "(none)", f.title,
            f.severity.value, "TBD", "TBD",
            "Open", "TBD", f"STIG {f.disa_stig} / CCI {f.cci}"
        ])
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(rows)
    text = buf.getvalue()
    if out: out.write_text(text)
    return text
