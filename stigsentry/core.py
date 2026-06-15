"""stigsentry — DISA STIG + NIST 800-53 evidence mapper, eMASS-import POAM emitter.

Cognis additions only. Pairs with Wazuh / OSSEC / Splunk / Elastic as a
SIEM-agnostic enrichment layer.
"""
from __future__ import annotations
import csv
import io
import json
import sys
from pathlib import Path

from cognis_mil import ScanResult, Finding, Severity

# Sample of the DISA STIG → NIST 800-53 crosswalk (public)
# Real operators load DISA's full SCAP / XCCDF benchmarks.
STIG_CONTROLS = {
    "V-238211": {
        "title": "Admin account lockout < 3 attempts",
        "nist": "AC-7(a)",
        "sev": Severity.HIGH,
        "cci": "CCI-000044",
    },
    "V-238213": {
        "title": "SSH root login permitted",
        "nist": "AC-6(2)",
        "sev": Severity.HIGH,
        "cci": "CCI-000206",
    },
    "V-238219": {
        "title": "PIV/CAC not required",
        "nist": "IA-2(11)",
        "sev": Severity.HIGH,
        "cci": "CCI-000765",
    },
    "V-238230": {
        "title": "Unsigned kernel modules",
        "nist": "SI-7",
        "sev": Severity.HIGH,
        "cci": "CCI-001749",
    },
    "V-238298": {
        "title": "FIPS 140 mode disabled",
        "nist": "SC-13",
        "sev": Severity.VERY_HIGH,
        "cci": "CCI-002450",
    },
    "V-238382": {
        "title": "World-writable file owned by root",
        "nist": "AC-3",
        "sev": Severity.HIGH,
        "cci": "CCI-000213",
    },
    "V-242414": {
        "title": "Kubernetes API not requiring auth",
        "nist": "IA-2",
        "sev": Severity.VERY_HIGH,
        "cci": "CCI-000764",
    },
    "V-242418": {
        "title": "Blank password permitted",
        "nist": "IA-5",
        "sev": Severity.VERY_HIGH,
        "cci": "CCI-000196",
    },
}


class StigsentryError(Exception):
    """Raised for user-facing errors (bad input, missing files, parse failures)."""


def parse_findings_file(path: Path) -> list[dict]:
    """Accept JSON list of {stig_id, host, status} OR CSV/TSV with same cols.

    Raises StigsentryError with a clear message on parse failure.
    Returns an empty list for an empty file.
    """
    if not path.exists():
        raise StigsentryError(f"Input file not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []

    if path.suffix == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StigsentryError(
                f"Invalid JSON in {path}: {exc}"
            ) from exc
        if not isinstance(data, list):
            raise StigsentryError(
                f"{path}: expected a JSON array of findings, got {type(data).__name__}"
            )
        return data

    if path.suffix in (".csv", ".tsv"):
        delimiter = "\t" if path.suffix == ".tsv" else ","
        try:
            reader = csv.DictReader(io.StringIO(raw), delimiter=delimiter)
            rows = list(reader)
        except csv.Error as exc:
            raise StigsentryError(f"CSV parse error in {path}: {exc}") from exc
        if reader.fieldnames is None:
            return []
        required = {"stig_id", "status"}
        missing = required - {f.strip() for f in (reader.fieldnames or [])}
        if missing:
            raise StigsentryError(
                f"{path}: CSV is missing required columns: {sorted(missing)}"
            )
        return rows

    return []


def scan(target=".", **opts):
    """Scan *target* (directory or single file) for STIG findings.

    Raises StigsentryError on unrecoverable input problems so callers can
    display a clean message instead of a raw traceback.
    """
    p = Path(target)
    if not p.exists():
        raise StigsentryError(f"Target not found: {target}")

    r = ScanResult(tool_name="stigsentry", tool_version="0.1.0")

    if p.is_dir():
        files = list(p.glob("*.json")) + list(p.glob("*.csv"))
    else:
        files = [p]

    r.items_scanned = len(files)

    for f in files:
        if not f.is_file():
            continue
        try:
            raw_findings = parse_findings_file(f)
        except StigsentryError as exc:
            # Surface parse errors as LOW-severity informational findings so
            # the scan still completes and the operator sees the problem.
            r.add(Finding(
                "SS-PARSE-ERR",
                Severity.LOW,
                str(exc),
                location=str(f),
                remediation="Fix the input file format and re-run.",
            ))
            continue

        for finding in raw_findings:
            if not isinstance(finding, dict):
                continue
            sid = (finding.get("stig_id") or finding.get("rule_id") or "").strip()
            status = (finding.get("status") or "").lower().strip()
            if status in ("pass", "not_a_finding"):
                continue
            if not sid:
                r.add(Finding(
                    "SS-NO-ID",
                    Severity.LOW,
                    "Finding row missing stig_id/rule_id",
                    location=str(f),
                    remediation="Populate stig_id or rule_id in the input file.",
                ))
                continue
            info = STIG_CONTROLS.get(sid)
            if not info:
                r.add(Finding(
                    f"SS-UNK-{sid}",
                    Severity.LOW,
                    f"Unknown STIG ID: {sid}",
                    location=str(f),
                    remediation="Add to STIG_CONTROLS table",
                ))
                continue
            r.add(Finding(
                f"SS-{sid}",
                info["sev"],
                info["title"],
                location=finding.get("host", str(f)),
                nist_800_53=info["nist"],
                disa_stig=sid,
                cci=info["cci"],
                remediation=(
                    f"Remediate per DISA {sid}, evidence to control {info['nist']}"
                ),
            ))

    r.finalize()
    return r


def emit_poam(result: ScanResult, out: Path = None) -> str:
    """Emit eMASS-compatible POAM (Plan of Action & Milestones) CSV."""
    rows = [
        [
            "Control", "Weakness", "Severity", "SCD", "POC",
            "Status", "Resources Required", "Comments",
        ]
    ]
    for f in result.findings:
        rows.append([
            f.nist_800_53 or "(none)",
            f.title,
            f.severity.value,
            "TBD",
            "TBD",
            "Open",
            "TBD",
            f"STIG {f.disa_stig} / CCI {f.cci}",
        ])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(rows)
    text = buf.getvalue()
    if out is not None:
        try:
            Path(out).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"Warning: could not write POAM to {out}: {exc}", file=sys.stderr)
    return text
