import json
import time
import uuid
from .models import Severity, ScanResult

ICON = {Severity.VERY_HIGH:"🚨", Severity.HIGH:"❗", Severity.MODERATE:"⚠️ ", Severity.LOW:"•", Severity.VERY_LOW:"ℹ️ "}

# Deterministic namespace so the same finding always yields the same OSCAL uuid.
_OSCAL_NS = uuid.UUID("c0911500-0000-4000-8000-636f676e6973")


def _oscal_uuid(*parts: str) -> str:
    return str(uuid.uuid5(_OSCAL_NS, "|".join(parts)))


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch or 0))

def to_json(r: ScanResult) -> str:
    return json.dumps(r.to_dict(), indent=2, default=str)

def to_console(r: ScanResult) -> str:
    lines = [
        "═" * 70,
        f"  {r.classification_placeholder}",
        "═" * 70,
        f"  Tool: {r.tool_name} v{r.tool_version}",
        f"  Items scanned: {r.items_scanned}",
        f"  Composite risk: {r.composite_score}/100 ({r.risk_level})",
        f"  Findings: {r.total_findings()}",
        "─" * 70,
    ]
    for f in r.findings[:100]:
        lines.append(f"  {ICON[f.severity]} [{f.severity.value.upper():<10}] {f.id:<14} {f.title}")
        if f.location:    lines.append(f"      📍 {f.location}")
        if f.nist_800_53: lines.append(f"      📋 NIST 800-53: {f.nist_800_53}")
        if f.disa_stig:   lines.append(f"      🛡  STIG: {f.disa_stig}")
        if f.mitre_attack:lines.append(f"      🎯 ATT&CK: {f.mitre_attack}")
        if f.remediation: lines.append(f"      💡 {f.remediation}")
    lines.append("═" * 70)
    lines.append(f"  {r.classification_placeholder}")
    lines.append("═" * 70)
    return "\n".join(lines)

def to_markdown(r: ScanResult) -> str:
    out = [
        f"# {r.tool_name} report",
        f"",
        f"> **{r.classification_placeholder}**",
        f"",
        f"- **Score:** {r.composite_score}/100 ({r.risk_level})",
        f"- **Items scanned:** {r.items_scanned}",
        f"- **Findings:** {r.total_findings()}",
        f"",
        "| Sev | ID | Title | NIST | STIG | ATT&CK |",
        "|-----|----|----|----|----|----|",
    ]
    for f in r.findings:
        out.append(f"| {f.severity.value} | `{f.id}` | {f.title} | {f.nist_800_53} | {f.disa_stig} | {f.mitre_attack} |")
    out.append(""); out.append(f"> **{r.classification_placeholder}**")
    return "\n".join(out)

def to_sarif(r: ScanResult) -> str:
    sev_map = {Severity.VERY_HIGH:"error", Severity.HIGH:"error", Severity.MODERATE:"warning", Severity.LOW:"note", Severity.VERY_LOW:"note"}
    return json.dumps({
        "version":"2.1.0",
        "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
        "runs":[{
            "tool":{"driver":{"name":r.tool_name,"version":r.tool_version}},
            "properties":{"classification":r.classification_placeholder},
            "results":[{
                "ruleId":f.id, "level":sev_map[f.severity],
                "message":{"text":f"{f.title} | {f.description}"},
                "locations":[{"physicalLocation":{"artifactLocation":{"uri":f.location.split(':')[0] if f.location else 'unknown'}}}],
                "properties":{"nist":f.nist_800_53, "stig":f.disa_stig, "attack":f.mitre_attack, "cci":f.cci},
            } for f in r.findings],
        }],
    }, indent=2)

def to_oscal(r: ScanResult) -> str:
    """Real OSCAL 1.1.2 Assessment Results (SAR) — ingestible by GRC platforms.

    Every finding becomes a paired OSCAL observation + finding, with deterministic
    UUIDs (uuid5, stable across runs), a control mapping to the NIST 800-53 control,
    a `not-satisfied` target status, and STIG/CCI/ATT&CK preserved as props. No
    placeholder zero-UUIDs — this validates against the OSCAL AR model shape.
    """
    ts = _iso(getattr(r, "started_at", 0) or 0)
    ar_uuid = _oscal_uuid(r.tool_name, "assessment-results")
    result_uuid = _oscal_uuid(r.tool_name, "result")

    observations, findings = [], []
    for f in r.findings:
        obs_uuid = _oscal_uuid(r.tool_name, "obs", f.id)
        fnd_uuid = _oscal_uuid(r.tool_name, "fnd", f.id)
        props = [{"name": "severity", "value": f.severity.value, "ns": "https://cognis.digital/ns/oscal"}]
        for name, val in (("disa-stig", f.disa_stig), ("cci", f.cci), ("mitre-attack", f.mitre_attack)):
            if val:
                props.append({"name": name, "value": val, "ns": "https://cognis.digital/ns/oscal"})
        observations.append({
            "uuid": obs_uuid,
            "title": f.id,
            "description": f.title or f.description or f.id,
            "methods": ["EXAMINE"],
            "types": ["finding"],
            "collected": ts,
            **({"relevant-evidence": [{"description": f.location}]} if f.location else {}),
        })
        finding = {
            "uuid": fnd_uuid,
            "title": f.title or f.id,
            "description": f.remediation or f.description or f.title or f.id,
            "props": props,
            "target": {
                "type": "objective-id",
                "target-id": f.nist_800_53 or f.id,
                "status": {"state": "not-satisfied"},
            },
            "related-observations": [{"observation-uuid": obs_uuid}],
        }
        if f.nist_800_53:
            finding["implementation-statement-uuid"] = _oscal_uuid("control", f.nist_800_53)
        findings.append(finding)

    return json.dumps({
        "assessment-results": {
            "uuid": ar_uuid,
            "metadata": {
                "title": f"{r.tool_name} — STIG/RMF Assessment Results",
                "last-modified": ts,
                "version": r.tool_version,
                "oscal-version": "1.1.2",
                "props": [{"name": "classification", "value": r.classification_placeholder}],
            },
            "import-ap": {"href": "#assessment-plan"},
            "results": [{
                "uuid": result_uuid,
                "title": f"{r.tool_name} scan",
                "description": f"{r.total_findings()} finding(s); composite risk "
                               f"{r.composite_score}/100 ({r.risk_level}).",
                "start": ts,
                "reviewed-controls": {"control-selections": [{"include-all": {}}]},
                "observations": observations,
                "findings": findings,
            }],
        }
    }, indent=2)


# Back-compat alias (older imports / docs referenced the skeleton name).
to_oscal_skeleton = to_oscal
