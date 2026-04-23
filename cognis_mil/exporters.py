import json
from .models import Severity, ScanResult

ICON = {Severity.VERY_HIGH:"🚨", Severity.HIGH:"❗", Severity.MODERATE:"⚠️ ", Severity.LOW:"•", Severity.VERY_LOW:"ℹ️ "}

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

def to_oscal_skeleton(r: ScanResult) -> str:
    """Minimal OSCAL 1.1 Assessment Results skeleton — operator fills the rest."""
    return json.dumps({
        "assessment-results":{
            "uuid": "00000000-0000-0000-0000-000000000000",
            "metadata":{"title":f"{r.tool_name} assessment",
                        "version":r.tool_version,
                        "oscal-version":"1.1.0",
                        "remarks":"PLACEHOLDER — operator must supply UUIDs, parties, system-security-plan link"},
            "results":[{
                "uuid":"00000000-0000-0000-0000-000000000001",
                "findings":[{
                    "uuid":f"finding-{i}", "title":f.title,
                    "description":f.description,
                    "related-controls":[{"control-id":f.nist_800_53}] if f.nist_800_53 else [],
                } for i, f in enumerate(r.findings, 1)]
            }]
        }
    }, indent=2)
