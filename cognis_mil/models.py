"""NIST 800-30 / DoD-aligned severity model. All values are placeholders."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
import time

class Severity(str, Enum):
    # NIST 800-30 Table I-2 maps. We keep CRITICAL as a synonym for VERY_HIGH.
    VERY_HIGH = "very_high"
    HIGH      = "high"
    MODERATE  = "moderate"
    LOW       = "low"
    VERY_LOW  = "very_low"
    CRITICAL  = "very_high"  # alias

WEIGHTS = {
    Severity.VERY_HIGH: 10.0,
    Severity.HIGH:       7.0,
    Severity.MODERATE:   4.0,
    Severity.LOW:        2.0,
    Severity.VERY_LOW:   0.5,
}

@dataclass
class Finding:
    id: str
    severity: Severity
    title: str
    description: str = ""
    location: str = ""
    remediation: str = ""
    category: str = ""
    # Compliance crosswalks (all placeholders unless operator fills in)
    nist_800_53: str = ""        # e.g. "AC-2(1)"
    disa_stig: str = ""          # e.g. "V-242414"
    mitre_attack: str = ""       # e.g. "T1078"
    cci: str = ""                # Control Correlation Identifier
    weight: float = 0.0

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if not self.weight:
            self.weight = WEIGHTS[self.severity]

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

@dataclass
class ScanResult:
    tool_name: str
    tool_version: str = "0.1.0"
    started_at: float = field(default_factory=time.time)
    items_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    composite_score: float = 0.0
    risk_level: str = "Very Low"
    meta: dict = field(default_factory=dict)
    # Classification fields are OPERATOR-SUPPLIED. We default to placeholder.
    classification_placeholder: str = "UNCLASSIFIED//FOR PUBLIC RELEASE"

    def add(self, f: Finding): self.findings.append(f)
    def all_findings(self): return self.findings
    def total_findings(self): return len(self.findings)

    def finalize(self):
        import math
        if not self.findings:
            self.composite_score = 0.0; self.risk_level = "Very Low"; return self
        score = sum(f.weight for f in self.findings) * 1.5
        self.composite_score = min(100.0, score)
        s = self.composite_score
        self.risk_level = "Very High" if s >= 80 else "High" if s >= 60 else "Moderate" if s >= 40 else "Low" if s >= 20 else "Very Low"
        return self

    def to_dict(self):
        return {
            "classification": self.classification_placeholder,
            "tool_name": self.tool_name, "tool_version": self.tool_version,
            "items_scanned": self.items_scanned,
            "composite_score": round(self.composite_score, 1),
            "risk_level": self.risk_level,
            "findings": [f.to_dict() for f in self.findings],
            "meta": self.meta,
        }
