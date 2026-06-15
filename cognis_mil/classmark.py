"""classmark — CAPCO-style banner builder. PLACEHOLDERS ONLY.

We do not ship real classification markings. Operators on cleared systems fill
in the values at runtime. This library validates *shape*, not content.

Reference: ODNI CAPCO Implementation Manual (unclassified, public).
"""
from __future__ import annotations

from dataclasses import dataclass, field

VALID_LEVELS = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"]
VALID_FGI = ["FGI"]  # Foreign Government Information marker placeholder


@dataclass
class ClassificationBanner:
    """Builds a CAPCO-shape banner. Validation of *form*, not content."""

    level: str = "UNCLASSIFIED"  # operator-supplied
    sci: list[str] = field(default_factory=list)  # operator-supplied SCI compartments
    sap: list[str] = field(default_factory=list)  # SAP program IDs (operator-supplied)
    dissem: list[str] = field(default_factory=list)  # NOFORN/REL TO/ORCON etc.
    nonic: list[str] = field(default_factory=list)  # Non-IC dissem (FOUO/CUI etc.)

    def validate(self) -> tuple[bool, list[str]]:
        errs = []
        if self.level not in VALID_LEVELS:
            errs.append(
                f"Invalid base level: {self.level}. Expected one of {VALID_LEVELS}."
            )
        # Higher levels with no markings is a smell, but not invalid
        if self.level == "UNCLASSIFIED" and (self.sci or self.sap):
            errs.append("UNCLASSIFIED cannot carry SCI/SAP compartments")
        return (len(errs) == 0, errs)

    def render(self) -> str:
        """Render the banner-line string. Operator content is passed through."""
        parts = [self.level]
        if self.sci:
            parts.append("/".join(self.sci))
        if self.sap:
            parts.append("SAR-" + "/".join(self.sap))
        suffix = []
        if self.dissem:
            suffix.extend(self.dissem)
        if self.nonic:
            suffix.extend(self.nonic)
        line = "//".join(parts)
        if suffix:
            line += "//" + "/".join(suffix)
        return line

    @classmethod
    def placeholder(cls) -> "ClassificationBanner":
        """Returns a safe, public-release placeholder."""
        return cls(level="UNCLASSIFIED", dissem=["FOR PUBLIC RELEASE"])
