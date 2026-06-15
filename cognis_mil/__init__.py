"""cognis_mil — shared library for the 12-repo military/IC ecosystem.

Public, unclassified, EAR99. Provides:
  - Finding/ScanResult models with classification-placeholder fields
  - Severity-weighted scoring (NIST 800-30 style: Very High → Very Low)
  - 5 exporters: console / JSON / SARIF / Markdown / OSCAL-skeleton
  - CLI builder with --classification flag (placeholder only)
  - Audit-log primitive (hash-chained, tamper-evident, local-only)
"""
from .models import Severity as Severity, Finding as Finding, ScanResult as ScanResult
from .exporters import (
    to_console as to_console,
    to_json as to_json,
    to_sarif as to_sarif,
    to_markdown as to_markdown,
    to_oscal_skeleton as to_oscal_skeleton,
)
from .cli import make_cli as make_cli
from .audit import AuditLog as AuditLog
from .classmark import ClassificationBanner as ClassificationBanner

__version__ = "0.1.0"
