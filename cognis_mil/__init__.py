"""cognis_mil — shared library for the 12-repo military/IC ecosystem.

Public, unclassified, EAR99. Provides:
  - Finding/ScanResult models with classification-placeholder fields
  - Severity-weighted scoring (NIST 800-30 style: Very High → Very Low)
  - 5 exporters: console / JSON / SARIF / Markdown / OSCAL-skeleton
  - CLI builder with --classification flag (placeholder only)
  - Audit-log primitive (hash-chained, tamper-evident, local-only)
"""
from .models import Severity, Finding, ScanResult
from .exporters import to_console, to_json, to_sarif, to_markdown, to_oscal_skeleton
from .cli import make_cli
from .audit import AuditLog
from .classmark import ClassificationBanner  # re-export for convenience

__version__ = "0.1.0"
