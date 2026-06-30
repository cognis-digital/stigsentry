"""Shared helpers for the stigsentry demo scenarios.

Every demo runs **fully offline**: the NIST 800-53 rev5 (OSCAL) catalog is served
from the trimmed snapshot bundled under ``tests/fixtures/`` via the edge / air-gap
``datafeeds`` cache, so the scenarios are byte-for-byte reproducible on a
disconnected box with zero network access. The data they scan is bundled sample
SCAP/SCC findings under ``demos/`` — no live host is touched.

Run one:    python demos/02_isso_poam.py
Run all:    python demos/run_all.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# allow `python demos/xx.py` from anywhere
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

DEMO_DIR = Path(__file__).resolve().parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"

# Point the feed cache at the bundled OSCAL snapshot (edge / air-gap mode) BEFORE
# importing anything that reads it. On a connected box you can drop this and the
# live NIST catalog is fetched + cached automatically.
os.environ.setdefault("COGNIS_FEEDS_CACHE", str(FIXTURES))

from stigsentry.core import scan, emit_poam, STIG_CONTROLS  # noqa: E402
from cognis_mil.exporters import (  # noqa: E402
    to_console, to_json, to_sarif, to_markdown, to_oscal,
)

# The bundled sample enclave: a small SCAP/SCC results set across a few hosts.
ENCLAVE = DEMO_DIR / "enclave"


def scan_enclave(target: Path = ENCLAVE):
    """Scan the bundled sample enclave, offline, with full NIST title enrichment."""
    return scan(str(target), offline=True)


def scan_demo():
    """Scan the original single-file demos/scap-results.json sample (offline)."""
    return scan(str(DEMO_DIR), offline=True)


def rule(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def kv(label: str, value) -> None:
    print(f"  {label:<26} {value}")
