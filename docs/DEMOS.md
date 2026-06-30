# Demos

Five runnable scenarios in [`../demos/`](../demos/), each targeting a different
federal-compliance audience. Every scenario re-scans the bundled sample enclave
(`demos/enclave/` — SCAP/SCC results across 4 hosts) and resolves NIST 800-53
control titles from the bundled OSCAL snapshot, so they run **fully offline** and
reproduce byte-for-byte on a disconnected box.

```bash
PYTHONUTF8=1 python demos/run_all.py        # all five, end to end (exit 0)
PYTHONUTF8=1 python demos/02_isso_poam.py    # or just one
```

## Audience map

| # | Scenario | Audience | What it shows |
|---|----------|----------|---------------|
| 1 | [`01_sysadmin_scan.py`](../demos/01_sysadmin_scan.py) | Sysadmins / engineers | Raw SCAP rows → severity-ranked, per-host fix-first worklist with remediation notes; passing rows dropped automatically. |
| 2 | [`02_isso_poam.py`](../demos/02_isso_poam.py) | ISSO / ISSM | STIG findings → eMASS-ready **POA&M CSV** with official NIST 800-53 rev5 **Control Title** column, resolved offline from the real OSCAL catalog. |
| 3 | [`03_auditor_oscal.py`](../demos/03_auditor_oscal.py) | Assessors / auditors (SCA, IG) | Real **OSCAL 1.1.2 Assessment Results**: paired observation+finding, deterministic UUIDs, `not-satisfied` control targets, STIG/CCI provenance, byte-identical re-export. |
| 4 | [`04_ato_risk_brief.py`](../demos/04_ato_risk_brief.py) | ATO / Authorizing Official | Severity-weighted **composite risk** + control-family rollup + the Markdown briefing block for the risk assessment. |
| 5 | [`05_airgap_pipeline.py`](../demos/05_airgap_pipeline.py) | Air-gapped enclaves / CI | Offline OSCAL resolve from cache, **SARIF 2.1.0** export, and the `--fail-on high` gate logic that blocks a non-compliant build. |

There is also [`enrich_oscal_demo.py`](../demos/enrich_oscal_demo.py): a focused
look at the OSCAL title-enrichment against the single-file `scap-results.json`.

---

Each demo prints clear, narrated output and exits 0, so they double as smoke
tests — [`tests/test_demos.py`](../tests/test_demos.py) covers the same code
paths under `pytest`.
