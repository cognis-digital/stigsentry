# Demos

Twenty runnable scenarios in [`../demos/`](../demos/), each targeting a different
federal-compliance audience or capability. Every scenario runs **fully offline**:
the NIST 800-53 rev5 (OSCAL) catalog is served from a bundled snapshot and no live
host is touched, so they reproduce byte-for-byte on a disconnected box. Scenarios
that need findings either re-scan the bundled sample enclave (`demos/enclave/` —
SCAP/SCC results across 4 hosts) or build inputs in a temp dir.

```bash
PYTHONUTF8=1 python demos/run_all.py        # all twenty, end to end (exit 0)
PYTHONUTF8=1 python demos/02_isso_poam.py    # or just one
```

## Audience / capability map

| # | Scenario | Audience | What it shows |
|---|----------|----------|---------------|
| 1 | [`01_sysadmin_scan.py`](../demos/01_sysadmin_scan.py) | Sysadmins / engineers | Raw SCAP rows → severity-ranked, per-host fix-first worklist with remediation notes; passing rows dropped automatically. |
| 2 | [`02_isso_poam.py`](../demos/02_isso_poam.py) | ISSO / ISSM | STIG findings → eMASS-ready **POA&M CSV** with official NIST 800-53 rev5 **Control Title** column, resolved offline from the real OSCAL catalog. |
| 3 | [`03_auditor_oscal.py`](../demos/03_auditor_oscal.py) | Assessors / auditors (SCA, IG) | Real **OSCAL 1.1.2 Assessment Results**: paired observation+finding, deterministic UUIDs, `not-satisfied` control targets, STIG/CCI provenance, byte-identical re-export. |
| 4 | [`04_ato_risk_brief.py`](../demos/04_ato_risk_brief.py) | ATO / Authorizing Official | Severity-weighted **composite risk** + control-family rollup + the Markdown briefing block for the risk assessment. |
| 5 | [`05_airgap_pipeline.py`](../demos/05_airgap_pipeline.py) | Air-gapped enclaves / CI | Offline OSCAL resolve from cache, **SARIF 2.1.0** export, and the `--fail-on high` gate logic that blocks a non-compliant build. |
| 6 | [`06_malformed_input_handling.py`](../demos/06_malformed_input_handling.py) | Robustness / SRE | A broken file in a results drop is flagged as its own finding (lenient) or fails the build (strict) — never silently swallowed into a false "all clear". |
| 7 | [`07_wrapper_json_shapes.py`](../demos/07_wrapper_json_shapes.py) | Integrators | Every common exporter JSON shape (bare list, `findings`/`results`/`rule_results` wrappers, single object) ingests identically. |
| 8 | [`08_rmf_mapping_gap.py`](../demos/08_rmf_mapping_gap.py) | RMF / eMASS engineers | Unmapped STIG IDs are kept as tracked LOW findings (the crosswalk gap), surfacing as `(none)` control rows in the POA&M. |
| 9 | [`09_control_id_normalization.py`](../demos/09_control_id_normalization.py) | Debuggers | 800-53 report IDs (`AC-6(2)`, `AC-7(a)`, `AC-6(2)(a)`) → OSCAL catalog ids → official titles. |
| 10 | [`10_snapshot_sneakernet.py`](../demos/10_snapshot_sneakernet.py) | Air-gap operators | `snapshot-export` → sneakernet → `snapshot-import` round-trip; resolver works from the imported cache alone. |
| 11 | [`11_ci_gate_exit_codes.py`](../demos/11_ci_gate_exit_codes.py) | Pipeline engineers | The `--fail-on` threshold matrix (PASS vs BLOCK) across clean / moderate / very-high runs. |
| 12 | [`12_audit_trail.py`](../demos/12_audit_trail.py) | Assessors / ISSM | Hash-chained, tamper-evident assessment log; a post-hoc edit breaks the chain. |
| 13 | [`13_classification_banner.py`](../demos/13_classification_banner.py) | Cleared-system operators | CAPCO-shape banner validation (placeholders only): rejects bad levels and UNCLASSIFIED+SCI. |
| 14 | [`14_severity_rollup.py`](../demos/14_severity_rollup.py) | Anyone reading the score | How severity weights roll up into the 0–100 composite risk band. |
| 15 | [`15_csv_tsv_ingest.py`](../demos/15_csv_tsv_ingest.py) | Spreadsheet exporters | CSV/TSV ingest with case-insensitive suffixes (`.CSV`, `.tsv`) and tab delimiters. |
| 16 | [`16_multi_format_export.py`](../demos/16_multi_format_export.py) | Toolchain integrators | One scan → console / JSON / Markdown / SARIF / OSCAL, all consistent. |
| 17 | [`17_poam_to_grc.py`](../demos/17_poam_to_grc.py) | ISSM | POA&M column-by-column for the eMASS / Xacta / Archer import (auto vs operator-TBD fields). |
| 18 | [`18_oscal_diff.py`](../demos/18_oscal_diff.py) | Assessors | Deterministic OSCAL lets you diff a baseline vs a post-remediation run and see exactly what closed. |
| 19 | [`19_per_host_triage.py`](../demos/19_per_host_triage.py) | Ops leads | Rank fleet hosts by aggregate risk, worst-first, for a remediation order. |
| 20 | [`20_end_to_end_pipeline.py`](../demos/20_end_to_end_pipeline.py) | Everyone | The full chain: scan → enrich → POA&M + OSCAL → verified audit log, end to end. |

There is also [`enrich_oscal_demo.py`](../demos/enrich_oscal_demo.py): a focused
look at the OSCAL title-enrichment against the single-file `scap-results.json`.

---

Each demo prints clear, narrated output and exits 0, so they double as smoke
tests — [`tests/test_demos.py`](../tests/test_demos.py) covers the same code
paths under `pytest`.
