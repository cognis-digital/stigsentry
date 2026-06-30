# Demo data

- `scap-results.json` — single-host SCAP sample (used by `enrich_oscal_demo.py`).
- `enclave/` — bundled sample enclave: SCAP/SCC results across 4 hosts
  (`rhel-web-tier.json` + `db-and-k8s.csv`), a mix of pass/fail plus one unknown
  STIG ID. Produces 9 open findings (3 very-high, 5 high, 1 low) and resolves 8
  NIST 800-53 rev5 control titles offline.

All demos run fully offline. See [`../docs/DEMOS.md`](../docs/DEMOS.md) for the
audience-by-scenario map.
