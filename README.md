# stigsentry — DISA STIG / NIST 800-53 evidence + POAM

[![CI](https://github.com/cognis-digital/stigsentry/workflows/CI/badge.svg)](https://github.com/cognis-digital/stigsentry/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> Ingest SCAP/SCC/OpenSCAP/Wazuh findings → produce eMASS-ready POAM + OSCAL Assessment Results.

## Usage — step by step

`stigsentry` uses the shared `cognis_mil` CLI: a positional target plus
standard output/scoring flags.

1. **Install** (editable from a clone, or from the wheel):
   ```bash
   pip install -e .
   # provides the `stigsentry` console script
   ```
2. **Run the primary scan** against a path or target (defaults to `.`):
   ```bash
   stigsentry .
   ```
3. **Emit machine-readable output** — `console|json|markdown|sarif|oscal`:
   ```bash
   stigsentry ./target --format json --out stigsentry-report.json
   ```
4. **Read / use the output.** The JSON report carries the findings list and a
   severity-weighted `composite_score`; `sarif` feeds code-scanning dashboards
   and `oscal` emits an OSCAL skeleton for compliance pipelines. An operator
   `--classification` banner can be stamped on (placeholder only):
   ```bash
   stigsentry ./target --classification "UNCLASSIFIED//FOR PUBLIC RELEASE" --format markdown
   ```
5. **Gate CI on severity** with `--fail-on` (`very_high|high|moderate|low|none`);
   the process exits non-zero when a finding at/above the threshold exists:
   ```bash
   stigsentry ./target --format sarif --out stigsentry.sarif --fail-on high
   ```

## Upstream

Forks / wraps **https://github.com/wazuh/wazuh**. See [`UPSTREAM.md`](./UPSTREAM.md) for the
licensing posture, supported commits, and how to upgrade.

## What this adds for military / IC use

- STIG → NIST 800-53 crosswalk
- CCI + MITRE ATT&CK enrichment
- POAM CSV for eMASS / Xacta / RSA Archer
- OSCAL Assessment Results JSON

## Install

```bash
# Shared library (only once for the whole ecosystem):
pip install -e ../../shared

# This tool:
pip install -e .
```

## Demo

```bash
stigsentry demos/scap-results.json
```

Outputs are available in five formats — all respect an operator-supplied
classification banner (passed via `--classification`):

```bash
stigsentry <target> --format=console     # default
stigsentry <target> --format=json
stigsentry <target> --format=sarif       # for code-scanning pipelines
stigsentry <target> --format=markdown    # for PRs / briefings
stigsentry <target> --format=oscal       # OSCAL Assessment Results skeleton
```

## Classification banner

All output is wrapped with an operator-supplied classification banner.
**Default**: `UNCLASSIFIED//FOR PUBLIC RELEASE`.

> ⚠️ This tool **does not** generate or validate the *content* of higher
> classifications. Operators on cleared systems supply real markings at runtime.
> See [`../shared/cognis_mil/classmark.py`](../../shared/cognis_mil/classmark.py).

## Compliance crosswalks (built in)

Every finding can carry references to:
- **NIST 800-53 Rev 5** controls (e.g. `AC-2(1)`)
- **DISA STIG** rule IDs (e.g. `V-242414`)
- **MITRE ATT&CK** technique IDs (e.g. `T1078`)
- **CCI** (Control Correlation Identifier)

These are emitted in JSON, SARIF, and the OSCAL skeleton.

## CI / RMF integration

```yaml
- name: stigsentry scan
  run: |
    pip install cognis-stigsentry
    stigsentry . --format=oscal --out=assessment-results.json --fail-on=high
- name: Upload to eMASS/Xacta
  run: cognis-rmf-package import assessment-results.json
```

## Part of the Cognis Digital military / IC ecosystem

12 repos. All MIT/Apache-2.0/GPL-3 (per upstream). Cognis additions are
Apache-2.0 unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).

## Interoperability

`stigsentry` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `stigsentry`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.
