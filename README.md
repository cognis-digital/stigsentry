# stigsentry — DISA STIG / NIST 800-53 evidence + POAM

[![CI](https://github.com/cognis-digital/stigsentry/workflows/CI/badge.svg)](https://github.com/cognis-digital/stigsentry/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> Ingest SCAP/SCC/OpenSCAP/Wazuh findings → produce eMASS-ready POAM + OSCAL Assessment Results.

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
    pip install "git+https://github.com/cognis-digital/stigsentry.git"
    stigsentry . --format=oscal --out=assessment-results.json --fail-on=high
- name: Upload to eMASS/Xacta
  run: cognis-rmf-package import assessment-results.json
```

## Part of the Cognis Digital military / IC ecosystem

12 repos. All MIT/Apache-2.0/GPL-3 (per upstream). Cognis additions are
Apache-2.0 unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).

<a name="verification"></a>
## Verification

[![tests](https://img.shields.io/badge/tests-3%20passing-2ea44f.svg)](AUDIT.md)

Every push is verified end-to-end. Latest audit (2026-06-12):

```text
tests        : 3 passed, 0 failed, 0 errored
compile      : all modules parse
cli          : stigsentry 0.1.0
package      : stigsentry
```

<details><summary>CLI surface (<code>--help</code>)</summary>

```text
usage: stigsentry [-h] [--format {console,json,markdown,sarif,oscal}]
                  [--out OUT] [--fail-on {very_high,high,moderate,low,none}]
                  [--classification CLASSIFICATION] [-v]
                  [target]

stigsentry — Cognis Digital · Military/IC ecosystem

positional arguments:
  target                Path/target

options:
  -h, --help            show this help message and exit
  --format {console,json,markdown,sarif,oscal}
  --out OUT             Write output to file
```
</details>

Full machine-readable results: [`AUDIT.md`](AUDIT.md) · regenerate with `python -m stigsentry --help` + `pytest -q`.

<div align="right"><a href="#top">↑ back to top</a></div>

