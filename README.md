# stigsentry — DISA STIG / NIST 800-53 evidence + POAM

[![CI](https://github.com/cognis-digital/stigsentry/workflows/CI/badge.svg)](https://github.com/cognis-digital/stigsentry/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> Ingest SCAP/SCC/OpenSCAP/Wazuh findings → produce eMASS-ready POAM + OSCAL Assessment Results.

<!-- cognis:layman:start -->
## What is this?

stigsentry is a command-line tool for security and compliance teams who need to track and report on system vulnerabilities against government standards. It reads scan results from security tools like Wazuh or OpenSCAP and automatically maps each finding to the specific NIST 800-53 control and DISA STIG rule it violates. The output is a ready-to-import spreadsheet (POAM) for risk management systems like eMASS or Xacta, saving hours of manual cross-referencing. It is built for military, federal, and defense contractor teams who must maintain continuous ATO (Authority to Operate) packages.
<!-- cognis:layman:end -->

## Upstream

Forks / wraps **https://github.com/wazuh/wazuh**. See [`UPSTREAM.md`](./UPSTREAM.md) for the
licensing posture, supported commits, and how to upgrade.

## What this adds for military / IC use

- STIG → NIST 800-53 crosswalk
- CCI + MITRE ATT&CK enrichment
- POAM CSV for eMASS / Xacta / RSA Archer
- OSCAL Assessment Results JSON

<!-- cognis:install:start -->
## Install

`stigsentry` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/stigsentry/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/stigsentry/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/stigsentry.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/stigsentry.git"  # uv
pip install "git+https://github.com/cognis-digital/stigsentry.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/stigsentry.git
cd stigsentry && pip install .
```

Then run:
```sh
stigsentry --help
```
<!-- cognis:install:end -->

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
