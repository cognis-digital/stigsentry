# UPSTREAM.md — stigsentry

> **Read this before contributing.**

## What this repo is

A Cognis Digital **military/IC adaptation layer** that sits *on top of* an
unmodified upstream open-source project. The upstream code is **not vendored**
in this repo — operators clone it separately.

## Upstream project

- **Repo**: https://github.com/wazuh/wazuh (AGPL-3) — also works with OSSEC, Splunk, Elastic
- **License**: AGPL-3 (Wazuh) / various
- **Forked at commit**: PLACEHOLDER (operator pins at deployment time)

## What Cognis Digital adds

- DISA STIG → NIST 800-53 crosswalk table
- CCI / ATT&CK enrichment per finding
- eMASS-compatible POAM CSV emitter
- OSCAL Assessment Results emitter (via shared exporter)

**License posture**: stigsentry is MIT/Apache. We *integrate* with Wazuh via
API / agent endpoints — we do not link to AGPL code. Safe to ship as additions.

## License posture

- This repo's *additions* are licensed under the file in `LICENSE`.
- The combined work (upstream + Cognis additions) inherits the upstream license
  if you redistribute together.
- We do **not** redistribute upstream code in this repo — `mil-additions/` is a
  separate module that calls/wraps upstream binaries.

## Upgrading the upstream

```
cd upstream/
git pull
git log --oneline ${LAST_TESTED_SHA}..HEAD     # review changes
# Then re-run our test suite against the new upstream
```

## Why we ship as an additions layer

1. **Legal clarity** — upstream license rules upstream code; ours rules ours.
2. **Operational** — operators on classified networks already have the
   upstream binary blessed by their ATO. We don't ask them to re-evaluate it.
3. **Maintenance** — we can ride upstream releases without re-forking.

## What's unclassified / EAR99

Everything in this repo is unclassified, public-release, EAR99 (no export
license required). Classification markings in code/output are
**operator-supplied placeholders**.
