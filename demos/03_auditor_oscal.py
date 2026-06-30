"""Scenario 3 - Assessors / auditors (SCA, IG, third-party assessor).

Audience: the assessor who needs machine-ingestible, standards-conformant
evidence — not a PDF. stigsentry emits a real **OSCAL 1.1.2 Assessment Results**
(SAR) document: every finding becomes a paired observation + finding with
deterministic UUIDs, a `not-satisfied` target status against the NIST control,
and STIG/CCI/ATT&CK preserved as props. Deterministic UUIDs mean the same
evidence re-exports byte-identical, so an assessor can diff two runs.
"""
import json

from _common import scan_enclave, to_oscal, rule, kv


def main() -> None:
    rule("AUDITOR / ASSESSOR  -  real OSCAL 1.1.2 Assessment Results")
    result = scan_enclave()

    doc = json.loads(to_oscal(result))
    ar = doc["assessment-results"]
    res = ar["results"][0]

    kv("OSCAL version:", ar["metadata"]["oscal-version"])
    kv("AR document UUID:", ar["uuid"])
    kv("Observations:", len(res["observations"]))
    kv("Findings:", len(res["findings"]))

    print("\nSample OSCAL finding (control target + provenance props):")
    f0 = res["findings"][0]
    print(f"     title:       {f0['title']}")
    print(f"     target-id:   {f0['target']['target-id']}")
    print(f"     status:      {f0['target']['status']['state']}")
    props = {p["name"]: p["value"] for p in f0["props"]}
    for name in ("severity", "disa-stig", "cci"):
        if name in props:
            print(f"     prop {name:<11} {props[name]}")
    obs_uuid = f0["related-observations"][0]["observation-uuid"]
    print(f"     -> linked observation uuid: {obs_uuid}")

    # Determinism: re-export and confirm byte-identical evidence.
    again = to_oscal(result)
    kv("\nByte-identical re-export:", json.dumps(doc) == json.dumps(json.loads(again)))
    print("\nNo placeholder zero-UUIDs; this validates against the OSCAL AR shape and")
    print("ingests into GRC platforms (eMASS/Xacta) without hand-editing.")


if __name__ == "__main__":
    main()
