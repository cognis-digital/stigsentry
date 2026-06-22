"""Demo: enrich STIG findings with official NIST 800-53 rev5 control titles.

Runs fully offline against the trimmed OSCAL catalog snapshot bundled under
tests/fixtures/ (the same real NIST catalog, just trimmed for demo/CI). On a
connected box, drop the COGNIS_FEEDS_CACHE line and the live catalog is fetched
+ cached automatically.

    python demos/enrich_oscal_demo.py
"""

import os
from pathlib import Path

# point the feed cache at the bundled offline snapshot (edge / air-gap mode)
os.environ.setdefault(
    "COGNIS_FEEDS_CACHE",
    str(Path(__file__).resolve().parent.parent / "tests" / "fixtures"),
)

from stigsentry.core import scan, emit_poam  # noqa: E402

DEMO = Path(__file__).resolve().parent  # contains scap-results.json


def main():
    # offline=True -> serve the NIST OSCAL catalog from cache only, no network
    result = scan(str(DEMO), offline=True)
    titles = result.meta.get("nist_800_53_controls_resolved", {})

    print("Resolved NIST 800-53 rev5 control titles (from real OSCAL catalog):")
    for cid, title in sorted(titles.items()):
        print(f"  {cid:10} {title}")

    print("\neMASS POAM (Control + official Control Title columns):\n")
    print(emit_poam(result))


if __name__ == "__main__":
    main()
