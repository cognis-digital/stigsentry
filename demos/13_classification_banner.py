"""Scenario 13 - Classification banners (CAPCO-shape, placeholders only).

Audience: operators on cleared systems who must stamp the right banner on a
report. cognis_mil's ClassificationBanner validates *shape* (not content) — it
won't let UNCLASSIFIED carry SCI/SAP, and rejects an unknown base level. This
demo renders a few banners, validates them, and shows the placeholder used for
public release. No real markings ship in the tool.
"""
from _common import rule, kv
from cognis_mil.classmark import ClassificationBanner


def main() -> None:
    rule("CLASSIFICATION  -  CAPCO-shape banner validation (placeholders only)")

    cases = [
        ClassificationBanner.placeholder(),
        ClassificationBanner(level="SECRET", dissem=["NOFORN"]),
        ClassificationBanner(level="SECRET", dissem=["REL TO USA, FVEY"]),
        ClassificationBanner(level="UNCLASSIFIED", sci=["SI"]),   # invalid: U + SCI
        ClassificationBanner(level="ULTRA SECRET"),               # invalid: bad level
    ]

    for b in cases:
        ok, errs = b.validate()
        status = "valid" if ok else "INVALID: " + "; ".join(errs)
        kv(b.render() + "  ->", status)

    print("\nThe library checks banner *form*; operators supply real markings at")
    print("runtime on the appropriate system. The default is FOR PUBLIC RELEASE.")


if __name__ == "__main__":
    main()
