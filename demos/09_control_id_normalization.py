"""Scenario 9 - Control-ID normalization (report form -> OSCAL catalog id).

Audience: anyone debugging why a control "didn't resolve". STIG findings carry
800-53 IDs in report form — ``AC-6(2)``, ``IA-2(11)``, ``AC-7(a)`` — while the
OSCAL catalog keys are ``ac-6.2``, ``ia-2.11``, ``ac-7``. This demo walks the
normalization rules (numeric enhancement -> ``.N``; alpha statement-part -> base
control; combined ``AC-6(2)(a)`` -> ``ac-6.2``) and resolves each to its real
title from the offline catalog.
"""
from _common import rule, kv
from stigsentry.feeds import normalize_control_id, ControlResolver


CASES = ["SC-13", "AC-6(2)", "IA-2(11)", "AC-7(a)", "AC-6(2)(a)", "AC-6 (2)"]


def main() -> None:
    rule("NORMALIZATION  -  800-53 report IDs -> OSCAL catalog ids -> titles")
    resolver = ControlResolver(offline=True)
    kv("OSCAL controls loaded:", len(resolver))

    print("\n  report form        OSCAL id      official title")
    print("  " + "-" * 66)
    for raw in CASES:
        oscal_id = normalize_control_id(raw)
        title = resolver.title(raw) or "(not in trimmed demo catalog)"
        print(f"  {raw:<18} {oscal_id:<13} {title}")

    # The two AC-6(2) spellings must collapse to the same control.
    assert normalize_control_id("AC-6(2)(a)") == normalize_control_id("AC-6 (2)")
    print("\nStatement-part and whitespace variants collapse to the same control id.")


if __name__ == "__main__":
    main()
