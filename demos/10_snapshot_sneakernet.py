"""Scenario 10 - Air-gap sneakernet: export the feed cache, import on the far side.

Audience: teams moving the NIST OSCAL catalog into a disconnected enclave. On a
connected box you fetch+cache the catalog once; then ``snapshot-export`` tars the
cache flat, you carry it across the air gap, ``snapshot-import`` drops it into the
enclave's (differently-named) cache dir, and the resolver works fully offline.
This demo performs the whole round-trip in temp dirs and proves resolution works
from the imported snapshot alone.
"""
import tempfile
from pathlib import Path

from _common import rule, kv, FIXTURES
from stigsentry import datafeeds as df
from stigsentry.feeds import ControlResolver


def main() -> None:
    rule("AIR-GAP  -  snapshot-export -> sneakernet -> snapshot-import")

    import os
    saved = os.environ.get("COGNIS_FEEDS_CACHE")
    try:
        # The "connected side" cache is the bundled fixture snapshot.
        os.environ["COGNIS_FEEDS_CACHE"] = str(FIXTURES)
        snap = Path(tempfile.mkdtemp(prefix="ss-demo10-")) / "feeds.tar.gz"
        n = df.snapshot_export(str(snap))
        kv("Exported feeds:", f"{n} -> {snap.name} ({snap.stat().st_size} bytes)")

        # The "enclave side" is a brand-new, differently-named empty cache dir.
        enclave_cache = Path(tempfile.mkdtemp(prefix="ss-enclave-"))
        os.environ["COGNIS_FEEDS_CACHE"] = str(enclave_cache)
        imported = df.snapshot_import(str(snap))
        kv("Imported into enclave:", f"{imported} feed(s) at {enclave_cache.name}")

        # Resolve entirely from the imported snapshot — no network on the enclave.
        resolver = ControlResolver(offline=True)
        kv("Resolver controls:", len(resolver))
        kv("Offline resolve check:", "SC-13 -> " + resolver.title("SC-13"))
        assert resolver.title("SC-13") == "Cryptographic Protection"

        print("\nThe enclave now resolves NIST 800-53 titles with zero network access.")
    finally:
        # restore the caller's cache env so other demos/tools are unaffected
        if saved is None:
            os.environ.pop("COGNIS_FEEDS_CACHE", None)
        else:
            os.environ["COGNIS_FEEDS_CACHE"] = saved


if __name__ == "__main__":
    main()
