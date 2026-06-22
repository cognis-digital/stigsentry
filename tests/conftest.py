"""Suite-wide offline guard.

Every test runs with COGNIS_FEEDS_CACHE pointed at tests/fixtures/ (the trimmed
OSCAL snapshot) and with datafeeds.fetch() hard-disabled, so the whole suite is
green on a fully air-gapped box with zero network access.
"""

import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURES))

    def _blocked(*a, **k):  # pragma: no cover - asserts no test reaches the net
        raise AssertionError("network access attempted during tests")

    try:
        from stigsentry import datafeeds
        monkeypatch.setattr(datafeeds, "fetch", _blocked)
    except Exception:
        pass
    yield
