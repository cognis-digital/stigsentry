"""stigsentry feed layer — real NIST 800-53 rev5 (OSCAL) control resolution.

stigsentry maps DISA STIG findings to NIST 800-53 control IDs (e.g. ``AC-6(2)``),
but the raw ID alone is opaque on a report. This module ingests the **authoritative**
NIST SP 800-53 rev5 catalog (native OSCAL JSON, published by NIST at usnistgov/
oscal-content) via the bundled edge/air-gap ``datafeeds`` layer and resolves each
control ID to its official **title** and **OSCAL group/family** — so a POAM or
OSCAL assessment-result carries the real control name, not just a code.

Edge / air-gap:
  * The catalog is fetched once over HTTPS, cached to disk (``COGNIS_FEEDS_CACHE``)
    and thereafter re-served with ``offline=True`` — no network on disconnected gear.
  * ``datafeeds snapshot-export`` / ``snapshot-import`` sneakernet the cache into an
    air-gapped enclave.

Only the compliance-domain feed(s) relevant to stigsentry are exposed:
``oscal-800-53-rev5-catalog``.

Defensive / authorized-use compliance tooling only.
"""

from __future__ import annotations

import re
from typing import Optional

from . import datafeeds as _df

# Feed ids this tool consumes (compliance domain only).
RELEVANT_FEEDS = ["oscal-800-53-rev5-catalog"]


def relevant_catalog() -> dict:
    """The feed catalog filtered to the feeds stigsentry actually uses."""
    full = _df.load_catalog()
    feeds = [f for f in full.get("feeds", []) if f["id"] in RELEVANT_FEEDS]
    return {"_meta": full.get("_meta", {}), "feeds": feeds}


def list_feeds() -> list[dict]:
    return relevant_catalog()["feeds"]


# --------------------------------------------------------------------------- #
# NIST 800-53 control-ID normalization
#   stigsentry finding form:  "AC-6(2)"  /  "IA-2(11)"  /  "SC-13"
#   OSCAL catalog control id: "ac-6.2"   /  "ia-2.11"   /  "sc-13"
# --------------------------------------------------------------------------- #
def normalize_control_id(cid: str) -> str:
    """Map an 800-53 control ID (report form) to the OSCAL catalog id form.

    * ``AC-6(2)``  -> ``ac-6.2``  (numeric group = control enhancement)
    * ``AC-7(a)``  -> ``ac-7``    (alpha group = statement part, not a catalog
                                   control id; resolve to the base control)
    """
    cid = (cid or "").strip().lower()
    if not cid:
        return ""
    # drop any trailing alpha statement-part refs first (AC-6(2)(a) -> AC-6(2)):
    # statement parts are not catalog control ids, the enhancement is.
    cid = re.sub(r"\s*\([a-z]+\)", "", cid)
    # numeric enhancement: AC-6(2) -> ac-6.2  (tolerates a space: "AC-6 (2)")
    cid = re.sub(r"\s*\((\d+)\)", r".\1", cid)
    cid = cid.replace(" ", "")
    return cid


def _index_catalog(catalog: dict) -> dict:
    """Flatten the OSCAL catalog into {control_id: {title, family, family_title}}."""
    idx: dict[str, dict] = {}
    cat = catalog.get("catalog", catalog)
    for group in cat.get("groups", []):
        fam = group.get("id", "")
        fam_title = group.get("title", "")

        def _add(ctrl: dict):
            idx[ctrl["id"]] = {
                "title": ctrl.get("title", ""),
                "family": fam,
                "family_title": fam_title,
            }
            for sub in ctrl.get("controls", []):
                _add(sub)

        for ctrl in group.get("controls", []):
            _add(ctrl)
    return idx


class ControlResolver:
    """Resolves NIST 800-53 control IDs to official titles from the real catalog.

    Loads the OSCAL 800-53 rev5 catalog through the bundled ``datafeeds`` cache.
    Pass ``offline=True`` on air-gapped gear (serves the cached snapshot only).
    """

    def __init__(self, offline: bool = False, catalog: Optional[dict] = None):
        if catalog is None:
            catalog = _df.get("oscal-800-53-rev5-catalog", offline=offline,
                              max_age_hours=24 * 30)
        self._index = _index_catalog(catalog)

    def __len__(self) -> int:
        return len(self._index)

    def resolve(self, control_id: str) -> Optional[dict]:
        return self._index.get(normalize_control_id(control_id))

    def title(self, control_id: str) -> str:
        info = self.resolve(control_id)
        return info["title"] if info else ""


def enrich_result(result, *, offline: bool = False,
                  catalog: Optional[dict] = None) -> dict:
    """Annotate every finding's ``nist_800_53`` control with its official title.

    Mutates ``finding.description`` to prepend the resolved control name when it
    is otherwise empty, stamps a per-control summary into ``result.meta``, and
    returns a {control_id: title} resolution map. Returns an empty map (and is a
    no-op on the findings) if the catalog is unavailable offline.
    """
    try:
        resolver = ControlResolver(offline=offline, catalog=catalog)
    except (FileNotFoundError, ConnectionError):
        result.meta.setdefault("nist_800_53_catalog", "unavailable (offline, no cache)")
        return {}

    resolved: dict[str, str] = {}
    for f in result.findings:
        cid = f.nist_800_53
        if not cid:
            continue
        info = resolver.resolve(cid)
        if not info:
            continue
        resolved[cid] = info["title"]
        tag = f"NIST 800-53 {cid} — {info['title']} ({info['family_title']})"
        if not f.description:
            f.description = tag
        elif info["title"] not in f.description:
            f.description = f"{f.description} | {tag}"

    result.meta["nist_800_53_catalog"] = "NIST SP 800-53 rev5 (OSCAL)"
    result.meta["nist_800_53_controls_resolved"] = resolved
    return resolved
