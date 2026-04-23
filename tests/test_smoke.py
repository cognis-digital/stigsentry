from pathlib import Path
from stigsentry.core import scan, emit_poam, STIG_CONTROLS
D = Path(__file__).parent.parent / "demos"
def test_crosswalk_present():
    assert "V-238298" in STIG_CONTROLS
    assert STIG_CONTROLS["V-238298"]["nist"] == "SC-13"
def test_scan():
    r = scan(str(D))
    ids = {f.id for f in r.findings}
    assert "SS-V-238298" in ids
    assert "SS-V-238213" in ids
    # passed ones not present
    assert "SS-V-238211" not in ids
def test_poam_emit(tmp_path):
    r = scan(str(D)); r.finalize()
    poam = emit_poam(r, tmp_path / "poam.csv")
    assert "Control,Weakness" in poam
    assert "SC-13" in poam
