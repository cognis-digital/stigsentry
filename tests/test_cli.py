"""CLI surface coverage: the feeds subcommand and the shared make_cli scan CLI.

The feeds CLI is exercised directly (it returns an int rc). make_cli reads
sys.argv and calls sys.exit(), so it is driven via monkeypatched argv and
SystemExit assertions.
"""
import json

import pytest

from stigsentry.cli import _feeds_cli, main


# --------------------------------------------------------------------------- #
# feeds subcommand
# --------------------------------------------------------------------------- #
def test_feeds_list_ok(capsys):
    assert _feeds_cli(["list"]) == 0
    assert "oscal-800-53-rev5-catalog" in capsys.readouterr().out


def test_feeds_default_to_list(capsys):
    assert _feeds_cli([]) == 0
    assert "oscal-800-53-rev5-catalog" in capsys.readouterr().out


def test_feeds_get_offline_ok(capsys):
    assert _feeds_cli(["get", "oscal-800-53-rev5-catalog", "--offline"]) == 0
    assert "catalog" in capsys.readouterr().out


def test_feeds_get_no_arg_usage(capsys):
    assert _feeds_cli(["get"]) == 2
    assert "usage" in capsys.readouterr().err


def test_feeds_get_rejects_foreign_feed(capsys):
    assert _feeds_cli(["get", "cisa-kev", "--offline"]) == 1
    assert "not a stigsentry feed" in capsys.readouterr().err


def test_feeds_update_rejects_foreign_feed(capsys):
    assert _feeds_cli(["update", "cisa-kev"]) == 1
    assert "not a stigsentry feed" in capsys.readouterr().err


def test_feeds_unknown_command_usage(capsys):
    assert _feeds_cli(["frobnicate"]) == 2
    assert "usage" in capsys.readouterr().err


def test_feeds_get_offline_missing_cache(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    rc = _feeds_cli(["get", "oscal-800-53-rev5-catalog", "--offline"])
    assert rc == 1
    assert "error" in capsys.readouterr().err.lower()


# --------------------------------------------------------------------------- #
# shared make_cli scan path (via main(), monkeypatched argv)
# --------------------------------------------------------------------------- #
def _run(monkeypatch, argv):
    monkeypatch.setattr("sys.argv", ["stigsentry"] + argv)
    with pytest.raises(SystemExit) as ei:
        main()
    return ei.value.code


def test_cli_json_format(monkeypatch, capsys, tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    code = _run(monkeypatch, [str(tmp_path), "--format", "json"])
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool_name"] == "stigsentry"


def test_cli_oscal_format(monkeypatch, capsys, tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    code = _run(monkeypatch, [str(tmp_path), "--format", "oscal"])
    assert code == 0
    assert "assessment-results" in capsys.readouterr().out


def test_cli_fail_on_high_exits_nonzero(monkeypatch, capsys, tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    code = _run(monkeypatch, [str(tmp_path), "--format", "json", "--fail-on", "high"])
    assert code == 1  # a VERY_HIGH finding trips --fail-on high


def test_cli_fail_on_none_exits_zero(monkeypatch, capsys, tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    code = _run(monkeypatch, [str(tmp_path), "--format", "json"])
    assert code == 0


def test_cli_clean_scan_passes_gate(monkeypatch, capsys, tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([{"stig_id": "V-238211", "status": "pass"}]), encoding="utf-8")
    code = _run(monkeypatch, [str(tmp_path), "--format", "json", "--fail-on", "very_high"])
    assert code == 0


def test_cli_writes_out_file(monkeypatch, capsys, tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([{"stig_id": "V-238298", "status": "fail"}]), encoding="utf-8")
    out = tmp_path / "report.json"
    code = _run(monkeypatch, [str(tmp_path), "--format", "json", "--out", str(out)])
    assert code == 0
    assert out.exists()
    assert json.loads(out.read_text())["tool_name"] == "stigsentry"
