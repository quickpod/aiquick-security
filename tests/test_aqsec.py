"""Headless, deterministic, offline tests for the aqsec core.

Nothing here touches the network, a real ClamAV binary, or anything outside a
pytest ``tmp_path``.  The one subprocess seam (``engine._execute``) and the
definitions updater are monkeypatched, so ClamAV behaviour is exercised with no
engine installed.  Any addresses used are from the TEST-NET-1 documentation
block (192.0.2.0/24, RFC 5737).
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

import pytest

import aqsec
from aqsec import (
    AQSecError,
    ScheduleConfig,
    default_rules,
    default_scan_roots,
    eicar_bytes,
    engine_status,
    is_due,
    next_run_after,
    parse_clamscan_output,
    scan_data,
    scan_file,
    scan_paths,
)
from aqsec import engine, defs, guiconfig, rules as rules_mod


# --------------------------------------------------------------------------- #
# rules: built-in matching (pure)
# --------------------------------------------------------------------------- #
def test_eicar_detected_by_substr_and_hash():
    matches = scan_data(eicar_bytes(), default_rules())
    ids = {m.rule_id for m in matches}
    assert "eicar" in ids           # substring rule
    assert "eicar-hash" in ids      # sha256 denylist rule
    assert all(m.severity == "critical" for m in matches)


def test_clean_data_has_no_matches():
    assert scan_data(b"the quick brown fox", default_rules()) == []


def test_php_webshell_heuristic():
    data = b"<?php eval(base64_decode($_POST['x'])); ?>"
    ids = {m.rule_id for m in scan_data(data, default_rules())}
    assert "php-webshell-eval" in ids


def test_ransom_shadow_delete_heuristic():
    data = b"cmd /c vssadmin.exe delete shadows /all /quiet"
    ids = {m.rule_id for m in scan_data(data, default_rules())}
    assert "ransom-shadow-delete" in ids


def test_substr_is_case_insensitive():
    r = rules_mod.Rule("m", "Marker", "substr", "MALWARE", "low", "")
    assert scan_data(b"contains malware here", [r])


def test_scan_file_reads_and_hashes(tmp_path):
    p = tmp_path / "sample.txt"
    p.write_bytes(eicar_bytes())
    matches = scan_file(str(p), default_rules())
    assert {m.rule_id for m in matches} >= {"eicar", "eicar-hash"}


def test_scan_file_missing_raises(tmp_path):
    with pytest.raises(AQSecError):
        scan_file(str(tmp_path / "nope.bin"), default_rules())


def test_sha256_file_matches_known_digest(tmp_path):
    p = tmp_path / "e.bin"
    p.write_bytes(eicar_bytes())
    assert rules_mod.sha256_file(str(p)) == rules_mod.EICAR_SHA256


# --------------------------------------------------------------------------- #
# rules: user-supplied rules file
# --------------------------------------------------------------------------- #
def test_load_user_rules(tmp_path):
    import json
    rf = tmp_path / "rules.json"
    rf.write_text(json.dumps([
        {"id": "u1", "name": "Custom.Marker", "kind": "substr",
         "pattern": "TOP-SECRET", "severity": "high"},
    ]))
    loaded = rules_mod.load_user_rules(str(rf))
    assert len(loaded) == 1 and loaded[0].id == "u1"
    assert scan_data(b"this is TOP-SECRET stuff", loaded)


def test_load_user_rules_missing_is_empty(tmp_path):
    assert rules_mod.load_user_rules(str(tmp_path / "absent.json")) == []


def test_load_user_rules_bad_regex_raises(tmp_path):
    import json
    rf = tmp_path / "rules.json"
    rf.write_text(json.dumps([
        {"id": "bad", "name": "x", "kind": "regex", "pattern": "("},
    ]))
    with pytest.raises(AQSecError):
        rules_mod.load_user_rules(str(rf))


# --------------------------------------------------------------------------- #
# engine: OS-aware scan roots (requirement A8)
# --------------------------------------------------------------------------- #
def test_default_scan_roots_are_existing_dirs():
    roots = default_scan_roots()
    assert isinstance(roots, list)
    for r in roots:
        assert os.path.isdir(r)
    # no duplicates
    assert len(roots) == len(set(os.path.normpath(r) for r in roots))


def test_scan_roots_are_os_appropriate():
    roots = [os.path.normpath(r) for r in default_scan_roots()]
    if sys.platform.startswith("linux"):
        # Home is always present on a normal box; /tmp virtually always exists.
        assert any(r == os.path.normpath(os.path.expanduser("~")) for r in roots)
    elif os.name == "nt":  # pragma: no cover - not run on CI linux
        assert any(r.endswith(":\\") for r in roots)


# --------------------------------------------------------------------------- #
# engine: clamscan output parsing (pure)
# --------------------------------------------------------------------------- #
def test_parse_clamscan_output():
    text = (
        "/home/u/evil.exe: Win.Test.EICAR_HDB-1 FOUND\n"
        "/home/u/ok.txt: OK\n"
        "C:\\Users\\u\\bad.bin: Trojan.Foo FOUND\n"
        "----------- SCAN SUMMARY -----------\n"
        "Infected files: 2\n"
    )
    out = parse_clamscan_output(text)
    assert ("/home/u/evil.exe", "Win.Test.EICAR_HDB-1") in out
    assert ("C:\\Users\\u\\bad.bin", "Trojan.Foo") in out
    assert len(out) == 2


def test_parse_clamscan_output_empty():
    assert parse_clamscan_output("") == []
    assert parse_clamscan_output("nothing infected here") == []


# --------------------------------------------------------------------------- #
# engine: full scan (built-in + monkeypatched ClamAV)
# --------------------------------------------------------------------------- #
@pytest.fixture
def tree(tmp_path):
    (tmp_path / "clean.txt").write_bytes(b"nothing to see")
    (tmp_path / "evil.txt").write_bytes(eicar_bytes())
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "shell.php").write_bytes(b"<?php system($_GET['c']); ?>")
    return tmp_path


def test_scan_paths_builtin_finds_threats(tree):
    res = scan_paths([str(tree)], use_clamav=False)
    assert res.files_scanned == 3
    sigs = {f.signature for f in res.findings}
    assert "EICAR-Test-File" in sigs
    assert any("PHP" in s for s in sigs)
    assert not res.clean
    assert res.clam_used is False


def test_scan_paths_clean_dir(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"harmless")
    res = scan_paths([str(tmp_path)], use_clamav=False)
    assert res.clean
    assert res.findings == []


def test_scan_paths_empty_raises():
    with pytest.raises(AQSecError):
        scan_paths([])


def test_scan_paths_should_stop(tree):
    res = scan_paths([str(tree)], use_clamav=False, should_stop=lambda: True)
    assert res.stopped is True
    assert res.files_scanned == 0


def test_scan_paths_with_monkeypatched_clamav(tree, monkeypatch):
    # Pretend ClamAV is installed and reports one extra detection.
    st = engine.EngineStatus(clamscan="/usr/bin/clamscan")

    def fake_status(*a, **k):
        return st

    def fake_execute(argv, timeout=3600):
        return (1, f"{tree}/evil.txt: Clam.Test.EICAR FOUND\n", "")

    monkeypatch.setattr(engine, "engine_status", fake_status)
    monkeypatch.setattr(engine, "_execute", fake_execute)
    res = scan_paths([str(tree)], use_clamav=True, status=st)
    assert res.clam_used is True
    engines = {f.engine for f in res.findings}
    assert "clamav" in engines and "builtin" in engines


def test_scan_paths_records_read_errors(tree, monkeypatch):
    def boom(path, ruleset, **kw):
        raise AQSecError(f"cannot read {path}")

    monkeypatch.setattr(rules_mod, "scan_file", boom)
    res = scan_paths([str(tree)], use_clamav=False)
    assert res.errors                # errors collected, scan not aborted
    assert res.findings == []


def test_engine_status_no_clamav(monkeypatch):
    monkeypatch.setattr(engine, "_which", lambda name: None)
    monkeypatch.setattr(engine, "_find_db_dir", lambda: (None, False))
    st = engine_status()
    assert st.clam_installed is False


# --------------------------------------------------------------------------- #
# defs: explicit-only updates
# --------------------------------------------------------------------------- #
def test_update_definitions_without_freshclam(monkeypatch):
    st = engine.EngineStatus(freshclam=None)
    res = defs.update_definitions(status=st)
    assert res.ran is False
    assert res.ok is False
    assert "not installed" in res.message.lower()


def test_update_definitions_runs_freshclam(monkeypatch):
    st = engine.EngineStatus(freshclam="/usr/bin/freshclam")
    monkeypatch.setattr(engine, "_execute",
                        lambda argv, timeout=1800: (0, "Database updated.", ""))
    res = defs.update_definitions(status=st)
    assert res.ran is True and res.ok is True


def test_update_definitions_already_current(monkeypatch):
    st = engine.EngineStatus(freshclam="/usr/bin/freshclam")
    monkeypatch.setattr(engine, "_execute",
                        lambda argv, timeout=1800: (1, "main.cvd is up to date", ""))
    res = defs.update_definitions(status=st)
    assert res.ok is True and "up to date" in res.message.lower()


def test_age_string():
    now = 1_000_000.0
    assert defs.age_string(None) == "unknown"
    assert defs.age_string(now - 120, now) == "2 min ago"
    assert defs.age_string(now - 7200, now) == "2 h ago"
    assert defs.age_string(now - 2 * 86400, now) == "2 d ago"


# --------------------------------------------------------------------------- #
# schedule: pure date maths
# --------------------------------------------------------------------------- #
def test_next_run_daily():
    cfg = ScheduleConfig(enabled=True, frequency="daily", hour=3, minute=0)
    now = datetime(2026, 8, 12, 10, 0)     # after 03:00 -> tomorrow
    nxt = next_run_after(cfg, now)
    assert nxt == datetime(2026, 8, 13, 3, 0)


def test_next_run_daily_before_time():
    cfg = ScheduleConfig(enabled=True, frequency="daily", hour=3, minute=0)
    now = datetime(2026, 8, 12, 1, 0)      # before 03:00 -> today
    assert next_run_after(cfg, now) == datetime(2026, 8, 12, 3, 0)


def test_next_run_weekly():
    # weekday=0 (Monday). 2026-08-12 is a Wednesday.
    cfg = ScheduleConfig(enabled=True, frequency="weekly", hour=2, minute=30,
                         weekday=0)
    now = datetime(2026, 8, 12, 12, 0)
    nxt = next_run_after(cfg, now)
    assert nxt.weekday() == 0
    assert nxt == datetime(2026, 8, 17, 2, 30)


def test_next_run_manual_is_none():
    cfg = ScheduleConfig(enabled=True, frequency="manual")
    assert next_run_after(cfg, datetime.now()) is None


def test_next_run_disabled_is_none():
    cfg = ScheduleConfig(enabled=False, frequency="daily")
    assert next_run_after(cfg, datetime.now()) is None


def test_is_due_fires_once_then_not(monkeypatch):
    cfg = ScheduleConfig(enabled=True, frequency="daily", hour=3, minute=0,
                         last_run=None)
    now = datetime(2026, 8, 12, 10, 0)     # past today's 03:00, never ran
    assert is_due(cfg, now) is True
    # After recording a run at/after the fire time, it is no longer due.
    cfg.last_run = datetime(2026, 8, 12, 3, 0, 1).isoformat()
    assert is_due(cfg, now) is False


def test_is_due_manual_never():
    cfg = ScheduleConfig(enabled=True, frequency="manual")
    assert is_due(cfg, datetime.now()) is False


def test_schedule_validate_rejects_bad_values():
    with pytest.raises(AQSecError):
        ScheduleConfig(enabled=True, frequency="daily", hour=99).validate()
    with pytest.raises(AQSecError):
        ScheduleConfig(enabled=True, frequency="nope").validate()


# --------------------------------------------------------------------------- #
# guiconfig: local, non-fatal persistence
# --------------------------------------------------------------------------- #
def test_guiconfig_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("AQSEC_HOME", str(tmp_path))
    guiconfig.set_theme("light")
    guiconfig.set_use_clamav(False)
    assert guiconfig.get_theme() == "light"
    assert guiconfig.get_use_clamav() is False
    sched = ScheduleConfig(enabled=True, frequency="weekly", hour=4, weekday=2)
    guiconfig.set_schedule(sched)
    got = guiconfig.get_schedule()
    assert got.enabled and got.frequency == "weekly" and got.weekday == 2


def test_guiconfig_corrupt_file_is_non_fatal(tmp_path, monkeypatch):
    monkeypatch.setenv("AQSEC_HOME", str(tmp_path))
    os.makedirs(str(tmp_path), exist_ok=True)
    with open(guiconfig.config_path(), "w") as fh:
        fh.write("{ not valid json")
    assert guiconfig.get_theme() in ("light", "dark")  # falls back, no raise


# --------------------------------------------------------------------------- #
# CLI (offline)
# --------------------------------------------------------------------------- #
def test_cli_scan_returns_2_on_detection(tree, capsys):
    from aqsec.__main__ import main
    rc = main(["scan", str(tree), "--no-clamav"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "EICAR-Test-File" in out


def test_cli_scan_clean_returns_0(tmp_path):
    (tmp_path / "ok.txt").write_bytes(b"fine")
    from aqsec.__main__ import main
    assert main(["scan", str(tmp_path), "--no-clamav"]) == 0


def test_cli_status_and_roots_ok(capsys):
    from aqsec.__main__ import main
    assert main(["status"]) == 0
    assert main(["roots"]) == 0


# --------------------------------------------------------------------------- #
# GUI / tray: import only, and skip building on headless / win32
# --------------------------------------------------------------------------- #
def test_gui_module_imports():
    # Importing must never require a display or customtkinter.
    from aqsec import gui
    assert gui.APP_NAME == "AIQuick Security"


def test_tray_module_imports():
    from aqsec import tray
    assert hasattr(tray, "start_tray")


@pytest.mark.skipif(not os.environ.get("DISPLAY") or sys.platform == "win32",
                    reason="GUI needs a display and is not built on win32 CI")
def test_gui_build_app_smoke():  # pragma: no cover - only with a display
    from aqsec import gui
    App = gui.build_app()
    assert App is not None


def test_public_version():
    assert aqsec.__version__ == "1.0.0"
