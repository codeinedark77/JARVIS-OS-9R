import threading, time
import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from fakes import FakeFrida, FakeRunner, default_responses
from warden import adb as adbmod, capture, doctor
from warden.schema import load_session


def _setup(server_ok=True):
    runner = FakeRunner(default_responses())
    return adbmod.Adb("SER1", runner=runner), runner, FakeFrida(server_ok)


def test_capture_phases_order_and_session_contents(tmp_path):
    adb, runner, fr = _setup()
    sleeps = []
    out, meta = capture.capture("com.example.app", tmp_path / "x.session.jsonl", seconds=45, bg_seconds=15, adb=adb, frida_mod=fr, sleep=sleeps.append)
    # force-stop precedes spawn; HOME is pressed between the fg and bg waits; app is stopped again at the end
    assert runner.index("force-stop") < len(runner.calls) and fr.log[:3] == ["spawn", "attach", "resume"]
    assert sleeps[:2] == [45, 15]
    assert runner.saw("input keyevent KEYCODE_HOME")
    assert runner.calls[-1].endswith("am force-stop com.example.app") or runner.saw("am force-stop com.example.app")
    s = load_session(out)
    assert s.package == "com.example.app" and len(s.events) == 3
    assert meta["perms"]["declared"] == ["CAMERA", "INTERNET", "READ_CONTACTS"]
    assert meta["phases"] == {"fg_s": 45, "bg_s": 15} and meta["profile"] == "full"
    assert meta["stats"]["counters"]["reflect_total"] == 7


def test_capture_defaults_do_not_grant_or_inject_input(tmp_path):
    adb, runner, fr = _setup()
    capture.capture("com.example.app", tmp_path / "x.session.jsonl", seconds=1, bg_seconds=0, adb=adb, frida_mod=fr, sleep=lambda s: None)
    assert not runner.saw("pm grant") and not runner.saw("monkey")


def test_capture_grant_only_dangerous_declared_permissions(tmp_path):
    adb, runner, fr = _setup()
    _, meta = capture.capture("com.example.app", tmp_path / "x.session.jsonl", seconds=1, bg_seconds=0, grant=True, adb=adb, frida_mod=fr, sleep=lambda s: None)
    assert sorted(meta["granted"]) == ["CAMERA", "READ_CONTACTS"]          # INTERNET is not a runtime permission
    assert runner.saw("pm grant com.example.app android.permission.CAMERA") and not runner.saw("android.permission.INTERNET")


def test_capture_monkey_only_when_requested(tmp_path):
    adb, runner, fr = _setup()
    capture.capture("com.example.app", tmp_path / "x.session.jsonl", seconds=1, bg_seconds=0, exercise="monkey", adb=adb, frida_mod=fr, sleep=lambda s: None)
    for _ in range(50):
        if runner.saw("monkey -p com.example.app"):
            break
        time.sleep(0.02)
    assert runner.saw("monkey -p com.example.app")


def test_capture_passes_profile_to_agent(tmp_path):
    adb, runner, fr = _setup()
    capture.capture("com.example.app", tmp_path / "x.session.jsonl", seconds=1, bg_seconds=0, profile="native", adb=adb, frida_mod=fr, sleep=lambda s: None)
    assert fr.device.scripts[0].started["profile"] == "native"


def test_capture_reports_unreachable_frida_server(tmp_path):
    adb, runner, fr = _setup(server_ok=False)
    with pytest.raises(RuntimeError, match="frida-server not responding"):
        capture.capture("com.example.app", tmp_path / "x.session.jsonl", adb=adb, frida_mod=fr, sleep=lambda s: None)


def test_capture_batch_resume_skips_existing(tmp_path):
    adb, runner, fr = _setup()
    (tmp_path / "com.example.app.session.jsonl").write_text('{"meta": {}}\n')
    res = capture.capture_batch(["com.example.app"], tmp_path, log=lambda *a: None, adb=adb, frida_mod=fr, sleep=lambda s: None, seconds=1, bg_seconds=0)
    assert res[0].get("skipped") is True


def test_doctor_all_green_and_android16_note():
    runner = FakeRunner({**default_responses(), "--version": (0, "17.23.3\n")})
    checks = doctor.doctor(adb=adbmod.Adb("SER1", runner=runner), frida_mod=FakeFrida())
    assert all(c["ok"] for c in checks), doctor.format_checks(checks)
    assert any(c["check"] == "Android 16+ note" for c in checks)


def test_doctor_flags_version_mismatch_and_missing_root():
    runner = FakeRunner({**default_responses(), "--version": (0, "16.5.9\n"), "su -c": (0, "")})
    checks = {c["check"]: c for c in doctor.doctor(adb=adbmod.Adb("SER1", runner=runner), frida_mod=FakeFrida())}
    assert not checks["frida versions compatible"]["ok"]
    assert not checks["root (su)"]["ok"]


def test_doctor_stops_early_without_device():
    runner = FakeRunner({"devices": (0, "List of devices attached\n")})
    checks = doctor.doctor(adb=adbmod.Adb(runner=runner), frida_mod=FakeFrida())
    assert len(checks) == 1 and not checks[0]["ok"]
