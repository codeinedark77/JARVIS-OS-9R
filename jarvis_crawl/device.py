"""Clocks, Device interface, adb backend, and the Frida event tail source.

Real runs use wall-clock time (time.time) on one host: adb commands and frida_host.py both run there, and
frida_host stamps each event on receipt, so action times and event times share a clock domain.
Tests/replay use FakeClock (virtual time, sleep() just advances it).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from typing import Dict, List, Optional

from .schema import Action, HookEvent


class Clock:
    def now(self) -> float:
        raise NotImplementedError

    def sleep(self, dt: float) -> None:
        raise NotImplementedError


class RealClock(Clock):
    def now(self) -> float:
        return time.time()

    def sleep(self, dt: float) -> None:
        if dt > 0:
            time.sleep(dt)


class FakeClock(Clock):
    def __init__(self, t0: float = 1_700_000_000.0):
        self.t = float(t0)

    def now(self) -> float:
        return self.t

    def sleep(self, dt: float) -> None:
        self.t += max(0.0, dt)


class Device:
    def dump_ui(self) -> str:
        raise NotImplementedError

    def current_package(self) -> str:
        raise NotImplementedError

    def act(self, a: Action) -> None:
        raise NotImplementedError

    def launch(self, pkg: str) -> None:
        raise NotImplementedError

    def force_stop(self, pkg: str) -> None:
        raise NotImplementedError

    def drain_events(self) -> List[HookEvent]:
        raise NotImplementedError

    def info(self) -> Dict:
        return {}


class JsonlTailSource:
    """Tails the JSONL file written by frida/frida_host.py. Tolerates a partially written last line."""

    def __init__(self, path: str):
        self.path, self.offset = path, 0

    def poll(self) -> List[HookEvent]:
        if not os.path.exists(self.path):
            return []
        out: List[HookEvent] = []
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            buf = f.read()
        end = buf.rfind(b"\n")
        if end < 0:
            return []
        self.offset += end + 1
        for ln in buf[:end].split(b"\n"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(HookEvent.from_dict(json.loads(ln)))
            except (ValueError, KeyError):
                continue
        return out


_SAFE_TEXT = re.compile(r"^[A-Za-z0-9@._+\- ]*$")
_FOCUS_RES = (re.compile(r"mCurrentFocus=Window\{[^ ]+ u\d+ ([\w.]+)/"),
              re.compile(r"(?:topResumedActivity|mResumedActivity)[^\n]*? u\d+ ([\w.]+)/"))


class AdbDevice(Device):
    """adb backend. root=True wraps shell commands in `su -c` (rooted 9R). UNTESTED against hardware here --
    the command shapes follow stock Android 10-14 behaviour; see README 'bring-up checklist'."""

    def __init__(self, serial: Optional[str] = None, root: bool = False, adb: str = "adb",
                 events: Optional[JsonlTailSource] = None, timeout: float = 30.0):
        self.serial, self.root, self.adb, self.events, self.timeout = serial, root, adb, events, timeout

    def _base(self) -> List[str]:
        return [self.adb] + (["-s", self.serial] if self.serial else [])

    def _run(self, args: List[str], check: bool = False) -> str:
        r = subprocess.run(self._base() + args, capture_output=True, timeout=self.timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"adb {' '.join(args)} failed: {r.stderr.decode(errors='replace')[:200]}")
        return r.stdout.decode("utf-8", errors="replace")

    def _sh(self, cmd: str, check: bool = False) -> str:
        if self.root:
            cmd = "su -c " + shlex.quote(cmd)
        return self._run(["shell", cmd], check=check)

    def dump_ui(self) -> str:
        out = self._run(["exec-out", "uiautomator", "dump", "/dev/tty"])
        i, j = out.find("<?xml"), out.rfind("</hierarchy>")
        if i < 0 or j < 0:  # fallback: dump to file, cat it
            self._sh("uiautomator dump /sdcard/jc_ui.xml")
            out = self._run(["exec-out", "cat", "/sdcard/jc_ui.xml"])
            i, j = out.find("<?xml"), out.rfind("</hierarchy>")
        if i < 0 or j < 0:
            raise RuntimeError("uiautomator dump returned no hierarchy")
        return out[i:j + len("</hierarchy>")]

    def current_package(self) -> str:
        out = self._sh("dumpsys window windows | grep -E 'mCurrentFocus'")
        m = _FOCUS_RES[0].search(out)
        if m:
            return m.group(1)
        out = self._sh("dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity'")
        m = _FOCUS_RES[1].search(out)
        return m.group(1) if m else ""

    def act(self, a: Action) -> None:
        k = a.kind
        if k == "tap":
            self._sh(f"input tap {a.x} {a.y}")
        elif k == "long_tap":
            self._sh(f"input swipe {a.x} {a.y} {a.x} {a.y} 800")
        elif k == "swipe":
            self._sh(f"input swipe {a.x} {a.y} {a.x2} {a.y2} 350")
        elif k == "text":
            txt = a.text or ""
            if not _SAFE_TEXT.match(txt):
                raise ValueError("refusing non-sandbox text")  # defence in depth; identity values are plain ascii
            self._sh(f"input tap {a.x} {a.y}")
            time.sleep(0.4)
            self._sh("input text " + shlex.quote(txt.replace(" ", "%s")))
        elif k == "back":
            self._sh("input keyevent 4")
        elif k == "home":
            self._sh("input keyevent 3")
        elif k == "wait":
            time.sleep(1.0)
        else:
            raise ValueError(f"unsupported action kind {k!r}")

    def launch(self, pkg: str) -> None:
        self._sh(f"monkey -p {shlex.quote(pkg)} -c android.intent.category.LAUNCHER 1")

    def force_stop(self, pkg: str) -> None:
        self._sh(f"am force-stop {shlex.quote(pkg)}")

    def drain_events(self) -> List[HookEvent]:
        return self.events.poll() if self.events else []

    def info(self) -> Dict:
        return {"kind": "adb", "serial": self.serial, "root": self.root}
