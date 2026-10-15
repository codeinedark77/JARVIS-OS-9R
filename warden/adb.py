"""adb wrapper with an injectable runner (tests use a fake). Defaults are conservative: no input injection, no permission grants."""
import shlex, subprocess

from . import manifest


def _default_runner(argv, timeout):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


class Adb:
    def __init__(self, serial=None, runner=None, su_style="c"):
        self.serial, self.runner, self.su_style = serial, runner or _default_runner, su_style   # su_style: c (su -c) | 0 (su 0 sh -c) | none (already root)

    def run(self, args, timeout=20):
        argv = ["adb"] + (["-s", self.serial] if self.serial else []) + list(args)
        return self.runner(argv, timeout)

    def shell(self, cmd, timeout=20):
        rc, out, err = self.run(["shell", cmd], timeout)
        return out if rc == 0 else ""

    def su(self, cmd, timeout=20):
        q = shlex.quote(cmd)
        wrapped = {"c": "su -c %s" % q, "0": "su 0 sh -c %s" % q}.get(self.su_style, cmd)
        return self.shell(wrapped, timeout)

    def devices(self):
        rc, out, _ = self.run(["devices"])
        return [l.split("\t")[0] for l in out.splitlines()[1:] if l.strip().endswith("device")] if rc == 0 else []

    def getprop(self, k):
        return self.shell("getprop %s" % k).strip() or None

    def device_info(self):
        return {"model": self.getprop("ro.product.model"), "api": self.getprop("ro.build.version.sdk"), "android": self.getprop("ro.build.version.release"),
                "abi": self.getprop("ro.product.cpu.abi"), "build": self.getprop("ro.build.display.id")}

    def packages(self, third_party=True):
        out = self.shell("pm list packages" + (" -3" if third_party else ""), 30)
        return sorted(l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("package:"))

    def force_stop(self, pkg):
        self.shell("am force-stop %s" % shlex.quote(pkg))

    def clear(self, pkg):
        self.shell("pm clear %s" % shlex.quote(pkg))

    def home(self):
        self.shell("input keyevent KEYCODE_HOME")

    def dumpsys_package(self, pkg):
        return self.shell("dumpsys package %s" % shlex.quote(pkg), 30)

    def permissions(self, pkg):
        txt = self.dumpsys_package(pkg)
        return manifest.parse_dumpsys(txt, pkg) if txt.strip() else None

    def grant(self, pkg, perms):
        """Grant declared *dangerous* runtime permissions. WARNING: the app gets real access to whatever data is on this device."""
        done = []
        for p in perms:
            if p in manifest.DANGEROUS:
                rc, _, _ = self.run(["shell", "pm grant %s android.permission.%s" % (shlex.quote(pkg), p)])
                if rc == 0:
                    done.append(p)
        return done

    def monkey(self, pkg, seconds, throttle_ms=250, seed=1):
        """Random UI input for ~seconds. Can trigger real in-app actions (messages, purchases): analysis devices only."""
        n = max(1, int(seconds * 1000 / throttle_ms))
        rc, _, _ = self.run(["shell", "monkey -p %s --throttle %d --pct-syskeys 0 --ignore-crashes --ignore-timeouts --ignore-security-exceptions -s %d %d" % (shlex.quote(pkg), throttle_ms, seed, n)], timeout=seconds + 30)
        return rc

    def frida_server_version(self, path="/data/local/tmp/frida-server"):
        return (self.su("%s --version" % path) or "").strip() or None
