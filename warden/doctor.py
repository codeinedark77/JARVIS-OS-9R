"""Preflight checks: adb, device, root, frida python vs frida-server versions, Android API caveats."""
import re

from .adb import Adb


def doctor(serial=None, adb=None, frida_mod=None, server_path="/data/local/tmp/frida-server"):
    adb = adb or Adb(serial)
    checks = []

    def add(name, ok, detail="", fix=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail, "fix": fix})

    devs = adb.devices()
    add("adb device", bool(devs), ", ".join(devs) or "none", "enable USB debugging, `adb devices` must show 'device'")
    if not devs:
        return checks
    info = adb.device_info()
    api = int(info["api"]) if (info.get("api") or "").isdigit() else None
    add("device", True, "%s / Android %s (API %s) / %s" % (info.get("model"), info.get("android"), info.get("api"), info.get("abi")))
    root = adb.su("id")
    add("root (su)", "uid=0" in root, root.strip() or "no su", "root the device (Magisk/KernelSU) or use a userdebug build with `adb root` (--su-style none)")
    try:
        frida = frida_mod or __import__("frida")
        add("frida (host)", True, frida.__version__)
    except ImportError:
        add("frida (host)", False, "not installed", "pip install frida frida-tools")
        return checks
    raw = adb.frida_server_version(server_path) or ""
    m_ = re.search(r"\d+\.\d+\.\d+", raw)
    srv = m_.group(0) if m_ else None            # ignore su/shell noise: only a real version string counts
    host_v = frida.__version__
    same = bool(srv) and srv.split(".")[0] == host_v.split(".")[0]
    add("frida-server on device", bool(srv), srv or "not found at %s" % server_path, "scripts/setup_device.sh pushes the matching build")
    if srv:
        add("frida versions compatible", same, "host %s / server %s" % (host_v, srv), "install the same frida-server version as the host package (at least the same major)")
    try:
        dev = frida.get_device(serial) if serial else frida.get_usb_device(timeout=5)
        dev.enumerate_processes()
        add("frida-server reachable", True)
    except Exception as e:
        add("frida-server reachable", False, str(e), "start it: adb shell su -c '%s -D'" % server_path)
    if api and api >= 36:
        add("Android 16+ note", int(host_v.split(".")[0]) >= 17, "API %d" % api, "use a recent Frida 17.x; if an app crashes on Java hooks run `--profile minimal` or `--profile native`")
    return checks


def format_checks(checks):
    out = []
    for c in checks:
        out.append("%s %-26s %s%s" % ("OK  " if c["ok"] else "FAIL", c["check"], c["detail"], "" if c["ok"] or not c["fix"] else "\n       fix: " + c["fix"]))
    return "\n".join(out)
