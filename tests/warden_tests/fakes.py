"""Test doubles: scripted adb runner and a fake `frida` module (no device needed)."""
import time

DUMP = """Packages:
  Package [com.example.app] (abc):
    versionName=1.2.3
    requested permissions:
      android.permission.INTERNET
      android.permission.READ_CONTACTS
      android.permission.CAMERA
"""


class FakeRunner:
    def __init__(self, responses=None):
        self.calls, self.responses = [], responses or {}

    def __call__(self, argv, timeout):
        joined = " ".join(argv)
        self.calls.append(joined)
        hits = [k for k in self.responses if k in joined]
        if hits:
            rc, out = self.responses[max(hits, key=len)]      # most specific key wins
            return rc, out, ""
        return 0, "", ""

    def saw(self, needle):
        return any(needle in c for c in self.calls)

    def index(self, needle):
        for i, c in enumerate(self.calls):
            if needle in c:
                return i
        return -1


def default_responses():
    return {"dumpsys package": (0, DUMP), "getprop ro.product.model": (0, "Pixel 9\n"), "getprop ro.build.version.sdk": (0, "36\n"),
            "getprop ro.build.version.release": (0, "16\n"), "getprop ro.product.cpu.abi": (0, "arm64-v8a\n"), "devices": (0, "List of devices attached\nSER1\tdevice\n"),
            "pm list packages": (0, "package:com.a\npackage:com.b\n"), "su -c": (0, "uid=0(root)\n")}


class FakeScript:
    def __init__(self, dev):
        self.dev, self.handler, self.started = dev, None, None
        self.exports_sync = self

    def on(self, name, cb):
        self.handler = cb

    def load(self):
        pass

    def start(self, cfg):
        self.started = cfg
        return {"java": True, "android": "16", "pid": 4242}

    def flush(self):
        return True

    def stats(self):
        return {"total": 3, "hooks": {"ok": 5, "fail": 0, "failed": []}, "counters": {"reflect_total": 7}, "java": True}

    def emit(self, payload):
        self.handler({"type": "send", "payload": payload}, None)


class FakeSession:
    def __init__(self, dev, pid):
        self.dev, self.pid, self.detached = dev, pid, False

    def create_script(self, src):
        s = FakeScript(self.dev)
        self.dev.scripts.append(s)
        return s

    def detach(self):
        self.detached = True


class FakeDevice:
    def __init__(self, log, server_ok=True):
        self.log, self.server_ok, self.scripts, self.sessions = log, server_ok, [], []

    def enumerate_processes(self):
        if not self.server_ok:
            raise RuntimeError("unable to connect to remote frida-server")
        return []

    def spawn(self, argv):
        self.log.append("spawn")
        return 4242

    def attach(self, pid):
        self.log.append("attach")
        s = FakeSession(self, pid)
        self.sessions.append(s)
        return s

    def resume(self, pid):
        self.log.append("resume")
        sc = self.scripts[0]
        sc.emit({"type": "meta", "pid": pid, "java": True, "android": "16"})
        sc.emit({"type": "hooks", "pid": pid, "hooks": {"ok": 5, "fail": 0, "failed": []}})
        sc.emit({"type": "batch", "pid": pid, "events": [
            {"t": 100, "api": "android.telephony.TelephonyManager.getImei", "cat": "identifier", "arg": None, "caller": "com.appsflyer.AppsFlyerLib", "fg": 1},
            {"t": 150, "api": "java.net.InetAddress.getAllByName", "cat": "network", "arg": "t.appsflyer.com", "caller": "com.appsflyer.AppsFlyerLib", "fg": 1},
            {"t": 9000, "api": "android.media.AudioRecord.startRecording", "cat": "sensor_av", "arg": None, "caller": "com.example.app.Rec", "fg": 0},
        ]})

    def on(self, *a):
        pass

    def enable_spawn_gating(self):
        pass

    def disable_spawn_gating(self):
        pass

    def enumerate_pending_spawn(self):
        return []


class FakeFrida:
    __version__ = "17.23.3"

    def __init__(self, server_ok=True):
        self.log = []
        self.device = FakeDevice(self.log, server_ok)

    def get_usb_device(self, timeout=5):
        return self.device

    def get_device(self, ident):
        return self.device
