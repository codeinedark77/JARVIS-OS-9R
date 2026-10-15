"""Synthetic session generator (pipeline/regression testing without a device). NOT real data: class boundaries are
authored by me, so accuracy on this corpus measures the plumbing and the confounder handling, not real-world performance.
Includes hard negatives (root-checking banking apps, Play split-install dex loads, legit bg location, contacts sync) and
easy-to-confuse positives (stealth droppers, single-SDK analytics) so metrics are not trivially 100%."""
import pathlib, random
from . import manifest
from .schema import Session, dump_session, SUFFIX

AD = [("com.applovin.sdk.AppLovinSdk", "d.applovin.com"), ("com.unity3d.ads.UnityAds", "auction.unityads.unity3d.com"),
      ("com.ironsource.mediationsdk.IronSource", "init.supersonicads.com"), ("com.google.android.gms.ads.MobileAds", "pagead2.googlesyndication.com"),
      ("com.inmobi.ads.InMobiAds", "api.w.inmobi.com"), ("com.vungle.warren.Vungle", "api.vungle.com"), ("com.chartboost.sdk.Chartboost", "live.chartboost.com")]
AN = [("com.google.firebase.analytics.FirebaseAnalytics", "app-measurement.com"), ("com.mixpanel.android.mpmetrics.MixpanelAPI", "api.mixpanel.com"),
      ("com.amplitude.api.Amplitude", "api2.amplitude.com"), ("com.appsflyer.AppsFlyerLib", "t.appsflyer.com"), ("com.adjust.sdk.Adjust", "app.adjust.com")]
WORDS = ["pixel", "nova", "quark", "lumen", "orbit", "delta", "ember", "frost", "gleam", "harbor", "ionic", "juno", "karma", "latch", "mosaic"]
A = {"gid": "android.provider.Settings$Secure.getString", "adid": "com.google.android.gms.ads.identifier.AdvertisingIdClient.getAdvertisingIdInfo",
     "imei": "android.telephony.TelephonyManager.getImei", "loc": "android.location.LocationManager.getLastKnownLocation",
     "q": "android.content.ContentResolver.query", "dns": "java.net.InetAddress.getAllByName", "url": "java.net.URL.openConnection",
     "sock": "java.net.Socket.connect", "ncon": "native.connect", "dex": "dalvik.system.DexClassLoader.$init", "mic": "android.media.AudioRecord.startRecording",
     "cam": "android.hardware.camera2.CameraManager.openCamera", "exec": "java.lang.Runtime.exec", "dl": "native.dlopen", "cph": "javax.crypto.Cipher.doFinal",
     "fex": "java.io.File.exists", "pkgi": "android.app.ApplicationPackageManager.getPackageInfo", "pkgs": "android.app.ApplicationPackageManager.getInstalledPackages",
     "clip": "android.content.ClipboardManager.getPrimaryClip", "root": "android.accessibilityservice.AccessibilityService.getRootInActiveWindow",
     "glob": "android.accessibilityservice.AccessibilityService.performGlobalAction", "ovl": "android.view.WindowManagerGlobal.addView",
     "sms": "android.telephony.SmsManager.sendTextMessage", "ptr": "native.ptrace"}

TRAIN_SUBTYPES = {0: [("plain", 28), ("analytics", 25), ("banking", 10), ("playcore", 10), ("navigation", 8), ("chat", 7), ("camera", 5), ("a11y_tool", 4), ("bg_sync", 6)],
                  1: [("ads_heavy", 42), ("attribution", 22), ("sdk_bg", 22), ("weak", 14)],
                  2: [("dropper", 25), ("a11y_overlay", 18), ("spyware", 18), ("sms_fraud", 12), ("miner", 12), ("stealth", 15)]}


def _pick(rng, table):
    r, acc = rng.uniform(0, sum(w for _, w in table)), 0
    for name, w in table:
        acc += w
        if r <= acc:
            return name
    return table[-1][0]


class _Gen:
    def __init__(self, rng, pkg, brand):
        self.r, self.pkg, self.brand = rng, pkg, brand
        self.own = pkg + ".ui.MainActivity"
        self.ev = []
        self.dfg = rng.randint(30000, 70000)
        self.dbg = rng.randint(10000, 25000)
        self.obf = rng.random() < 0.20          # R8-obfuscated build: attribution degrades
        self.lossy = rng.random() < 0.15        # hook failures: some events never observed

    def at(self, lo=0, hi=None, bg=False):
        hi = hi or (self.dfg if not bg else self.dfg + self.dbg)
        return self.r.randint(lo if not bg else self.dfg + 500, hi)

    def E(self, t, api, cat, arg=None, caller=None):
        c = caller or self.own
        if self.obf and not c.startswith(("com.android", "java")):
            c = "a.b." + c.rsplit(".", 1)[-1][:1].lower()
        self.ev.append({"t": t, "api": api, "cat": cat, "arg": arg, "caller": c, "fg": 1 if t < self.dfg else 0})

    def net(self, t, host, caller=None, scheme="https", port=None, nbytes=None):
        self.E(t, A["dns"], "network", host, caller)
        self.E(t + 5, A["url"], "network", "%s://%s/v1/e?k&s" % (scheme, host), caller)
        self.E(t + 6, A["ncon"], "network", "198.51.100.%d:%d" % (self.r.randint(2, 250), port or 443), None)   # resolved IP, as on a real device
        nb = nbytes or self.r.randint(300, 20000)
        fgf = 1 if t < self.dfg else 0
        self.ev.append({"t": t + 120, "api": "TLS.write", "cat": "traffic", "arg": "tls", "caller": "?", "fg": fgf, "n": nb})
        self.ev.append({"t": t + 121, "api": "sock.send", "cat": "traffic", "arg": "raw", "caller": "?", "fg": fgf, "n": int(nb * self.r.uniform(1.0, 1.15))})   # ciphertext mirror

    def finish(self):
        r = self.r
        ev = self.ev
        if self.lossy:
            ev = [e for e in ev if r.random() > 0.3 or e["cat"] == "lifecycle"]
        ev.append({"t": 0, "api": "Activity.onResume", "cat": "lifecycle", "arg": "fg", "caller": "?", "fg": 1})
        ev.append({"t": self.dfg, "api": "Activity.onPause", "cat": "lifecycle", "arg": "bg", "caller": "?", "fg": 0})
        ev.sort(key=lambda e: e["t"])
        return ev


def _own_traffic(g):
    r = g.r
    for _ in range(r.randint(4, 22)):
        t = g.at(200)
        if r.random() < 0.4:
            g.E(t - 30, A["cph"], "crypto", "AES/GCM/NoPadding")
        g.net(t, "api.%s.com" % g.brand)
    if r.random() < 0.3:
        g.net(g.at(200), "cdn.%s.com" % g.brand)


def _sdk_reads(g, sdks, n, bg=False, loc_p=0.3, pk_p=0.0):
    r = g.r
    for cls, host in sdks:
        for _ in range(r.randint(1, n)):
            t = g.at(100, bg=bg)
            g.E(t, A["gid"], "identifier", "android_id", cls)
            if r.random() < .55:
                g.E(t + 8, A["adid"], "identifier", None, cls)
            if r.random() < loc_p:
                g.E(t + 15, A["loc"], "location", None, cls)
            if r.random() < pk_p:
                g.E(t + 20, A["pkgs"], "pkg_enum", None, cls)
            g.net(t + r.randint(20, 900), host, cls)


def gen_session(label, sub, rng, pkg, brand):
    g = _Gen(rng, pkg, brand)
    r = rng
    _own_traffic(g)
    perms = ["INTERNET", "ACCESS_NETWORK_STATE"]
    L = lambda: "com.%s.core.%s" % (r.choice(["x7", "qz", "zk3", "libk"]), r.choice(["Loader", "Svc", "Sync"]))
    if label == 0:
        if sub == "analytics":
            _sdk_reads(g, r.sample(AN, r.randint(1, 2)), 3, loc_p=0.05)
        elif sub == "banking":
            for p in ["/system/xbin/su", "/sbin/su", "/data/adb/magisk"]:
                g.E(g.at(50, 1500), A["fex"], "env_probe", p, "com.secure.rootcheck.RootBeer")
            g.E(g.at(50, 1500), A["pkgi"], "env_probe", "com.topjohnwu.magisk", "com.secure.rootcheck.RootBeer")
            if r.random() < .3:
                g.E(g.at(50, 1500), A["ptr"], "env_probe", "req=0", None)
        elif sub == "playcore":
            g.E(g.at(500, 5000), A["dex"], "dyn_code", r.choice(["/data/user/0/%s/files/splitcompat/base-master.apk" % pkg, "/data/app/~~x/%s-1/base.apk" % pkg]), "com.google.android.play.core.splitcompat.SplitCompat")
        elif sub == "navigation":
            for _ in range(r.randint(8, 20)):
                g.E(g.at(bg=r.random() < .6), A["loc"], "location", None)
        elif sub == "chat":
            for _ in range(r.randint(1, 3)):
                t = g.at(500)
                g.E(t, A["q"], "contacts_sms", "content://com.android.contacts/data/phones")
                g.net(t + 300, "api.%s.com" % brand)
            perms += ["READ_CONTACTS"]
        elif sub == "a11y_tool":
            for _ in range(r.randint(5, 20)):
                g.E(g.at(), A["root"], "a11y", None)
            for _ in range(r.randint(0, 2)):
                g.E(g.at(500), A["ovl"], "overlay", "type=2038")
            perms += ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"][: r.randint(1, 2)]
        elif sub == "bg_sync":
            for _ in range(r.randint(2, 6)):
                g.net(g.at(bg=True), "api.%s.com" % brand)
        elif sub == "camera":
            for _ in range(r.randint(1, 3)):
                g.E(g.at(1000), A["cam" if r.random() < .6 else "mic"], "sensor_av", None)
            perms += ["CAMERA", "RECORD_AUDIO"]
        elif r.random() < .2:
            g.E(g.at(1000), A["loc"], "location", None)
    elif label == 1:
        if sub == "weak":
            _sdk_reads(g, r.sample(AN, 1), 2, loc_p=0.1)
        elif sub == "attribution":
            _sdk_reads(g, r.sample([x for x in AN if "appsflyer" in x[0] or "adjust" in x[0]] + r.sample(AN, 1), 2), 4, pk_p=0.4)
        else:
            _sdk_reads(g, r.sample(AD, r.randint(2, 4)) + r.sample(AN, 1), 5, loc_p=0.35)
            if sub == "sdk_bg":
                _sdk_reads(g, r.sample(AD, 2), 3, bg=True, loc_p=0.2)
        perms += ["READ_PHONE_STATE", "ACCESS_COARSE_LOCATION"][: r.randint(0, 2)]
    else:
        def ip_net(t, nb=None):     # exfil channel: ~60% hard-coded IP, ~40% throwaway domain (so 'direct IP' is not a shortcut)
            port = r.choice([4443, 8888, 9001, 1337, 443, 8443])
            if r.random() < 0.4:
                host = "%s-%d.%s" % (r.choice(["upd", "sync", "api2", "cdn"]), r.randint(100, 9999), r.choice(["top", "xyz", "cc", "club"]))
                g.E(t - 20, A["dns"], "network", host, L())
                g.E(t, A["sock"], "network", "%s/203.0.113.%d:%d" % (host, r.randint(2, 250), port), L())
            else:
                g.E(t, A["sock"], "network", "/203.0.113.%d:%d" % (r.randint(2, 250), port), L())
            g.E(t + 3, A["ncon"], "network", "203.0.113.%d:%d" % (r.randint(2, 250), port), None)
            n_ = nb or r.randint(20000, 400000)
            fgf = 1 if t < g.dfg else 0
            if r.random() < 0.5:    # TLS to the C2 (ciphertext mirrored in raw) vs plain custom protocol (raw only)
                g.ev.append({"t": t + 100, "api": "TLS.write", "cat": "traffic", "arg": "tls", "caller": "?", "fg": fgf, "n": n_})
                g.ev.append({"t": t + 101, "api": "sock.send", "cat": "traffic", "arg": "raw", "caller": "?", "fg": fgf, "n": int(n_ * 1.08)})
            else:
                g.ev.append({"t": t + 100, "api": "sock.send", "cat": "traffic", "arg": "raw", "caller": "?", "fg": fgf, "n": n_})
        loader = L()
        if sub in ("dropper", "stealth"):
            t0 = g.at(300, 8000)
            g.E(t0, A["dex"], "dyn_code", r.choice(["/data/data/%s/cache/p.dex" % pkg, "/sdcard/Android/data/.cache/u.jar", "in-memory"]), loader)
            n = 1 if sub == "stealth" else r.randint(2, 6)
            for _ in range(n):
                t = t0 + r.randint(100, 9000) + (g.dfg if (sub == "dropper" and r.random() < .6) else 0)
                if sub == "dropper":
                    g.E(t, A["q"], "contacts_sms", "content://sms/inbox", loader)
                    g.E(t + 4, A["q"], "contacts_sms", "content://com.android.contacts/data", loader)
                ip_net(t + 40)
            perms += ["READ_SMS", "READ_CONTACTS", "REQUEST_INSTALL_PACKAGES"][: (1 if sub == "stealth" else 3)]
        elif sub == "a11y_overlay":
            for _ in range(r.randint(6, 25)):
                g.E(g.at(bg=r.random() < .5), A["root"], "a11y", None, loader)
            for _ in range(r.randint(1, 4)):
                g.E(g.at(1000, bg=r.random() < .4), A["ovl"], "overlay", "type=2038", loader)
            if r.random() < .5:
                g.E(g.at(100, 1500), A["fex"], "env_probe", "/system/xbin/su", loader)
            for _ in range(r.randint(2, 6)):
                ip_net(g.at(bg=r.random() < .6))
            perms += ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "READ_SMS"]
        elif sub == "spyware":
            for _ in range(r.randint(2, 6)):
                t = g.at(bg=True)
                g.E(t, A["mic"], "sensor_av", None, loader)
                g.E(t + 10, A["loc"], "location", None, loader)
                if r.random() < .5:
                    g.E(t + 12, A["clip"], "clipboard", None, loader)
                ip_net(t + 200, r.randint(50000, 600000))
            g.E(g.at(bg=True), A["pkgs"], "pkg_enum", None, loader)
            perms += ["RECORD_AUDIO", "ACCESS_BACKGROUND_LOCATION", "QUERY_ALL_PACKAGES"]
        elif sub == "sms_fraud":
            for _ in range(r.randint(1, 4)):
                t = g.at(bg=True)
                g.E(t, A["q"], "contacts_sms", "content://sms/inbox", loader)
                g.E(t + 30, A["sms"], "sms_call", None, loader)
                g.net(t + 80, "sms-gw.%s-svc.example" % r.choice(["quick", "relay"]), loader, nbytes=r.randint(200, 900))
            perms += ["SEND_SMS", "READ_SMS", "RECEIVE_SMS"]
        elif sub == "miner":
            g.E(g.at(300, 6000), A["exec"], "exec", "chmod 755 /data/data/%s/files/.m" % pkg, loader)
            g.E(g.at(300, 6000), A["dl"], "native", "/data/data/%s/files/.libm.so" % pkg, loader)
            for _ in range(r.randint(3, 10)):
                t = g.at(bg=True)
                g.E(t, A["dns"], "network", "pool.xmr-%s.example" % r.choice(["cloud", "mesh"]), loader)
                g.E(t + 5, A["ncon"], "network", "198.51.100.%d:%d" % (r.randint(2, 250), r.choice([3333, 4444, 5555])), None)
                g.ev.append({"t": t + 100, "api": "sock.send", "cat": "traffic", "arg": "raw", "caller": "?", "fg": 0, "n": r.randint(20000, 200000)})
            perms += ["RECEIVE_BOOT_COMPLETED"]
    HR = ["RECEIVE_BOOT_COMPLETED", "QUERY_ALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "WRITE_SETTINGS"]
    if label < 2:
        if r.random() < (0.30 if label == 0 else 0.25):
            perms.append(r.choice(HR))          # benign apps declare risky perms too
    else:
        perms = [p for p in perms if p not in manifest.HIGH_RISK or r.random() < 0.7]   # malware under-declares sometimes
    # declared perms: add noise (benign apps over-declare; some malware under-declares because of root/ADB installs)
    perms += r.sample(["READ_CONTACTS", "CAMERA", "ACCESS_FINE_LOCATION", "READ_PHONE_STATE", "RECORD_AUDIO"], r.randint(0, 3 if label < 2 else 1))
    return g.finish(), sorted(set(perms))


def make(n_apps_per_class=60, sessions_per_app=3, seed=0, outdir=None):
    rng = random.Random(seed)
    out = []
    used = set()
    for label in (0, 1, 2):
        for i in range(n_apps_per_class):
            sub = _pick(rng, TRAIN_SUBTYPES[label])
            brand = "%s%d" % (rng.choice(WORDS), rng.randint(10, 999))
            while brand in used:                 # package name is the CV group key and the file stem: must be unique
                brand = "%s%d" % (rng.choice(WORDS), rng.randint(10, 999999))
            used.add(brand)
            pkg = "com.%s.app" % brand
            for k in range(sessions_per_app):
                ev, perms = gen_session(label, sub, rng, pkg, brand)
                meta = {"sid": "%s-%d" % (pkg, k), "package": pkg, "label": label, "subtype": sub, "synthetic": True, "perms": {"declared": perms, "granted": perms}, "session": k}
                s = Session(meta, ev, "")
                if outdir:
                    p = pathlib.Path(outdir) / ("%s-%d%s" % (pkg, k, SUFFIX))
                    dump_session(p, meta, ev)
                    s.path = str(p)
                out.append(s)
    return out
