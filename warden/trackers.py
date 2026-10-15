"""Seed tracker/SDK signature DB + attribution. Seed list is hand-written and small; import Exodus Privacy's
JSON (https://reports.exodus-privacy.eu.org/api/trackers) with `warden trackers import FILE` for real coverage."""
import json, os, pathlib, re

KINDS = ("analytics", "ads", "attribution", "crash", "push", "social", "engagement", "profiling", "other")

# (class-name prefix, SDK name, kind)
SDK_SEED = [
    ("com.google.firebase.analytics", "Firebase Analytics", "analytics"), ("com.google.android.gms.measurement", "Google Measurement", "analytics"),
    ("com.google.firebase.crashlytics", "Crashlytics", "crash"), ("com.crashlytics", "Crashlytics", "crash"),
    ("com.google.android.gms.ads", "Google AdMob", "ads"), ("com.google.ads", "Google Ads", "ads"),
    ("com.google.firebase.messaging", "Firebase Messaging", "push"), ("com.google.android.gms.location", "Play Location", "other"),
    ("com.google.android.gms", "Google Play services", "other"), ("com.google.firebase", "Firebase", "other"),
    ("com.facebook.appevents", "Facebook App Events", "analytics"), ("com.facebook.ads", "Facebook Audience Network", "ads"),
    ("com.facebook", "Facebook SDK", "social"), ("com.twitter.sdk", "Twitter SDK", "social"),
    ("com.appsflyer", "AppsFlyer", "attribution"), ("com.adjust.sdk", "Adjust", "attribution"), ("io.branch", "Branch", "attribution"),
    ("com.kochava", "Kochava", "attribution"), ("com.singular", "Singular", "attribution"),
    ("com.mixpanel", "Mixpanel", "analytics"), ("com.amplitude", "Amplitude", "analytics"), ("com.segment.analytics", "Segment", "analytics"),
    ("com.flurry", "Flurry", "analytics"), ("com.localytics", "Localytics", "analytics"), ("com.umeng", "Umeng", "analytics"),
    ("com.baidu.mobstat", "Baidu Mobstat", "analytics"), ("com.tencent.bugly", "Bugly", "crash"),
    ("com.clevertap", "CleverTap", "engagement"), ("com.moengage", "MoEngage", "engagement"), ("com.webengage", "WebEngage", "engagement"),
    ("com.leanplum", "Leanplum", "engagement"), ("com.braze", "Braze", "engagement"), ("com.appboy", "Braze", "engagement"),
    ("com.onesignal", "OneSignal", "push"), ("com.urbanairship", "Airship", "push"), ("com.pushwoosh", "Pushwoosh", "push"), ("cn.jpush", "JPush", "push"),
    ("com.unity3d.ads", "Unity Ads", "ads"), ("com.unity3d.services", "Unity Ads", "ads"), ("com.unity3d.mediation", "Unity LevelPlay", "ads"),
    ("com.applovin", "AppLovin", "ads"), ("com.ironsource", "ironSource", "ads"), ("com.inmobi", "InMobi", "ads"), ("com.mopub", "MoPub", "ads"),
    ("com.vungle", "Vungle", "ads"), ("com.chartboost", "Chartboost", "ads"), ("com.adcolony", "AdColony", "ads"), ("com.tapjoy", "Tapjoy", "ads"),
    ("com.startapp", "StartApp", "ads"), ("com.smaato", "Smaato", "ads"), ("com.bytedance.sdk.openadsdk", "Pangle", "ads"), ("com.pangle", "Pangle", "ads"),
    ("com.mbridge", "Mintegral", "ads"), ("com.mintegral", "Mintegral", "ads"), ("com.fyber", "Fyber", "ads"), ("com.yandex.mobile.ads", "Yandex Ads", "ads"),
    ("com.my.target", "MyTarget", "ads"), ("com.criteo", "Criteo", "ads"), ("com.amazon.device.ads", "Amazon Ads", "ads"), ("com.amazon.aps", "Amazon APS", "ads"),
    ("io.sentry", "Sentry", "crash"), ("com.bugsnag", "Bugsnag", "crash"), ("com.instabug", "Instabug", "crash"), ("org.acra", "ACRA", "crash"),
]
# (host regex, name, kind)
HOST_SEED = [
    (r"(^|\.)doubleclick\.net$", "DoubleClick", "ads"), (r"googlesyndication\.com$", "Google Ads", "ads"), (r"googleadservices\.com$", "Google Ads", "ads"),
    (r"(^|\.)google-analytics\.com$", "Google Analytics", "analytics"), (r"app-measurement\.com$", "Firebase Analytics", "analytics"),
    (r"firebaselogging", "Firebase", "analytics"), (r"crashlytics\.com$", "Crashlytics", "crash"),
    (r"(^|\.)graph\.facebook\.com$", "Facebook Graph", "social"), (r"(^|\.)facebook\.com$", "Facebook", "social"), (r"(^|\.)fbcdn\.net$", "Facebook CDN", "other"),
    (r"appsflyer\.com$", "AppsFlyer", "attribution"), (r"adjust\.(com|io)$", "Adjust", "attribution"), (r"branch\.io$", "Branch", "attribution"),
    (r"kochava\.com$", "Kochava", "attribution"), (r"singular\.net$", "Singular", "attribution"),
    (r"mixpanel\.com$", "Mixpanel", "analytics"), (r"amplitude\.com$", "Amplitude", "analytics"), (r"segment\.(io|com)$", "Segment", "analytics"),
    (r"flurry\.com$", "Flurry", "analytics"), (r"umeng\.com$", "Umeng", "analytics"), (r"clevertap", "CleverTap", "engagement"),
    (r"braze\.com$|appboy\.com$", "Braze", "engagement"), (r"onesignal\.com$", "OneSignal", "push"),
    (r"unity3d\.com$|unityads", "Unity Ads", "ads"), (r"applovin\.com$", "AppLovin", "ads"), (r"(ironsrc|supersonicads|is\.com)", "ironSource", "ads"),
    (r"inmobi\.com$", "InMobi", "ads"), (r"mopub\.com$", "MoPub", "ads"), (r"vungle\.com$", "Vungle", "ads"), (r"chartboost\.com$", "Chartboost", "ads"),
    (r"adcolony\.com$", "AdColony", "ads"), (r"tapjoy\.com$", "Tapjoy", "ads"), (r"startappservice\.com$", "StartApp", "ads"),
    (r"(pangleglobal|pangle|byteoversea|bytedance)\.com$", "Pangle", "ads"), (r"mintegral\.com$|mbridge", "Mintegral", "ads"),
    (r"sentry\.io$", "Sentry", "crash"), (r"bugsnag\.com$", "Bugsnag", "crash"),
]

_OBF_FIRST = re.compile(r"^[a-z]{1,2}$|^defpackage$")
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f:]+\]?$", re.I)


class Matcher:
    def __init__(self, extra_sdk=None, extra_hosts=None):
        self.sdk = sorted(list(SDK_SEED) + list(extra_sdk or []), key=lambda r: -len(r[0]))   # longest prefix wins
        self.hosts = [(re.compile(p, re.I), n, k) for p, n, k in list(HOST_SEED) + list(extra_hosts or [])]

    def host(self, h):
        if not h or _IP.match(h):
            return None
        for rx, n, k in self.hosts:
            if rx.search(h):
                return n, k
        return None

    def cls(self, c):
        for pre, n, k in self.sdk:
            if c == pre or c.startswith(pre + ".") or c.startswith(pre + "$"):
                return n, k
        return None


def is_ip(h):
    return bool(h and _IP.match(h))


def user_db_path():
    return pathlib.Path(os.environ.get("WARDEN_HOME", pathlib.Path.home() / ".warden")) / "trackers.json"


def from_exodus(obj):
    """Exodus API shape: {"trackers": {id: {name, code_signature, network_signature, categories, ...}}}.
    code_signature / network_signature are '|'-joined regex fragments (matched with re.search)."""
    sdk, hosts = [], []
    cat_map = {"analytics": "analytics", "advertisement": "ads", "crash reporting": "crash", "profiling": "profiling",
               "identification": "attribution", "location": "profiling"}
    for t in (obj.get("trackers") or {}).values():
        kind = "other"
        for c in t.get("categories") or []:
            kind = cat_map.get(str(c).lower(), kind)
            if kind != "other":
                break
        name = t.get("name") or "?"
        for sig in filter(None, (t.get("code_signature") or "").split("|")):
            # literal package prefixes only (strip regex escapes); regex-y ones are kept as host-style regexes below
            lit = sig.replace("\\.", ".").rstrip(".")
            if re.fullmatch(r"[A-Za-z0-9_.$]+", lit):
                sdk.append((lit, name, kind))
        for sig in filter(None, (t.get("network_signature") or "").split("|")):
            try:
                re.compile(sig)
                hosts.append((sig, name, kind))
            except re.error:
                pass
    return sdk, hosts


def import_exodus(path):
    sdk, hosts = from_exodus(json.load(open(path)))
    dst = user_db_path()
    dst.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"sdk": sdk, "hosts": hosts}, open(dst, "w"))
    return len(sdk), len(hosts), dst


def fetch_exodus(url="https://reports.exodus-privacy.eu.org/api/trackers", out="exodus_trackers.json", timeout=30):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "warden/2"})
    data = urllib.request.urlopen(req, timeout=timeout).read()
    pathlib.Path(out).write_bytes(data)
    return out


_MATCHER = None


def matcher(refresh=False):
    global _MATCHER
    if _MATCHER is None or refresh:
        extra_sdk, extra_hosts = [], []
        p = user_db_path()
        if p.exists():
            try:
                d = json.load(open(p))
                extra_sdk = [tuple(x) for x in d.get("sdk", [])]
                extra_hosts = [tuple(x) for x in d.get("hosts", [])]
            except (OSError, ValueError):
                pass
        _MATCHER = Matcher(extra_sdk, extra_hosts)
    return _MATCHER


def attribute(caller, package, m=None):
    """-> (owner, name, kind); owner in app|sdk|lib|obf|unknown"""
    m = m or matcher()
    if not caller or caller == "?":
        return "unknown", None, None
    hit = m.cls(caller)
    if hit:
        return "sdk", hit[0], hit[1]
    if package and (caller == package or caller.startswith(package + ".")):
        return "app", None, None
    parts = (package or "").split(".")
    if len(parts) >= 2 and caller.startswith(".".join(parts[:2]) + "."):
        return "app", None, None
    if _OBF_FIRST.match(caller.split(".")[0]):
        return "obf", None, None
    return "lib", ".".join(caller.split(".")[:3]), "other"


_STOP = {"com", "org", "net", "io", "android", "app", "apps", "mobile", "free", "pro", "lite", "the", "my", "google", "www"}


def first_party_host(host, package):
    if not host or not package:
        return False
    toks = [t for t in re.split(r"[._]", package.lower()) if len(t) >= 4 and t not in _STOP]
    h = host.lower()
    return any(t in h for t in toks)
