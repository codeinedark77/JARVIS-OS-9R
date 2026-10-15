from warden import explain, features, trackers
from warden.schema import Session


def _ev(t, api, cat, arg=None, caller="com.app.Main", fg=1, **kw):
    return {"t": t, "api": api, "cat": cat, "arg": arg, "caller": caller, "fg": fg, **kw}


def test_featurize_is_deterministic_and_covers_all_keys():
    s = Session({"package": "com.app"}, [_ev(1, "x", "network", "https://api.app.com/e")])
    f1, f2 = features.featurize(s), features.featurize(s)
    assert f1 == f2
    assert set(f1) == set(features.keys())


def test_direct_ip_feature_ignores_ip_right_after_dns_of_named_host():
    m = trackers.matcher()
    ev = [_ev(0, "java.net.InetAddress.getAllByName", "network", "api.app.com"),
          _ev(5, "native.connect", "network", "203.0.113.5:443")]
    f = features.featurize(Session({"package": "com.app"}, ev), m)
    assert f["ip_host_frac"] == 0.0           # resolved via the named host, not counted as a bare-IP contact
    ev2 = [_ev(0, "native.connect", "network", "203.0.113.5:443")]   # no preceding DNS -> genuinely a bare IP
    f2 = features.featurize(Session({"package": "com.app"}, ev2), m)
    assert f2["ip_host_frac"] == 1.0


def test_sdk_attribution_flows_into_third_party_frac():
    ev = [_ev(0, "g", "identifier", "android_id", caller="com.appsflyer.AppsFlyerLib")]
    f = features.featurize(Session({"package": "com.app"}, ev))
    assert f["third_party_frac"] == 1.0
    assert f["sens_third_frac"] == 1.0


def test_sens_to_net_requires_window_and_counts_same_caller():
    ev = [_ev(0, "q", "contacts_sms", "content://sms/inbox", caller="com.x.Loader"),
          _ev(1000, "n", "network", "203.0.113.1:443", caller="com.x.Loader"),
          _ev(50000, "q", "location", None, caller="com.x.Loader")]
    f = features.featurize(Session({"package": "com.app"}, ev))
    assert f["sens_to_net"] == 0.5              # 1 of 2 sensitive events has network within window
    assert f["sens_to_net_same"] == 0.5


def test_background_sensor_flag():
    ev = [_ev(0, "m", "sensor_av", None, fg=0)]
    f = features.featurize(Session({"package": "com.app"}, ev))
    assert f["bg_sensor_av"] == 1.0
    assert f["fg_frac"] == 0.0


def test_evidence_and_reasons_flag_dynamic_code_from_writable_path():
    ev = [_ev(0, "dalvik.system.DexClassLoader.$init", "dyn_code", "/data/data/com.app/cache/p.dex", caller="com.x.Loader"),
          _ev(50, "android.content.ContentResolver.query", "contacts_sms", "content://sms/inbox", caller="com.x.Loader"),
          _ev(80, "native.connect", "network", "203.0.113.9:443", caller=None)]
    s = Session({"package": "com.app"}, ev)
    f = features.featurize(s)
    evd = explain.evidence(s)
    rs = explain.reasons(f, evd)
    assert any("writable location" in r for r in rs)
