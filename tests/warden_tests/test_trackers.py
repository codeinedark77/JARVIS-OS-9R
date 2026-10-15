from warden import trackers


def test_sdk_prefix_attribution_longest_match_wins():
    m = trackers.matcher()
    assert m.cls("com.google.firebase.crashlytics.Init")[1] == "crash"
    assert m.cls("com.google.firebase.analytics.Foo")[1] == "analytics"
    assert m.cls("com.google.firebase.SomethingElse")[1] == "other"


def test_host_matching_ignores_ips():
    m = trackers.matcher()
    assert m.host("198.51.100.4") is None
    assert m.host("app.adjust.com") == ("Adjust", "attribution")
    assert m.host("api.myrandomapp.com") is None


def test_attribute_app_vs_sdk_vs_obfuscated_vs_unknown():
    m = trackers.matcher()
    assert trackers.attribute("com.app.ui.Main", "com.app", m)[0] == "app"
    assert trackers.attribute("com.appsflyer.AppsFlyerLib", "com.app", m)[0] == "sdk"
    assert trackers.attribute("a.b.c", "com.app", m)[0] == "obf"
    assert trackers.attribute("?", "com.app", m)[0] == "unknown"
    assert trackers.attribute("org.random.Lib", "com.app", m)[0] == "lib"


def test_first_party_host_uses_package_tokens():
    assert trackers.first_party_host("api.myspecialapp.com", "com.myspecialapp.android")
    assert not trackers.first_party_host("api.adjust.com", "com.myspecialapp.android")


def test_from_exodus_parses_literal_and_regex_signatures():
    obj = {"trackers": {"1": {"name": "Foo", "code_signature": "com\\.foo\\.sdk|com\\.foo\\.sdk\\.internal", "network_signature": "foo\\.example\\.com", "categories": ["Analytics"]}}}
    sdk, hosts = trackers.from_exodus(obj)
    assert ("com.foo.sdk", "Foo", "analytics") in sdk
    assert any(h[0] == "foo\\.example\\.com" for h in hosts)


def test_import_and_use_exodus_db(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_HOME", str(tmp_path))
    f = tmp_path / "exodus.json"
    f.write_text('{"trackers": {"1": {"name": "Zed", "code_signature": "com.zed.sdk", "network_signature": "zed\\\\.example\\\\.com", "categories": ["Advertisement"]}}}')
    n_sdk, n_host, dst = trackers.import_exodus(f)
    assert n_sdk == 1 and n_host == 1 and dst.exists()
    m = trackers.matcher(refresh=True)
    assert m.cls("com.zed.sdk.Impl")[0] == "Zed"
    assert m.host("api.zed.example.com")[0] == "Zed"
