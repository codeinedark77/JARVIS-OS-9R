from warden import manifest

DUMP = """Packages:
  Package [com.example.app] (abc):
    versionName=1.2.3
    requested permissions:
      android.permission.INTERNET
      android.permission.READ_CONTACTS
      android.permission.SYSTEM_ALERT_WINDOW: restricted=false
    install permissions:
      android.permission.INTERNET: granted=true
    User 0:
      runtime permissions:
        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET]
  Package [com.other.app] (def):
    requested permissions:
      android.permission.CAMERA
"""


def test_parse_dumpsys_scopes_to_package():
    r = manifest.parse_dumpsys(DUMP, "com.example.app")
    assert r["declared"] == ["INTERNET", "READ_CONTACTS", "SYSTEM_ALERT_WINDOW"]
    assert r["granted"] == ["INTERNET", "READ_CONTACTS"]
    assert r["version"] == "1.2.3"
    assert "CAMERA" not in r["declared"]


def test_perm_summary_and_declared_vs_observed():
    perms = {"declared": ["READ_SMS", "INTERNET", "SYSTEM_ALERT_WINDOW"]}
    summ = manifest.perm_summary(perms)
    assert "READ_SMS" in summ["dangerous"] and "READ_SMS" in summ["high_risk"]
    dvo = manifest.declared_vs_observed(perms, {"contacts_sms": 0})
    row = next(r for r in dvo if r["perm"] == "READ_SMS")
    assert row["observed"] is False
