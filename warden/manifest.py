"""Permission parsing from `adb shell dumpsys package <pkg>` + risk tables."""
import re

DANGEROUS = {
    "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "ANSWER_PHONE_CALLS", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "BODY_SENSORS", "ACTIVITY_RECOGNITION", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO", "POST_NOTIFICATIONS", "NEARBY_WIFI_DEVICES", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN",
}
HIGH_RISK = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES",
    "QUERY_ALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE", "BIND_DEVICE_ADMIN", "ACCESS_BACKGROUND_LOCATION", "READ_PHONE_NUMBERS",
    "REQUEST_DELETE_PACKAGES", "WRITE_SETTINGS", "RECEIVE_BOOT_COMPLETED", "USE_FULL_SCREEN_INTENT", "BIND_NOTIFICATION_LISTENER_SERVICE",
}
# permission -> behavior category that exercises it (used for declared-vs-observed)
PERM_CAT = {
    "READ_SMS": "contacts_sms", "RECEIVE_SMS": "contacts_sms", "READ_CONTACTS": "contacts_sms", "READ_CALL_LOG": "contacts_sms", "READ_CALENDAR": "contacts_sms",
    "RECORD_AUDIO": "sensor_av", "CAMERA": "sensor_av", "ACCESS_FINE_LOCATION": "location", "ACCESS_COARSE_LOCATION": "location",
    "ACCESS_BACKGROUND_LOCATION": "location", "READ_PHONE_STATE": "identifier", "READ_PHONE_NUMBERS": "identifier", "GET_ACCOUNTS": "identifier",
    "QUERY_ALL_PACKAGES": "pkg_enum", "SEND_SMS": "sms_call", "CALL_PHONE": "sms_call", "SYSTEM_ALERT_WINDOW": "overlay",
    "BIND_ACCESSIBILITY_SERVICE": "a11y", "REQUEST_INSTALL_PACKAGES": "dyn_code",
}


def short(p):
    return p.rsplit(".", 1)[-1]


def parse_dumpsys(text, package=None):
    """-> {'declared': [short names], 'granted': [short names], 'version': str|None}. Tolerates format drift across Android versions."""
    declared, granted, version = [], [], None
    sect = None
    in_pkg = package is None
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if package and s.startswith("Package [") and "]" in s:
            in_pkg = s.startswith("Package [%s]" % package)
            sect = None
            continue
        if not in_pkg:
            continue
        if s.startswith("versionName="):
            version = s.split("=", 1)[1].strip()
        if s == "requested permissions:":
            sect = "req"; continue
        if s in ("install permissions:", "runtime permissions:"):
            sect = "grant"; continue
        if s.endswith(":") and not s.startswith(("android.permission", "com.", "org.")) and not s.endswith("permissions:"):
            if sect in ("req",) and not re.match(r"^[\w.]+(:.*)?$", s):
                sect = None
        m = re.match(r"^([A-Za-z0-9_.]+\.[A-Za-z0-9_]+)(?::\s*(.*))?$", s)
        if sect == "req" and m and ("permission" in m.group(1).lower() or m.group(1).count(".") >= 2):
            declared.append(short(m.group(1)))
        elif sect == "grant" and m and m.group(2) and "granted=true" in m.group(2):
            granted.append(short(m.group(1)))
        elif sect and not s:
            sect = None
    return {"declared": sorted(set(declared)), "granted": sorted(set(granted)), "version": version}


def perm_summary(perms):
    d = set((perms or {}).get("declared", []))
    return {"dangerous": sorted(d & DANGEROUS), "high_risk": sorted(d & HIGH_RISK)}


def declared_vs_observed(perms, cat_counts):
    out = []
    for p in sorted(set((perms or {}).get("declared", [])) & set(PERM_CAT)):
        c = PERM_CAT[p]
        out.append({"perm": p, "cat": c, "observed": cat_counts.get(c, 0) > 0})
    return out
