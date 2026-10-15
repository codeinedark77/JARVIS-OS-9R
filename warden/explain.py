"""Evidence extraction, rule reasons, and occlusion-based attribution."""
import re
from collections import Counter, defaultdict
from bisect import bisect_left, bisect_right

import numpy as np

from . import manifest, trackers
from .features import GROUP, WINDOW_MS, _host_port, FRIDA, SU, WRITABLE
from .schema import SENSITIVE


def evidence(sess, m=None):
    m = m or trackers.matcher()
    pkg = sess.package
    ev = [e for e in sess.events if e["cat"] not in ("traffic", "lifecycle")]
    ctr = Counter(e["cat"] for e in ev)
    hosts = defaultdict(int)
    for e in ev:
        if e["cat"] == "network":
            h, _, _ = _host_port(e["api"], e["cat"], e["arg"])
            if h:
                hosts[h] += 1
    host_rows = []
    for h, n in sorted(hosts.items(), key=lambda kv: -kv[1]):
        hit = m.host(h)
        host_rows.append({"host": h, "n": n, "ip": trackers.is_ip(h), "tracker": bool(hit), "name": hit[0] if hit else None, "kind": hit[1] if hit else None,
                          "first_party": trackers.first_party_host(h, pkg)})
    sdk = defaultdict(lambda: {"n": 0, "cats": Counter(), "kind": None})
    for e in ev:
        ow, name, kind = trackers.attribute(e["caller"], pkg, m)
        if ow in ("sdk", "lib"):
            d = sdk[name]; d["n"] += 1; d["kind"] = kind; d["cats"][e["cat"]] += 1
    sdk_rows = [{"name": k, "kind": v["kind"], "n": v["n"], "cats": dict(v["cats"])} for k, v in sorted(sdk.items(), key=lambda kv: -kv[1]["n"])]
    net = [e for e in ev if e["cat"] == "network"]
    net_t = [e["t"] for e in net]
    chains = []
    for s in ev:
        if s["cat"] not in SENSITIVE:
            continue
        i, j = bisect_left(net_t, s["t"]), bisect_right(net_t, s["t"] + WINDOW_MS)
        for k in range(i, min(j, i + 3)):
            n = net[k]
            h, _, _ = _host_port(n["api"], n["cat"], n["arg"])
            chains.append({"t": s["t"], "sens": s["api"].rsplit(".", 2)[-2] + "." + s["api"].rsplit(".", 1)[-1], "cat": s["cat"], "caller": s["caller"], "host": h or n["arg"],
                           "dt": n["t"] - s["t"], "same_caller": s["caller"] != "?" and s["caller"] == n["caller"], "fg": s["fg"]})
            break
    chains.sort(key=lambda c: (not c["same_caller"], not (c["caller"] != "?" and not c["caller"].startswith(pkg)), c["dt"]))
    dyn = [{"api": e["api"], "arg": e["arg"], "caller": e["caller"], "t": e["t"]} for e in ev if e["cat"] in ("dyn_code",)]
    execs = [{"arg": e["arg"], "caller": e["caller"]} for e in ev if e["cat"] == "exec"]
    env = sorted({e["arg"] for e in ev if e["cat"] == "env_probe" and e["arg"]})[:12]
    bg = Counter((e["cat"], e["caller"]) for e in ev if not e["fg"] and e["cat"] in SENSITIVE)
    traffic = sess.events and [e for e in sess.events if e["cat"] == "traffic"] or []
    return {"counts": dict(ctr), "hosts": host_rows, "sdks": sdk_rows, "chains": chains[:8], "dyn": dyn[:6], "exec": execs[:6], "env": env,
            "bg_sens": [{"cat": c, "caller": k, "n": n} for (c, k), n in bg.most_common(8)],
            "perms": manifest.declared_vs_observed(sess.meta.get("perms"), ctr),
            "tls_bytes": sum(e.get("n", 0) for e in traffic if e["arg"] == "tls"), "raw_bytes": sum(e.get("n", 0) for e in traffic if e["arg"] == "raw"),
            "fg_frac": (sum(1 for e in ev if e["fg"]) / max(len(ev), 1))}


def reasons(f, evd):
    r = []
    ip_ports = [h for h in evd["hosts"] if h["ip"]]
    for d in evd["dyn"]:
        if d["arg"] and WRITABLE.match(d["arg"]):
            r.append("loads code from writable location (%s) via %s" % (d["arg"], d["caller"])); break
    same = [c for c in evd["chains"] if c["same_caller"] and c["caller"] != "?"]
    if same:
        c = same[0]
        r.append("%s read %s then contacted %s within %d ms (same caller)" % (c["caller"], c["cat"], c["host"], c["dt"]))
    if f.get("bg_sensor_av"):
        r.append("microphone/camera access while app in background")
    if f.get("bg_contacts_sms"):
        r.append("contacts/SMS/call-log reads while app in background")
    if f.get("bg_location") and f.get("bg_net_n", 0) > 0:
        r.append("background location access with background network activity")
    if f.get("n_a11y", 0) > 0 and f.get("n_overlay", 0) > 0:
        r.append("accessibility-service APIs and screen overlays used together")
    if f.get("bg_sms_call"):
        r.append("sends SMS / places calls while in background")
    if evd["exec"]:
        r.append("shell execution: %s" % evd["exec"][0]["arg"])
    if len(ip_ports) >= 1 and f.get("ip_host_frac", 0) > 0.3:
        r.append("direct-to-IP connections (%d) instead of named hosts" % len(ip_ports))
    if f.get("nonstd_port_n", 0) > 0:
        r.append("connections on non-standard ports")
    trk = [h for h in evd["hosts"] if h["tracker"]]
    if len(trk) >= 2 or f.get("tracker_host_frac", 0) >= 0.4:
        r.append("%d tracker/ad hosts (%s)" % (len(trk), ", ".join(sorted({h["name"] for h in trk})[:5])))
    sdk_sens = [s for s in evd["sdks"] if any(c in SENSITIVE for c in s["cats"])]
    if sdk_sens:
        r.append("sensitive reads by third-party code: %s" % ", ".join("%s(%s)" % (s["name"], s["kind"]) for s in sdk_sens[:4]))
    if f.get("cleartext_http_frac", 0) > 0.3:
        r.append("cleartext HTTP requests")
    if f.get("frida_probe") or f.get("env_su_probe") or f.get("emu_probe") or f.get("native_ptrace"):
        r.append("probes for root/emulator/instrumentation (informational; app may behave differently when watched)")
    return r


def group_occlusion(bundle, vec, predict):
    """Replace each feature group with benign medians; delta = drop in probability of the predicted class."""
    keys, med = bundle["keys"], bundle["median"]
    base = predict(vec)
    cls = int(np.argmax(base))
    groups = defaultdict(list)
    for i, k in enumerate(keys):
        groups[GROUP.get(k, "misc")].append(i)
    out = []
    for g, idx in groups.items():
        v = vec.copy()
        v[idx] = med[idx]
        d = float(base[cls] - predict(v)[cls])
        out.append((g, d))
    out.sort(key=lambda x: -abs(x[1]))
    return cls, out


def feature_occlusion(bundle, vec, predict, groups, top=6):
    keys, med = bundle["keys"], bundle["median"]
    base = predict(vec)
    cls = int(np.argmax(base))
    res = []
    for i, k in enumerate(keys):
        if GROUP.get(k) in groups and vec[i] != med[i]:
            v = vec.copy(); v[i] = med[i]
            res.append((k, float(vec[i]), float(base[cls] - predict(v)[cls])))
    res.sort(key=lambda x: -abs(x[2]))
    return res[:top]
