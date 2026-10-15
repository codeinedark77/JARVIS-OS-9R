"""Label store (labels.jsonl): hand > meta(label in session header; synthetic/imported) > weak rules. Active-learning queue."""
import json, pathlib, time
import numpy as np

RANK = {"weak": 0, "meta": 1, "hand": 2}


def labels_path(root):
    root = pathlib.Path(root)
    return (root if root.is_dir() else root.parent) / "labels.jsonl"


def append_label(root, sid, label, source="hand", note=None):
    p = labels_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps({"sid": sid, "label": int(label), "source": source, "ts": time.time(), **({"note": note} if note else {})}) + "\n")


def load_label_file(root):
    out = {}
    p = labels_path(root)
    if p.exists():
        for line in p.open():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            cur = out.get(d["sid"])
            if cur is None or RANK.get(d.get("source"), 0) >= RANK.get(cur[1], 0):
                out[d["sid"]] = (int(d["label"]), d.get("source", "weak"))
    return out


def resolve(sessions, root):
    lab = load_label_file(root) if root else {}
    for s in sessions:
        if "label" in s.meta and (s.sid not in lab or RANK["meta"] > RANK[lab[s.sid][1]]):
            lab[s.sid] = (int(s.meta["label"]), "meta")
    return lab


def weak_label(f, evd):
    """Bootstrap rules (deliberately simple; hand labels override). -> (label, fired_rules, strength)."""
    mal, fired = 0, []
    if f["dyn_writable_path"] and (f["sens_to_net_same_n"] > 0 or f["n_exec"] > 0 or f["dyn_then_sens"] > 0):
        mal += 2; fired.append("dyn-load-from-writable + sensitive/exec")
    if f["bg_contacts_sms"] and f["ip_host_frac"] > 0.3:
        mal += 2; fired.append("bg contacts/SMS + direct-IP network")
    if f["bg_sensor_av"] and (f["ip_host_frac"] > 0 or f["bg_net_n"] > 0):
        mal += 2; fired.append("bg mic/camera + network")
    if f["n_a11y"] > 0 and f["n_overlay"] > 0:
        mal += 2; fired.append("a11y + overlay")
    if f["bg_sms_call"]:
        mal += 2; fired.append("bg SMS/call")
    if f["n_exec"] > 0 and f["nonstd_port_n"] > 0:
        mal += 2; fired.append("exec + non-standard ports")
    if mal >= 2:
        return 2, fired, min(1.0, 0.4 + 0.2 * mal)
    trk = f["tracker_host_frac"] >= 0.4 or f["n_sdk_ads"] > 0 or (f["n_sdk_tracker"] > 0.7 and f["sens_third_frac"] > 0.4)
    if trk:
        return 1, ["tracker hosts/SDKs with sensitive reads"], 0.6
    return 0, [], 0.5


def uncertainty_queue(proba_by_sid, labels, n=20):
    """Margin sampling over sessions without a hand label. proba_by_sid: {sid: [p0,p1,p2]}"""
    rows = []
    for sid, p in proba_by_sid.items():
        if labels.get(sid, (None, None))[1] == "hand":
            continue
        s = sorted(p, reverse=True)
        rows.append((s[0] - s[1], sid, p))
    rows.sort()
    return rows[:n]
