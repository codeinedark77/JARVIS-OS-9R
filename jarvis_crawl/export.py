"""Warden-facing export: behaviour sequences + per-app feature rows from episode traces.

sequences.jsonl : per episode, ordered (screen, action, [attributed events]) -- the sequence-model view
features.jsonl  : per episode, flat feature dict -- the tabular-classifier view
Both are plain JSON; adapt field names to warden's loader on the way in (this module is the only seam).
"""
from __future__ import annotations

import json
import os
from typing import Dict, Iterable, List, Optional

from .attribution import event_signature, host_of
from .schema import A_BACKGROUND, A_IDLE, A_LAUNCH, Episode, read_episode

SENSITIVE_KINDS = ("loc.read", "contacts.query", "sms.read", "calllog.read", "calendar.read", "mic.start",
                   "cam.open", "clip.read", "ident.read", "dex.load", "exec", "wifi.read")
PERM_TO_EVENT = {"loc": ("loc.read",), "contacts": ("contacts.query",), "mic": ("mic.start",), "cam": ("cam.open",),
                 "sms": ("sms.read",), "calendar": ("calendar.read",), "calllog": ("calllog.read",),
                 "wifi": ("wifi.read",)}


def episode_sequence(ep: Episode, min_conf: float = 0.0) -> Dict:
    rows = []
    for s in ep.steps:
        rows.append({
            "idx": s.idx, "t": s.t_start,
            "screen": s.before.hash if s.before else None, "pkg": s.before.pkg if s.before else None,
            "action": s.action.key or s.action.kind, "tier": s.safety.get("tier"), "executed": s.executed,
            "permission": s.meta.get("permission"),
            "events": [{"kind": e.event.kind, "target": e.event.target, "attr": e.attribution,
                        "conf": e.confidence, "caller": _caller(e.event.stack, ep.header.get("app", ""))}
                       for e in s.events if e.confidence >= min_conf or e.attribution == A_BACKGROUND]})
    return {"episode_id": ep.header.get("episode_id"), "app": ep.header.get("app"), "steps": rows}


def _caller(stack: List[str], app: str) -> Optional[str]:
    """'app' | '<third-party package prefix>' | None -- first frame outside the framework."""
    own = ".".join(app.split(".")[:3])
    for fr in stack:
        if fr.startswith(("android.", "java.", "javax.", "dalvik.", "libcore.", "com.android.", "androidx.")):
            continue
        return "app" if own and fr.startswith(own) else ".".join(fr.split(".")[:3])
    return None


def episode_features(ep: Episode, conf_floor: float = 0.5) -> Dict:
    app = ep.header.get("app", "")
    f: Dict = {"episode_id": ep.header.get("episode_id"), "app": app, "n_steps": len(ep.steps),
               "n_states": (ep.end or {}).get("n_app_states"), "seed": ep.header.get("seed")}
    direct: Dict[str, int] = {}
    background: Dict[str, int] = {}
    launch: Dict[str, int] = {}
    hosts, hosts_bg = set(), set()
    callers: Dict[str, int] = {}
    t_launch = ep.steps[0].t_start if ep.steps else 0.0
    first_net = None
    all_events = []
    denies = []
    for s in ep.steps:
        perm = s.meta.get("permission")
        if perm and perm.get("choice") == "deny" and s.executed:
            denies.append((perm.get("kind"), s.t_end))
        for e in s.events:
            ev = e.event
            all_events.append(ev)
            if e.attribution == A_BACKGROUND:
                background[ev.kind] = background.get(ev.kind, 0) + 1
                if ev.kind.startswith("net."):
                    hosts_bg.add(host_of(ev.target))
                continue
            if e.attribution == A_IDLE or e.confidence < conf_floor:
                continue
            bucket = launch if e.attribution == A_LAUNCH else direct
            bucket[ev.kind] = bucket.get(ev.kind, 0) + 1
            if ev.kind.startswith("net."):
                h = host_of(ev.target)
                hosts.add(h)
                if first_net is None:
                    first_net = ev.t - t_launch
            c = _caller(ev.stack, app)
            if c:
                callers[c] = callers.get(c, 0) + 1
    f["direct_event_counts"] = dict(sorted(direct.items()))
    f["launch_event_counts"] = dict(sorted(launch.items()))
    f["background_event_counts"] = dict(sorted(background.items()))
    f["n_hosts"] = len(hosts)
    f["hosts"] = sorted(hosts)
    f["background_hosts"] = sorted(hosts_bg)
    f["time_to_first_net_s"] = None if first_net is None else round(first_net, 3)
    f["sensitive_kinds_seen"] = sorted({k for k in list(direct) + list(launch) + list(background) if k in SENSITIVE_KINDS})
    f["caller_counts"] = dict(sorted(callers.items()))
    f["third_party_caller_share"] = round(
        sum(v for k, v in callers.items() if k != "app") / max(1, sum(callers.values())), 4)
    # strongest privacy signal: a resource read AFTER the user-level denial of that permission
    after_deny = 0
    detail: List[Dict] = []
    for kind, t_deny in denies:
        for ev in all_events:
            if ev.t > t_deny and ev.kind in PERM_TO_EVENT.get(kind or "", ()):
                after_deny += 1
                detail.append({"perm": kind, "event": ev.kind, "dt": round(ev.t - t_deny, 3),
                               "caller": _caller(ev.stack, app)})
    f["sensitive_after_deny"] = after_deny
    f["sensitive_after_deny_detail"] = detail[:10]
    f["denied_actions"] = (ep.end or {}).get("denied_total")
    f["escalations_pending"] = len((ep.end or {}).get("escalation_queue", []))
    return f


def export_dataset(episode_paths: Iterable[str], out_dir: str) -> Dict:
    os.makedirs(out_dir, exist_ok=True)
    n = 0
    with open(os.path.join(out_dir, "sequences.jsonl"), "w", encoding="utf-8") as fs, \
         open(os.path.join(out_dir, "features.jsonl"), "w", encoding="utf-8") as ff:
        for p in episode_paths:
            ep = read_episode(p)
            fs.write(json.dumps(episode_sequence(ep), sort_keys=True) + "\n")
            ff.write(json.dumps(episode_features(ep), sort_keys=True) + "\n")
            n += 1
    manifest = {"episodes": n, "files": ["sequences.jsonl", "features.jsonl"]}
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest
