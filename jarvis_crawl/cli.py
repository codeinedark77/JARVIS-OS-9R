"""CLI: python -m jarvis_crawl {run,replay,show,export,selftest}"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import tempfile
from typing import List, Optional

from .device import AdbDevice, FakeClock, JsonlTailSource, RealClock
from .export import export_dataset
from .replay import verify_episode
from .runner import RunConfig, Runner
from .safety import KillSwitch
from .schema import read_episode


def _summary(ep) -> str:
    end = ep.end or {}
    attr: dict = {}
    for s in ep.steps:
        for e in s.events:
            attr[e.attribution] = attr.get(e.attribution, 0) + 1
    kinds: dict = {}
    for s in ep.steps:
        for e in s.events:
            if e.attribution not in ("background", "idle"):
                kinds[e.event.kind] = kinds.get(e.event.kind, 0) + 1
    return json.dumps({"episode": ep.header.get("episode_id"), "reason": end.get("reason"), "steps": len(ep.steps),
                       "states": end.get("n_states"), "app_states": end.get("n_app_states"),
                       "executed_by_tier": end.get("executed_by_tier"), "denied_total": end.get("denied_total"),
                       "escalations_pending": len(end.get("escalation_queue", [])),
                       "events_by_attribution": attr, "behaviour_events": kinds,
                       "late_events": end.get("late_events")}, indent=2, sort_keys=True)


def cmd_run(a) -> int:
    cfg = RunConfig(app_pkg=a.app, out_dir=a.out, max_steps=a.steps, seed=a.seed, dry_run=a.dry_run,
                    permission_mode=a.permission_mode, policy=a.policy, settle_s=a.settle,
                    calibration_s=a.calibration, extra_allowed_pkgs=tuple(a.allow_pkg or ()))
    kill = KillSwitch(path=a.kill_file)
    if a.device == "fake":
        from .fakeapp import FakeDevice
        clock = FakeClock()
        dev = FakeDevice(clock, seed=a.seed)
        cfg.app_pkg = "com.fake.shop"
    else:
        clock = RealClock()
        dev = AdbDevice(serial=a.serial, root=a.root, events=JsonlTailSource(a.events) if a.events else None)
    res = Runner(cfg, dev, clock, kill=kill).run()
    ep = read_episode(res["episode_path"])
    print(_summary(ep))
    print("episode:", res["episode_dir"])
    return 0


def _paths(args) -> List[str]:
    out: List[str] = []
    for p in args:
        out.extend(sorted(glob.glob(os.path.join(p, "*", "episode.jsonl")))
                   if os.path.isdir(p) and not os.path.exists(os.path.join(p, "episode.jsonl")) else [p])
    return out


def cmd_replay(a) -> int:
    bad = 0
    for p in _paths(a.episodes):
        rep = verify_episode(p)
        print(p, rep.summary())
        for m in (rep.problems + rep.decision_mismatches + rep.attribution_mismatches)[:20]:
            print("   -", m)
        bad += 0 if rep.ok else 1
    return 1 if bad else 0


def cmd_show(a) -> int:
    for p in _paths(a.episodes):
        print(_summary(read_episode(p)))
    return 0


def cmd_export(a) -> int:
    m = export_dataset(_paths(a.episodes), a.out)
    print(json.dumps(m))
    return 0


def cmd_selftest(a) -> int:
    from .fakeapp import FakeDevice
    with tempfile.TemporaryDirectory(prefix="jc_selftest_") as tmp:
        clock = FakeClock()
        dev = FakeDevice(clock, seed=7)
        res = Runner(RunConfig(app_pkg="com.fake.shop", out_dir=tmp, max_steps=50, seed=7), dev, clock).run()
        rep = verify_episode(res["episode_path"], tmp_root=tmp)
        ep = read_episode(res["episode_path"])
        print(_summary(ep))
        print("verify:", rep.summary())
        export_dataset([res["episode_path"]], os.path.join(tmp, "export"))
        from .fakeapp import DANGEROUS_RIDS
        tapped = {r for _, _, r in dev.tap_log if r in DANGEROUS_RIDS}
        print("dangerous controls tapped:", sorted(tapped) or "none")
        return 0 if rep.ok and not tapped else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="jarvis_crawl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--app", default="com.fake.shop")
    r.add_argument("--device", choices=["fake", "adb"], default="fake")
    r.add_argument("--serial")
    r.add_argument("--root", action="store_true", help="wrap shell commands in su -c (rooted device)")
    r.add_argument("--events", help="JSONL file written by frida/frida_host.py")
    r.add_argument("--steps", type=int, default=50)
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--out", default="traces")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--policy", choices=["frontier", "random"], default="frontier")
    r.add_argument("--permission-mode", choices=["deny", "grant"], default="deny")
    r.add_argument("--settle", type=float, default=0.8)
    r.add_argument("--calibration", type=float, default=6.0)
    r.add_argument("--allow-pkg", action="append")
    r.add_argument("--kill-file", help="touch this path to stop the crawler before its next action")
    r.set_defaults(fn=cmd_run)
    for name, fn in (("replay", cmd_replay), ("show", cmd_show), ("export", cmd_export)):
        s = sub.add_parser(name)
        s.add_argument("episodes", nargs="+")
        if name == "export":
            s.add_argument("--out", required=True)
        s.set_defaults(fn=fn)
    t = sub.add_parser("selftest")
    t.set_defaults(fn=cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
