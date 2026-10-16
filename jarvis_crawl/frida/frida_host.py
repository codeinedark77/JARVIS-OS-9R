#!/usr/bin/env python3
"""Spawn-gating Frida host for jarvis_crawl (runs on the PC; frida-server runs as root on the device).

  pip install frida frida-tools
  python frida_host.py --pkg com.example.app --out events.jsonl [--serial SERIAL]
  python -m jarvis_crawl run --device adb --root --app com.example.app --events events.jsonl ...

Start this BEFORE the crawler: the runner force-stops and relaunches the app (also on every relaunch
mid-episode), and spawn gating attaches the agent to each fresh process before it resumes.
Events are stamped with host time.time() on receipt -- same clock domain as the runner's action times.
UNTESTED against hardware in this build.
"""
import argparse
import json
import os
import sys
import threading
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--serial")
    ap.add_argument("--agent", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.js"))
    args = ap.parse_args()

    import frida  # imported late so the rest of the repo needs no third-party deps

    dev = frida.get_device(args.serial, timeout=10) if args.serial else frida.get_usb_device(timeout=10)
    source = open(args.agent, "r", encoding="utf-8").read()
    out = open(args.out, "a", buffering=1, encoding="utf-8")
    lock = threading.Lock()
    keep = {}

    def write(rec):
        with lock:
            out.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def make_handler(pid):
        def on_message(msg, _data):
            if msg["type"] == "send":
                p = msg["payload"]
                if p.get("type") == "hook_event":
                    ev = p["event"]
                    detail = dict(ev.get("detail") or {})
                    detail.update(pid=pid, t_dev=ev.get("t_dev"))
                    write({"t": time.time(), "kind": ev.get("kind", ""), "target": ev.get("target", ""),
                           "api": ev.get("api", ""), "pkg": args.pkg, "tid": ev.get("tid", 0),
                           "stack": ev.get("stack", []), "detail": detail})
                elif p.get("type") == "agent_ready":
                    sys.stderr.write(f"[agent pid={pid}] hooks={len(p.get('installed', []))} "
                                     f"missing={len(p.get('missing', []))}\n")
            elif msg["type"] == "error":
                sys.stderr.write(f"[agent pid={pid}] {msg.get('stack') or msg}\n")
        return on_message

    def on_spawn_added(spawn):
        try:
            if spawn.identifier == args.pkg:
                session = dev.attach(spawn.pid)
                script = session.create_script(source)
                script.on("message", make_handler(spawn.pid))
                script.load()
                keep[spawn.pid] = (session, script)
        except Exception as e:  # never leave a process suspended
            sys.stderr.write(f"[host] attach failed for pid {spawn.pid}: {e}\n")
        finally:
            dev.resume(spawn.pid)

    dev.on("spawn-added", on_spawn_added)
    dev.enable_spawn_gating()
    sys.stderr.write(f"[host] spawn gating on for {args.pkg}; writing {args.out}\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
