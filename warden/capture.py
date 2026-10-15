"""Host side: run the agent against a package over adb+Frida, write a schema-2 JSONL session.
Phases: launch+observe (foreground, optional exerciser) -> HOME -> observe (background) -> flush/stats -> detach.
The background phase is what makes the bg_* features meaningful; sessions without it look permanently foreground.
Defaults are conservative: no random input, no permission grants (both act on the real device)."""
import json, threading, time
from pathlib import Path

from . import adb as adbmod
from .agentsrc import load_source
from .schema import dump_session


def get_device(frida, device=None, remote=None):
    if remote:
        return frida.get_device_manager().add_remote_device(remote)
    return frida.get_device(device) if device else frida.get_usb_device(timeout=5)


def frida_server_check(frida, device=None, remote=None):
    try:
        dev = get_device(frida, device, remote)
    except Exception as e:
        return None, "no device: %s" % e
    try:
        dev.enumerate_processes()
    except Exception as e:
        return dev, "frida-server not responding (%s). Run `warden doctor`." % e
    return dev, None


def capture(package, out, seconds=45, bg_seconds=15, device=None, remote=None, serial=None, spawn=True, profile="full", native=True, tls=True,
            exercise="none", grant=False, fresh=False, multiprocess=False, max_per_api=2500, max_total=50000, agent=None,
            on_event=None, adb=None, frida_mod=None, sleep=time.sleep, log=lambda *a: None):
    frida = frida_mod or __import__("frida")
    adb = adb or adbmod.Adb(serial or device)
    dev, err = frida_server_check(frida, device, remote)
    if err:
        raise RuntimeError(err)
    src = load_source(agent=agent)
    if spawn:
        adb.force_stop(package)
        if fresh:
            adb.clear(package)
    perms = adb.permissions(package)
    granted = adb.grant(package, perms["declared"]) if (grant and perms) else []
    cfg = {"profile": profile, "native": native, "tls": tls, "max_per_api": max_per_api, "max_total": max_total}
    events, meta_extra, errors, attached = [], {}, [], []

    def make_handler(tag_pid):
        def on_msg(m, _data):
            if m["type"] != "send":
                if m["type"] == "error":
                    errors.append(m.get("description", str(m)))
                return
            p = m["payload"]
            if p["type"] == "batch":
                for e in p["events"]:
                    if tag_pid:
                        e["p"] = p.get("pid")
                    events.append(e)
                    if on_event:
                        on_event(e)
            elif p["type"] == "meta":
                meta_extra.setdefault("agent_meta", {})[str(p.get("pid"))] = p
            elif p["type"] == "hooks":
                meta_extra.setdefault("hooks", {})[str(p.get("pid"))] = p["hooks"]
            elif p["type"] == "error":
                errors.append("%s: %s" % (p.get("where"), p.get("msg")))
        return on_msg

    def instrument(pid):
        s = dev.attach(pid)
        sc = s.create_script(src)
        sc.on("message", make_handler(multiprocess))
        sc.load()
        sc.exports_sync.start(cfg)
        attached.append((s, sc))
        return s, sc

    try:
        pid = dev.spawn([package]) if spawn else dev.get_process(package).pid
    except Exception as e:
        raise RuntimeError("could not %s %s: %s" % ("spawn" if spawn else "find", package, e))
    if multiprocess:     # experimental: also instrument the app's other processes (':push', ':remote', ...)
        def on_spawn(spawn_info):
            try:
                if (spawn_info.identifier or "").split(":")[0] == package:
                    instrument(spawn_info.pid)
            finally:
                dev.resume(spawn_info.pid)       # never leave anything gated: gating pauses every new process on the device
        dev.on("spawn_added", on_spawn)
        dev.enable_spawn_gating()
    main_session, main_script = instrument(pid)
    t_start = time.time()
    dev.resume(pid) if spawn else None
    ex_thread = None
    try:
        if exercise == "monkey":
            ex_thread = threading.Thread(target=adb.monkey, args=(package, seconds), daemon=True)
            ex_thread.start()
        sleep(seconds)
        if bg_seconds:
            adb.home()
            sleep(bg_seconds)
        stats = {}
        for s, sc in attached:
            try:
                sc.exports_sync.flush()
                stats[str(getattr(s, "pid", ""))] = sc.exports_sync.stats()
            except Exception as e:
                stats["err"] = str(e)
        sleep(0.2)
    finally:
        if multiprocess:
            try:
                dev.disable_spawn_gating()
                for sp in dev.enumerate_pending_spawn():
                    dev.resume(sp.pid)
            except Exception:
                pass
        for s, _ in attached:
            try:
                s.detach()
            except Exception:
                pass
        if spawn:
            adb.force_stop(package)
    only = next(iter(stats.values()), None) if len(stats) == 1 else None
    meta = {"package": package, "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "duration_s": round(time.time() - t_start, 1), "phases": {"fg_s": seconds, "bg_s": bg_seconds},
            "exerciser": exercise, "granted": granted, "device": adb.device_info(), "frida": frida.__version__, "profile": profile, "perms": perms,
            "stats": only or stats, "errors": errors[:20], **meta_extra}
    out = Path(out)
    dump_session(out, meta, events)
    return out, meta


def capture_batch(packages, outdir, log=print, resume=True, **kw):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    results = []
    for i, pkg in enumerate(packages, 1):
        path = outdir / ("%s.session.jsonl" % pkg)
        if resume and path.exists():
            log("[%d/%d] %s: exists, skipping" % (i, len(packages), pkg))
            results.append({"package": pkg, "ok": True, "path": str(path), "skipped": True}); continue
        log("[%d/%d] %s" % (i, len(packages), pkg))
        try:
            p, meta = capture(pkg, path, log=log, **kw)
            n = sum(1 for _ in open(p)) - 1
            log("  -> %d events, %d agent errors" % (n, len(meta.get("errors", []))))
            results.append({"package": pkg, "ok": True, "path": str(p), "events": n})
        except Exception as e:
            log("  FAILED: %s" % e)
            results.append({"package": pkg, "ok": False, "error": str(e)})
        with open(outdir / "batch_log.jsonl", "a") as f:
            f.write(json.dumps(results[-1]) + "\n")
        time.sleep(1.5)
    return results
