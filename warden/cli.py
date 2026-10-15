"""warden CLI. `python3 -m warden <cmd>` or the installed `warden` entry point."""
import argparse, json, sys, time
from pathlib import Path

from . import export, labeling, model, report, trackers
from .schema import SUFFIX, dump_session, iter_session_paths, load_corpus, load_session

DEFAULT_MODEL = Path.home() / ".warden" / "warden.joblib"


def _load_corpus_or_die(path):
    sessions = load_corpus(path)
    if not sessions:
        sys.exit("no sessions found under %s (expected *%s files)" % (path, SUFFIX))
    return sessions


def cmd_devices(a):
    import frida
    for d in frida.enumerate_devices():
        print(d.id, d.type, d.name)


def cmd_apps(a):
    from . import adb
    for p in adb.Adb(a.serial).packages(third_party=not a.all):
        print(p)


def cmd_doctor(a):
    from . import doctor
    from .adb import Adb
    checks = doctor.doctor(adb=Adb(a.serial, su_style=a.su_style), serial=a.serial, server_path=a.server_path)
    print(doctor.format_checks(checks))
    sys.exit(0 if all(c["ok"] for c in checks) else 1)


def _capture_opts(a):
    return dict(seconds=a.seconds, bg_seconds=a.bg_seconds, device=a.device, remote=a.remote, serial=a.serial, profile=a.profile, spawn=not a.attach,
                exercise=a.exercise, grant=a.grant_perms, fresh=a.fresh, multiprocess=a.multiprocess)


def cmd_capture(a):
    from . import capture
    pkgs = list(a.packages)
    if a.package_file:
        pkgs += [l.strip() for l in open(a.package_file) if l.strip() and not l.startswith("#")]
    if not pkgs:
        sys.exit("pass package name(s) or --package-file")
    if a.grant_perms or a.exercise == "monkey":
        print("NOTE: --grant-perms / --exercise monkey act on the real device (the app gets real data access; random input can trigger real actions). Use a dedicated analysis device/profile.", file=sys.stderr)
    out = Path(a.out)
    if len(pkgs) == 1 and not str(a.out).endswith("/") and not out.is_dir():
        p, meta = capture.capture(pkgs[0], out, **_capture_opts(a), log=lambda *x: print(*x, file=sys.stderr))
        print(json.dumps({"path": str(p), "events": sum(1 for _ in open(p)) - 1, "errors": meta.get("errors", [])}, indent=2))
    else:
        res = capture.capture_batch(pkgs, out, **_capture_opts(a))
        print("%d/%d captured into %s" % (sum(r["ok"] for r in res), len(res), out))


def cmd_synth(a):
    from . import synth
    s = synth.make(a.n, a.sessions, seed=a.seed, outdir=a.out)
    print("%d sessions -> %s" % (len(s), a.out))


def cmd_label(a):
    sessions = _load_corpus_or_die(a.corpus)
    if a.set:
        sid, lab = a.set
        labeling.append_label(a.corpus, sid, int(lab), source="hand", note=a.note)
        print("labeled %s -> %s" % (sid, lab)); return
    lab = labeling.resolve(sessions, a.corpus)
    if a.queue:
        m = trackers.matcher()
        proba = {}
        try:
            b = model.load(a.model or DEFAULT_MODEL)
            for s in sessions:
                v = model.score(b, s, explain_on=False)
                proba[s.sid] = [v["proba"]["benign"], v["proba"]["tracker/sdk-leaky"], v["proba"]["malicious-shaped"]]
        except FileNotFoundError:
            sys.exit("no model to rank uncertainty by; train one first or pass --model")
        q = labeling.uncertainty_queue(proba, lab, n=a.queue)
        for margin, sid, p in q:
            print("%.3f margin  %-50s  [%.2f %.2f %.2f]" % (margin, sid, *p))
        return
    counts = {}
    for sid, (l, src) in lab.items():
        counts.setdefault((l, src), 0); counts[(l, src)] += 1
    print(json.dumps({"%s/%s" % (model.CLASSES[l], src): n for (l, src), n in sorted(counts.items())}, indent=2))


def cmd_weak_label(a):
    from . import explain, features
    sessions = _load_corpus_or_die(a.corpus)
    m = trackers.matcher()
    existing_labels = labeling.load_label_file(a.corpus)
    n = 0
    for s in sessions:
        existing = existing_labels.get(s.sid)
        if existing and existing[1] == "hand":
            continue
        f = features.featurize(s, m)
        evd = explain.evidence(s, m)
        lab, fired, strength = labeling.weak_label(f, evd)
        labeling.append_label(a.corpus, s.sid, lab, source="weak", note="; ".join(fired) if fired else None)
        n += 1
    print("weak-labeled %d sessions -> %s" % (n, labeling.labels_path(a.corpus)))


def cmd_train(a):
    sessions = _load_corpus_or_die(a.corpus)
    lab = labeling.resolve(sessions, a.corpus)
    if a.weak_fallback:
        from . import explain, features
        m = trackers.matcher()
        for s in sessions:
            if s.sid not in lab:
                f = features.featurize(s, m); evd = explain.evidence(s, m)
                l, _, _ = labeling.weak_label(f, evd)
                lab[s.sid] = (l, "weak")
    out = Path(a.model or DEFAULT_MODEL)
    out.parent.mkdir(parents=True, exist_ok=True)
    bundle, oof, (sids, y) = model.train(sessions, lab, seed=a.seed, n_splits=a.folds)
    model.save(bundle, out)
    if a.metrics_out:
        Path(a.metrics_out).write_text(json.dumps(bundle["metrics"], indent=2, default=str))
    print("saved model trained_at=%s id=%s -> %s" % (bundle["trained_at"], bundle["model_id"], out))


def cmd_score(a):
    b = model.load(a.model or DEFAULT_MODEL)
    m = trackers.matcher()
    targets = [a.session] if Path(a.session).is_file() else iter_session_paths(a.session)
    verdicts = []
    for p in targets:
        s = load_session(p)
        v = model.score(b, s, m)
        verdicts.append((s, v))
        out = {k: x for k, x in v.items() if not k.startswith("_")}
        print(json.dumps(out, indent=2) if a.json else "%-45s %-18s risk=%-3d alert=%-5s %s" % (s.package or s.sid, v["class"], v["risk"], v["alert"], "; ".join(v["reasons"][:2])))
    if a.report:
        if len(verdicts) == 1:
            Path(a.report).write_text(report.render(*verdicts[0]))
        else:
            report.write_corpus([s for s, v in verdicts], [v for s, v in verdicts], a.report)
        print("report -> %s" % a.report, file=sys.stderr)
    if a.export_cypher:
        Path(a.export_cypher).write_text(export.to_cypher([v for _, v in verdicts]))
    if a.webhook:
        for _, v in verdicts:
            if v["alert"] or a.webhook_all:
                export.post_webhook(a.webhook, v, token=a.webhook_token)


def cmd_evaluate(a):
    sessions = _load_corpus_or_die(a.corpus)
    lab = labeling.resolve(sessions, a.corpus)
    bundle, oof, (sids, y) = model.train(sessions, lab, seed=a.seed, n_splits=a.folds)
    print(json.dumps(bundle["metrics"], indent=2, default=str))


def cmd_replay(a):
    from . import replay as rp
    b = model.load(a.model or DEFAULT_MODEL)
    summary, verdicts = rp.replay(a.corpus, b, prev_path=a.prev, labels_root=a.corpus)
    print(json.dumps(summary, indent=2, default=str))
    if a.out:
        rp.write_verdicts(a.out, verdicts)


def cmd_trackers(a):
    if a.action == "fetch":
        p = trackers.fetch_exodus(out=a.out)
        print("fetched -> %s" % p)
    elif a.action == "import":
        n_sdk, n_host, dst = trackers.import_exodus(a.file)
        print("imported %d SDK + %d host signatures -> %s" % (n_sdk, n_host, dst))
    elif a.action == "stats":
        m = trackers.matcher(refresh=True)
        print("%d SDK signatures, %d host signatures (seed + imported, at %s)" % (len(m.sdk), len(m.hosts), trackers.user_db_path()))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="warden", description="Frida-based Android app behavior / privacy-risk classifier")
    from . import __version__
    ap.add_argument("--version", action="version", version="warden %s" % __version__)
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("devices", help="list Frida devices"); p.set_defaults(fn=cmd_devices)

    p = sp.add_parser("apps", help="list installed packages on device")
    p.add_argument("--serial"); p.add_argument("--all", action="store_true", help="include system packages")
    p.set_defaults(fn=cmd_apps)

    p = sp.add_parser("doctor", help="preflight: adb, root, frida host/server versions, Android API caveats")
    p.add_argument("--serial"); p.add_argument("--su-style", choices=["c", "0", "none"], default="c", help="how to run commands as root (none = adb root / userdebug)")
    p.add_argument("--server-path", default="/data/local/tmp/frida-server"); p.set_defaults(fn=cmd_doctor)

    p = sp.add_parser("capture", help="instrument package(s) on-device (fg phase, HOME, bg phase) and write session file(s)")
    p.add_argument("packages", nargs="*"); p.add_argument("--package-file"); p.add_argument("-o", "--out", required=True, help="session file (one package) or directory")
    p.add_argument("-s", "--seconds", type=int, default=45, help="foreground observation"); p.add_argument("--bg-seconds", type=int, default=15, help="background observation after HOME (0 disables)")
    p.add_argument("--serial", help="adb serial"); p.add_argument("--device", help="frida device id"); p.add_argument("--remote", help="frida remote host:port (after `adb forward`)")
    p.add_argument("--profile", choices=["full", "minimal", "native"], default="full", help="minimal/native reduce Java-hook surface (use if an app crashes on Android 16)")
    p.add_argument("--exercise", choices=["none", "monkey"], default="none", help="monkey = random UI input (analysis devices only)")
    p.add_argument("--grant-perms", action="store_true", help="grant declared dangerous runtime permissions before launch (analysis devices only)")
    p.add_argument("--fresh", action="store_true", help="pm clear the app first"); p.add_argument("--multiprocess", action="store_true", help="experimental: instrument the app's other processes")
    p.add_argument("--attach", action="store_true", help="attach to a running instance instead of spawning")
    p.set_defaults(fn=cmd_capture)

    p = sp.add_parser("synth", help="generate a synthetic corpus for pipeline testing (not real data)")
    p.add_argument("-n", type=int, default=60, help="apps per class"); p.add_argument("--sessions", type=int, default=3, help="sessions per app")
    p.add_argument("--seed", type=int, default=0); p.add_argument("-o", "--out", required=True)
    p.set_defaults(fn=cmd_synth)

    p = sp.add_parser("label", help="hand-label a session, list label counts, or print an uncertainty queue")
    p.add_argument("corpus"); p.add_argument("--set", nargs=2, metavar=("SID", "LABEL")); p.add_argument("--note")
    p.add_argument("--queue", type=int, metavar="N", help="print the N most uncertain unlabeled sessions"); p.add_argument("--model")
    p.set_defaults(fn=cmd_label)

    p = sp.add_parser("weak-label", help="apply bootstrap rule-based labels to unlabeled sessions")
    p.add_argument("corpus"); p.set_defaults(fn=cmd_weak_label)

    p = sp.add_parser("train", help="train+evaluate (grouped CV) and save a model bundle")
    p.add_argument("corpus"); p.add_argument("-o", "--model"); p.add_argument("--seed", type=int, default=0)
    p.add_argument("--folds", type=int, default=5); p.add_argument("--weak-fallback", action="store_true", help="weak-label any session missing a label")
    p.add_argument("--metrics-out"); p.set_defaults(fn=cmd_train)

    p = sp.add_parser("evaluate", help="cross-validate without saving a model")
    p.add_argument("corpus"); p.add_argument("--seed", type=int, default=0); p.add_argument("--folds", type=int, default=5)
    p.set_defaults(fn=cmd_evaluate)

    p = sp.add_parser("score", help="score a session or a directory of sessions")
    p.add_argument("session"); p.add_argument("-m", "--model"); p.add_argument("--json", action="store_true")
    p.add_argument("--report", metavar="PATH", help="write an HTML report (file for one session, directory for many)")
    p.add_argument("--export-cypher", metavar="PATH"); p.add_argument("--webhook"); p.add_argument("--webhook-token")
    p.add_argument("--webhook-all", action="store_true", help="post every session, not just alerts")
    p.set_defaults(fn=cmd_score)

    p = sp.add_parser("replay", help="re-score a stored corpus with the current model and diff vs previous verdicts")
    p.add_argument("corpus"); p.add_argument("-m", "--model"); p.add_argument("--prev", help="previous verdicts.jsonl")
    p.add_argument("-o", "--out", help="write new verdicts.jsonl here"); p.set_defaults(fn=cmd_replay)

    p = sp.add_parser("trackers", help="manage the Exodus tracker signature DB")
    p.add_argument("action", choices=["fetch", "import", "stats"]); p.add_argument("file", nargs="?"); p.add_argument("-o", "--out", default="exodus_trackers.json")
    p.set_defaults(fn=cmd_trackers)

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
