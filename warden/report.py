"""Self-contained HTML reports (no external assets): per-session page with SVG timeline + corpus index."""
import html, json, pathlib
from . import trackers
from .schema import CATS, AUX

CSS = """
:root{--bg:#fff;--fg:#14171a;--mut:#667;--card:#f5f6f8;--line:#d9dde3;--ok:#1a7f4b;--warn:#b7791f;--bad:#c53030;--dot-fg:#2b6cb0;--dot-bg:#d69e2e;--shade:rgba(120,120,140,.12)}
@media (prefers-color-scheme:dark){:root{--bg:#101215;--fg:#e6e8eb;--mut:#98a;--card:#1a1d22;--line:#2b3037;--ok:#48bb78;--warn:#ecc94b;--bad:#fc8181;--dot-fg:#63b3ed;--dot-bg:#f6ad55;--shade:rgba(160,160,190,.10)}}
*{box-sizing:border-box}body{margin:0;padding:20px;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;max-width:1040px;margin:auto}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:22px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.mut{color:var(--mut)}.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:600;color:#fff}
.b0{background:var(--ok)}.b1{background:var(--warn)}.b2{background:var(--bad)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:8px 0}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
.bar{height:8px;border-radius:4px;background:var(--line);overflow:hidden}.bar>i{display:block;height:100%}
code{font:12px ui-monospace,monospace;word-break:break-all}.warn{border-left:4px solid var(--warn)}.crit{border-left:4px solid var(--bad)}
svg{width:100%;height:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}svg text{fill:var(--fg);font:11px system-ui}
.dfg{fill:var(--dot-fg)}.dbg{fill:var(--dot-bg)}.ext{stroke:var(--bad);stroke-width:1.6}.shade{fill:var(--shade)}
a{color:var(--dot-fg)}
"""
E = html.escape


def _bar(p, cls):
    col = ["var(--ok)", "var(--warn)", "var(--bad)"][cls]
    return '<div class="bar"><i style="width:%d%%;background:%s"></i></div>' % (round(100 * p), col)


def timeline_svg(sess, m=None):
    m = m or trackers.matcher()
    pkg = sess.package
    ev = [e for e in sess.events if e["cat"] not in AUX]
    if not ev:
        return "<p class=mut>no events</p>"
    lanes = [c for c in CATS if any(e["cat"] == c for e in ev)]
    W, L, R, TOP, LH = 1000, 118, 16, 8, 22
    H = TOP + LH * len(lanes) + 26
    tmax = max(e["t"] for e in sess.events) or 1
    x = lambda t: L + (W - L - R) * t / tmax
    parts = ['<svg viewBox="0 0 %d %d" role="img" aria-label="event timeline">' % (W, H)]
    segs, cur, start = [], 1, None          # background (fg=0) shading
    for e in sorted(sess.events, key=lambda e: e["t"]):
        if e["fg"] == 0 and cur == 1:
            start, cur = e["t"], 0
        elif e["fg"] == 1 and cur == 0:
            segs.append((start, e["t"])); cur = 1
    if cur == 0:
        segs.append((start, tmax))
    for a, b in segs:
        parts.append('<rect class="shade" x="%.1f" y="%d" width="%.1f" height="%d"/>' % (x(a), TOP, max(1, x(b) - x(a)), LH * len(lanes)))
    for i, c in enumerate(lanes):
        y = TOP + LH * i + LH / 2
        parts.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--line)"/><text x="4" y="%.1f">%s</text>' % (L, W - R, y, y, y + 4, E(c)))
        pts = [e for e in ev if e["cat"] == c]
        step = max(1, len(pts) // 500)
        for e in pts[::step]:
            ow = trackers.attribute(e["caller"], pkg, m)[0]
            cls = "dfg" if e["fg"] else "dbg"
            ext = " ext" if ow in ("sdk", "lib") else ""
            tip = "%.2fs  %s  %s  <- %s" % (e["t"] / 1000, e["api"].rsplit(".", 2)[-2:] and ".".join(e["api"].rsplit(".", 2)[-2:]), e["arg"] or "", e["caller"])
            parts.append('<circle class="%s%s" cx="%.1f" cy="%.1f" r="3.2" fill="%s"><title>%s</title></circle>' % (cls, ext, x(e["t"]), y, "currentColor" if False else "", E(tip)))
    ay = TOP + LH * len(lanes) + 14
    for k in range(0, 6):
        t = tmax * k / 5
        parts.append('<text x="%.1f" y="%d" text-anchor="middle">%.0fs</text>' % (x(t), ay, t / 1000))
    parts.append("</svg>")
    return "".join(parts).replace(' fill=""', "")


def _tbl(head, rows):
    if not rows:
        return "<p class=mut>none observed</p>"
    return "<table><tr>%s</tr>%s</table>" % ("".join("<th>%s</th>" % E(h) for h in head), "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in r) for r in rows))


def render(sess, v):
    evd = v.get("_evidence") or {}
    st = sess.meta.get("stats") or {}
    hooks = st.get("hooks") or {}
    warn = []
    if sess.meta.get("synthetic"):
        warn.append("Synthetic session (generated); verdict demonstrates the pipeline, not a real app.")
    if st and not st.get("java", True):
        warn.append("Java hooks were not active: verdict is based on the native layer only.")
    if hooks.get("fail") or hooks.get("failed"):
        warn.append("%d Java hooks failed to install (%s)" % (hooks.get("fail", 0), E(", ".join(hooks.get("failed", [])[:6]))))
    if st.get("dropped"):
        warn.append("events dropped by rate caps: %s" % E(json.dumps(st["dropped"])[:160]))
    if evd.get("env"):
        warn.append("app probed for root/instrumentation: observation may have changed its behavior")
    cls = v["class_id"]
    h = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>warden - %s</title><style>%s</style></head><body>' % (E(sess.package or sess.sid), CSS)]
    h.append('<h1>%s <span class="badge b%d">%s</span> %s%s</h1>' % (E(sess.package or sess.sid), cls, E(v["class"]), "<span class='badge b2'>ALERT</span> " if v["alert"] else "", "<span class='badge b1'>NOVEL</span>" if v["novel"] else ""))
    meta = [("session", sess.sid), ("model", v["model_id"]), ("device", (sess.meta.get("device") or {}).get("model")), ("android", (sess.meta.get("device") or {}).get("api")),
            ("frida", sess.meta.get("frida")), ("profile", sess.meta.get("profile")), ("events", len(sess.events))]
    h.append('<div class="mut">%s</div>' % " &middot; ".join("%s: %s" % (k, E(str(x))) for k, x in meta if x is not None))
    h.append('<div class="card"><b>risk %d / 100</b><div class="bar"><i style="width:%d%%;background:var(--bad)"></i></div>' % (v["risk"], v["risk"]))
    for i, name in enumerate(["benign", "tracker/sdk-leaky", "malicious-shaped"]):
        p = v["proba"][name]
        h.append('<div style="display:flex;gap:10px;align-items:center;margin-top:6px"><span style="width:150px">%s</span><div style="flex:1">%s</div><span style="width:46px;text-align:right">%.0f%%</span></div>' % (E(name), _bar(p, i), 100 * p))
    h.append("</div>")
    for w in warn:
        h.append('<div class="card warn">%s</div>' % w)
    h.append("<h2>Why</h2>")
    if v.get("reasons"):
        h.append("<ul>%s</ul>" % "".join("<li>%s</li>" % E(r) for r in v["reasons"]))
    else:
        h.append("<p class=mut>no rule-level findings</p>")
    if v.get("top_groups"):
        h.append('<p class="mut">model attribution (drop in P(%s) when the group is set to benign-median): %s</p>' % (E(v["class"]), ", ".join("%s %+.2f" % (E(g), d) for g, d in v["top_groups"])))
    h.append("<h2>Timeline</h2>" + timeline_svg(sess) + '<p class="mut">shaded = app in background &middot; red ring = third-party / SDK caller &middot; hover for API, argument, caller</p>')
    h.append("<h2>Third-party code</h2>" + _tbl(["SDK / library", "kind", "events", "categories"], [[E(s["name"]), E(s["kind"] or ""), s["n"], E(", ".join("%s&times;%d" % kv for kv in s["cats"].items()))] for s in evd.get("sdks", [])[:15]]))
    h.append("<h2>Hosts</h2>" + _tbl(["host", "events", "class"], [[ "<code>%s</code>" % E(r["host"]), r["n"], E(("tracker: %s (%s)" % (r["name"], r["kind"])) if r["tracker"] else ("direct IP" if r["ip"] else ("first-party" if r["first_party"] else "other")))] for r in evd.get("hosts", [])[:20]]))
    h.append("<h2>Sensitive read &rarr; network (within 3 s)</h2>" + _tbl(["t", "read", "caller", "host", "dt", "same caller", "fg"], [["%.1fs" % (c["t"] / 1000), E(c["sens"]), "<code>%s</code>" % E(c["caller"]), "<code>%s</code>" % E(str(c["host"])), "%d ms" % c["dt"], "yes" if c["same_caller"] else "", "fg" if c["fg"] else "bg"] for c in evd.get("chains", [])]))
    h.append("<h2>Background sensitive access</h2>" + _tbl(["category", "caller", "n"], [[E(b["cat"]), "<code>%s</code>" % E(b["caller"]), b["n"]] for b in evd.get("bg_sens", [])]))
    h.append("<h2>Code loading / exec / probes</h2>" + _tbl(["kind", "detail", "caller"], [["dyn", "<code>%s</code>" % E(str(d["arg"])), "<code>%s</code>" % E(d["caller"])] for d in evd.get("dyn", [])] + [["exec", "<code>%s</code>" % E(str(d["arg"])), "<code>%s</code>" % E(d["caller"])] for d in evd.get("exec", [])] + [["probe", "<code>%s</code>" % E(a), ""] for a in evd.get("env", [])]))
    h.append("<h2>Permissions: declared vs observed</h2>" + _tbl(["permission", "behavior", "observed"], [[E(p["perm"]), E(p["cat"]), "yes" if p["observed"] else "<span class=mut>not seen</span>"] for p in evd.get("perms", [])]))
    h.append('<p class="mut">traffic: %d B TLS plaintext written, %d B raw sends &middot; foreground share of events %.0f%%</p>' % (evd.get("tls_bytes", 0), evd.get("raw_bytes", 0), 100 * evd.get("fg_frac", 0)))
    h.append("</body></html>")
    return "".join(h)


def write_corpus(sessions, verdicts, out_dir):
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for s, v in sorted(zip(sessions, verdicts), key=lambda sv: -sv[1]["risk"]):
        fn = "%s.html" % "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in s.sid)
        (out / fn).write_text(render(s, v))
        rows.append((s, v, fn))
    h = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>warden corpus</title><style>%s</style></head><body><h1>warden corpus</h1><p class="mut">%d sessions, sorted by risk</p>' % (CSS, len(rows))]
    h.append(_tbl(["package", "verdict", "risk", "alert", "novel", "top finding"], [['<a href="%s">%s</a>' % (E(fn), E(s.package or s.sid)), '<span class="badge b%d">%s</span>' % (v["class_id"], E(v["class"])), v["risk"], "yes" if v["alert"] else "", "yes" if v["novel"] else "", E((v.get("reasons") or [""])[0])] for s, v, fn in rows]))
    h.append("</body></html>")
    (out / "index.html").write_text("".join(h))
    return out / "index.html"
