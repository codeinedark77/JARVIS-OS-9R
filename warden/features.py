"""Session -> fixed numeric feature vector (schema 2). Feature names are grouped for explanation (see GROUP)."""
import math, re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict

from . import manifest, trackers
from .schema import CATS, SENSITIVE, Session

FEATURE_VERSION = 2
WINDOW_MS = 3000
LATE_MS = 20000
RESOLVE_MS = 8000
DNS_APIS = {"java.net.InetAddress.getAllByName", "java.net.InetAddress.getByName", "native.getaddrinfo"}
CONNECT_APIS = {"native.connect", "java.net.Socket.connect"}
WRITABLE = re.compile(r"^(/data/(data|user)|/sdcard|/storage|/data/local/tmp|/mnt|in-memory$)")
SU = re.compile(r"(/su$|/su\b|magisk|supersu|xposed|lsposed|zygisk|kernelsu|apatch|busybox)", re.I)
FRIDA = re.compile(r"(frida|gum-js|linjector|re\.frida|:27042|/proc/(self|\d+)/maps)", re.I)
EMU = re.compile(r"(qemu|goldfish|ranchu|genymotion|ro\.kernel|ro\.hardware)", re.I)
HOST = re.compile(r"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?(\[[0-9a-f:]+\]|[^/:?#]+)(?::(\d+))?", re.I)
HOSTPORT = re.compile(r"^/?(?P<h>\[[0-9a-f:]+\]|[^/:\s]+)(?:/[\d.]+)?:(?P<p>\d+)$", re.I)

GROUP = {}          # feature name -> group (filled by featurize; populated at import via an empty session)


def _host_port(api, cat, arg):
    """Extract (host, port|None, is_url) from a network event."""
    if not arg:
        return None, None, False
    m = HOST.match(arg)
    if m:
        return m.group(1).strip("[]"), int(m.group(2)) if m.group(2) else (80 if arg.lower().startswith("http:") else 443), True
    m = HOSTPORT.match(arg)                      # native.connect 'ip:port' | java.net.Socket.connect 'host/ip:port'
    if m:
        return m.group("h").strip("[]"), int(m.group("p")), False
    if re.match(r"^[A-Za-z0-9._-]+$", arg):      # bare hostname (DNS / getaddrinfo)
        return arg, None, False
    return None, None, False


def _ent(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _burst(ts):
    if len(ts) < 3:
        return 0.0
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    m = sum(gaps) / len(gaps)
    if m == 0:
        return 3.0
    return (sum((g - m) ** 2 for g in gaps) / len(gaps)) ** 0.5 / m


def featurize(sess, m=None):
    m = m or trackers.matcher()
    pkg = sess.package
    ev = [e for e in sess.events if e["cat"] not in ("traffic", "lifecycle")]
    traffic = [e for e in sess.events if e["cat"] == "traffic"]
    N = max(len(ev), 1)
    f = {}

    def put(group, name, val):
        f[name] = float(val)
        GROUP[name] = group

    cnt = Counter(e["cat"] for e in ev)
    dur = (max((e["t"] for e in sess.events), default=0)) / 1000.0
    put("volume", "dur_s_log", math.log1p(dur))
    put("volume", "ev_rate_log", math.log1p(len(ev) / (dur + 1.0)))
    for c in CATS:
        put("volume", "n_" + c, math.log1p(cnt[c]))
        put("volume", "frac_" + c, cnt[c] / N)

    # ---- attribution per event
    own = [(trackers.attribute(e["caller"], pkg, m), e) for e in ev]
    owners = Counter(o[0][0] for o in own)
    known = max(N - owners["unknown"] - owners["obf"], 1)

    # ---- network
    net = [e for e in ev if e["cat"] == "network"]
    hosts, ports, url_n, clear_n, first_seen = {}, [], 0, 0, {}
    dns_t = sorted(e["t"] for e in net if e["api"] in DNS_APIS)
    for e in net:
        h, p, is_url = _host_port(e["api"], e["cat"], e["arg"])
        if not h:
            continue
        if trackers.is_ip(h) and e["api"] in CONNECT_APIS:
            i = bisect_right(dns_t, e["t"])
            if i > 0 and e["t"] - dns_t[i - 1] <= RESOLVE_MS:    # IP of a connection whose name was just resolved: counted via the name
                if p:
                    ports.append(p)
                continue
        hosts.setdefault(h, 0); hosts[h] += 1
        first_seen.setdefault(h, e["t"])
        if p:
            ports.append(p)
        if is_url:
            url_n += 1
            if e["arg"].lower().startswith("http:"):
                clear_n += 1
    hs = set(hosts)
    ip_hosts = {h for h in hs if trackers.is_ip(h)}
    named = hs - ip_hosts
    tr_hosts = {h for h in named if m.host(h)}
    fp_hosts = {h for h in named if trackers.first_party_host(h, pkg)}
    other = named - tr_hosts - fp_hosts
    put("network", "n_hosts", math.log1p(len(hs)))
    put("network", "n_hosts_tracker", math.log1p(len(tr_hosts)))
    put("network", "tracker_host_frac", len(tr_hosts) / max(len(named), 1))
    put("network", "n_ip_hosts", math.log1p(len(ip_hosts)))
    put("network", "ip_host_frac", len(ip_hosts) / max(len(hs), 1))
    put("network", "third_party_host_frac", len(other) / max(len(named), 1))
    put("network", "nonstd_port_n", math.log1p(sum(1 for p in ports if p not in (80, 443, 8080, 8443))))
    put("network", "cleartext_http_frac", clear_n / max(url_n, 1))
    put("network", "host_entropy", sum(_ent(h.split(".")[0]) for h in named) / max(len(named), 1))
    put("network", "late_new_hosts", math.log1p(sum(1 for h, t in first_seen.items() if t > LATE_MS)))
    tls = sum(e.get("n", 0) for e in traffic if e["arg"] == "tls")
    raw = sum(e.get("n", 0) for e in traffic if e["arg"] == "raw")
    put("network", "tls_bytes_log", math.log1p(tls))
    put("network", "raw_tls_ratio_log", math.log1p(raw / (tls + 1.0)))   # raw sendto/send includes TLS ciphertext on some stacks; the ratio isolates non-TLS channels

    # ---- SDK / third-party code
    sens = [(o, e) for o, e in own if e["cat"] in SENSITIVE]
    sdk_names, sdk_trk, sdk_ads, sdk_sens_cats = set(), set(), set(), set()
    for (ow, name, kind), e in own:
        if ow == "sdk":
            sdk_names.add(name)
            if kind in ("analytics", "ads", "attribution", "profiling", "engagement"):
                sdk_trk.add(name)
            if kind == "ads":
                sdk_ads.add(name)
            if e["cat"] in SENSITIVE:
                sdk_sens_cats.add(e["cat"])
    ext = lambda o: o[0] in ("sdk", "lib")
    put("sdk", "third_party_frac", sum(1 for o, e in own if ext(o)) / known)
    put("sdk", "sens_third_frac", sum(1 for o, e in sens if ext(o)) / max(len(sens), 1))
    put("sdk", "sens_unknown_lib_frac", sum(1 for o, e in sens if o[0] == "lib") / max(len(sens), 1))
    put("sdk", "n_sdk", math.log1p(len(sdk_names)))
    put("sdk", "n_sdk_tracker", math.log1p(len(sdk_trk)))
    put("sdk", "n_sdk_ads", math.log1p(len(sdk_ads)))
    put("sdk", "sdk_sens_cats", len(sdk_sens_cats))
    put("sdk", "obf_frac", owners["obf"] / N)
    put("sdk", "unknown_caller_frac", owners["unknown"] / N)

    # ---- sequences
    net_t = [e["t"] for e in net]
    adj = adj_same = adj_ext = 0
    for (o, s) in sens:
        i, j = bisect_left(net_t, s["t"]), bisect_right(net_t, s["t"] + WINDOW_MS)
        if j > i:
            adj += 1
            if ext(o):
                adj_ext += 1
            if s["caller"] != "?" and any(net[k]["caller"] == s["caller"] for k in range(i, j)):
                adj_same += 1
    ns = max(len(sens), 1)
    put("sequence", "sens_to_net", adj / ns)
    put("sequence", "sens_to_net_n", math.log1p(adj))
    put("sequence", "sens_to_net_ext_frac", adj_ext / ns)
    put("sequence", "sens_to_net_same", adj_same / ns)
    put("sequence", "sens_to_net_same_n", math.log1p(adj_same))
    cr_t = [e["t"] for e in ev if e["cat"] == "crypto"]
    cb = 0
    for e in net:
        i, j = bisect_left(cr_t, e["t"] - 1000), bisect_right(cr_t, e["t"])
        cb += j > i
    put("sequence", "crypto_before_net", cb / max(len(net), 1))
    dyn = [e for e in ev if e["cat"] == "dyn_code"]
    dts = min((e["t"] for e in dyn), default=None)
    dts_sens = 0
    if dts is not None:
        dts_sens = sum(1 for o, e in sens if dts <= e["t"] <= dts + 10000 and o[0] != "app")
    put("sequence", "dyn_then_sens", math.log1p(dts_sens))
    put("sequence", "exec_after_dyn", float(dts is not None and any(e["cat"] == "exec" and e["t"] >= dts for e in ev)))
    put("sequence", "t_first_sens", math.log1p(sens[0][1]["t"]) if sens else 12.0)
    put("sequence", "burstiness", _burst([e["t"] for o, e in sens]))

    # ---- foreground / background
    tot_fg = sum(1 for e in ev if e["fg"])
    bgs = [(o, e) for o, e in sens if not e["fg"]]
    bgn = [e for e in net if not e["fg"]]
    put("background", "fg_frac", tot_fg / N)
    put("background", "bg_n", math.log1p(N - tot_fg))
    put("background", "bg_sens_n", math.log1p(len(bgs)))
    put("background", "bg_sens_frac", len(bgs) / ns)
    put("background", "bg_sensor_av", float(any(e["cat"] == "sensor_av" for o, e in bgs)))
    put("background", "bg_location", float(any(e["cat"] == "location" for o, e in bgs)))
    put("background", "bg_contacts_sms", float(any(e["cat"] == "contacts_sms" for o, e in bgs)))
    put("background", "bg_net_n", math.log1p(len(bgn)))
    put("background", "bg_net_frac", len(bgn) / max(len(net), 1))
    put("background", "bg_traffic_log", math.log1p(sum(e.get("n", 0) for e in traffic if not e["fg"])))
    put("background", "bg_sms_call", float(any((e["cat"] == "sms_call") and not e["fg"] for e in ev)))

    # ---- evasion / environment probing
    probes = [e for e in ev if e["cat"] == "env_probe"]
    stats = (sess.meta.get("stats") or {}).get("counters", {})
    put("evasion", "env_probe_early", float(any(e["t"] < 2000 for e in probes)))
    put("evasion", "env_su_probe", float(any(e["arg"] and SU.search(e["arg"]) for e in probes)))
    put("evasion", "frida_probe", float(any(e["arg"] and FRIDA.search(e["arg"]) for e in probes)))
    put("evasion", "emu_probe", float(any(e["arg"] and EMU.search(e["arg"]) for e in probes)))
    put("evasion", "native_ptrace", float(any(e["api"] == "native.ptrace" for e in probes)))
    put("evasion", "reflect_total_log", math.log1p(stats.get("reflect_total", cnt["reflection"])))
    put("evasion", "native_dlopen_n", math.log1p(sum(1 for e in ev if e["api"] == "native.dlopen")))

    # ---- dynamic code
    put("dyncode", "dyn_writable_path", float(any(e["arg"] and WRITABLE.match(e["arg"]) for e in dyn)))
    put("dyncode", "dyn_and_net", float(bool(dyn) and bool(net)))
    put("dyncode", "pkg_install", float(any(e["arg"] == "package-install" for e in dyn)))
    put("dyncode", "native_lib_writable", float(any(e["cat"] == "native" and e["arg"] and WRITABLE.match(e["arg"]) for e in ev)))

    # ---- permissions
    perms = sess.meta.get("perms")
    summ = manifest.perm_summary(perms)
    put("perms", "perm_known", float(bool(perms and perms.get("declared"))))
    put("perms", "perm_dangerous_n", math.log1p(len(summ["dangerous"])))
    put("perms", "perm_highrisk_n", len(summ["high_risk"]))
    dvo = manifest.declared_vs_observed(perms, cnt)
    unused = sum(1 for r in dvo if not r["observed"])
    put("perms", "perm_declared_unused", unused / max(len(dvo), 1))
    put("perms", "perm_used_n", sum(1 for r in dvo if r["observed"]))

    # ---- misc
    put("misc", "n_distinct_sens_cats", len({e["cat"] for o, e in sens}))
    put("misc", "webview_js_iface", float(any("addJavascriptInterface" in e["api"] for e in ev)))
    put("misc", "sms_send_n", math.log1p(sum(1 for e in ev if e["cat"] == "sms_call")))
    return f


def keys():
    return sorted(GROUP)


def vector(feats, ks=None):
    ks = ks or sorted(feats)
    return [feats.get(k, 0.0) for k in ks]


featurize(Session({}, []))      # populate GROUP
