"""Session/event schema. A session is a JSONL file: line 1 {"meta": {...}}, then one event per line.
event: {t: ms since agent start, api, cat, arg|null, caller, fg: 0/1, n?: int (traffic bytes), p?: pid}"""
import json, pathlib
from dataclasses import dataclass, field

SCHEMA = 2
CATS = ["identifier", "location", "contacts_sms", "sensor_av", "network", "dyn_code", "exec", "env_probe", "clipboard",
        "pkg_enum", "a11y", "crypto", "reflection", "sms_call", "webview", "native", "overlay"]
SENSITIVE = {"identifier", "location", "contacts_sms", "sensor_av", "clipboard", "pkg_enum"}
AUX = {"traffic", "lifecycle"}          # not behavior: byte counters and fg/bg transitions
SUFFIX = ".session.jsonl"
RESERVED = {"labels.jsonl", "verdicts.jsonl", "batch_log.jsonl"}


@dataclass
class Session:
    meta: dict
    events: list
    path: str = ""

    @property
    def package(self):
        return self.meta.get("package", "")

    @property
    def sid(self):
        if self.path:
            n = pathlib.Path(self.path).name
            return n[:-len(SUFFIX)] if n.endswith(SUFFIX) else n
        return self.meta.get("sid", "")


def normalize_event(e):
    """Coerce an event to schema v2 (v1 events lack fg). Returns None if unusable."""
    try:
        if "cat" not in e or "t" not in e:
            return None
        out = {"t": int(e["t"]), "api": str(e.get("api", "")), "cat": str(e["cat"]),
               "arg": None if e.get("arg") is None else str(e["arg"]),
               "caller": str(e.get("caller") or "?"), "fg": 1 if e.get("fg", 1) else 0}
        if e.get("n"):
            out["n"] = int(e["n"])
        if e.get("p") is not None:
            out["p"] = e["p"]
        return out
    except (TypeError, ValueError):
        return None


def load_session(path):
    meta, ev = {}, []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "meta" in d:
                meta = d["meta"]
            else:
                e = normalize_event(d)
                if e:
                    ev.append(e)
    ev.sort(key=lambda e: e["t"])
    return Session(meta, ev, str(path))


def dump_session(path, meta, events):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        f.write(json.dumps({"meta": dict(meta, schema=SCHEMA)}) + "\n")
        for e in events:
            f.write(json.dumps(e) + "\n")
    tmp.replace(path)
    return path


def iter_session_paths(root):
    root = pathlib.Path(root)
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*.jsonl") if p.name not in RESERVED and (p.name.endswith(SUFFIX) or not p.name.endswith(".tmp")))


def load_corpus(root):
    return [load_session(p) for p in iter_session_paths(root)]
