"""Episode schema (stdlib only). On disk: JSONL, one record per line.

Record types: episode_header, baseline, step, episode_end.
A Step is: observation (before) -> action (+ safety decision) -> attributed hook events -> observation (after).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "jarvis_crawl.episode/1"

# action-tier permission model
T_OBSERVE, T_NAVIGATE, T_INPUT, T_CONSEQUENTIAL, T_FORBIDDEN = 0, 1, 2, 3, 4
TIER_NAMES = {0: "observe", 1: "navigate", 2: "input", 3: "consequential", 4: "forbidden"}
V_ALLOW, V_DENY, V_ESCALATE = "allow", "deny", "escalate"

# hook-event attribution classes
A_DIRECT, A_TAIL, A_BACKGROUND, A_LAUNCH, A_IDLE = "direct", "tail", "background", "launch", "idle"
ATTRIBUTIONS = (A_DIRECT, A_TAIL, A_BACKGROUND, A_LAUNCH, A_IDLE)

_ACTION_FIELDS = ("kind", "target_path", "target_sig", "x", "y", "x2", "y2", "text", "pkg", "key", "origin")


@dataclass
class Action:
    kind: str                         # tap long_tap swipe text back home launch wait
    target_path: Optional[str] = None  # structural path of target node
    target_sig: Optional[str] = None   # cls|rid|normalised-label
    x: Optional[int] = None
    y: Optional[int] = None
    x2: Optional[int] = None
    y2: Optional[int] = None
    text: Optional[str] = None
    pkg: Optional[str] = None
    key: str = ""                      # stable policy key
    origin: str = "policy"             # policy | system

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in _ACTION_FIELDS}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Action":
        return Action(**{k: d[k] for k in _ACTION_FIELDS if k in d})

    def identity(self) -> tuple:
        return tuple(getattr(self, k) for k in _ACTION_FIELDS)


@dataclass
class HookEvent:
    t: float
    kind: str                          # net.url net.connect net.dns loc.read clip.read mic.start cam.open
    target: str = ""                   # contacts.query sms.read ident.read dex.load exec wifi.read ...
    api: str = ""
    pkg: str = ""
    tid: int = 0
    stack: List[str] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"t": self.t, "kind": self.kind, "target": self.target, "api": self.api, "pkg": self.pkg,
                "tid": self.tid, "stack": list(self.stack), "detail": dict(self.detail)}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "HookEvent":
        return HookEvent(t=float(d["t"]), kind=d["kind"], target=d.get("target", "") or "", api=d.get("api", "") or "",
                         pkg=d.get("pkg", "") or "", tid=int(d.get("tid", 0) or 0),
                         stack=list(d.get("stack") or []), detail=dict(d.get("detail") or {}))


@dataclass
class AttributedEvent:
    event: HookEvent
    attribution: str
    action_idx: Optional[int]
    confidence: float
    latency: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        d = self.event.to_dict()
        d.update(attr=self.attribution, action_idx=self.action_idx, conf=self.confidence, lat=self.latency)
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AttributedEvent":
        return AttributedEvent(HookEvent.from_dict(d), d["attr"], d.get("action_idx"),
                               float(d.get("conf", 0.0)), d.get("lat"))


@dataclass
class ScreenRef:
    state_id: int
    hash: str
    simhash: str
    pkg: str
    node_count: int
    xml_ref: str
    new_state: bool
    near_dup_of: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)

    @staticmethod
    def from_dict(d: Optional[Dict[str, Any]]) -> Optional["ScreenRef"]:
        if d is None:
            return None
        return ScreenRef(**{k: d.get(k) for k in ScreenRef.__dataclass_fields__})


@dataclass
class Step:
    idx: int
    t_start: float                     # wall/virtual time immediately before the action executes
    t_end: float
    before: Optional[ScreenRef]        # None only for the initial launch step
    action: Action
    safety: Dict[str, Any]
    executed: bool
    after: Optional[ScreenRef] = None
    events: List[AttributedEvent] = field(default_factory=list)
    policy: Dict[str, Any] = field(default_factory=dict)
    denied: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "step", "idx": self.idx, "t_start": self.t_start, "t_end": self.t_end,
                "before": self.before.to_dict() if self.before else None,
                "after": self.after.to_dict() if self.after else None,
                "action": self.action.to_dict(), "safety": self.safety, "executed": self.executed,
                "events": [e.to_dict() for e in self.events], "policy": self.policy,
                "denied": self.denied, "meta": self.meta}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Step":
        return Step(idx=d["idx"], t_start=d["t_start"], t_end=d["t_end"], before=ScreenRef.from_dict(d.get("before")),
                    action=Action.from_dict(d["action"]), safety=d.get("safety", {}), executed=bool(d.get("executed")),
                    after=ScreenRef.from_dict(d.get("after")),
                    events=[AttributedEvent.from_dict(e) for e in d.get("events", [])],
                    policy=d.get("policy", {}), denied=d.get("denied", []), meta=d.get("meta", {}))


@dataclass
class Episode:
    header: Dict[str, Any]
    steps: List[Step]
    baseline: Optional[Dict[str, Any]] = None
    end: Optional[Dict[str, Any]] = None
    path: str = ""

    @property
    def dir(self) -> str:
        return os.path.dirname(self.path)


class EpisodeWriter:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self._f = open(path, "w", encoding="utf-8")

    def write(self, rec: Dict[str, Any]) -> None:
        self._f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
        self._f.flush()

    def close(self) -> None:
        if not self._f.closed:
            self._f.close()


def read_episode(path: str) -> Episode:
    if os.path.isdir(path):
        path = os.path.join(path, "episode.jsonl")
    header: Dict[str, Any] = {}
    baseline = end = None
    steps: List[Step] = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                break  # torn final line from a crash; keep what we have
            t = rec.get("type")
            if t == "episode_header":
                header = rec
            elif t == "baseline":
                baseline = rec
            elif t == "step":
                steps.append(Step.from_dict(rec))
            elif t == "episode_end":
                end = rec
    return Episode(header=header, steps=steps, baseline=baseline, end=end, path=path)


def validate_episode(ep: Episode) -> List[str]:
    """Structural invariants. Empty list == valid."""
    p: List[str] = []
    if ep.header.get("schema") != SCHEMA_VERSION:
        p.append(f"schema mismatch: {ep.header.get('schema')!r}")
    if ep.end is None:
        p.append("truncated: no episode_end record")
    for i, s in enumerate(ep.steps):
        if s.idx != i:
            p.append(f"step index gap: position {i} has idx {s.idx}")
        if s.before is None and i != 0:
            p.append(f"step {i}: missing before-screen")
        if s.after is None:
            p.append(f"step {i}: missing after-screen")
        if s.t_end < s.t_start:
            p.append(f"step {i}: t_end < t_start")
        last = None
        for e in s.events:
            if e.attribution not in ATTRIBUTIONS:
                p.append(f"step {i}: bad attribution {e.attribution!r}")
            if last is not None and e.event.t < last:
                p.append(f"step {i}: events not time-ordered")
            last = e.event.t
            if e.attribution == A_IDLE and e.action_idx is not None:
                p.append(f"step {i}: idle event carries action_idx")
            if e.attribution != A_IDLE and e.action_idx != s.idx:
                p.append(f"step {i}: event attributed to action {e.action_idx}")
    return p


def safety_violations(ep: Episode, max_tier: int = T_INPUT) -> List[str]:
    """Hard invariant: nothing above max_tier, and nothing non-ALLOW, was ever executed."""
    v: List[str] = []
    for s in ep.steps:
        if not s.executed:
            continue
        if s.safety.get("verdict") != V_ALLOW:
            v.append(f"step {s.idx}: executed with verdict {s.safety.get('verdict')}")
        if int(s.safety.get("tier", 99)) > max_tier:
            v.append(f"step {s.idx}: executed tier {s.safety.get('tier')} > {max_tier}")
    return v


def flatten_for_trace(ep: Episode) -> List[Dict[str, Any]]:
    """Generic flat records for ingestion by jarvis_trace (adapt field names to its schema)."""
    eid = ep.header.get("episode_id", "")
    out: List[Dict[str, Any]] = []
    for s in ep.steps:
        out.append({"ts": s.t_start, "span": f"{eid}/{s.idx}", "kind": "crawl.action",
                    "attrs": {"action": s.action.to_dict(), "safety": s.safety, "executed": s.executed,
                              "before": s.before.hash if s.before else None,
                              "after": s.after.hash if s.after else None}})
        for e in s.events:
            out.append({"ts": e.event.t, "span": f"{eid}/{s.idx}", "kind": "crawl.hook." + e.event.kind,
                        "attrs": {"target": e.event.target, "attr": e.attribution, "conf": e.confidence,
                                  "api": e.event.api, "stack": e.event.stack[:6]}})
    return out
