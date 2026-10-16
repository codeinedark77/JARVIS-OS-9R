"""Hook-event -> action attribution.

Each action owns the interval [t_i, t_{i+1}). Within it an event's latency L = t_event - t_i is classed:
  launch      L <= launch_window (action is a launch)
  direct      L <= settle                      conf = max(floor, exp(-L/tau))
  tail        settle < L <= settle + tail_s    conf = floor * exp(-(L-settle)/tau)
  idle        later                            conf 0, action_idx None
Then idle-baseline demotion: signatures (kind|target) that fire at a measured rate while no action is running
are relabelled `background` -- up to ceil(rate * window) events per span -- earliest first; any excess keeps its
class with confidence scaled by (excess / total). Deterministic and pure: replay recomputes it from raw events.
"""
from __future__ import annotations

import bisect
import math
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

from .schema import A_BACKGROUND, A_DIRECT, A_IDLE, A_LAUNCH, A_TAIL, AttributedEvent, HookEvent


@dataclass
class AttrConfig:
    tail_s: float = 3.0
    launch_window_s: float = 2.5
    tau_s: float = 2.0
    min_direct_conf: float = 0.6
    baseline_min_count: int = 2

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ActionSpan:
    idx: int
    kind: str
    t: float
    settle: float


def host_of(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        try:
            return (urlsplit(t).hostname or "").lower()
        except ValueError:
            return ""
    h = t.split("/", 1)[0]
    if h.count(":") == 1:
        h = h.split(":")[0]
    return h.lower()


def event_signature(ev: HookEvent) -> str:
    t = host_of(ev.target) if ev.kind.startswith("net.") else (ev.target or "")
    return f"{ev.kind}|{t}"


@dataclass
class Baseline:
    window_s: float
    counts: Dict[str, int]

    @staticmethod
    def from_events(events: Iterable[HookEvent], window_s: float) -> "Baseline":
        c: Dict[str, int] = {}
        for e in events:
            s = event_signature(e)
            c[s] = c.get(s, 0) + 1
        return Baseline(window_s=window_s, counts=c)

    def rate(self, sig: str) -> float:
        return self.counts.get(sig, 0) / self.window_s if self.window_s > 0 else 0.0

    def to_dict(self) -> Dict:
        return {"window_s": self.window_s, "counts": dict(sorted(self.counts.items()))}

    @staticmethod
    def from_dict(d: Optional[Dict]) -> "Baseline":
        if not d:
            return Baseline(0.0, {})
        return Baseline(float(d.get("window_s", 0.0)), dict(d.get("counts", {})))


def _classify(ev: HookEvent, span: ActionSpan, cfg: AttrConfig):
    lat = ev.t - span.t
    if span.kind == "launch" and lat <= cfg.launch_window_s:
        return A_LAUNCH, max(cfg.min_direct_conf, math.exp(-lat / cfg.tau_s)), lat
    if lat <= span.settle:
        return A_DIRECT, max(cfg.min_direct_conf, math.exp(-lat / cfg.tau_s)), lat
    if lat <= span.settle + cfg.tail_s:
        return A_TAIL, cfg.min_direct_conf * math.exp(-(lat - span.settle) / cfg.tau_s), lat
    return A_IDLE, 0.0, lat


def attribute_span(span: ActionSpan, events: Sequence[HookEvent], baseline: Optional[Baseline],
                   cfg: AttrConfig) -> List[AttributedEvent]:
    evs = sorted(events, key=lambda e: (e.t, e.kind, e.target))
    rows = []  # [event, attr, conf, lat]
    for e in evs:
        a, c, l = _classify(e, span, cfg)
        rows.append([e, a, c, l])

    if baseline is not None and baseline.counts:
        win = cfg.launch_window_s if span.kind == "launch" else span.settle + cfg.tail_s
        groups: Dict[str, List[int]] = {}
        for i, (e, a, _c, _l) in enumerate(rows):
            if a in (A_DIRECT, A_TAIL, A_LAUNCH):
                groups.setdefault(event_signature(e), []).append(i)
        for sig, idxs in groups.items():
            n_base = baseline.counts.get(sig, 0)
            if n_base < cfg.baseline_min_count:
                continue
            k = min(len(idxs), int(math.ceil(baseline.rate(sig) * win - 1e-9)))
            if k <= 0:
                continue
            for j in idxs[:k]:
                rows[j][1] = A_BACKGROUND
                rows[j][2] = 0.5 + 0.5 * min(1.0, n_base / (cfg.baseline_min_count * 3))
            n = len(idxs)
            if n > k:
                for j in idxs[k:]:
                    rows[j][2] = rows[j][2] * (n - k) / n

    out: List[AttributedEvent] = []
    for e, a, c, l in rows:
        out.append(AttributedEvent(event=e, attribution=a, action_idx=None if a == A_IDLE else span.idx,
                                   confidence=round(c, 4), latency=round(l, 4)))
    return out


def attribute_all(spans: Sequence[ActionSpan], events: Sequence[HookEvent], baseline: Optional[Baseline],
                  cfg: AttrConfig) -> List[List[AttributedEvent]]:
    """Per-span attributed events; events before the first span are dropped (pre-launch noise)."""
    ts = [s.t for s in spans]
    buckets: List[List[HookEvent]] = [[] for _ in spans]
    for e in events:
        i = bisect.bisect_right(ts, e.t) - 1
        if i >= 0:
            buckets[i].append(e)
    return [attribute_span(s, b, baseline, cfg) for s, b in zip(spans, buckets)]
