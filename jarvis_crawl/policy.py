"""Exploration policies. Candidates come from the UI tree; safety filters them before the policy sees them.

FrontierPolicy: one-step-lookahead frontier exploration over the observed state graph.
  unexplored edge   2.0 / (1 + visits of this structural control in this state)   (list rows share a skey, so
                    the 5th product row is worth less than an unseen control)
  explored edge     0.3 / (1 + exact visits) + 1.5 * unexplored_ratio(resulting state)  -> walks back toward frontier
  back              0.5 base on first try (prefers real controls), then scored like any explored edge
  + w_ext * reward_fn(...)   plug warden uncertainty here (active learning)
All randomness comes from ctx.rng (seeded), candidate order is DFS order => decisions replay exactly.
"""
from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .safety import SandboxIdentity, field_kind
from .schema import Action
from .statehash import ScreenAnalysis, UINode, norm_text, short_cls, short_rid
from .textutil import has_term, joined


@dataclass
class Candidate:
    action: Action
    node: Optional[UINode]
    key: str      # exact: kind:cls|rid|label
    skey: str     # structural: kind:cls|rid
    label: str = ""


class ExplorationGraph:
    def __init__(self):
        self.edges: Dict[Tuple[int, str], int] = {}
        self.seen: Dict[int, List[str]] = {}
        self.v_exact: Counter = Counter()
        self.v_struct: Counter = Counter()
        self.dead: set = set()      # states outside the app under test: never a frontier
        self.leaves: set = set()    # (state, key) edges known to exit the app: never offered again

    def see(self, state: int, keys: List[str]) -> None:
        s = self.seen.setdefault(state, [])
        known = set(s)
        for k in keys:
            if k != "back" and k not in known:
                s.append(k)
                known.add(k)

    def record(self, state: int, key: str, skey: str, after: int) -> None:
        self.edges[(state, key)] = after
        self.v_exact[(state, key)] += 1
        self.v_struct[(state, skey)] += 1

    def unexplored_ratio(self, state: int) -> float:
        if state in self.dead:
            return 0.0
        keys = self.seen.get(state)
        if not keys:
            return 1.0
        done = sum(1 for k in keys if (state, k) in self.edges)
        return 1.0 - done / len(keys)


@dataclass
class PolicyContext:
    step_idx: int
    state_id: int
    analysis: ScreenAnalysis
    graph: ExplorationGraph
    rng: random.Random
    reward_fn: Optional[Callable[[int, str, int], float]] = None


def candidates_from_screen(an: ScreenAnalysis, identity: Optional[SandboxIdentity] = None,
                           max_per_key: int = 2, include_long_tap: bool = False) -> List[Candidate]:
    ident = identity or SandboxIdentity(0)
    out: List[Candidate] = []
    count: Counter = Counter()

    def add(c: Candidate) -> None:
        if count[c.key] >= max_per_key:
            return
        count[c.key] += 1
        out.append(c)

    for n in an.nodes:
        if not n.interactive or n.area < 100:
            continue
        label = an.subtree_text(n.idx)
        # an editable field's text is its (changing) content, not its identity: key on rid/desc/path instead
        lab = (norm_text(n.desc) or ("" if n.rid else n.path)) if n.editable else norm_text(n.text or n.desc or label)
        base = f"{short_cls(n.cls)}|{short_rid(n.rid)}"
        sig = f"{base}|{lab}"
        cx, cy = n.center
        l, t, r, b = n.bounds
        if n.editable:
            fk = field_kind(n, label)
            a = Action("text", target_path=n.path, target_sig=sig, x=cx, y=cy, text=ident.value_for(fk),
                       key=f"text:{sig}")
            add(Candidate(a, n, a.key, f"text:{base}", label))
            continue
        if n.clickable or n.checkable:
            a = Action("tap", target_path=n.path, target_sig=sig, x=cx, y=cy, key=f"tap:{sig}")
            add(Candidate(a, n, a.key, f"tap:{base}", label))
        if include_long_tap and n.long_clickable:
            a = Action("long_tap", target_path=n.path, target_sig=sig, x=cx, y=cy, key=f"long_tap:{sig}")
            add(Candidate(a, n, a.key, f"long_tap:{base}", label))
        if n.scrollable and (b - t) > 200:
            h = b - t
            up = Action("swipe", target_path=n.path, target_sig=sig, x=cx, y=t + int(h * 0.75), x2=cx,
                        y2=t + int(h * 0.25), key=f"swipe_up:{sig}")
            dn = Action("swipe", target_path=n.path, target_sig=sig, x=cx, y=t + int(h * 0.25), x2=cx,
                        y2=t + int(h * 0.75), key=f"swipe_down:{sig}")
            add(Candidate(up, n, up.key, f"swipe_up:{base}", label))
            add(Candidate(dn, n, dn.key, f"swipe_down:{base}", label))
    out.append(Candidate(Action("back", key="back"), None, "back", "back"))
    return out


_BACKISH = ("back", "up", "close", "cancel", "navigate", "dismiss")
_SUBMIT = ("sign in", "log in", "login", "next", "continue", "search", "done", "save", "apply")


def prior(c: Candidate) -> float:
    """Small ordering prior for UNEXPLORED edges: fill forms, then submit, before backing out."""
    if c.key == "back" or c.node is None:
        return 0.0
    j = joined(c.node.rid, c.node.desc, c.node.text, c.label)
    p = 0.0
    if any(has_term(j, t) for t in _BACKISH):
        p -= 0.4
    if any(has_term(j, t) for t in _SUBMIT):
        p += 0.3
    if c.action.kind == "text":
        p += 0.5
    return p


class Policy:
    name = "base"

    def choose(self, ctx: PolicyContext, cands: List[Candidate]) -> Tuple[int, Dict]:
        raise NotImplementedError


class RandomPolicy(Policy):
    name = "random"

    def choose(self, ctx, cands):
        i = ctx.rng.randrange(len(cands))
        return i, {"name": self.name, "chosen_key": cands[i].key}


class FrontierPolicy(Policy):
    name = "frontier"

    def __init__(self, w_ext: float = 1.0):
        self.w_ext = w_ext

    def choose(self, ctx, cands):
        g, s = ctx.graph, ctx.state_id
        scored: List[Tuple[float, int]] = []
        ext_rec: Dict[str, float] = {}
        for i, c in enumerate(cands):
            e = g.edges.get((s, c.key))
            if e is None:
                base = (0.5 if c.key == "back" else 2.0) / (1 + g.v_struct[(s, c.skey)]) + prior(c)
            else:
                base = 0.3 / (1 + g.v_exact[(s, c.key)]) + 1.5 * g.unexplored_ratio(e)
            ext = 0.0
            if ctx.reward_fn is not None:
                ext = float(ctx.reward_fn(s, c.key, ctx.step_idx))
                if ext:
                    ext_rec[c.key] = round(ext, 6)
            scored.append((base + self.w_ext * ext + ctx.rng.random() * 1e-6, i))
        best = max(scored, key=lambda x: (x[0], -x[1]))
        top = sorted(scored, key=lambda x: (-x[0], x[1]))[:5]
        info = {"name": self.name, "chosen_key": cands[best[1]].key, "chosen_score": round(best[0], 6),
                "top": [[cands[i].key, round(sc, 6)] for sc, i in top]}
        if ext_rec:
            info["ext"] = ext_rec
        return best[1], info


def build_prompt(an: ScreenAnalysis, cands: List[Candidate], recent: List[str]) -> Dict:
    """Compact prompt payload for a small local model (6GB VRAM class)."""
    return {"package": an.pkg,
            "screen": [{"i": i, "action": c.key[:80]} for i, c in enumerate(cands)],
            "recent": recent[-6:],
            "instruction": "Pick the index of the action most likely to reveal a screen or behaviour not yet seen. "
                           "Reply JSON: {\"choice\": <int>}"}


class LLMPolicy(Policy):
    """Planner callable(prompt dict) -> raw model text (or None). Invalid output falls back to `fallback`.
    The raw choice is recorded in the step so replay can feed it back (see RecordedPlanner)."""
    name = "llm"

    def __init__(self, planner: Callable[[Dict], Optional[str]], fallback: Optional[Policy] = None):
        self.planner = planner
        self.fallback = fallback or FrontierPolicy()
        self.recent: List[str] = []

    def choose(self, ctx, cands):
        raw = None
        try:
            raw = self.planner(build_prompt(ctx.analysis, cands, self.recent))
        except Exception:
            raw = None
        choice = None
        if raw is not None:
            try:
                v = json.loads(raw)["choice"] if isinstance(raw, str) else raw
                if isinstance(v, int) and 0 <= v < len(cands):
                    choice = v
            except Exception:
                choice = None
        if choice is None:
            i, info = self.fallback.choose(ctx, cands)
            info = dict(info, name="llm.fallback", llm_choice=None)
        else:
            i, info = choice, {"name": self.name, "chosen_key": cands[choice].key, "llm_choice": choice}
        self.recent.append(cands[i].key[:60])
        return i, info


class RecordedPlanner:
    """Replays recorded llm_choice values by step index, for deterministic replay of LLMPolicy episodes."""

    def __init__(self, choices: List[Optional[int]]):
        self.choices, self.pos = choices, 0

    def __call__(self, prompt: Dict) -> Optional[str]:
        c = self.choices[self.pos] if self.pos < len(self.choices) else None
        self.pos += 1
        return None if c is None else json.dumps({"choice": c})


def make_policy(name: str) -> Policy:
    if name == "random":
        return RandomPolicy()
    if name == "frontier":
        return FrontierPolicy()
    raise ValueError(f"unknown policy {name!r} (llm policies are constructed in code)")
