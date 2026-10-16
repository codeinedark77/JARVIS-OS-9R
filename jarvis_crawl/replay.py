"""Deterministic replay.

decisions : re-run the full Runner (same config, seed, safety config) against a ReplayDevice that serves the
            recorded UI dumps in order. Every state id/hash, candidate denial, policy choice, safety decision
            and executed action must match the recording. Catches nondeterminism and regressions in hashing,
            safety rules or policy code against a corpus of real traces.
attribution: recompute hook-event attribution from the recorded raw events + baseline with the CURRENT code.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .attribution import ActionSpan, AttrConfig, Baseline, attribute_span
from .device import Device, FakeClock
from .policy import FrontierPolicy, LLMPolicy, Policy, RecordedPlanner, make_policy
from .runner import BlobStore, RunConfig, Runner
from .safety import SafetyConfig, SafetyPolicy
from .schema import Action, Episode, HookEvent, read_episode, safety_violations, validate_episode


@dataclass
class ReplayReport:
    ok: bool
    problems: List[str] = field(default_factory=list)
    decision_mismatches: List[str] = field(default_factory=list)
    attribution_mismatches: List[str] = field(default_factory=list)

    def summary(self) -> str:
        return (f"ok={self.ok} problems={len(self.problems)} decision_mismatches={len(self.decision_mismatches)} "
                f"attribution_mismatches={len(self.attribution_mismatches)}")


class ReplayDevice(Device):
    def __init__(self, ep: Episode):
        blobs = BlobStore(os.path.join(ep.dir, "blobs"))
        self.obs: List[Tuple[str, str]] = []
        self.expected: List[Optional[Action]] = []
        self.abort: List[Optional[str]] = []
        for s in ep.steps[1:]:
            self.obs.append((blobs.get(s.before.xml_ref), s.before.pkg))
            self.expected.append(s.action if s.executed else None)
            ab = s.meta.get("abort")
            self.abort.append(ab.split(":", 1)[1] if ab else None)
        fin = (ep.end or {}).get("final_xml_ref")
        if fin:
            self.obs.append((blobs.get(fin), ""))
            self.expected.append(None)
            self.abort.append(None)
        self.pos = 0
        self.mismatches: List[str] = []

    def dump_ui(self) -> str:
        if self.pos >= len(self.obs):
            raise RuntimeError("replay exhausted: runner asked for more observations than were recorded")
        xml = self.obs[self.pos][0]
        self.pos += 1
        return xml

    def current_package(self) -> str:
        j = self.pos - 1
        return (self.abort[j] or self.obs[j][1]) if 0 <= j < len(self.obs) else ""

    def act(self, a: Action) -> None:
        j = self.pos - 1
        exp = self.expected[j] if 0 <= j < len(self.expected) else None
        if exp is None or exp.identity() != a.identity():
            self.mismatches.append(f"obs {j}: runner executed {a.to_dict()} but recording has {exp.to_dict() if exp else None}")

    def launch(self, pkg: str) -> None:
        if self.pos == 0:
            return  # startup launch
        j = self.pos - 1
        exp = self.expected[j] if 0 <= j < len(self.expected) else None
        if exp is None or exp.kind != "launch" or exp.pkg != pkg:
            self.mismatches.append(f"obs {j}: runner launched {pkg} but recording has {exp.to_dict() if exp else None}")

    def force_stop(self, pkg: str) -> None:
        pass

    def drain_events(self) -> List[HookEvent]:
        return []

    def info(self) -> Dict:
        return {"kind": "replay"}


def _safety_from_header(h: Dict) -> SafetyPolicy:
    d = h["safety"]
    return SafetyPolicy(SafetyConfig(
        allowed_packages=frozenset(d["allowed_packages"]), permission_pkgs=frozenset(d["permission_pkgs"]),
        permission_mode=d["permission_mode"], max_autonomous_tier=d["max_autonomous_tier"],
        allow_leave_app=d["allow_leave_app"], extra_t3=frozenset(d["extra_t3"]), extra_t4=frozenset(d["extra_t4"]),
        extra_benign=frozenset(d["extra_benign"]), max_text_inputs=d["max_text_inputs"], max_actions=d["max_actions"]))


def replay_decisions(ep: Episode, tmp_root: Optional[str] = None) -> List[str]:
    h = ep.header
    out: List[str] = []
    tmp = tempfile.mkdtemp(prefix="jc_replay_", dir=tmp_root)
    cfg = RunConfig.from_dict(h["config"], out_dir=tmp)
    cfg.max_steps = len(ep.steps) - 1
    dev = ReplayDevice(ep)
    pol: Policy
    if h.get("policy", "").startswith("llm"):
        pol = LLMPolicy(RecordedPlanner([s.policy.get("llm_choice") for s in ep.steps[1:]
                                         if str(s.policy.get("name", "")).startswith("llm")]))
    else:
        pol = make_policy(h.get("policy", "frontier"))
    ext: Dict[int, Dict[str, float]] = {s.idx: s.policy["ext"] for s in ep.steps if "ext" in s.policy}
    reward = (lambda sid, key, step_idx: ext.get(step_idx, {}).get(key, 0.0)) if ext else None
    attr_cfg = AttrConfig(**h["attr_config"])
    runner = Runner(cfg, dev, FakeClock(h["started_at"]), policy=pol, safety=_safety_from_header(h),
                    reward_fn=reward, attr_cfg=attr_cfg)
    res = runner.run()
    new = read_episode(res["episode_path"])
    out.extend(dev.mismatches)
    if len(new.steps) != len(ep.steps):
        out.append(f"step count: recorded {len(ep.steps)} vs replay {len(new.steps)}")
    for a, b in zip(ep.steps, new.steps):
        if a.idx == 0:
            continue
        def tag(what: str, x, y) -> None:
            out.append(f"step {a.idx}: {what}: recorded={json.dumps(x, sort_keys=True)[:200]} replay={json.dumps(y, sort_keys=True)[:200]}")
        if (a.before.hash, a.before.state_id, a.before.new_state, a.before.near_dup_of) != \
           (b.before.hash, b.before.state_id, b.before.new_state, b.before.near_dup_of):
            tag("before-screen", a.before.to_dict(), b.before.to_dict())
        if a.action.identity() != b.action.identity():
            tag("action", a.action.to_dict(), b.action.to_dict())
        if a.safety != b.safety:
            tag("safety", a.safety, b.safety)
        if a.denied != b.denied:
            tag("denied", a.denied, b.denied)
        if a.policy != b.policy:
            tag("policy", a.policy, b.policy)
        if a.executed != b.executed:
            tag("executed", a.executed, b.executed)
        if a.meta != b.meta:
            tag("meta", a.meta, b.meta)
    return out


def replay_attribution(ep: Episode) -> List[str]:
    h = ep.header
    cfg = RunConfig.from_dict(h["config"])
    acfg = AttrConfig(**h["attr_config"])
    base = Baseline.from_dict(ep.baseline)
    out: List[str] = []
    for s in ep.steps:
        settle = cfg.launch_wait_s if s.action.kind == "launch" else cfg.settle_s
        span = ActionSpan(s.idx, s.action.kind, s.t_start, settle)
        recomputed = attribute_span(span, [e.event for e in s.events], base, acfg)
        a = [e.to_dict() for e in s.events]
        b = [e.to_dict() for e in recomputed]
        if a != b:
            diffs = [(x["kind"], x["target"], x["attr"], y["attr"]) for x, y in zip(a, b) if x != y][:3]
            out.append(f"step {s.idx}: attribution drift {diffs}")
    return out


def verify_episode(path: str, tmp_root: Optional[str] = None, max_tier: int = 2) -> ReplayReport:
    ep = read_episode(path)
    rep = ReplayReport(ok=True)
    rep.problems = validate_episode(ep) + safety_violations(ep, max_tier)
    rep.decision_mismatches = replay_decisions(ep, tmp_root) if len(ep.steps) > 1 else []
    rep.attribution_mismatches = replay_attribution(ep)
    rep.ok = not (rep.problems or rep.decision_mismatches or rep.attribution_mismatches)
    return rep
