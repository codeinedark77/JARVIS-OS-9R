"""Episode runner: observe -> hash -> candidates -> safety filter -> policy -> execute -> settle -> attribute.

Invariants (checked by tests / `validate`):
  * nothing executes unless its SafetyDecision verdict is ALLOW (T3 skipped + queued, T4 never)
  * kill switch is checked before every observation-to-action cycle
  * decisions depend only on recorded observations + seed (+ recorded ext rewards) => replayable
  * dry-run never calls device.act/launch: it plans on the live screen and logs what it WOULD do
"""
from __future__ import annotations

import hashlib
import os
import random
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .attribution import ActionSpan, AttrConfig, Baseline, attribute_span
from .device import Clock, Device
from .policy import ExplorationGraph, Policy, PolicyContext, candidates_from_screen, make_policy
from .safety import (KillSwitch, SafetyConfig, SafetyPolicy, SandboxIdentity, permission_prompt_kind)
from .schema import (SCHEMA_VERSION, T_NAVIGATE, V_ALLOW, Action, EpisodeWriter, HookEvent, ScreenRef, Step)
from .statehash import ScreenAnalysis, ScreenIndex, analyze


@dataclass
class RunConfig:
    app_pkg: str
    out_dir: str
    max_steps: int = 50
    seed: int = 0
    settle_s: float = 0.8
    tail_s: float = 3.0
    launch_wait_s: float = 2.0
    calibration_s: float = 6.0
    stuck_steps: int = 8
    max_relaunches: int = 4
    dry_run: bool = False
    permission_mode: str = "deny"
    policy: str = "frontier"
    near_threshold: int = 3
    extra_allowed_pkgs: Tuple[str, ...] = ()
    max_autonomous_tier: int = 2

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["extra_allowed_pkgs"] = list(self.extra_allowed_pkgs)
        return d

    @staticmethod
    def from_dict(d: Dict, out_dir: Optional[str] = None) -> "RunConfig":
        d = dict(d)
        d["extra_allowed_pkgs"] = tuple(d.get("extra_allowed_pkgs", ()))
        if out_dir is not None:
            d["out_dir"] = out_dir
        return RunConfig(**{k: v for k, v in d.items() if k in RunConfig.__dataclass_fields__})


class BlobStore:
    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def put(self, text: str) -> str:
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]
        p = os.path.join(self.root, h + ".xml")
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
        return h

    def get(self, ref: str) -> str:
        with open(os.path.join(self.root, ref + ".xml"), "r", encoding="utf-8") as f:
            return f.read()


class Runner:
    def __init__(self, cfg: RunConfig, device: Device, clock: Clock, *, policy: Optional[Policy] = None,
                 safety: Optional[SafetyPolicy] = None, kill: Optional[KillSwitch] = None,
                 identity: Optional[SandboxIdentity] = None,
                 reward_fn: Optional[Callable[[int, str, int], float]] = None,
                 attr_cfg: Optional[AttrConfig] = None):
        self.cfg, self.device, self.clock = cfg, device, clock
        allowed = frozenset({cfg.app_pkg} | set(cfg.extra_allowed_pkgs))
        self.safety = safety or SafetyPolicy(SafetyConfig(
            allowed_packages=allowed, permission_mode=cfg.permission_mode,
            max_autonomous_tier=cfg.max_autonomous_tier))
        self.policy = policy or make_policy(cfg.policy)
        self.kill = kill or KillSwitch()
        self.identity = identity or SandboxIdentity(cfg.seed)
        self.reward_fn = reward_fn
        self.attr_cfg = attr_cfg or AttrConfig(tail_s=cfg.tail_s)
        self.rng = random.Random(f"policy:{cfg.seed}")
        self.steps: List[Step] = []
        self.spans: List[ActionSpan] = []
        self.events_all: List[HookEvent] = []
        self.baseline = Baseline(0.0, {})
        self.blobs: Optional[BlobStore] = None
        self.writer: Optional[EpisodeWriter] = None
        self._next_flush = 0
        self._late = 0
        self._states: List[Dict] = []
        self._index = ScreenIndex(cfg.near_threshold)
        self._escalations: Dict[str, Dict] = {}

    # ---- helpers -----------------------------------------------------------------------------------------
    def _pkg_ok(self, pkg: str) -> bool:
        return pkg in self.safety.cfg.allowed_packages or pkg in self.safety.cfg.permission_pkgs

    def _observe(self, xml: str) -> Tuple[ScreenRef, ScreenAnalysis]:
        an = analyze(xml)
        sid, is_new, near = self._index.observe(an)
        ref_id = self.blobs.put(xml)
        if sid == len(self._states):
            self._states.append({"state_id": sid, "hash": an.hash, "pkg": an.pkg, "node_count": an.node_count,
                                 "xml_ref": ref_id, "first_step": len(self.steps)})
        return ScreenRef(sid, an.hash, an.simhash_hex, an.pkg, an.node_count, ref_id, is_new, near), an

    def _drain(self, into_calibration: Optional[List[HookEvent]] = None, t_cal0: float = 0.0) -> None:
        fresh = self.device.drain_events()
        boundary = self.spans[self._next_flush].t if self._next_flush < len(self.spans) else None
        for e in fresh:
            if into_calibration is not None and e.t >= t_cal0:
                into_calibration.append(e)
                continue
            if boundary is not None and e.t < boundary:
                self._late += 1           # arrived after its step was flushed
                continue
            self.events_all.append(e)

    def _flush(self, now: float, force: bool = False) -> None:
        cfg = self.cfg
        while self._next_flush < len(self.steps):
            i = self._next_flush
            s, sp = self.steps[i], self.spans[i]
            closed = force or now > sp.t + sp.settle + self.attr_cfg.tail_s + 0.25
            if not closed or (s.after is None and not force):
                break
            t_next = self.spans[i + 1].t if i + 1 < len(self.spans) else float("inf")
            evs = [e for e in self.events_all if sp.t <= e.t < t_next]
            s.events = attribute_span(sp, evs, self.baseline, self.attr_cfg)
            self.writer.write(s.to_dict())
            self._next_flush += 1

    def _span_settle(self, kind: str) -> float:
        return self.cfg.launch_wait_s if kind == "launch" else self.cfg.settle_s

    # ---- main --------------------------------------------------------------------------------------------
    def run(self) -> Dict:
        cfg, dev, clk = self.cfg, self.device, self.clock
        t_begin = clk.now()
        episode_id = f"{cfg.app_pkg}-s{cfg.seed}-{int(t_begin)}"
        ep_dir = os.path.join(cfg.out_dir, episode_id)
        os.makedirs(ep_dir, exist_ok=True)
        self.blobs = BlobStore(os.path.join(ep_dir, "blobs"))
        self.writer = EpisodeWriter(os.path.join(ep_dir, "episode.jsonl"))
        self.writer.write({"type": "episode_header", "schema": SCHEMA_VERSION, "episode_id": episode_id,
                           "app": cfg.app_pkg, "seed": cfg.seed, "started_at": t_begin, "config": cfg.to_dict(),
                           "attr_config": self.attr_cfg.to_dict(), "safety": self.safety.cfg.to_dict(),
                           "policy": self.policy.name, "device": dev.info()})

        # --- step 0: launch + idle calibration ---------------------------------------------------------------
        launch_act = Action("launch", pkg=cfg.app_pkg, key="launch", origin="system")
        d0 = self.safety.evaluate(launch_act, None, "", cfg.app_pkg)
        t_launch = clk.now()
        self.spans.append(ActionSpan(0, "launch", t_launch, cfg.launch_wait_s))
        cal: List[HookEvent] = []
        if not cfg.dry_run:
            dev.force_stop(cfg.app_pkg)
            dev.drain_events()
            t_launch = clk.now()
            self.spans[0].t = t_launch
            dev.launch(cfg.app_pkg)
            clk.sleep(cfg.launch_wait_s)
            self._drain()
            t_c0 = clk.now()
            if cfg.calibration_s > 0:
                clk.sleep(cfg.calibration_s)
                self._drain(into_calibration=cal, t_cal0=t_c0)
            self.baseline = Baseline.from_events(cal, cfg.calibration_s)
        self.writer.write({"type": "baseline", **self.baseline.to_dict(), "n_events": len(cal)})
        launch_step = Step(idx=0, t_start=t_launch, t_end=clk.now(), before=None, action=launch_act,
                           safety=d0.to_dict(), executed=not cfg.dry_run, policy={"name": "system", "reason": "startup"})
        self.steps.append(launch_step)

        graph = ExplorationGraph()
        counters = {"text_inputs": 0, "actions": 0}
        n_actions = 0
        steps_since_new = 0
        relaunches = 0
        foreign_run = 0
        end_reason = "max_steps"
        prev = launch_step
        final_ref: Optional[ScreenRef] = None
        denied_total = 0

        def close_prev(ref: ScreenRef) -> None:
            nonlocal steps_since_new
            prev.after = ref
            if prev.idx > 0:
                steps_since_new = 0 if ref.new_state else steps_since_new + 1
                if prev.action.origin == "policy" and prev.before is not None:
                    graph.record(prev.before.state_id, prev.action.key, prev.meta.get("skey", prev.action.key),
                                 ref.state_id)

        while True:
            ks = self.kill.tripped()
            if ks:
                end_reason = f"kill_switch:{ks}"
                break
            if n_actions >= cfg.max_steps:
                end_reason = "max_steps"
                break
            xml = dev.dump_ui()
            ref, an = self._observe(xml)
            if not self._pkg_ok(an.pkg):
                graph.dead.add(ref.state_id)
                if prev.action.origin == "policy" and prev.before is not None:
                    graph.leaves.add((prev.before.state_id, prev.action.key))
            close_prev(ref)
            step_idx = len(self.steps)

            denied: List[Dict] = []
            meta: Dict = {}
            chosen_action: Optional[Action] = None
            decision = None
            info: Dict = {}

            if not self._pkg_ok(an.pkg):
                foreign_run += 1
                if foreign_run > 6:
                    end_reason = "stuck_foreign"
                    break
                if foreign_run == 1:
                    chosen_action = Action("back", key="sys_back", origin="system")
                else:
                    chosen_action = Action("launch", pkg=cfg.app_pkg, key="sys_launch", origin="system")
                info = {"name": "system", "reason": "foreign_package", "pkg": an.pkg}
                decision = self.safety.evaluate(chosen_action, None, "", an.pkg, counters)
            else:
                foreign_run = 0
                if steps_since_new >= cfg.stuck_steps and relaunches < cfg.max_relaunches:
                    chosen_action = Action("launch", pkg=cfg.app_pkg, key="sys_launch", origin="system")
                    relaunches += 1
                    steps_since_new = 0
                    info = {"name": "system", "reason": "stuck"}
                    decision = self.safety.evaluate(chosen_action, None, "", an.pkg, counters)
                else:
                    allowed_c = []
                    for c in candidates_from_screen(an, self.identity):
                        d = self.safety.evaluate(c.action, c.node, c.label, an.pkg, counters)
                        if d.verdict == V_ALLOW:
                            allowed_c.append((c, d))
                        else:
                            denied_total += 1
                            if len(denied) < 8:
                                denied.append({"key": c.key, "tier": d.tier, "verdict": d.verdict, "rules": d.rules[:3]})
                            if d.verdict == "escalate":
                                self._escalations.setdefault(f"{an.hash}:{c.key}", {
                                    "state_hash": an.hash, "key": c.key, "rules": d.rules[:3], "step": step_idx})
                    kept = [(c, d) for c, d in allowed_c if (ref.state_id, c.key) not in graph.leaves]
                    allowed_c = kept or allowed_c   # never leave the policy without a move
                    graph.see(ref.state_id, [c.key for c, _ in allowed_c])
                    cands = [c for c, _ in allowed_c]
                    ctx = PolicyContext(step_idx, ref.state_id, an, graph, self.rng, self.reward_fn)
                    i, info = self.policy.choose(ctx, cands)
                    c, decision = allowed_c[i]
                    chosen_action = c.action
                    meta["skey"] = c.skey
                    if self._pkg_ok(an.pkg) and an.pkg in self.safety.cfg.permission_pkgs and c.node is not None:
                        rid = c.node.rid.split("/", 1)[-1]
                        meta["permission"] = {"kind": permission_prompt_kind(an), "choice":
                                              "allow" if rid.startswith("permission_allow") else
                                              "deny" if rid.startswith("permission_deny") else "other"}

            ks = self.kill.tripped()
            if ks:
                end_reason = f"kill_switch:{ks}"
                break

            executed = False
            t0 = clk.now()
            self.spans.append(ActionSpan(step_idx, chosen_action.kind, t0, self._span_settle(chosen_action.kind)))
            if not cfg.dry_run and decision.verdict == V_ALLOW:
                cur = dev.current_package()
                if cur and not self._pkg_ok(cur) and chosen_action.kind not in ("back", "launch"):
                    meta["abort"] = "pkg_changed:" + cur
                else:
                    if chosen_action.kind == "launch":
                        dev.launch(chosen_action.pkg)
                    else:
                        dev.act(chosen_action)
                    executed = True
                    counters["actions"] += 1
                    if chosen_action.kind == "text":
                        counters["text_inputs"] += 1
            clk.sleep(self._span_settle(chosen_action.kind) if executed else 0.0)
            self._drain()
            step = Step(idx=step_idx, t_start=t0, t_end=clk.now(), before=ref, action=chosen_action,
                        safety=decision.to_dict(), executed=executed, policy=info, denied=denied, meta=meta)
            self.steps.append(step)
            prev = step
            n_actions += 1
            self._flush(clk.now())

        # --- closing observation + drain --------------------------------------------------------------------
        if prev.after is None:
            xml = dev.dump_ui()
            final_ref, _an = self._observe(xml)
            close_prev(final_ref)
        else:
            final_ref = prev.after
        if not cfg.dry_run:
            clk.sleep(self.attr_cfg.tail_s + 0.3)
            self._drain()
        self._flush(clk.now(), force=True)

        tiers: Dict[str, int] = {}
        for s in self.steps:
            if s.executed:
                tiers[str(s.safety.get("tier"))] = tiers.get(str(s.safety.get("tier")), 0) + 1
        app_states = [st for st in self._states if st["pkg"] == cfg.app_pkg]
        end = {"type": "episode_end", "reason": end_reason, "n_steps": len(self.steps), "t_end": clk.now(),
               "states": self._states, "n_states": len(self._states), "n_app_states": len(app_states),
               "executed_by_tier": tiers, "denied_total": denied_total, "late_events": self._late,
               "final_xml_ref": final_ref.xml_ref if final_ref else None,
               "escalation_queue": list(self._escalations.values())[:50]}
        self.writer.write(end)
        self.writer.close()
        return {"episode_dir": ep_dir, "episode_path": self.writer.path, "end": end}
