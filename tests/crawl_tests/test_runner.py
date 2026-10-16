import tempfile
import unittest

from jarvis_crawl.fakeapp import DANGEROUS_RIDS
from jarvis_crawl.policy import LLMPolicy
from jarvis_crawl.safety import KillSwitch
from jarvis_crawl.schema import (A_BACKGROUND, A_DIRECT, A_IDLE, A_LAUNCH, A_TAIL, read_episode, safety_violations,
                                 validate_episode)
from .helpers import run_fake


class CountdownKill(KillSwitch):
    def __init__(self, n):
        super().__init__()
        self.n = n

    def tripped(self):
        self.n -= 1
        return "countdown" if self.n < 0 else None


class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dev, cls.ep, cls.res = run_fake(cls.tmp.name, seed=7, steps=50)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_episode_valid(self):
        self.assertEqual(validate_episode(self.ep), [])
        self.assertEqual(len(self.ep.steps), 51)
        self.assertEqual(self.ep.end["reason"], "max_steps")
        self.assertEqual(self.ep.end["late_events"], 0)

    def test_never_executes_above_tier2_and_never_taps_dangerous_controls(self):
        self.assertEqual(safety_violations(self.ep, 2), [])
        self.assertEqual([r for _, _, r in self.dev.tap_log if r in DANGEROUS_RIDS], [])
        self.assertEqual(self.ep.end["executed_by_tier"].get("3"), None)
        self.assertEqual(self.ep.end["executed_by_tier"].get("4"), None)

    def test_t3_actions_are_queued_for_review_not_executed(self):
        keys = " ".join(q["key"] for q in self.ep.end["escalation_queue"])
        self.assertIn("buy now", keys)
        self.assertGreater(self.ep.end["denied_total"], 0)

    def test_coverage_and_state_dedup(self):
        self.assertGreaterEqual(self.ep.end["n_app_states"], 7)
        self.assertLessEqual(self.ep.end["n_states"], 14)      # volatile clock/'updated' text must not explode states

    def test_leaving_the_app_is_recovered(self):
        foreign = [s for s in self.ep.steps if s.before and s.before.pkg == "com.android.chrome"]
        self.assertTrue(foreign)
        self.assertTrue(all(s.action.origin == "system" for s in foreign))

    def test_forms_use_sandbox_identity_only(self):
        texts = [s.action.text for s in self.ep.steps if s.action.kind == "text"]
        self.assertTrue(texts)
        self.assertTrue(all(t == "test" or "example.invalid" in t or t.startswith("Cr4wl-") for t in texts))

    def test_attribution_vs_ground_truth(self):
        tp = fp = missed = total = 0
        bg_total = bg_hit = 0
        for s in self.ep.steps:
            for e in s.events:
                cause = e.event.detail.get("cause")
                if cause == -1:
                    bg_total += 1
                    bg_hit += e.attribution == A_BACKGROUND
                    continue
                total += 1
                if e.attribution in (A_DIRECT, A_TAIL, A_LAUNCH):
                    if e.action_idx == cause:
                        tp += 1
                    else:
                        fp += 1
                else:
                    missed += 1
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, total)
        self.assertGreaterEqual(precision, 0.95, (tp, fp, missed))
        self.assertGreaterEqual(recall, 0.85, (tp, fp, missed))
        self.assertGreaterEqual(bg_hit / max(1, bg_total), 0.8, (bg_hit, bg_total))

    def test_planted_privacy_bug_visible_in_trace(self):
        denies = [s for s in self.ep.steps if s.meta.get("permission", {}).get("choice") == "deny"]
        self.assertTrue(denies)
        t_deny = denies[0].t_end
        later = [e for s in self.ep.steps for e in s.events if e.event.kind == "loc.read" and e.event.t > t_deny]
        self.assertTrue(later)
        self.assertTrue(any("adsdk" in " ".join(e.event.stack) for e in later))

    def test_deterministic_for_same_seed(self):
        with tempfile.TemporaryDirectory() as t2:
            _, ep2, _ = run_fake(t2, seed=7, steps=50)
        a = [(s.action.key, s.before.hash if s.before else None) for s in self.ep.steps]
        b = [(s.action.key, s.before.hash if s.before else None) for s in ep2.steps]
        self.assertEqual(a, b)

    def test_different_seed_explores_differently(self):
        with tempfile.TemporaryDirectory() as t2:
            _, ep2, _ = run_fake(t2, seed=8, steps=50)
        self.assertNotEqual([s.action.key for s in self.ep.steps], [s.action.key for s in ep2.steps])

    def test_dry_run_never_touches_the_device(self):
        with tempfile.TemporaryDirectory() as t2:
            dev, ep, _ = run_fake(t2, seed=3, steps=10, dry_run=True)
        self.assertEqual(dev.act_log, [])
        self.assertEqual(dev.tap_log, [])
        self.assertEqual(dev.seq, -1)                       # not even launched
        self.assertFalse(any(s.executed for s in ep.steps))
        self.assertEqual(validate_episode(ep), [])

    def test_kill_switch_stops_before_next_action(self):
        with tempfile.TemporaryDirectory() as t2:
            dev, ep, _ = run_fake(t2, seed=7, steps=50, kill=CountdownKill(9))
        self.assertTrue(ep.end["reason"].startswith("kill_switch"))
        self.assertLess(len(ep.steps), 51)
        executed_non_launch = sum(1 for s in ep.steps[1:] if s.executed and s.action.kind != "launch")
        self.assertEqual(len(dev.act_log), executed_non_launch)
        self.assertEqual(validate_episode(ep), [])

    def test_random_policy_also_safe(self):
        with tempfile.TemporaryDirectory() as t2:
            dev, ep, _ = run_fake(t2, seed=5, steps=60, policy="random")
        self.assertEqual(safety_violations(ep, 2), [])
        self.assertEqual([r for _, _, r in dev.tap_log if r in DANGEROUS_RIDS], [])

    def test_llm_policy_with_fallback(self):
        calls = []

        def planner(prompt):
            calls.append(prompt)
            return '{"choice": 0}' if len(calls) % 3 else "garbage"

        with tempfile.TemporaryDirectory() as t2:
            dev, ep, res = run_fake(t2, seed=2, steps=20, policy_obj=LLMPolicy(planner))
            names = {s.policy.get("name") for s in ep.steps[1:]}
            self.assertIn("llm", names)
            self.assertIn("llm.fallback", names)
            from jarvis_crawl.replay import verify_episode
            self.assertTrue(verify_episode(res["episode_path"], t2).ok)

    def test_reward_hook_steers_and_replays(self):
        reward = lambda sid, key, i: 5.0 if "tab_cart" in key else 0.0
        with tempfile.TemporaryDirectory() as t2:
            dev, ep, res = run_fake(t2, seed=4, steps=12, reward_fn=reward)
            self.assertTrue(any("ext" in s.policy for s in ep.steps))
            self.assertTrue(any("tab_cart" in s.action.key for s in ep.steps[:4]))
            from jarvis_crawl.replay import verify_episode
            self.assertTrue(verify_episode(res["episode_path"], t2).ok)


if __name__ == "__main__":
    unittest.main()
