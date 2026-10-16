import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis_crawl import statehash
from jarvis_crawl.replay import replay_attribution, replay_decisions, verify_episode
from jarvis_crawl.schema import read_episode
from .helpers import run_fake


def rewrite(path, fn):
    out = []
    with open(path) as f:
        for ln in f:
            out.append(json.dumps(fn(json.loads(ln)), sort_keys=True, separators=(",", ":")))
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        _, self.ep, self.res = run_fake(self.tmp.name, seed=7, steps=40)
        self.path = self.res["episode_path"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_episode_verifies(self):
        rep = verify_episode(self.path, self.tmp.name)
        self.assertTrue(rep.ok, rep.summary())

    def test_tampered_action_detected(self):
        def f(r):
            if r.get("type") == "step" and r["idx"] == 6:
                r["action"]["x"] = (r["action"]["x"] or 0) + 1
            return r
        rewrite(self.path, f)
        rep = verify_episode(self.path, self.tmp.name)
        self.assertFalse(rep.ok)
        self.assertTrue(any("step 6" in m and "action" in m for m in rep.decision_mismatches), rep.decision_mismatches[:3])

    def test_executed_non_allow_detected(self):
        def f(r):
            if r.get("type") == "step" and r["idx"] == 3:
                r["safety"]["verdict"] = "escalate"
                r["safety"]["tier"] = 3
            return r
        rewrite(self.path, f)
        rep = verify_episode(self.path, self.tmp.name)
        self.assertFalse(rep.ok)
        self.assertTrue(any("step 3" in p for p in rep.problems))

    def test_attribution_drift_detected(self):
        def f(r):
            if r.get("type") == "step" and r["events"]:
                r["events"][0]["attr"] = "idle" if r["events"][0]["attr"] != "idle" else "direct"
            return r
        rewrite(self.path, f)
        self.assertTrue(replay_attribution(read_episode(self.path)))

    def test_hash_regression_detected(self):
        real = statehash._token
        with mock.patch.object(statehash, "_token", lambda n, use_text: real(n, use_text) + "~"):
            mism = replay_decisions(read_episode(self.path), self.tmp.name)
        self.assertTrue(mism)
        self.assertTrue(any("before-screen" in m for m in mism))

    def test_safety_rule_regression_detected(self):
        from jarvis_crawl import safety
        with mock.patch.object(safety, "T3_TERMS", safety.T3_TERMS | {"cart"}):
            mism = replay_decisions(read_episode(self.path), self.tmp.name)
        self.assertTrue(mism)

    def test_truncated_file_still_readable(self):
        with open(self.path, "rb") as f:
            raw = f.read()
        with open(self.path, "wb") as f:
            f.write(raw[: len(raw) // 2])
        ep = read_episode(self.path)
        self.assertIsNone(ep.end)
        self.assertGreater(len(ep.steps), 0)


if __name__ == "__main__":
    unittest.main()
