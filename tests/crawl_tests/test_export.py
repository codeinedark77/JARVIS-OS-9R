import json
import os
import tempfile
import unittest

from jarvis_crawl.export import episode_features, episode_sequence, export_dataset
from jarvis_crawl.schema import (A_BACKGROUND, A_DIRECT, Action, AttributedEvent, Episode, HookEvent, ScreenRef, Step,
                                 flatten_for_trace, read_episode)
from .helpers import run_fake


def ref(i):
    return ScreenRef(i, f"h{i}", "0" * 16, "com.x.app", 10, "r", True)


def step(idx, t, events=(), meta=None):
    s = Step(idx, t, t + 1, ref(idx), Action("tap", key=f"k{idx}"), {"tier": 1, "verdict": "allow"}, True, ref(idx + 1))
    s.meta = meta or {}
    s.events = [AttributedEvent(e, a, idx, c, 0.1) for e, a, c in events]
    return s


class ExportTests(unittest.TestCase):
    def test_sensitive_after_deny_counts_only_later_reads(self):
        early = HookEvent(t=5.0, kind="loc.read", target="gps", stack=["com.x.app.Loc.get"])
        late1 = HookEvent(t=20.0, kind="loc.read", target="gps", stack=["android.location.LocationManager.get", "com.adsdk.t.Collector.run"])
        late2 = HookEvent(t=30.0, kind="net.url", target="https://a.x/")
        ep = Episode(header={"app": "com.x.app", "episode_id": "e"}, steps=[
            step(0, 0.0),
            step(1, 4.0, [(early, A_DIRECT, 0.9)]),
            step(2, 10.0, meta={"permission": {"kind": "loc", "choice": "deny"}}),
            step(3, 19.0, [(late1, A_DIRECT, 0.9)]),
            step(4, 29.0, [(late2, A_DIRECT, 0.9)])], end={"n_app_states": 3, "denied_total": 2, "escalation_queue": []})
        f = episode_features(ep)
        self.assertEqual(f["sensitive_after_deny"], 1)
        self.assertEqual(f["sensitive_after_deny_detail"][0]["caller"], "com.adsdk.t")
        self.assertIn("loc.read", f["sensitive_kinds_seen"])
        self.assertEqual(f["hosts"], ["a.x"])

    def test_background_events_are_not_counted_as_behaviour(self):
        bg = HookEvent(t=1.0, kind="net.connect", target="analytics.x:443")
        ep = Episode(header={"app": "com.x.app"}, steps=[step(0, 0.0, [(bg, A_BACKGROUND, 0.9)])], end={})
        f = episode_features(ep)
        self.assertEqual(f["direct_event_counts"], {})
        self.assertEqual(f["background_event_counts"], {"net.connect": 1})
        self.assertEqual(f["n_hosts"], 0)

    def test_end_to_end_export_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, ep, res = run_fake(tmp, seed=7, steps=50)
            f = episode_features(ep)
            self.assertGreaterEqual(f["sensitive_after_deny"], 1)          # planted bug is found
            self.assertIn("ident.read", f["sensitive_kinds_seen"])
            self.assertGreater(f["third_party_caller_share"], 0)
            self.assertIn("ads.tracker.example", f["hosts"])
            self.assertNotIn("analytics.fakeshop.example", f["hosts"])      # background beacon excluded
            out = os.path.join(tmp, "export")
            m = export_dataset([res["episode_path"]], out)
            self.assertEqual(m["episodes"], 1)
            with open(os.path.join(out, "sequences.jsonl")) as fh:
                seq = json.loads(fh.readline())
            self.assertEqual(len(seq["steps"]), len(ep.steps))
            rec = flatten_for_trace(ep)
            self.assertTrue(any(r["kind"].startswith("crawl.hook.") for r in rec))


if __name__ == "__main__":
    unittest.main()
