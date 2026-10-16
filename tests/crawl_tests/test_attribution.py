import unittest

from jarvis_crawl.attribution import (ActionSpan, AttrConfig, Baseline, attribute_all, attribute_span, event_signature,
                                      host_of)
from jarvis_crawl.schema import (A_BACKGROUND, A_DIRECT, A_IDLE, A_LAUNCH, A_TAIL, HookEvent)

CFG = AttrConfig(tail_s=3.0, launch_window_s=2.5)


def ev(t, kind="net.url", target="https://api.x.example/a"):
    return HookEvent(t=t, kind=kind, target=target)


class AttributionTests(unittest.TestCase):
    def test_host_of(self):
        self.assertEqual(host_of("https://API.x.example:8443/a?b=1"), "api.x.example")
        self.assertEqual(host_of("analytics.x.example:443"), "analytics.x.example")
        self.assertEqual(host_of("x.example"), "x.example")
        self.assertEqual(host_of(""), "")

    def test_signature_normalises_net_targets_only(self):
        self.assertEqual(event_signature(ev(0, "net.url", "https://a.b/c")), event_signature(ev(0, "net.url", "https://a.b/zzz")))
        self.assertNotEqual(event_signature(ev(0, "loc.read", "gps")), event_signature(ev(0, "loc.read", "net")))

    def test_direct_tail_idle(self):
        span = ActionSpan(1, "tap", 10.0, 0.8)
        out = attribute_span(span, [ev(10.1), ev(11.2, target="https://b.x/"), ev(14.5, target="https://c.x/")], None, CFG)
        self.assertEqual([e.attribution for e in out], [A_DIRECT, A_TAIL, A_IDLE])
        self.assertEqual([e.action_idx for e in out], [1, 1, None])
        self.assertGreaterEqual(out[0].confidence, 0.6)
        self.assertLess(out[1].confidence, out[0].confidence)
        self.assertEqual(out[2].confidence, 0.0)

    def test_launch_window(self):
        span = ActionSpan(0, "launch", 100.0, 2.0)
        out = attribute_span(span, [ev(100.5), ev(103.0, target="https://z.x/")], None, CFG)
        self.assertEqual([e.attribution for e in out], [A_LAUNCH, A_TAIL])

    def test_baseline_demotes_background_earliest_first(self):
        base = Baseline(6.0, {"net.connect|analytics.x.example": 3})        # 0.5/s
        span = ActionSpan(2, "tap", 10.0, 0.8)                              # window 3.8s -> expect 1.9 -> demote 2
        evs = [ev(10.1, "net.connect", "analytics.x.example:443"), ev(10.5, "net.connect", "analytics.x.example:443"),
               ev(11.0, "net.connect", "analytics.x.example:443")]
        out = attribute_span(span, evs, base, CFG)
        self.assertEqual([e.attribution for e in out], [A_BACKGROUND, A_BACKGROUND, A_TAIL])
        self.assertAlmostEqual(out[2].confidence, round(0.6 * 2.718281828 ** (-(1.0 - 0.8) / 2.0) * (1 / 3), 4), places=3)

    def test_baseline_needs_min_count(self):
        base = Baseline(6.0, {"net.connect|analytics.x.example": 1})
        out = attribute_span(ActionSpan(1, "tap", 10.0, 0.8),
                             [ev(10.1, "net.connect", "analytics.x.example:443")], base, CFG)
        self.assertEqual(out[0].attribution, A_DIRECT)

    def test_unrelated_signature_untouched_by_baseline(self):
        base = Baseline(6.0, {"net.connect|analytics.x.example": 5})
        out = attribute_span(ActionSpan(1, "tap", 10.0, 0.8), [ev(10.1)], base, CFG)
        self.assertEqual(out[0].attribution, A_DIRECT)

    def test_attribute_all_partitions_by_latest_preceding_action(self):
        spans = [ActionSpan(0, "launch", 0.0, 2.0), ActionSpan(1, "tap", 5.0, 0.8), ActionSpan(2, "tap", 6.0, 0.8)]
        events = [ev(-1.0, target="https://pre.x/"), ev(0.2, target="https://a.x/"), ev(5.3, target="https://b.x/"),
                  ev(6.2, target="https://c.x/")]
        res = attribute_all(spans, events, None, CFG)
        self.assertEqual([len(r) for r in res], [1, 1, 1])                    # pre-launch event dropped
        self.assertEqual(res[2][0].action_idx, 2)

    def test_pure_and_deterministic(self):
        span = ActionSpan(1, "tap", 10.0, 0.8)
        evs = [ev(10.1), ev(10.4, target="https://q.x/"), ev(11.0, "loc.read", "gps")]
        a = [e.to_dict() for e in attribute_span(span, evs, None, CFG)]
        b = [e.to_dict() for e in attribute_span(span, list(reversed(evs)), None, CFG)]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
