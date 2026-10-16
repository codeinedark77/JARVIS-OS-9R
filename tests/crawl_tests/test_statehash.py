import unittest

from jarvis_crawl.fakeapp import PKG, _Builder
from jarvis_crawl.statehash import ScreenIndex, analyze, hamming


def screen(rows=3, title="Shop", clock="12:01", extra_button=False, rid=True, labels=("Home", "Cart", "Profile")):
    b = _Builder()
    r = (lambda x: x) if rid else (lambda x: "")
    items = [b.n("android.view.ViewGroup", (0, 230 + 200 * k, 1080, 430 + 200 * k), [
        b.n("android.widget.TextView", (40, 250 + 200 * k, 800, 330 + 200 * k), rid=r("item_title"), text=f"Product {k * 7}")],
        rid=r("item_row"), clickable=True) for k in range(rows)]
    kids = [b.n("android.widget.TextView", (0, 80, 1080, 150), rid=r("title"), text=title),
            b.n("androidx.recyclerview.widget.RecyclerView", (0, 230, 1080, 2100), items, rid=r("list"), scrollable=True)]
    for i, lab in enumerate(labels):
        kids.append(b.n("android.widget.TextView", (360 * i, 2100, 360 * i + 360, 2400), rid=r(f"tab_{i}"), text=lab, clickable=True))
    if extra_button:
        kids.append(b.n("android.widget.Button", (60, 2000, 1020, 2090), rid=r("btn_extra"), text="Extra", clickable=True))
    sysui = b.n("android.widget.FrameLayout", (0, 0, 1080, 80), [
        b.n("android.widget.TextView", (400, 10, 700, 70), text=clock, pkg="com.android.systemui")], pkg="com.android.systemui")
    root = b.n("android.widget.FrameLayout", (0, 0, 1080, 2400), kids, rid=r("content"))
    return '<?xml version="1.0"?><hierarchy rotation="0">' + sysui + root + "</hierarchy>"


class StateHashTests(unittest.TestCase):
    def test_dynamic_text_and_status_bar_do_not_change_hash(self):
        a = analyze(screen(title="Shop", clock="12:01"))
        b = analyze(screen(title="Shop (3 new)", clock="12:59"))
        self.assertEqual(a.hash, b.hash)

    def test_list_length_collapses(self):
        self.assertEqual(analyze(screen(rows=3)).hash, analyze(screen(rows=9)).hash)

    def test_structure_change_changes_hash(self):
        self.assertNotEqual(analyze(screen()).hash, analyze(screen(extra_button=True)).hash)

    def test_text_fallback_when_no_resource_ids(self):
        a, b = analyze(screen(rid=False)), analyze(screen(rid=False, labels=("Play", "Cart", "Profile")))
        self.assertTrue(a.text_fallback)
        self.assertNotEqual(a.hash, b.hash)                      # labels matter when ids are absent
        c = analyze(screen(rid=False, labels=("Home 2", "Cart", "Profile")))
        d = analyze(screen(rid=False, labels=("Home 7", "Cart", "Profile")))
        self.assertEqual(c.hash, d.hash)                         # ...but digits are masked

    def test_rid_trees_do_not_use_text(self):
        self.assertFalse(analyze(screen()).text_fallback)

    def test_package_is_dominant_window(self):
        self.assertEqual(analyze(screen()).pkg, PKG)

    def test_simhash_near_is_closer_than_far(self):
        base, near = analyze(screen()), analyze(screen(extra_button=True))
        far = analyze(screen(rid=False, labels=("A", "B", "C", "D")))
        self.assertLess(hamming(base.simhash, near.simhash), hamming(base.simhash, far.simhash))

    def test_index_semantics(self):
        idx = ScreenIndex(near_threshold=12)
        s0, new0, _ = idx.observe(analyze(screen()))
        s1, new1, _ = idx.observe(analyze(screen(title="x")))
        self.assertEqual((s0, new0, s1, new1), (0, True, 0, False))
        s2, new2, near = idx.observe(analyze(screen(extra_button=True)))
        self.assertEqual(s2, 1)
        self.assertFalse(new2)
        self.assertEqual(near, 0)
        far = analyze(screen(rid=False, labels=("A", "B", "C", "D")))
        _, new3, _ = idx.observe(far)
        self.assertTrue(new3)


if __name__ == "__main__":
    unittest.main()
