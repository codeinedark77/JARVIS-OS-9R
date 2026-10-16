import os
import tempfile
import unittest

from jarvis_crawl.safety import (KillSwitch, SafetyConfig, SafetyPolicy, SandboxIdentity, field_kind)
from jarvis_crawl.schema import Action, V_ALLOW, V_DENY, V_ESCALATE
from .helpers import node

PKG = "com.fake.shop"
PERM = "com.google.android.permissioncontroller"


def pol(**kw):
    return SafetyPolicy(SafetyConfig(allowed_packages=frozenset({PKG}), **kw))


def tap(p, n, label="", screen=PKG, counters=None):
    return p.evaluate(Action("tap"), n, label, screen, counters)


class SafetyTests(unittest.TestCase):
    def test_benign_navigation_allowed(self):
        d = tap(pol(), node("Settings", "btn_settings"))
        self.assertEqual((d.tier, d.verdict), (1, V_ALLOW))

    def test_consequential_terms_escalate(self):
        for text, rid in (("Buy now", "btn_buy_now"), ("", "btn_checkout"), ("Share", ""), ("Create account", ""),
                          ("Log out", ""), ("Send", ""), ("Confirm", "")):
            d = tap(pol(), node(text, rid))
            self.assertEqual((d.tier, d.verdict), (3, V_ESCALATE), (text, rid))

    def test_label_of_descendants_counts(self):
        d = tap(pol(), node("", "row", cls="android.view.ViewGroup"), label="Buy now")
        self.assertEqual(d.verdict, V_ESCALATE)

    def test_forbidden_terms_deny(self):
        for text in ("Delete account", "Factory reset", "Uninstall", "Emergency call"):
            d = tap(pol(), node(text))
            self.assertEqual((d.tier, d.verdict), (4, V_DENY), text)

    def test_benign_phrases_and_word_boundaries(self):
        for text in ("Order history", "Payment methods", "Sender info", "Posts", "Add to cart", "Location sharing"):
            self.assertEqual(tap(pol(), node(text)).verdict, V_ALLOW, text)

    def test_foreign_node_and_screen_denied(self):
        self.assertEqual(tap(pol(), node("Open", pkg="com.evil")).verdict, V_DENY)
        self.assertEqual(tap(pol(), node("Open"), screen="com.android.chrome").verdict, V_DENY)

    def test_system_actions(self):
        p = pol()
        self.assertEqual(p.evaluate(Action("back"), None, "", "com.android.chrome").verdict, V_ALLOW)
        self.assertEqual(p.evaluate(Action("launch", pkg=PKG), None, "", "com.android.launcher3").verdict, V_ALLOW)
        self.assertEqual(p.evaluate(Action("launch", pkg="com.other"), None, "", PKG).verdict, V_DENY)
        self.assertEqual(p.evaluate(Action("home"), None, "", PKG).verdict, V_DENY)
        self.assertEqual(pol(allow_leave_app=True).evaluate(Action("home"), None, "", PKG).verdict, V_ALLOW)
        self.assertEqual(p.evaluate(Action("tap"), None, "", PKG).verdict, V_DENY)          # untargeted
        self.assertEqual(p.evaluate(Action("nuke"), None, "", PKG).verdict, V_DENY)

    def test_permission_dialog_modes(self):
        allow = node("While using the app", PERM + ":id/permission_allow_foreground_only_button", pkg=PERM)
        deny = node("Don't allow", PERM + ":id/permission_deny_button", pkg=PERM)
        weird = node("Learn more", PERM + ":id/learn_more", pkg=PERM)
        p = pol()
        self.assertEqual(tap(p, allow, screen=PERM).verdict, V_ESCALATE)
        self.assertEqual(tap(p, deny, screen=PERM).verdict, V_ALLOW)
        self.assertEqual(tap(p, weird, screen=PERM).verdict, V_DENY)
        g = pol(permission_mode="grant")
        d = tap(g, allow, screen=PERM)
        self.assertEqual((d.tier, d.verdict), (2, V_ALLOW))

    def test_in_app_allow_button_follows_mode(self):
        self.assertEqual(tap(pol(), node("Allow notifications")).verdict, V_ESCALATE)
        self.assertEqual(tap(pol(permission_mode="grant"), node("Allow notifications")).verdict, V_ALLOW)

    def test_text_input_rules(self):
        p = pol()
        f = node("Email", "field_email", cls="android.widget.EditText", editable=True)
        self.assertEqual(p.evaluate(Action("text"), f, "", PKG).tier, 2)
        self.assertEqual(p.evaluate(Action("text"), f, "", PKG).verdict, V_ALLOW)
        card = node("Card number", "field_cc", cls="android.widget.EditText", editable=True)
        self.assertEqual(p.evaluate(Action("text"), card, "", PKG).verdict, V_DENY)
        capped = p.evaluate(Action("text"), f, "", PKG, {"text_inputs": 12})
        self.assertEqual(capped.verdict, V_DENY)
        self.assertIn("cap:text_inputs", capped.reasons)
        self.assertEqual(p.evaluate(Action("tap"), node("Go"), "", PKG, {"actions": 500}).verdict, V_DENY)

    def test_tier_ceiling_is_configurable_but_t4_never(self):
        p = pol(max_autonomous_tier=3)
        self.assertEqual(tap(p, node("Buy now")).verdict, V_ALLOW)
        self.assertEqual(tap(p, node("Delete account")).verdict, V_DENY)

    def test_extra_terms(self):
        p = pol(extra_t4=frozenset({"vote"}), extra_t3=frozenset({"fave"}))
        self.assertEqual(tap(p, node("Vote")).verdict, V_DENY)
        self.assertEqual(tap(p, node("Fave")).verdict, V_ESCALATE)

    def test_kill_switch_paths(self):
        k = KillSwitch()
        self.assertIsNone(k.tripped())
        k.trip("test")
        self.assertEqual(k.tripped(), "test")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "STOP")
            k2 = KillSwitch(path=path)
            self.assertIsNone(k2.tripped())
            open(path, "w").close()
            self.assertTrue(k2.tripped().startswith("file:"))
        os.environ["JARVIS_CRAWL_KILL"] = "1"
        try:
            self.assertEqual(KillSwitch().tripped(), "env")
        finally:
            del os.environ["JARVIS_CRAWL_KILL"]

    def test_identity_is_synthetic_and_deterministic(self):
        a, b, c = SandboxIdentity(5), SandboxIdentity(5), SandboxIdentity(6)
        self.assertEqual(a.email, b.email)
        self.assertNotEqual(a.email, c.email)
        self.assertTrue(a.email.endswith("@example.invalid"))
        self.assertTrue(a.phone.startswith("555010"))
        self.assertRegex(a.password, r"^[A-Za-z0-9-]+$")      # safe for `adb input text`

    def test_field_kind(self):
        self.assertEqual(field_kind(node("Email", "field_email", editable=True)), "email")
        self.assertEqual(field_kind(node("", "pw", password=True, editable=True)), "password")
        self.assertEqual(field_kind(node("Search", "q", editable=True)), "search")
        self.assertEqual(field_kind(node("Zip", "", editable=True)), "zip")


if __name__ == "__main__":
    unittest.main()
