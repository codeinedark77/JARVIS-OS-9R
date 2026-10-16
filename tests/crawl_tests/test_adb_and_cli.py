"""AdbDevice is exercised against a stub `adb` executable: verifies command shapes + output parsing only.
It says nothing about real Android behaviour -- that needs the bring-up checklist in README.md."""
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout

from jarvis_crawl import cli
from jarvis_crawl.device import AdbDevice, JsonlTailSource
from jarvis_crawl.fakeapp import FakeDevice
from jarvis_crawl.schema import Action
from jarvis_crawl.statehash import analyze

STUB = r'''#!/bin/sh
echo "$@" >> "$STUB_LOG"
case "$*" in
  *"exec-out uiautomator dump"*) cat "$STUB_XML"; echo; echo "UI hierchary dumped to: /dev/tty" ;;
  *mCurrentFocus*) [ -z "$STUB_NO_FOCUS" ] && echo "  mCurrentFocus=Window{a1b2c3d u0 com.fake.shop/com.fake.shop.MainActivity}" ;;
  *mResumedActivity*) echo "  mResumedActivity: ActivityRecord{9f u0 com.other.app/.Main t12}" ;;
esac
exit 0
'''


class AdbStubTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.adb = os.path.join(d, "adb")
        with open(self.adb, "w") as f:
            f.write(STUB)
        os.chmod(self.adb, os.stat(self.adb).st_mode | stat.S_IEXEC)
        self.log = os.path.join(d, "log.txt")
        self.xml = os.path.join(d, "ui.xml")
        fake = FakeDevice()
        fake.launch("com.fake.shop")          # home screen, not the bare launcher
        with open(self.xml, "w") as f:
            f.write(fake.dump_ui())
        os.environ.update(STUB_LOG=self.log, STUB_XML=self.xml)
        os.environ.pop("STUB_NO_FOCUS", None)

    def tearDown(self):
        for k in ("STUB_LOG", "STUB_XML", "STUB_NO_FOCUS"):
            os.environ.pop(k, None)
        self.tmp.cleanup()

    def lines(self):
        with open(self.log) as f:
            return f.read().splitlines()

    def test_dump_ui_trims_and_parses(self):
        xml = AdbDevice(serial="S1", adb=self.adb).dump_ui()
        self.assertTrue(xml.startswith("<?xml") and xml.endswith("</hierarchy>"))
        self.assertGreater(analyze(xml).node_count, 5)
        self.assertIn("-s S1 exec-out uiautomator dump /dev/tty", self.lines()[0])

    def test_current_package_both_formats(self):
        d = AdbDevice(adb=self.adb)
        self.assertEqual(d.current_package(), "com.fake.shop")
        os.environ["STUB_NO_FOCUS"] = "1"
        self.assertEqual(d.current_package(), "com.other.app")

    def test_input_commands_and_root_wrapping(self):
        d = AdbDevice(adb=self.adb, root=True)
        d.act(Action("tap", x=10, y=20))
        d.act(Action("swipe", x=1, y=2, x2=3, y2=4))
        d.act(Action("back"))
        d.launch("com.fake.shop")
        d.force_stop("com.fake.shop")
        out = "\n".join(self.lines())
        for needle in ("shell su -c 'input tap 10 20'", "input swipe 1 2 3 4 350", "input keyevent 4",
                       "monkey -p com.fake.shop -c android.intent.category.LAUNCHER 1", "am force-stop com.fake.shop"):
            self.assertIn(needle, out)

    def test_text_input_escaping_and_refusal(self):
        d = AdbDevice(adb=self.adb)
        d.act(Action("text", x=5, y=6, text="Alex Tester"))
        self.assertIn("input text Alex%sTester", "\n".join(self.lines()))
        with self.assertRaises(ValueError):
            d.act(Action("text", x=5, y=6, text="x; rm -rf /"))

    def test_jsonl_tail_waits_for_complete_lines(self):
        p = os.path.join(self.tmp.name, "ev.jsonl")
        src = JsonlTailSource(p)
        self.assertEqual(src.poll(), [])
        with open(p, "w") as f:
            f.write(json.dumps({"t": 1.5, "kind": "loc.read", "target": "gps"}) + "\n" + '{"t": 2.0, "ki')
        got = src.poll()
        self.assertEqual([(e.t, e.kind) for e in got], [(1.5, "loc.read")])
        with open(p, "a") as f:
            f.write('nd": "net.url", "target": "https://a.x/"}\n')
        self.assertEqual([(e.t, e.kind) for e in src.poll()], [(2.0, "net.url")])
        self.assertEqual(src.poll(), [])


class CliTests(unittest.TestCase):
    def test_run_replay_show_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(cli.main(["run", "--device", "fake", "--steps", "15", "--seed", "3", "--out", tmp]), 0)
                self.assertEqual(cli.main(["replay", tmp]), 0)
                self.assertEqual(cli.main(["show", tmp]), 0)
                self.assertEqual(cli.main(["export", tmp, "--out", os.path.join(tmp, "x")]), 0)
            self.assertIn("ok=True", buf.getvalue())
            self.assertTrue(os.path.exists(os.path.join(tmp, "x", "features.jsonl")))

    def test_selftest(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["selftest"]), 0)


if __name__ == "__main__":
    unittest.main()
