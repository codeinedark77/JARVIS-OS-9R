"""Agent checks. The integration test runs the REAL compiled agent under real Frida against a local Linux process (native layer only;
the Java layer needs ART and is only exercised on a device). Skipped automatically if Frida can't spawn/attach here (e.g. ptrace blocked)."""
import shutil, subprocess, sys, time

import pytest

from warden import agentsrc


def test_agent_source_is_valid_esm():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    src = (agentsrc.AGENT_DIR / "agent.js").read_text()
    r = subprocess.run([node, "--check", "--input-type=module"], input=src, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_bundle_present_and_exposes_rpc():
    b = agentsrc.bundle_path()
    assert b.exists() and b.stat().st_size > 10000
    txt = b.read_text()
    assert "rpc.exports" in txt and "start(cfg)" in txt


def test_agent_native_layer_live():
    frida = pytest.importorskip("frida")
    code = ("import socket,time\ntime.sleep(0.8)\ns=socket.socket();s.settimeout(0.15)\n"
            "try: s.connect(('198.51.100.7',443))\nexcept Exception: pass\n"
            "try: socket.getaddrinfo('tracker.example.test',443)\nexcept Exception: pass\n"
            "try: open('/system/xbin/su')\nexcept Exception: pass\ntime.sleep(4)\n")
    try:
        dev = frida.get_local_device()
        pid = dev.spawn([sys.executable, "-c", code])
        sess = dev.attach(pid)
    except Exception as e:
        pytest.skip("frida cannot spawn/attach locally: %s" % e)
    msgs = []
    try:
        scr = sess.create_script(agentsrc.load_source())
        scr.on("message", lambda m, d: msgs.append(m))
        scr.load()
        info = scr.exports_sync.start({"profile": "native"})
        assert info["java"] is False
        dev.resume(pid)
        time.sleep(2.6)
        scr.exports_sync.flush()
        stats = scr.exports_sync.stats()
    finally:
        try:
            dev.kill(pid)
        except Exception:
            pass
    ev = [e for m in msgs if m["type"] == "send" and m["payload"]["type"] == "batch" for e in m["payload"]["events"]]
    apis = {(e["api"], e["arg"]) for e in ev}
    assert ("native.connect", "198.51.100.7:443") in apis
    assert ("native.getaddrinfo", "tracker.example.test") in apis
    assert ("native.open", "/system/xbin/su") in apis
    assert stats["hooks"]["native_ok"] >= 8 and all(e["cat"] for e in ev)
