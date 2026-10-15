"""Locate/build the agent bundle. Frida >= 17 needs a compiled bundle (bridges are imported, not built in).
Config is NOT substituted into the bundle (the bundle is a size-prefixed package; editing it corrupts it) —
it is passed through rpc: script.exports_sync.start(cfg) before the app is resumed."""
import pathlib

AGENT_DIR = pathlib.Path(__file__).parent / "agent"

def bundle_path():
    return AGENT_DIR / "agent.bundle.js"

def ensure_bundle(rebuild=False):
    b, src = bundle_path(), AGENT_DIR / "agent.js"
    stale = src.exists() and b.exists() and b.stat().st_mtime + 1 < src.stat().st_mtime
    if rebuild or not b.exists() or stale:
        from .agent import build as _b   # imports frida lazily; needs node_modules/frida-java-bridge in agent/
        _b.build(b)
    return b

def load_source(agent=None, rebuild=False):
    path = pathlib.Path(agent) if agent else ensure_bundle(rebuild)
    return path.read_text()
