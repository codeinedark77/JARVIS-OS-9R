"""Build the agent bundle with frida.Compiler (Frida >= 17: bridges are imported, not bundled in GumJS)."""
import pathlib, sys

def build(out=None):
    import frida
    here = pathlib.Path(__file__).parent
    comp = frida.Compiler()
    bundle = comp.build(str(here / "agent.js"), project_root=str(here))
    out = pathlib.Path(out) if out else here / "agent.bundle.js"
    out.write_text(bundle)
    return out

if __name__ == "__main__":
    p = build(sys.argv[1] if len(sys.argv) > 1 else None)
    print(p, p.stat().st_size, "bytes")
