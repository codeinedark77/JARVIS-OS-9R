import json, os, pathlib, subprocess, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(*args, ok=True):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, "-m", "warden", *map(str, args)], capture_output=True, text=True, cwd=ROOT, env=env, timeout=240)
    if ok:
        assert r.returncode == 0, r.stderr[-1500:]
    return r


def test_cli_round_trip(tmp_path):
    corpus, model = tmp_path / "c", tmp_path / "m.joblib"
    run("synth", "-n", 6, "--sessions", 2, "--seed", 1, "-o", corpus)
    assert len(list(corpus.glob("*.session.jsonl"))) == 36
    run("weak-label", corpus)
    first = sorted(corpus.glob("*.session.jsonl"))[0]
    sid = first.name[:-len(".session.jsonl")]
    run("label", corpus, "--set", sid, 1, "--note", "t")
    counts = json.loads(run("label", corpus).stdout)
    assert any(k.endswith("/hand") for k in counts)
    run("train", corpus, "-o", model, "--folds", 3, "--metrics-out", tmp_path / "metrics.json")
    metrics = json.loads((tmp_path / "metrics.json").read_text())
    assert metrics["n_sessions"] == 36 and "macro_f1" in metrics
    v = json.loads(run("score", first, "-m", model, "--json", "--report", tmp_path / "r.html").stdout)
    assert v["package"] and 0 <= v["risk"] <= 100 and (tmp_path / "r.html").stat().st_size > 2000
    run("score", corpus, "-m", model, "--export-cypher", tmp_path / "g.cypher")
    assert "MERGE (a:App" in (tmp_path / "g.cypher").read_text()
    q = run("label", corpus, "--queue", 3, "--model", model).stdout.strip().splitlines()
    assert len(q) == 3


def test_cli_errors_are_clean():
    assert run("score", "/nonexistent", ok=False).returncode != 0
    r = run("capture", "-o", "/tmp/x", ok=False)
    assert r.returncode != 0 and "package" in r.stderr.lower()
