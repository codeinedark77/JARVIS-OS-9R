import http.server, json, threading
from html.parser import HTMLParser

import pytest

from warden import export, labeling, model, replay, report, synth
from warden.schema import Session, dump_session


@pytest.fixture(scope="module")
def trained():
    S = synth.make(14, 2, seed=5)
    lab = labeling.resolve(S, None)
    b, oof, _ = model.train(S, lab, seed=0, n_splits=3, log=lambda *a: None)
    return S, b


class _Bal(HTMLParser):
    VOID = {"meta", "br", "line", "rect", "circle", "input", "link"}

    def __init__(self):
        super().__init__(); self.stack, self.err = [], []

    def handle_starttag(self, t, a):
        if t not in self.VOID:
            self.stack.append(t)

    def handle_endtag(self, t):
        if t in self.VOID:
            return
        if self.stack and self.stack[-1] == t:
            self.stack.pop()
        else:
            self.err.append(t)


def test_score_shape_and_probabilities(trained):
    S, b = trained
    v = model.score(b, S[0])
    assert {"class", "risk", "alert", "novel", "proba", "reasons", "top_groups", "model_id"} <= set(v)
    assert abs(sum(v["proba"].values()) - 1.0) < 0.01
    assert 0 <= v["risk"] <= 100


def test_malicious_sessions_outscore_benign_on_average(trained):
    S, b = trained
    mal = [model.score(b, s, explain_on=False)["risk"] for s in S if s.meta["label"] == 2][:10]
    ben = [model.score(b, s, explain_on=False)["risk"] for s in S if s.meta["label"] == 0][:10]
    assert sum(mal) / len(mal) > sum(ben) / len(ben) + 30


def test_save_load_roundtrip_and_version_guard(trained, tmp_path):
    S, b = trained
    p = tmp_path / "m.joblib"
    model.save(b, p)
    b2 = model.load(p)
    assert model.score(b2, S[3], explain_on=False)["risk"] == model.score(b, S[3], explain_on=False)["risk"]
    model.save(dict(b, feature_version=999), p)
    with pytest.raises(ValueError, match="retrain"):
        model.load(p)


def test_train_requires_two_classes():
    S = [s for s in synth.make(4, 1, seed=1) if s.meta["label"] == 0]
    with pytest.raises(ValueError):
        model.train(S, labeling.resolve(S, None), log=lambda *a: None)


def test_group_cv_never_splits_a_package_across_folds():
    from sklearn.model_selection import StratifiedGroupKFold
    import numpy as np
    S = synth.make(8, 3, seed=2)
    groups = np.array([s.package for s in S]); y = np.array([s.meta["label"] for s in S])
    for tr, te in StratifiedGroupKFold(3, shuffle=True, random_state=0).split(np.zeros(len(y)), y, groups):
        assert not (set(groups[tr]) & set(groups[te]))


def test_report_is_balanced_and_escapes_untrusted_strings(trained):
    S, b = trained
    evil = '"><script>alert(1)</script>'
    s = Session({"package": "com.evil" + evil}, [{"t": 1, "api": "x." + evil, "cat": "network", "arg": evil, "caller": "com.x." + evil, "fg": 1},
                                                  {"t": 2, "api": "y", "cat": "dyn_code", "arg": "/data/data/" + evil, "caller": "c", "fg": 0}])
    html = report.render(s, model.score(b, s))
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
    p = _Bal(); p.feed(html)
    assert not p.err and not p.stack


def test_corpus_index_written(trained, tmp_path):
    S, b = trained
    V = [model.score(b, s) for s in S[:5]]
    idx = report.write_corpus(S[:5], V, tmp_path)
    assert idx.exists() and len(list(tmp_path.glob("*.html"))) == 6


def test_cypher_quoting_is_injection_safe(trained):
    S, b = trained
    s = Session({"package": "com.o'brien\\app"}, [{"t": 1, "api": "x", "cat": "network", "arg": "evil'host\n}) DETACH DELETE (n //", "caller": "?", "fg": 1}])
    v = model.score(b, s)
    cy = export.to_cypher([v])
    assert "com.o\\'brien\\\\app" in cy
    for line in cy.splitlines():
        if line.startswith("MERGE"):
            assert line.count("'") % 2 == 0 or "\\'" in line       # no unescaped quote can terminate a literal early
            assert "\n" not in line


def test_webhook_posts_json_without_private_fields(trained):
    S, b = trained
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            got["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            got["tok"] = self.headers.get("X-Warden-Token")
            self.send_response(200); self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert export.post_webhook("http://127.0.0.1:%d/h" % srv.server_port, model.score(b, S[0]), token="t0k") == 200
    finally:
        srv.shutdown()
    assert got["tok"] == "t0k" and "_evidence" not in got["body"] and "hosts" in got["body"]


def test_replay_detects_flips(trained, tmp_path):
    S, b = trained
    for s in S[:6]:
        dump_session(tmp_path / ("%s.session.jsonl" % s.sid), s.meta, s.events)
    summary, verdicts = replay.replay(tmp_path, b)
    assert summary["n"] == 6 and summary["flips"] == {}
    prev = tmp_path / "prev.jsonl"
    replay.write_verdicts(prev, verdicts)
    lines = [json.loads(l) for l in prev.read_text().splitlines()]
    lines[0]["class"], lines[0]["class_id"] = ("benign" if lines[0]["class_id"] != 0 else "malicious-shaped"), 0 if lines[0]["class_id"] != 0 else 2
    prev.write_text("\n".join(json.dumps(l) for l in lines) + "\n")
    summary2, _ = replay.replay(tmp_path, b, prev_path=prev)
    assert sum(summary2["flips"].values()) == 1


def test_tiny_corpus_does_not_collapse_to_a_constant_predictor():
    """Regression: HistGradientBoosting min_samples_leaf=20 silently produced one-class output on ~36 sessions (macro-F1 0.167)."""
    S = synth.make(6, 2, seed=3)
    logs = []
    b, oof, _ = model.train(S, labeling.resolve(S, None), seed=0, n_splits=3, log=logs.append)
    assert len(set(oof.argmax(1))) == 3
    assert b["metrics"]["macro_f1"] > 0.5
    assert any("WARNING" in l for l in logs)
