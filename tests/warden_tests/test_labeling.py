from warden import labeling
from warden.schema import Session


def test_resolve_precedence_hand_over_meta(tmp_path):
    (tmp_path / "labels.jsonl").write_text('{"sid": "a", "label": 2, "source": "hand"}\n')
    s = Session({"label": 0}, [], str(tmp_path / "a.session.jsonl"))
    lab = labeling.resolve([s], tmp_path)
    assert lab["a"] == (2, "hand")


def test_resolve_meta_used_when_no_hand_label(tmp_path):
    s = Session({"label": 1}, [], str(tmp_path / "b.session.jsonl"))
    lab = labeling.resolve([s], tmp_path)
    assert lab["b"] == (1, "meta")


def test_append_label_is_last_write_wins_for_same_rank(tmp_path):
    labeling.append_label(tmp_path, "x", 0, source="hand")
    labeling.append_label(tmp_path, "x", 2, source="hand")
    lab = labeling.load_label_file(tmp_path)
    assert lab["x"] == (2, "hand")


def test_uncertainty_queue_sorts_by_margin_and_skips_hand_labeled():
    proba = {"a": [0.5, 0.49, 0.01], "b": [0.9, 0.08, 0.02], "c": [0.4, 0.35, 0.25]}
    labels = {"a": (0, "hand")}
    q = labeling.uncertainty_queue(proba, labels, n=5)
    sids = [sid for _, sid, _ in q]
    assert "a" not in sids
    assert sids[0] == "c"           # smallest top1-top2 margin among non-hand-labeled
