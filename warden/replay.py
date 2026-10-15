"""Regression replay: re-score a stored corpus with the current features+model and diff against previous verdicts / labels."""
import json
from collections import Counter

from . import labeling, model
from .schema import load_corpus


def read_verdicts(path):
    out = {}
    try:
        for line in open(path):
            d = json.loads(line)
            out[d["sid"]] = d
    except OSError:
        pass
    return out


def write_verdicts(path, verdicts):
    with open(path, "w") as f:
        for v in verdicts:
            f.write(json.dumps({k: x for k, x in v.items() if not k.startswith("_")}) + "\n")


def replay(corpus, bundle, prev_path=None, labels_root=None):
    sessions = load_corpus(corpus)
    new = [model.score(bundle, s, explain_on=False) for s in sessions]
    prev = read_verdicts(prev_path) if prev_path else {}
    flips, movers = Counter(), []
    for v in new:
        o = prev.get(v["sid"])
        if o and o["class"] != v["class"]:
            flips["%s -> %s" % (o["class"], v["class"])] += 1
        if o:
            movers.append((abs(v["risk"] - o["risk"]), v["sid"], o["risk"], v["risk"]))
    movers.sort(reverse=True)
    acc = None
    lab = labeling.resolve(sessions, labels_root or corpus)
    hand = {sid: l for sid, (l, src) in lab.items() if src == "hand"}
    if hand:
        ok = sum(1 for v in new if v["sid"] in hand and v["class_id"] == hand[v["sid"]])
        acc = {"hand_labeled": len(hand), "correct": ok, "accuracy": ok / len(hand)}
        if prev:
            okp = sum(1 for sid, l in hand.items() if sid in prev and prev[sid]["class_id"] == l)
            acc["prev_accuracy"] = okp / max(sum(1 for sid in hand if sid in prev), 1)
    return {"n": len(new), "compared": len(prev), "flips": dict(flips), "top_risk_moves": movers[:10], "hand_label_accuracy": acc}, new
