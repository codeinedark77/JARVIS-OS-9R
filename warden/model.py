"""Train / evaluate / score. Calibrated gradient boosting + isolation-forest novelty flag, group-aware CV (no app leakage)."""
import hashlib, json, time
from collections import Counter

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix, f1_score, precision_recall_curve
from sklearn.model_selection import StratifiedGroupKFold

from . import explain, features, trackers
from .schema import SCHEMA

CLASSES = {0: "benign", 1: "tracker/sdk-leaky", 2: "malicious-shaped"}


def _clf(seed, n=None):
    # HistGradientBoosting's default min_samples_leaf=20 makes trees unable to split below ~40 samples -> silent constant predictor.
    leaf = 20 if n is None else max(2, min(20, n // 10))
    return HistGradientBoostingClassifier(max_depth=5, learning_rate=0.08, max_iter=200, l2_regularization=1.0, min_samples_leaf=leaf, class_weight="balanced", random_state=seed)


def _fit(X, y, seed, calibrate):
    clf = _clf(seed, len(y))
    mdl = CalibratedClassifierCV(estimator=clf, method="sigmoid", cv=3) if calibrate else clf
    return mdl.fit(X, y)


def _proba(mdl, X):
    p = mdl.predict_proba(X)
    out = np.zeros((len(X), 3))
    for j, c in enumerate(mdl.classes_):
        out[:, int(c)] = p[:, j]
    return out


def dataset(sessions, labels, m=None):
    ks = features.keys()
    rows, y, groups, sids, src = [], [], [], [], []
    for s in sessions:
        lab = labels.get(s.sid)
        if lab is None:
            continue
        f = features.featurize(s, m)
        rows.append([f[k] for k in ks]); y.append(lab[0]); groups.append(s.package or s.sid); sids.append(s.sid); src.append(lab[1])
    return np.array(rows), np.array(y), np.array(groups), sids, ks, src


def train(sessions, labels, seed=0, n_splits=5, calibrate=True, m=None, log=print):
    X, y, groups, sids, ks, src = dataset(sessions, labels, m)
    if len(set(y)) < 2:
        raise ValueError("need at least two label classes to train (have %s)" % sorted(set(y)))
    smallest = min(Counter(y).values())
    if smallest < 30:
        log("WARNING: smallest class has only %d sessions; metrics are noisy and the model will be weak. Capture/label more before trusting it." % smallest)
    n_groups = {c: len(set(groups[y == c])) for c in set(y)}
    n_splits = max(2, min(n_splits, min(n_groups.values())))
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    oof = np.zeros((len(y), 3))
    first = None
    for k, (tr, te) in enumerate(cv.split(X, y, groups)):
        mdl = _fit(X[tr], y[tr], seed, calibrate and min(Counter(y[tr]).values()) >= 3)
        oof[te] = _proba(mdl, X[te])
        if first is None:
            first = (tr, te)
    pred = oof.argmax(1)
    present = sorted(set(y))
    rep = classification_report(y, pred, labels=present, target_names=[CLASSES[i] for i in present], output_dict=True, zero_division=0)
    cm = confusion_matrix(y, pred, labels=[0, 1, 2]).tolist()
    ap = {CLASSES[c]: float(average_precision_score(y == c, oof[:, c])) for c in present}
    alert_thr, alert_prec, alert_rec = 0.5, None, None
    if 2 in present:
        pr, rc, th = precision_recall_curve(y == 2, oof[:, 2])
        ok = [i for i in range(len(th)) if pr[i] >= 0.90]
        if ok:
            i = ok[0]; alert_thr, alert_prec, alert_rec = float(th[i]), float(pr[i]), float(rc[i])
    final = _fit(X, y, seed, calibrate and min(Counter(y).values()) >= 3)
    benign = X[y == 0] if (y == 0).any() else X
    iso = IsolationForest(n_estimators=200, random_state=seed).fit(benign)
    iso_thr = float(np.percentile(iso.score_samples(benign), 2))
    imp = []
    try:
        tr, te = first
        base = _clf(seed, len(tr)).fit(X[tr], y[tr])
        pi = permutation_importance(base, X[te], y[te], n_repeats=4, random_state=seed, scoring="f1_macro")
        imp = sorted(zip(ks, pi.importances_mean.tolist()), key=lambda kv: -kv[1])[:20]
    except Exception:
        pass
    trained_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    model_id = hashlib.sha1((",".join(ks) + trained_at + str(len(y))).encode()).hexdigest()[:10]
    metrics = {"n_sessions": int(len(y)), "n_packages": int(len(set(groups))), "label_sources": dict(Counter(src)), "class_counts": {CLASSES[int(c)]: int((y == c).sum()) for c in present},
               "cv": "StratifiedGroupKFold(%d), grouped by package" % n_splits, "report": rep, "confusion[benign,sdk,malicious]": cm, "macro_f1": float(f1_score(y, pred, average="macro")),
               "avg_precision": ap, "alert": {"thr_p_malicious": alert_thr, "oof_precision": alert_prec, "oof_recall": alert_rec},
               "perm_importance_top20(single fold)": imp}
    bundle = {"clf": final, "iso": iso, "iso_thr": iso_thr, "keys": ks, "median": np.median(benign, axis=0), "alert_thr": alert_thr, "classes": CLASSES,
              "feature_version": features.FEATURE_VERSION, "schema": SCHEMA, "trained_at": trained_at, "model_id": model_id, "metrics": metrics}
    log("macro-F1 %.3f | n=%d sessions / %d packages | %s" % (metrics["macro_f1"], len(y), len(set(groups)), metrics["cv"]))
    log(classification_report(y, pred, labels=present, target_names=[CLASSES[i] for i in present], digits=3, zero_division=0))
    log("confusion [rows=true, cols=pred]:\n%s" % np.array(cm))
    return bundle, oof, (sids, y)


def save(bundle, path):
    joblib.dump(bundle, path, compress=3)


def load(path):
    b = joblib.load(path)
    if b.get("feature_version") != features.FEATURE_VERSION:
        raise ValueError("model feature_version %s != code %s: retrain" % (b.get("feature_version"), features.FEATURE_VERSION))
    return b


def score(bundle, sess, m=None, explain_on=True):
    m = m or trackers.matcher()
    f = features.featurize(sess, m)
    vec = np.array([f.get(k, 0.0) for k in bundle["keys"]])
    pred = lambda v: _proba(bundle["clf"], v.reshape(1, -1))[0]
    p = pred(vec)
    cls = int(p.argmax())
    anomaly = float(bundle["iso"].score_samples(vec.reshape(1, -1))[0])
    out = {"sid": sess.sid, "package": sess.package, "class_id": cls, "class": CLASSES[cls], "proba": {CLASSES[i]: round(float(p[i]), 4) for i in range(3)},
           "risk": int(round(100 * min(1.0, 0.35 * p[1] + p[2]))), "alert": bool(p[2] >= bundle["alert_thr"]), "novel": bool(anomaly < bundle["iso_thr"]),
           "anomaly": round(anomaly, 4), "model_id": bundle["model_id"], "schema": bundle["schema"]}
    if explain_on:
        evd = explain.evidence(sess, m)
        out["reasons"] = explain.reasons(f, evd)
        _, groups = explain.group_occlusion(bundle, vec, pred)
        out["top_groups"] = [(g, round(d, 3)) for g, d in groups[:3]]
        out["top_features"] = [(k, round(v, 3), round(d, 3)) for k, v, d in explain.feature_occlusion(bundle, vec, pred, {g for g, _ in groups[:2]})]
        out["_evidence"] = evd
    return out
