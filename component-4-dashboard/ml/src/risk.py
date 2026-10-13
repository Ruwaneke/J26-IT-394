"""Phase 3: classify each developer's FUTURE behaviour risk as LOW / MEDIUM / HIGH.

This is a research risk profile based on measured behaviour, never a
judgment of the person. All results come from SIMULATED data.

Rows and labels
---------------
One row per developer per origin week t in 6..12.
- Features use weeks <= t only. The developer's weekly arrays are cut at week
  t before any feature is computed, so a later week cannot leak in.
- The label uses weeks t+1..t+4 only. The label is the developer's FUTURE
  behaviour. If the label came from the same weeks as the features, the model
  would just relearn the scoring formula from its own inputs.

Future risk score (computed on weeks t+1..t+4, pooled over the 4 weeks):
    0.4 * severity-weighted ignore rate   (ignored severity weight / total severity weight)
  + 0.3 * (1 - fix rate)
  + 0.2 * normalised repeat rate         (repeat_count / vuln_count, min-max scaled)
  + 0.1 * normalised log response time   (log1p of mean seconds, min-max scaled)
Min-max constants come from TRAIN developers only. The score is banded with
thresholds frozen in config.yaml. They were chosen once as the 40th/80th
percentiles of the train-developer scores, so about 40% LOW, 40% MEDIUM and
20% HIGH. Rows whose label window has no detections have no score and are
dropped (and counted).

Split
-----
12 developers are held out as the final test set, stratified by simulated
archetype. The archetype is used for this split only and is never a feature.
The other 48 developers are used for tuning with GroupKFold(5): all rows of a
developer stay in one fold, so the model is always scored on developers it has
never seen. Inside each training fold, 20% of developers are set aside for
XGBoost early stopping.

Models
------
- XGBoost multiclass (softprob) with balanced class weights, tuned by CV macro F1.
- Baselines: majority class; the proposal's static fix-rate rule; persistence
  (the same risk score on weeks t-3..t, banded with the same thresholds:
  "the next 4 weeks look like the last 4"); multinomial logistic regression on
  the same features.
"""

import argparse
import csv
import itertools
import json

import numpy as np
import pandas as pd
import shap
from scipy.stats import binomtest
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from .config import load_config, resolve
from .features import type_column
from .trends import ols_slope

BANDS = ["LOW", "MEDIUM", "HIGH"]
BASE_METRICS = ["fix_rate", "ignore_rate", "false_positive_rate", "repeat_rate",
                "severity_weighted_load", "high_severity_share", "log_response_time", "vuln_count"]
SUM_COLUMNS = ["vuln_count", "n_fixed", "n_ignored", "n_false_positive", "repeat_count",
               "severity_weighted_load", "ignored_severity_load", "n_high_severity"]
SIMULATED_NOTE = "Simulated data generated from stated assumptions; not real developer data."
FRAMING = "Research risk profile based on measured behaviour; not a judgment of the person."
METRIC_WORDS = {
    "fix_rate": "fix rate", "ignore_rate": "ignore rate", "false_positive_rate": "false-positive rate",
    "repeat_rate": "repeat rate", "severity_weighted_load": "severity-weighted load",
    "high_severity_share": "share of high-severity findings", "log_response_time": "response time",
    "vuln_count": "weekly findings",
}


# ---------------------------------------------------------------- weekly arrays and window statistics

def developer_arrays(dw, cfg):
    """dict developer_id -> dict of weekly numpy arrays (index 0 = week 1)."""
    df = dw.sort_values(["developer_id", "week"]).copy()
    df["response_total"] = df["avg_response_time"].fillna(0) * df["vuln_count"]
    df["active"] = df["active"].astype(float)
    cols = SUM_COLUMNS + ["response_total", "active"] + [type_column(v) for v in cfg["vulnerability_types"]]
    return {dev: {c: g[c].to_numpy(dtype=float) for c in cols} for dev, g in df.groupby("developer_id")}


def cut(arrays, last_week):
    """Keep weeks 1..last_week only. Features are always computed on a cut copy."""
    return {k: v[:last_week] for k, v in arrays.items()}


def window_stats(a, first, last):
    """Pooled statistics over weeks first..last (1-based, inclusive). Rates are NaN with no detections."""
    sl = slice(max(first, 1) - 1, last)
    s = {k: v[sl].sum() for k, v in a.items()}
    n_weeks = max(len(a["vuln_count"][sl]), 1)
    vc = s["vuln_count"]

    def rate(num, den):
        return num / den if den > 0 else np.nan

    return {
        "fix_rate": rate(s["n_fixed"], vc),
        "ignore_rate": rate(s["n_ignored"], vc),
        "false_positive_rate": rate(s["n_false_positive"], vc),
        "repeat_rate": rate(s["repeat_count"], vc),
        "high_severity_share": rate(s["n_high_severity"], vc),
        "log_response_time": np.log1p(s["response_total"] / vc) if vc > 0 else np.nan,
        "severity_weighted_ignore_rate": rate(s["ignored_severity_load"], s["severity_weighted_load"]),
        "severity_weighted_load": s["severity_weighted_load"] / n_weeks,
        "vuln_count": vc / n_weeks,
    }


def features_at(arrays, t, vtypes):
    """Feature dict for origin t. Uses ONLY weeks <= t (the arrays are cut first)."""
    a = cut(arrays, t)
    last4, history = window_stats(a, t - 3, t), window_stats(a, 1, t)
    feats = {}
    for m in BASE_METRICS:
        feats[f"{m}_last4"] = last4[m]
        feats[f"{m}_all"] = history[m]
        weekly = np.array([window_stats(a, w, w)[m] for w in range(max(1, t - 3), t + 1)])
        feats[f"{m}_slope4"] = ols_slope(weekly) if np.sum(~np.isnan(weekly)) >= 3 else np.nan
    total = a["vuln_count"].sum()
    for v in vtypes:
        feats[f"share_{v.lower()}"] = a[type_column(v)].sum() / total if total > 0 else np.nan
    active = np.flatnonzero(a["active"] > 0)
    feats["active_week_ratio"] = a["active"].mean()
    feats["weeks_since_first_activity"] = float(t - active[0]) if len(active) else 0.0
    return feats


def score_components(arrays, first, last):
    s = window_stats(arrays, first, last)
    return {k: s[k] for k in ("severity_weighted_ignore_rate", "fix_rate", "repeat_rate", "log_response_time")}


class Normaliser:
    """Min-max scaling of repeat rate and log response time, fitted on TRAIN developers only."""

    def __init__(self, components):
        df = pd.DataFrame(components)
        self.bounds = {c: (float(df[c].min()), float(df[c].max())) for c in ("repeat_rate", "log_response_time")}

    def __call__(self, name, x):
        lo, hi = self.bounds[name]
        return float(np.clip((x - lo) / (hi - lo), 0, 1)) if hi > lo else 0.0


def risk_score(comp, norm, weights):
    """Weighted risk score in [0, 1]; NaN when the window had no detections."""
    if any(np.isnan(v) for v in comp.values()):
        return np.nan
    return (weights["severity_weighted_ignore_rate"] * comp["severity_weighted_ignore_rate"]
            + weights["one_minus_fix_rate"] * (1 - comp["fix_rate"])
            + weights["normalised_repeat_rate"] * norm("repeat_rate", comp["repeat_rate"])
            + weights["normalised_log_response_time"] * norm("log_response_time", comp["log_response_time"]))


def to_band(score, thresholds):
    """0 = LOW, 1 = MEDIUM, 2 = HIGH."""
    return 2 if score >= thresholds["high"] else 1 if score >= thresholds["medium"] else 0


def fix_rate_rule(fix_rate, rule):
    """Proposal baseline. A developer with no findings yet has no fix rate and is treated as LOW."""
    if np.isnan(fix_rate):
        return 0
    return 2 if fix_rate < rule["high_below"] else 1 if fix_rate < rule["medium_below"] else 0


# ---------------------------------------------------------------- rows

def build_rows(arrays, origins, cfg):
    """One row per (developer, origin): features, future label components, persistence components."""
    rc = cfg["risk"]
    rows = []
    for dev, a in arrays.items():
        n_weeks = len(a["vuln_count"])
        for t in origins:
            row = {"developer_id": dev, "origin": t, **features_at(a, t, cfg["vulnerability_types"])}
            if t + rc["label_weeks"] <= n_weeks:
                future = {k: v[t:t + rc["label_weeks"]] for k, v in a.items()}  # weeks t+1..t+4 only
                row.update({f"label_{k}": v for k, v in score_components(future, 1, rc["label_weeks"]).items()})
            past = cut(a, t)
            row.update({f"persist_{k}": v for k, v in
                        score_components(past, t - rc["persistence_weeks"] + 1, t).items()})
            row.update({f"history_{k}": v for k, v in score_components(past, 1, t).items()})
            rows.append(row)
    return pd.DataFrame(rows)


def components(df, prefix):
    keys = ("severity_weighted_ignore_rate", "fix_rate", "repeat_rate", "log_response_time")
    return [{k: r[f"{prefix}_{k}"] for k in keys} for _, r in df.iterrows()]


def feature_columns(df):
    skip = ("developer_id", "origin", "label_", "persist_", "history_", "score", "y")
    return [c for c in df.columns if not c.startswith(skip)]


def holdout_split(dev_ids, archetypes, n_test, seed):
    """Stratified by simulated archetype (used for this split only)."""
    strata = [archetypes[d] for d in dev_ids]
    train, test = train_test_split(sorted(dev_ids), test_size=n_test, stratify=strata, random_state=seed)
    return sorted(train), sorted(test)


# ---------------------------------------------------------------- models

def fit_xgb(X, y, groups, params, cfg, seed):
    """XGBoost with balanced class weights and early stopping on an inner developer split."""
    rc = cfg["risk"]
    inner = GroupShuffleSplit(n_splits=1, test_size=rc["inner_val_fraction"], random_state=seed)
    tr, va = next(inner.split(X, y, groups))
    model = XGBClassifier(objective="multi:softprob", num_class=3, eval_metric="mlogloss",
                          tree_method="hist", early_stopping_rounds=rc["early_stopping_rounds"],
                          random_state=seed, n_jobs=1, **params)
    model.fit(X.iloc[tr], y[tr], sample_weight=compute_sample_weight("balanced", y[tr]),
              eval_set=[(X.iloc[va], y[va])], verbose=False)
    return model


def fit_xgb_fixed(X, y, params, n_trees, seed):
    """Refit without early stopping for a fixed number of trees (deployment)."""
    p = dict(params, n_estimators=n_trees)
    model = XGBClassifier(objective="multi:softprob", num_class=3, eval_metric="mlogloss",
                          tree_method="hist", random_state=seed, n_jobs=1, **p)
    model.fit(X, y, sample_weight=compute_sample_weight("balanced", y), verbose=False)
    return model


def fit_logreg(X, y, C, seed):
    """Multinomial logistic regression; median imputation and scaling fitted inside the pipeline."""
    model = make_pipeline(SimpleImputer(strategy="median"), StandardScaler(),
                          LogisticRegression(C=C, class_weight="balanced", max_iter=5000, random_state=seed))
    return model.fit(X, y)


def baseline_predictions(df, cfg, thresholds, norm, majority):
    """Majority, fix-rate rule and persistence predictions for the rows in df."""
    rc = cfg["risk"]
    w = rc["score_weights"]
    persistence = []
    for p, h in zip(components(df, "persist"), components(df, "history")):
        s = risk_score(p, norm, w)
        if np.isnan(s):
            s = risk_score(h, norm, w)  # no findings in the last 4 weeks: use all history
        persistence.append(majority if np.isnan(s) else to_band(s, thresholds))
    return {
        "majority": np.full(len(df), majority),
        "fix_rate_rule": np.array([fix_rate_rule(f, rc["fix_rate_rule"]) for f in df["fix_rate_all"]]),
        "persistence": np.array(persistence),
    }


def classification_metrics(y, pred):
    labels = [0, 1, 2]
    recall = recall_score(y, pred, labels=labels, average=None, zero_division=0)
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "macroPrecision": float(precision_score(y, pred, labels=labels, average="macro", zero_division=0)),
        "macroRecall": float(recall_score(y, pred, labels=labels, average="macro", zero_division=0)),
        "macroF1": float(f1_score(y, pred, labels=labels, average="macro", zero_division=0)),
        "recall": {b: float(r) for b, r in zip(BANDS, recall)},
        "confusionMatrix": confusion_matrix(y, pred, labels=labels).tolist(),
    }


def macro_f1(y, pred):
    return f1_score(y, pred, labels=[0, 1, 2], average="macro", zero_division=0)


def mcnemar(y, pred_a, pred_b):
    """Exact McNemar test on per-row correctness. b = only A right, c = only B right."""
    a_ok, b_ok = pred_a == y, pred_b == y
    b, c = int(np.sum(a_ok & ~b_ok)), int(np.sum(~a_ok & b_ok))
    p = float(binomtest(min(b, c), b + c, 0.5).pvalue) if b + c > 0 else 1.0
    return {"onlyXgbCorrect": b, "onlyBaselineCorrect": c, "pValue": p}


def developer_bootstrap(y, pred_a, pred_b, devs, reps, seed):
    """Resample DEVELOPERS with replacement; 95% CI of macro-F1(A) - macro-F1(B).

    Resampling developers rather than rows respects that one developer's rows
    are correlated.
    """
    rng = np.random.default_rng(seed)
    unique = np.unique(devs)
    rows_of = {d: np.flatnonzero(devs == d) for d in unique}
    diffs = []
    for _ in range(reps):
        idx = np.concatenate([rows_of[d] for d in rng.choice(unique, size=len(unique), replace=True)])
        diffs.append(macro_f1(y[idx], pred_a[idx]) - macro_f1(y[idx], pred_b[idx]))
    diffs = np.array(diffs)
    return {"meanDiff": float(diffs.mean()), "ciLow": float(np.percentile(diffs, 2.5)),
            "ciHigh": float(np.percentile(diffs, 97.5)), "xgbBetterShare": float(np.mean(diffs > 0))}


# ---------------------------------------------------------------- explanations

def shap_values(model, X):
    """SHAP values with shape (rows, features, classes).

    TreeSHAP: for each prediction, a feature's SHAP value is its average
    marginal contribution to the model output (log-odds of each class) over
    all orders in which features could be added. For trees this is computed
    exactly and quickly. The values for a row add up to (prediction - average
    prediction).
    """
    values = shap.TreeExplainer(model).shap_values(X)
    values = np.stack(values, axis=-1) if isinstance(values, list) else np.asarray(values)
    return values


def describe(feature, value, medians):
    """Plain-words description of one feature value, e.g. 'ignore rate rising'."""
    if feature.startswith("share_"):
        vtype = feature[len("share_"):].replace("_", " ")
        level = "high" if value > medians[feature] else "low"
        return f"{level} share of {vtype} findings"
    if feature == "active_week_ratio":
        return "often inactive" if value < medians[feature] else "consistently active"
    if feature == "weeks_since_first_activity":
        return "new to the study" if value < medians[feature] else "long history in the study"
    metric, agg = feature.rsplit("_", 1)
    words = METRIC_WORDS[metric]
    if np.isnan(value):
        return f"{words} not measured (no recent findings)"
    if agg == "slope4":
        return f"{words} rising" if value > 0 else f"{words} falling" if value < 0 else f"{words} flat"
    level = "high" if value > medians[feature] else "low"
    return f"{level} {words} ({'last 4 weeks' if agg == 'last4' else 'all history'})"


def top_factors(values_row, x_row, predicted, features, medians, k=3):
    """The k features pushing hardest TOWARD the predicted band (largest positive SHAP)."""
    contrib = values_row[:, predicted]
    order = np.argsort(-contrib)[:k]
    return [{"feature": features[i], "value": None if np.isnan(x_row[i]) else round(float(x_row[i]), 4),
             "shap": round(float(contrib[i]), 4), "text": describe(features[i], x_row[i], medians)}
            for i in order]


# ---------------------------------------------------------------- pipeline

def prepare(cfg, dw, train_devs):
    """Rows for all developers, normaliser from train developers, label scores."""
    rc = cfg["risk"]
    arrays = developer_arrays(dw, cfg)
    rows = build_rows(arrays, rc["origins"], cfg)
    norm = Normaliser(components(rows[rows["developer_id"].isin(train_devs)], "label"))
    rows["score"] = [risk_score(c, norm, rc["score_weights"]) for c in components(rows, "label")]
    return arrays, rows, norm


def run(quick=False, fit_thresholds=False):
    cfg = load_config()
    rc = cfg["risk"]
    seed = cfg["seed"]
    dw = pd.read_csv(resolve(cfg["paths"]["developer_weeks"]))
    archetypes = pd.read_csv(resolve(cfg["paths"]["developers"])).set_index("developerId")["archetype"].to_dict()
    dev_ids = sorted(dw["developer_id"].unique())
    train_devs, test_devs = holdout_split(dev_ids, archetypes, rc["holdout_developers"], seed)

    arrays, rows, norm = prepare(cfg, dw, train_devs)
    n_dropped = int(rows["score"].isna().sum())
    rows = rows.dropna(subset=["score"]).reset_index(drop=True)
    train_scores = rows.loc[rows["developer_id"].isin(train_devs), "score"]
    suggested = {k: float(np.percentile(train_scores, p)) for k, p in zip(("medium", "high"), rc["threshold_percentiles"])}
    if fit_thresholds or rc["thresholds"]["medium"] is None:
        print(f"Suggested thresholds (percentiles {rc['threshold_percentiles']} of train scores): "
              f"medium={suggested['medium']:.4f} high={suggested['high']:.4f}")
        print("Freeze them in config.yaml (risk.thresholds) and run again.")
        return None
    thresholds = rc["thresholds"]
    rows["y"] = [to_band(s, thresholds) for s in rows["score"]]

    features = feature_columns(rows)
    train = rows[rows["developer_id"].isin(train_devs)].reset_index(drop=True)
    test = rows[rows["developer_id"].isin(test_devs)].reset_index(drop=True)
    assert not set(train["developer_id"]) & set(test["developer_id"])
    Xtr, ytr, gtr = train[features], train["y"].to_numpy(), train["developer_id"].to_numpy()
    Xte, yte = test[features], test["y"].to_numpy()

    # 1. Cross-validation on the 48 training developers (grouped by developer)
    grid_cfg = rc["grid"]
    grid = list(itertools.product(grid_cfg["max_depth"], grid_cfg["n_estimators"],
                                  grid_cfg["learning_rate"], grid_cfg["min_child_weight"]))
    if quick:
        grid = grid[:1]
    folds = list(GroupKFold(n_splits=rc["cv_folds"]).split(Xtr, ytr, gtr))
    tuning, cv_scores = [], {}
    for depth, n_est, lr, mcw in grid:
        params = {"max_depth": depth, "n_estimators": n_est, "learning_rate": lr, "min_child_weight": mcw}
        f1s = [macro_f1(ytr[va], fit_xgb(Xtr.iloc[tr], ytr[tr], gtr[tr], params, cfg, seed).predict(Xtr.iloc[va]))
               for tr, va in folds]
        tuning.append({"model": "xgboost", **params, "cv_macro_f1_mean": float(np.mean(f1s)),
                       "cv_macro_f1_std": float(np.std(f1s))})
        print(f"  xgb depth={depth} n={n_est} lr={lr} mcw={mcw}: CV macro F1 {np.mean(f1s):.3f} +/- {np.std(f1s):.3f}")
    for C in rc["logreg_C"]:
        f1s = [macro_f1(ytr[va], fit_logreg(Xtr.iloc[tr], ytr[tr], C, seed).predict(Xtr.iloc[va])) for tr, va in folds]
        tuning.append({"model": "logreg", "C": C, "cv_macro_f1_mean": float(np.mean(f1s)),
                       "cv_macro_f1_std": float(np.std(f1s))})
    best_xgb = max((r for r in tuning if r["model"] == "xgboost"), key=lambda r: r["cv_macro_f1_mean"])
    best_lr = max((r for r in tuning if r["model"] == "logreg"), key=lambda r: r["cv_macro_f1_mean"])
    xgb_params = {k: best_xgb[k] for k in ("max_depth", "n_estimators", "learning_rate", "min_child_weight")}
    cv_scores["xgboost"] = (best_xgb["cv_macro_f1_mean"], best_xgb["cv_macro_f1_std"])
    cv_scores["logreg"] = (best_lr["cv_macro_f1_mean"], best_lr["cv_macro_f1_std"])
    for name in ("majority", "fix_rate_rule", "persistence"):
        f1s = []
        for tr, va in folds:
            majority = int(np.bincount(ytr[tr], minlength=3).argmax())
            f1s.append(macro_f1(ytr[va], baseline_predictions(train.iloc[va], cfg, thresholds, norm, majority)[name]))
        cv_scores[name] = (float(np.mean(f1s)), float(np.std(f1s)))

    # 2. Final models on all 48 developers, evaluated once on the 12 held-out developers
    xgb = fit_xgb(Xtr, ytr, gtr, xgb_params, cfg, seed)
    logreg = fit_logreg(Xtr, ytr, best_lr["C"], seed)
    majority = int(np.bincount(ytr, minlength=3).argmax())
    preds = {"xgboost": xgb.predict(Xte), "logreg": logreg.predict(Xte),
             **baseline_predictions(test, cfg, thresholds, norm, majority)}
    test_metrics = [{"model": m, **classification_metrics(yte, p)} for m, p in preds.items()]
    reps = rc["quick"]["bootstrap_reps"] if quick else rc["bootstrap_reps"]
    significance = [{"baseline": b,
                     "mcnemar": mcnemar(yte, preds["xgboost"], preds[b]),
                     "bootstrapMacroF1Diff": developer_bootstrap(yte, preds["xgboost"], preds[b],
                                                                 test["developer_id"].to_numpy(), reps, seed)}
                    for b in ("majority", "fix_rate_rule", "persistence", "logreg")]

    # 3. Explanations: gain importance, mean |SHAP|, and top factors per developer at t = 12
    medians = Xtr.median()
    gain = xgb.get_booster().get_score(importance_type="gain")
    sv_train = shap_values(xgb, Xtr)
    importance = sorted(({"feature": f, "gain": float(gain.get(f, 0.0)),
                          "meanAbsShap": float(np.abs(sv_train[:, i, :]).mean())}
                         for i, f in enumerate(features)), key=lambda r: -r["meanAbsShap"])
    latest = rows[rows["origin"] == max(rc["origins"])].reset_index(drop=True)
    sv_latest = shap_values(xgb, latest[features])
    pred_latest = xgb.predict(latest[features])
    explanations = [{"developerId": r.developer_id, "set": "test" if r.developer_id in test_devs else "train",
                     "originWeek": int(r.origin), "band": BANDS[pred_latest[i]], "actualBand": BANDS[int(r.y)],
                     "topFactors": top_factors(sv_latest[i], latest[features].to_numpy(dtype=float)[i],
                                               pred_latest[i], features, medians)}
                    for i, r in enumerate(latest.itertuples())]

    # 4. Deployment: refit on all 60 developers, score everyone at the last week
    n_weeks = cfg["study"]["n_weeks"]
    n_trees = int(xgb.best_iteration) + 1
    deploy = fit_xgb_fixed(rows[features], rows["y"].to_numpy(), xgb_params, n_trees, seed)
    now = pd.DataFrame([features_at(arrays[d], n_weeks, cfg["vulnerability_types"]) for d in dev_ids])[features]
    probs = deploy.predict_proba(now)
    bands = probs.argmax(1)
    sv_now = shap_values(deploy, now)
    risk_out = {
        "meta": {"dataSource": "simulated", "disclaimer": SIMULATED_NOTE, "framing": FRAMING,
                 "scoredAtWeek": n_weeks, "predictsWeeks": [n_weeks + 1, n_weeks + rc["label_weeks"]],
                 "thresholds": thresholds, "scoreHistoryNote": "measured risk score on the 4 weeks ending at each week"},
        "developers": [{
            "developerId": d, "band": BANDS[bands[i]],
            "probabilities": {b: round(float(p), 4) for b, p in zip(BANDS, probs[i])},
            "topFactors": top_factors(sv_now[i], now.to_numpy(dtype=float)[i], bands[i], features, medians),
            "scoreHistory": _score_history(arrays[d], norm, rc, thresholds, n_weeks),
        } for i, d in enumerate(dev_ids)],
    }

    balance = {name: {b: int((part["y"] == i).sum()) for i, b in enumerate(BANDS)}
               for name, part in (("train", train), ("test", test))}
    metrics_out = {
        "meta": {"dataSource": "simulated", "disclaimer": SIMULATED_NOTE, "framing": FRAMING, "quick": quick,
                 "origins": rc["origins"], "labelWeeks": rc["label_weeks"], "scoreWeights": rc["score_weights"],
                 "thresholds": thresholds, "thresholdPercentiles": rc["threshold_percentiles"],
                 "percentilesOnCurrentData": suggested, "normaliser": norm.bounds,
                 "nRows": {"train": len(train), "test": len(test)}, "droppedRowsNoFindings": n_dropped,
                 "testDevelopers": test_devs, "nFeatures": len(features)},
        "classBalance": balance,
        "cv": [{"model": m, "macroF1": {"mean": s[0], "std": s[1]}} for m, s in cv_scores.items()],
        "selected": {"xgboost": {**xgb_params, "bestIteration": int(xgb.best_iteration)}, "logreg": {"C": best_lr["C"]},
                     "deploymentTrees": n_trees},
        "test": test_metrics,
        "significance": significance,
        "featureImportance": importance,
        "explanationsOrigin12": explanations,
    }
    _write_json(resolve(rc["outputs"]["metrics"]), metrics_out)
    _write_json(resolve(rc["outputs"]["risk"]), risk_out)
    with open(resolve(rc["outputs"]["tuning"]), "w", newline="", encoding="utf-8") as f:
        fields = sorted({k for r in tuning for k in r}, key=lambda k: list(tuning[0]).index(k) if k in tuning[0] else 99)
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(tuning)
    _print_summary(metrics_out)
    return metrics_out


def _score_history(a, norm, rc, thresholds, n_weeks):
    out = []
    for t in range(4, n_weeks + 1):
        s = risk_score(score_components(cut(a, t), t - 3, t), norm, rc["score_weights"])
        out.append({"week": t, "score": None if np.isnan(s) else round(float(s), 4),
                    "band": None if np.isnan(s) else BANDS[to_band(s, thresholds)]})
    return out


def _write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)


def _print_summary(out):
    print(f"\nClass balance: {out['classBalance']}   dropped rows (no findings): {out['meta']['droppedRowsNoFindings']}")
    print("CV macro F1 (48 developers):", {r["model"]: f"{r['macroF1']['mean']:.3f}+/-{r['macroF1']['std']:.3f}" for r in out["cv"]})
    print("\nHeld-out test (12 developers), SIMULATED data:")
    print(f"{'model':14s} {'acc':>6s} {'macP':>6s} {'macR':>6s} {'macF1':>6s} {'recHIGH':>8s}")
    for r in out["test"]:
        print(f"{r['model']:14s} {r['accuracy']:6.3f} {r['macroPrecision']:6.3f} {r['macroRecall']:6.3f} "
              f"{r['macroF1']:6.3f} {r['recall']['HIGH']:8.3f}")
    print("\nXGBoost vs baselines:")
    for s in out["significance"]:
        b = s["bootstrapMacroF1Diff"]
        print(f"  vs {s['baseline']:14s} McNemar p={s['mcnemar']['pValue']:.4f}  "
              f"dF1={b['meanDiff']:+.3f} [{b['ciLow']:+.3f}, {b['ciHigh']:+.3f}]")
    print("\nTop features (mean |SHAP|):", [r["feature"] for r in out["featureImportance"][:8]])


def main():
    parser = argparse.ArgumentParser(description="Phase 3 risk classification (simulated data).")
    parser.add_argument("--quick", action="store_true", help="one grid point, fewer bootstrap resamples")
    parser.add_argument("--fit-thresholds", action="store_true", help="print train-percentile thresholds and stop")
    args = parser.parse_args()
    run(quick=args.quick, fit_thresholds=args.fit_thresholds)


if __name__ == "__main__":
    main()
