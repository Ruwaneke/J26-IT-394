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

Future risk score (weeks t+1..t+4, pooled over the 4 weeks):
    0.4 * severity-weighted ignore rate   (ignored severity weight / total severity weight)
  + 0.3 * (1 - fix rate)
  + 0.2 * normalised repeat rate         (repeat_count / vuln_count, min-max scaled)
  + 0.1 * normalised log response time   (log1p of mean seconds, min-max scaled)
The label is a fixed measuring instrument. Its two min-max constant pairs and
its two band thresholds (40th/80th percentiles, frozen in config.yaml) were
set once in round 1 from the 48 round-1 training developers.

Features (weeks <= t)
---------------------
Original set (round 1): for fix rate, ignore rate, false-positive rate, repeat
rate, severity-weighted load, high-severity share, log response time and
weekly findings: last-4-week value, all-history value and 4-week slope; plus
per-type shares, active-week ratio and weeks since first activity.
Extended set (added post-hoc in round 2): the original set plus the
severity-weighted ignore rate (last 4 / all / slope) and the past risk score
(the label's exact formula) over weeks t-3..t and over all history. The
past-score features are min-max normalised with constants from the TRAINING
developers of each fold only.

Evaluation
----------
- Selection: GroupKFold(5) by developer on the 48 round-1 training developers.
- Headline: repeated GroupKFold (5 repeats x 5 folds, developers shuffled
  differently each repeat, all 60 developers). Macro F1 is computed on the
  pooled out-of-fold predictions of each repeat (mean +/- std over repeats),
  with a 95% CI from a developer-level bootstrap. A paired developer-level
  bootstrap is the main significance test.
- Round 1: the 12 held-out developers. They have already been seen, so their
  numbers are kept as a record and are not the headline.

Baselines: majority class; the proposal's static fix-rate rule; persistence
(the same risk score on weeks t-3..t, banded with the frozen thresholds:
"the next 4 weeks look like the last 4"); multinomial logistic regression.
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
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from .config import load_config, resolve
from .features import type_column
from .trends import ols_slope

BANDS = ["LOW", "MEDIUM", "HIGH"]
MODELS = ["xgboost", "logreg", "persistence", "fix_rate_rule", "majority"]
BASE_METRICS = ["fix_rate", "ignore_rate", "false_positive_rate", "repeat_rate", "severity_weighted_load",
                "high_severity_share", "log_response_time", "vuln_count", "severity_weighted_ignore_rate"]
ADDED_METRICS = ["severity_weighted_ignore_rate"]
PAST_SCORE_FEATURES = ["past_score_last4", "past_score_all"]
SUM_COLUMNS = ["vuln_count", "n_fixed", "n_ignored", "n_false_positive", "repeat_count",
               "severity_weighted_load", "ignored_severity_load", "n_high_severity"]
COMPONENT_KEYS = ("severity_weighted_ignore_rate", "fix_rate", "repeat_rate", "log_response_time")
SIMULATED_NOTE = "Simulated data generated from stated assumptions; not real developer data."
FRAMING = "Research risk profile based on measured behaviour; not a judgment of the person."
SHAP_CAVEAT = ("Global importance only. Correlated features (for example the last-4-week and all-history "
               "versions of the same metric) share credit, so read this as which feature groups matter, "
               "not as causal effects or as reasons for any one developer.")
DRIVERS_NOTE = ("Drivers are the developer's own measured metrics for the last 4 weeks compared with the "
                "study median for the same weeks. They are not model explanations.")
MCNEMAR_NOTE = ("Secondary only: McNemar treats rows as independent, but the 7 rows of one developer "
                "are correlated, so its p-value is optimistic.")

# measured metrics used as per-developer drivers: (window_stats key, higher_is_worse, label, kind)
DRIVER_METRICS = [
    ("severity_weighted_ignore_rate", True, "Severity-weighted ignore rate", "pct"),
    ("fix_rate", False, "Fix rate", "pct"),
    ("repeat_rate", True, "Repeat rate (same type and file within 4 weeks)", "pct"),
    ("response_time_sec", True, "Average response time", "minutes"),
    ("vuln_count", True, "Findings per week", "count"),
]


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
        "response_time_sec": s["response_total"] / vc if vc > 0 else np.nan,
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
    return {k: s[k] for k in COMPONENT_KEYS}


class Normaliser:
    """Min-max scaling of repeat rate and log response time, fitted on TRAINING developers only."""

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


# ---------------------------------------------------------------- rows and design matrices

def build_rows(arrays, origins, cfg):
    """One row per (developer, origin): features, future label components, past score components."""
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
    return [{k: r[f"{prefix}_{k}"] for k in COMPONENT_KEYS} for _, r in df.iterrows()]


def feature_columns(df):
    """Feature columns stored on the rows (past-score features are added per fold by design())."""
    skip = ("developer_id", "origin", "label_", "persist_", "history_", "score", "y")
    return [c for c in df.columns if not c.startswith(skip)]


def feature_sets(df):
    base = feature_columns(df)
    original = [c for c in base if not any(c.startswith(m) for m in ADDED_METRICS)]
    return {"original": original, "extended": base + PAST_SCORE_FEATURES}


def design(df, columns, norm, weights):
    """Feature matrix; past-score features use `norm`, fitted on the training developers of this fold."""
    out = df.copy()
    out["past_score_last4"] = [risk_score(c, norm, weights) for c in components(df, "persist")]
    out["past_score_all"] = [risk_score(c, norm, weights) for c in components(df, "history")]
    return out[columns]


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


def baseline_predictions(df, cfg, thresholds, label_norm, majority):
    """Majority, fix-rate rule and persistence predictions for the rows in df.

    Persistence applies the label instrument (its normaliser and thresholds)
    to weeks t-3..t, so it is exactly "the label, measured on the past".
    """
    rc = cfg["risk"]
    w = rc["score_weights"]
    persistence = []
    for p, h in zip(components(df, "persist"), components(df, "history")):
        s = risk_score(p, label_norm, w)
        if np.isnan(s):
            s = risk_score(h, label_norm, w)  # no findings in the last 4 weeks: use all history
        persistence.append(majority if np.isnan(s) else to_band(s, thresholds))
    return {
        "majority": np.full(len(df), majority),
        "fix_rate_rule": np.array([fix_rate_rule(f, rc["fix_rate_rule"]) for f in df["fix_rate_all"]]),
        "persistence": np.array(persistence),
    }


def fold_predictions(train, val, columns, xgb_params, C, cfg, label_norm, thresholds, seed):
    """Train on `train` rows, predict `val` rows with XGBoost, logistic regression and the 3 baselines."""
    w = cfg["risk"]["score_weights"]
    norm = Normaliser(components(train, "label"))           # training developers only
    Xtr, Xva = design(train, columns, norm, w), design(val, columns, norm, w)
    ytr = train["y"].to_numpy()
    xgb = fit_xgb(Xtr, ytr, train["developer_id"].to_numpy(), xgb_params, cfg, seed)
    logreg = fit_logreg(Xtr, ytr, C, seed)
    majority = int(np.bincount(ytr, minlength=3).argmax())
    return {"xgboost": xgb.predict(Xva), "logreg": logreg.predict(Xva),
            **baseline_predictions(val, cfg, thresholds, label_norm, majority)}


# ---------------------------------------------------------------- metrics and significance

def macro_f1(y, pred):
    """Macro F1 over LOW/MEDIUM/HIGH from a 3x3 confusion matrix (a class with no support scores 0)."""
    cm = np.bincount(3 * np.asarray(y) + np.asarray(pred), minlength=9).reshape(3, 3).astype(float)
    tp = np.diag(cm)
    precision = np.divide(tp, cm.sum(0), out=np.zeros(3), where=cm.sum(0) > 0)
    recall = np.divide(tp, cm.sum(1), out=np.zeros(3), where=cm.sum(1) > 0)
    denom = precision + recall
    return float(np.mean(np.divide(2 * precision * recall, denom, out=np.zeros(3), where=denom > 0)))


def classification_metrics(y, pred):
    labels = [0, 1, 2]
    recall = recall_score(y, pred, labels=labels, average=None, zero_division=0)
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "macroPrecision": float(precision_score(y, pred, labels=labels, average="macro", zero_division=0)),
        "macroRecall": float(recall_score(y, pred, labels=labels, average="macro", zero_division=0)),
        "macroF1": macro_f1(y, pred),
        "recall": {b: float(r) for b, r in zip(BANDS, recall)},
        "confusionMatrix": confusion_matrix(y, pred, labels=labels).tolist(),
    }


def mcnemar(y, pred_a, pred_b):
    """Exact McNemar test on per-row correctness. b = only A right, c = only B right."""
    a_ok, b_ok = pred_a == y, pred_b == y
    b, c = int(np.sum(a_ok & ~b_ok)), int(np.sum(~a_ok & b_ok))
    p = float(binomtest(min(b, c), b + c, 0.5).pvalue) if b + c > 0 else 1.0
    return {"onlyXgbCorrect": b, "onlyBaselineCorrect": c, "pValue": p, "note": MCNEMAR_NOTE}


def developer_bootstrap(y, oof, devs, reps, seed):
    """Developer-level bootstrap over pooled out-of-fold predictions.

    oof: {model: [predictions for repeat 1, repeat 2, ...]}. Each resample draws
    developers with replacement (all rows of a drawn developer come along),
    computes macro F1 per repeat and averages over repeats. Returns per-model
    95% CIs and, for each baseline, the paired difference XGBoost - baseline
    on the same resamples.
    """
    rng = np.random.default_rng(seed)
    unique = np.unique(devs)
    rows_of = {d: np.flatnonzero(devs == d) for d in unique}
    draws = {m: [] for m in oof}
    for _ in range(reps):
        idx = np.concatenate([rows_of[d] for d in rng.choice(unique, size=len(unique), replace=True)])
        for m, preds in oof.items():
            draws[m].append(np.mean([macro_f1(y[idx], p[idx]) for p in preds]))
    draws = {m: np.array(v) for m, v in draws.items()}
    ci = {m: (float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))) for m, v in draws.items()}
    paired = {}
    for m in oof:
        if m == "xgboost":
            continue
        diff = draws["xgboost"] - draws[m]
        paired[m] = {"meanDiff": float(diff.mean()), "ciLow": float(np.percentile(diff, 2.5)),
                     "ciHigh": float(np.percentile(diff, 97.5)), "xgbBetterShare": float(np.mean(diff > 0))}
    return ci, paired


def _mean_std(values):
    return {"mean": float(np.mean(values)), "std": float(np.std(values))}


# ---------------------------------------------------------------- per-developer drivers (measured, not SHAP)

def _fmt(value, kind):
    if kind == "pct":
        return f"{100 * value:.0f}%"
    if kind == "minutes":
        return f"{value / 60:.1f} min"
    return f"{value:.1f}"


def measured_drivers(arrays, t, reference, band, max_drivers):
    """Reasons from the developer's OWN measured metrics (weeks t-3..t) vs the study median.

    For MEDIUM/HIGH bands, the metrics furthest on the worse side of the median
    are listed; for LOW, those furthest on the better side. Distance is scaled
    by the interquartile range so different units are comparable.
    """
    stats = window_stats(cut(arrays, t), t - 3, t)
    candidates = []
    for key, higher_worse, label, kind in DRIVER_METRICS:
        value = stats[key]
        med, iqr = reference[key]
        if np.isnan(value):
            continue
        worse_by = (value - med) / iqr if higher_worse else (med - value) / iqr
        side = "above" if value > med else "below" if value < med else "at"
        candidates.append({"metric": key, "value": round(float(value), 4), "studyMedian": round(float(med), 4),
                           "direction": "worse" if worse_by > 0 else "better" if worse_by < 0 else "same",
                           "worseBy": worse_by,
                           "text": f"{label} {_fmt(value, kind)} in weeks {t - 3}-{t} ({side} the study median of {_fmt(med, kind)})"})
    if band == "LOW":
        chosen = sorted((c for c in candidates if c["worseBy"] < 0), key=lambda c: c["worseBy"])
    else:
        chosen = sorted((c for c in candidates if c["worseBy"] > 0), key=lambda c: -c["worseBy"])
    return [{k: v for k, v in c.items() if k != "worseBy"} for c in chosen[:max_drivers]]


def driver_reference(arrays, t):
    """Study median and IQR of each driver metric over weeks t-3..t (descriptive, all developers)."""
    ref = {}
    for key, *_ in DRIVER_METRICS:
        values = np.array([window_stats(cut(a, t), t - 3, t)[key] for a in arrays.values()])
        values = values[~np.isnan(values)]
        q1, med, q3 = np.percentile(values, [25, 50, 75])
        ref[key] = (float(med), float(q3 - q1) or 1.0)
    return ref


# ---------------------------------------------------------------- pipeline

def prepare(cfg, dw, train_devs):
    """Rows for all developers, label instrument from round-1 training developers, label scores."""
    rc = cfg["risk"]
    arrays = developer_arrays(dw, cfg)
    rows = build_rows(arrays, rc["origins"], cfg)
    label_norm = Normaliser(components(rows[rows["developer_id"].isin(train_devs)], "label"))
    rows["score"] = [risk_score(c, label_norm, rc["score_weights"]) for c in components(rows, "label")]
    return arrays, rows, label_norm


def select_config(train, columns, grid, cfg, label_norm, seed, tuning):
    """Grid search by GroupKFold CV macro F1 on the round-1 training developers only."""
    rc = cfg["risk"]
    w = rc["score_weights"]
    y, groups = train["y"].to_numpy(), train["developer_id"].to_numpy()
    folds = list(GroupKFold(n_splits=rc["cv_folds"]).split(train, y, groups))
    mats = []
    for tr, va in folds:
        norm = Normaliser(components(train.iloc[tr], "label"))
        mats.append((design(train.iloc[tr], columns, norm, w), design(train.iloc[va], columns, norm, w)))
    for depth, n_est, lr, mcw in grid:
        params = {"max_depth": depth, "n_estimators": n_est, "learning_rate": lr, "min_child_weight": mcw}
        f1s = [macro_f1(y[va], fit_xgb(Xtr, y[tr], groups[tr], params, cfg, seed).predict(Xva))
               for (tr, va), (Xtr, Xva) in zip(folds, mats)]
        tuning.append({"model": "xgboost", **params, "cv_macro_f1_mean": float(np.mean(f1s)),
                       "cv_macro_f1_std": float(np.std(f1s))})
        print(f"  xgb depth={depth} n={n_est} lr={lr} mcw={mcw}: CV macro F1 {np.mean(f1s):.3f} +/- {np.std(f1s):.3f}")
    for C in rc["logreg_C"]:
        f1s = [macro_f1(y[va], fit_logreg(Xtr, y[tr], C, seed).predict(Xva))
               for (tr, va), (Xtr, Xva) in zip(folds, mats)]
        tuning.append({"model": "logreg", "C": C, "cv_macro_f1_mean": float(np.mean(f1s)),
                       "cv_macro_f1_std": float(np.std(f1s))})
    best_xgb = max((r for r in tuning if r["model"] == "xgboost"), key=lambda r: r["cv_macro_f1_mean"])
    best_lr = max((r for r in tuning if r["model"] == "logreg"), key=lambda r: r["cv_macro_f1_mean"])
    params = {k: best_xgb[k] for k in ("max_depth", "n_estimators", "learning_rate", "min_child_weight")}
    return params, best_lr["C"], best_xgb["cv_macro_f1_mean"]


def repeated_cv(rows, columns, xgb_params, C, cfg, label_norm, thresholds, seed, repeats):
    """Out-of-fold predictions for every model, for each repeat of a shuffled GroupKFold(5)."""
    y, groups = rows["y"].to_numpy(), rows["developer_id"].to_numpy()
    oof = {m: [] for m in MODELS}
    for r in range(repeats):
        preds = {m: np.zeros(len(rows), dtype=int) for m in MODELS}
        splitter = GroupKFold(n_splits=cfg["risk"]["cv_folds"], shuffle=True, random_state=seed + r)
        for tr, va in splitter.split(rows, y, groups):
            assert not set(groups[tr]) & set(groups[va])
            fold = fold_predictions(rows.iloc[tr], rows.iloc[va], columns, xgb_params, C, cfg,
                                    label_norm, thresholds, seed)
            for m in MODELS:
                preds[m][va] = fold[m]
        for m in MODELS:
            oof[m].append(preds[m])
        print(f"  repeat {r + 1}/{repeats}: " + ", ".join(f"{m} {macro_f1(y, preds[m]):.3f}" for m in MODELS))
    return oof


def run(quick=False, fit_thresholds=False):
    cfg = load_config()
    rc = cfg["risk"]
    seed = cfg["seed"]
    w = rc["score_weights"]
    dw = pd.read_csv(resolve(cfg["paths"]["developer_weeks"]))
    archetypes = pd.read_csv(resolve(cfg["paths"]["developers"])).set_index("developerId")["archetype"].to_dict()
    dev_ids = sorted(dw["developer_id"].unique())
    train_devs, test_devs = holdout_split(dev_ids, archetypes, rc["holdout_developers"], seed)

    arrays, rows, label_norm = prepare(cfg, dw, train_devs)
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
    sets = feature_sets(rows)
    train = rows[rows["developer_id"].isin(train_devs)].reset_index(drop=True)
    test = rows[rows["developer_id"].isin(test_devs)].reset_index(drop=True)
    assert not set(train["developer_id"]) & set(test["developer_id"])

    # 1. Select the extended-feature configuration on the 48 round-1 training developers
    g = rc["grid"]
    grid = list(itertools.product(g["max_depth"], g["n_estimators"], g["learning_rate"], g["min_child_weight"]))
    if quick:
        grid = grid[:1]
    tuning = []
    xgb_params, C, selection_f1 = select_config(train, sets["extended"], grid, cfg, label_norm, seed, tuning)

    # 2. Headline: repeated GroupKFold over all 60 developers with the selected configuration
    repeats = rc["quick"]["cv_repeats"] if quick else rc["cv_repeats"]
    reps = rc["quick"]["bootstrap_reps"] if quick else rc["bootstrap_reps"]
    y, devs = rows["y"].to_numpy(), rows["developer_id"].to_numpy()
    oof = repeated_cv(rows, sets["extended"], xgb_params, C, cfg, label_norm, thresholds, seed, repeats)
    ci, paired = developer_bootstrap(y, oof, devs, reps, seed)
    headline = []
    for m in MODELS:
        per_repeat = [classification_metrics(y, p) for p in oof[m]]
        headline.append({
            "model": m,
            "macroF1": {**_mean_std([r["macroF1"] for r in per_repeat]), "ciLow": ci[m][0], "ciHigh": ci[m][1]},
            "accuracy": _mean_std([r["accuracy"] for r in per_repeat]),
            "recallHigh": _mean_std([r["recall"]["HIGH"] for r in per_repeat]),
            "confusionMatrixSum": np.sum([r["confusionMatrix"] for r in per_repeat], axis=0).tolist(),
        })
    significance = [{"baseline": b, "bootstrapMacroF1Diff": paired[b],
                     "mcnemarRepeat1": mcnemar(y, oof["xgboost"][0], oof[b][0])} for b in MODELS[1:]]

    # 3. Round 1 (already seen): the 12 held-out developers
    r1 = rc["round1"]
    round1 = {
        "note": "Round 1 held-out developers. These results have already been seen, so they are a record, not the headline.",
        "originalFeatures": [{"model": m, **classification_metrics(test["y"].to_numpy(), p)} for m, p in
                             fold_predictions(train, test, sets["original"], r1["xgboost"], r1["logreg_C"], cfg,
                                              label_norm, thresholds, seed).items()],
        "extendedFeatures": [{"model": m, **classification_metrics(test["y"].to_numpy(), p)} for m, p in
                             fold_predictions(train, test, sets["extended"], xgb_params, C, cfg,
                                              label_norm, thresholds, seed).items()],
    }

    # 4. Deployment model on all 60 developers; global importance (gain and mean |SHAP|)
    cols = sets["extended"]
    norm_all = Normaliser(components(rows, "label"))
    X_all = design(rows, cols, norm_all, w)
    n_trees = int(fit_xgb(X_all, y, devs, xgb_params, cfg, seed).best_iteration) + 1
    deploy = fit_xgb_fixed(X_all, y, xgb_params, n_trees, seed)
    gain = deploy.get_booster().get_score(importance_type="gain")
    sv = shap.TreeExplainer(deploy).shap_values(X_all)
    sv = np.stack(sv, axis=-1) if isinstance(sv, list) else np.asarray(sv)
    importance = sorted(({"feature": f, "gain": float(gain.get(f, 0.0)),
                          "meanAbsShap": float(np.abs(sv[:, i, :]).mean())} for i, f in enumerate(cols)),
                        key=lambda r: -r["meanAbsShap"])

    # 5. Score every developer at the last week; drivers come from measured metrics
    n_weeks = cfg["study"]["n_weeks"]
    now_rows = build_rows(arrays, [n_weeks], cfg)
    probs = deploy.predict_proba(design(now_rows, cols, norm_all, w))
    bands = probs.argmax(1)
    reference = driver_reference(arrays, n_weeks)
    risk_out = {
        "meta": {"dataSource": "simulated", "disclaimer": SIMULATED_NOTE, "framing": FRAMING,
                 "scoredAtWeek": n_weeks, "predictsWeeks": [n_weeks + 1, n_weeks + rc["label_weeks"]],
                 "thresholds": thresholds, "driversNote": DRIVERS_NOTE,
                 "scoreHistoryNote": "measured risk score on the 4 weeks ending at each week"},
        "developers": [{
            "developerId": d, "band": BANDS[bands[i]],
            "probabilities": {b: round(float(p), 4) for b, p in zip(BANDS, probs[i])},
            "drivers": measured_drivers(arrays[d], n_weeks, reference, BANDS[bands[i]], rc["max_drivers"]),
            "scoreHistory": _score_history(arrays[d], label_norm, rc, thresholds, n_weeks),
        } for i, d in enumerate(now_rows["developer_id"])],
    }

    balance = {name: {b: int((part["y"] == i).sum()) for i, b in enumerate(BANDS)}
               for name, part in (("all", rows), ("round1Train", train), ("round1Test", test))}
    metrics_out = {
        "meta": {"dataSource": "simulated", "disclaimer": SIMULATED_NOTE, "framing": FRAMING, "quick": quick,
                 "origins": rc["origins"], "labelWeeks": rc["label_weeks"], "scoreWeights": w,
                 "thresholds": thresholds, "thresholdPercentiles": rc["threshold_percentiles"],
                 "labelNormaliser": label_norm.bounds, "nRows": len(rows), "droppedRowsNoFindings": n_dropped,
                 "round1TestDevelopers": test_devs,
                 "featureSets": {k: len(v) for k, v in sets.items()},
                 "postHocNote": "The extended features (severity-weighted ignore rate and past risk score) were added "
                                "after round-1 results were seen.",
                 "headlineMethod": f"repeated GroupKFold ({repeats} repeats x {rc['cv_folds']} folds, all "
                                   f"{len(dev_ids)} developers, groups = developer); 95% CI from a developer-level "
                                   f"bootstrap ({reps} resamples)"},
        "classBalance": balance,
        "selected": {"xgboost": xgb_params, "logreg": {"C": C}, "selectionCvMacroF1": selection_f1,
                     "deploymentTrees": n_trees},
        "headline": headline,
        "significance": significance,
        "round1": round1,
        "featureImportance": importance,
        "featureImportanceNote": SHAP_CAVEAT,
    }
    _write_json(resolve(rc["outputs"]["metrics"]), metrics_out)
    _write_json(resolve(rc["outputs"]["risk"]), risk_out)
    with open(resolve(rc["outputs"]["tuning"]), "w", newline="", encoding="utf-8") as f:
        fields = list(dict.fromkeys(k for r in tuning for k in r))
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
    print(f"\nClass balance: {out['classBalance']}")
    print(f"Selected: {out['selected']}")
    print(f"\nHeadline ({out['meta']['headlineMethod']}), SIMULATED data:")
    print(f"{'model':14s} {'macro F1 (mean +/- sd) [95% CI]':>36s} {'acc':>7s} {'recHIGH':>8s}")
    for r in out["headline"]:
        f = r["macroF1"]
        print(f"{r['model']:14s} {f['mean']:.3f} +/- {f['std']:.3f} [{f['ciLow']:.3f}, {f['ciHigh']:.3f}]"
              f"{r['accuracy']['mean']:>12.3f} {r['recallHigh']['mean']:8.3f}")
    print("\nXGBoost - baseline (paired developer bootstrap):")
    for s in out["significance"]:
        b = s["bootstrapMacroF1Diff"]
        print(f"  vs {s['baseline']:14s} dF1={b['meanDiff']:+.3f} [{b['ciLow']:+.3f}, {b['ciHigh']:+.3f}] "
              f"P(xgb better)={b['xgbBetterShare']:.3f}  McNemar(rep1) p={s['mcnemarRepeat1']['pValue']:.4f}")
    for key in ("originalFeatures", "extendedFeatures"):
        print(f"Round 1 (already seen) {key}: " +
              ", ".join(f"{r['model']} {r['macroF1']:.3f}" for r in out["round1"][key]))
    print("Top features (mean |SHAP|):", [r["feature"] for r in out["featureImportance"][:8]])


def main():
    parser = argparse.ArgumentParser(description="Phase 3 risk classification (simulated data).")
    parser.add_argument("--quick", action="store_true", help="one grid point, 2 CV repeats, fewer bootstrap resamples")
    parser.add_argument("--fit-thresholds", action="store_true", help="print train-percentile thresholds and stop")
    args = parser.parse_args()
    run(quick=args.quick, fit_thresholds=args.fit_thresholds)


if __name__ == "__main__":
    main()
