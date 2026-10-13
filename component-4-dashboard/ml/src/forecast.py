"""Phase 2: forecast each developer's next 2 weeks of vuln_count and fix_rate.

Task
----
From a window of the last L weeks (default 4) of 7 weekly inputs, predict
vuln_count and fix_rate for weeks t+1 and t+2 directly (4 outputs at once,
"direct multi-output"). One model is shared by all developers (pooled), because
60 developers x 16 weeks is far too little data for a model per developer.

Model
-----
A 1-layer recurrent network (GRU or LSTM, set by config) reads the window week
by week. Its last hidden state summarises the window and goes through dropout
and a linear layer that outputs the 4 standardised predictions.
  GRU:  r = sigmoid(W_ir x + b_ir + W_hr h + b_hr)          reset gate
        z = sigmoid(W_iz x + b_iz + W_hz h + b_hz)          update gate
        n = tanh(W_in x + b_in + r * (W_hn h + b_hn))       candidate state
        h' = (1 - z) * n + z * h
  LSTM adds a separate cell state with input/forget/output gates.
Predictions are converted back to original units and clipped to valid ranges
(counts >= 0, fix_rate in [0, 1]).

Target mode
-----------
raw:      the network predicts the targets directly.
residual: the network predicts the difference from each target's 4-week mean;
          final prediction = 4-week mean + predicted residual (then clipped).
          The 4-week mean was the strongest baseline, so the network only has to
          learn when and how far to depart from it. This mode was added after
          the first test results were seen (post-hoc). Raw vs residual, and the
          deployed variant, are chosen on validation only, using one common
          score (see common_scale_loss).

Missing data
------------
- Inactive weeks (and active weeks with no detections) leave fix_rate,
  ignore_rate and response time undefined. As INPUTS, these carry the last
  known value forward, and the `active` flag tells the model the week was
  inactive. Values before a developer's first known week use the train-period
  mean. Only past values are carried, so no future information leaks in.
- As TARGETS, undefined values are masked: an inactive target week is
  excluded from the loss and every metric, and fix_rate is also masked in an
  active week with zero detections (0/0 has no meaning).

Split (strictly chronological by target week)
---------------------------------------------
"Origin" t = last input week. Train: origins whose targets are all <= week 9.
Validation: origins 9-10 (targets 10-12). Test: origins 12-14 (targets 13-16).
Origins 8 and 11 are skipped so that no split's targets overlap the next one.
Standardisation statistics come from train-period weeks (<= 9) only, and
tuning uses validation only. The test set is touched once, at the end.

Baselines (same test windows and masks)
---------------------------------------
- naive: last known value (vuln_count from the last active week).
- mean4: mean of the last 4 weeks' defined values.
- linear: per-developer least-squares line through the window, extrapolated
  to t+1 and t+2, then clipped.
"""

import argparse
import copy
import csv
import itertools
import json
from dataclasses import dataclass

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from scipy.stats import wilcoxon
from torch import nn

from .config import load_config, resolve

FILLED_INPUTS = ["fix_rate", "ignore_rate", "log_response_time"]
TARGET_NAMES = {"vuln_count": "vulnCount", "fix_rate": "fixRate"}
SIMULATED_NOTE = "Simulated data generated from stated assumptions; not real developer data."
BAND_NOTE = "seed spread, not a calibrated confidence interval"
ARCHETYPE_NOTE = "diagnostic, simulated data only"
RESIDUAL_NOTE = ("The residual target mode was added after the first test results were seen (post-hoc); "
                 "raw vs residual is still selected on validation only.")

torch.set_num_threads(1)  # small model; one thread keeps runs reproducible across machines


# ---------------------------------------------------------------- data preparation

@dataclass
class Panel:
    """Per-developer weekly arrays. Index [d, w] = developer d, week w+1."""
    dev_ids: list
    inputs: np.ndarray        # (D, W, F) model inputs, gaps filled
    target_vuln: np.ndarray   # (D, W) vuln_count, NaN when inactive
    target_fix: np.ndarray    # (D, W) fix_rate, NaN when undefined
    vuln_carried: np.ndarray  # (D, W) vuln_count carried over inactive weeks (naive baseline)
    fix_carried: np.ndarray   # (D, W) fix_rate carried forward (naive baseline)


def build_panel(dw, cfg, stats_max_week):
    """Turn the developer-week table into arrays, filling input gaps from the past only."""
    inputs = cfg["forecast"]["inputs"]
    df = dw.sort_values(["developer_id", "week"]).copy()
    df["log_response_time"] = np.log1p(df["avg_response_time"])
    df["active"] = df["active"].astype(float)
    df["target_vuln"] = df["vuln_count"].where(df["active"] > 0)
    df["target_fix"] = df["fix_rate"]

    train = df["week"] <= stats_max_week
    fill_means = df.loc[train, FILLED_INPUTS].mean()
    df[FILLED_INPUTS] = df.groupby("developer_id")[FILLED_INPUTS].ffill().fillna(fill_means)
    df["vuln_carried"] = (df.groupby("developer_id")["target_vuln"].ffill()
                          .fillna(df.loc[train, "target_vuln"].mean()))

    dev_ids = sorted(df["developer_id"].unique())
    n_dev, n_weeks = len(dev_ids), df["week"].nunique()

    def grid(cols):
        return df[cols].to_numpy(dtype=float, copy=True).reshape(n_dev, n_weeks, -1).squeeze(-1)

    return Panel(dev_ids, df[inputs].to_numpy(dtype=float, copy=True).reshape(n_dev, n_weeks, len(inputs)),
                 grid(["target_vuln"]), grid(["target_fix"]), grid(["vuln_carried"]), grid(["fix_rate"]))


@dataclass
class Windows:
    X: np.ndarray       # (N, L, F) inputs
    Y: np.ndarray       # (N, 2H) targets [vuln t+1..t+H, fix t+1..t+H], 0 where masked
    M: np.ndarray       # (N, 2H) 1 = valid target, 0 = masked
    base: np.ndarray    # (N, 2H) 4-week mean of each target at the origin (residual mode and mean4 baseline)
    dev: np.ndarray     # (N,) developer index
    origin: np.ndarray  # (N,) origin week t (1-based, last input week)


def mean4_level(panel, d, t):
    """Mean of the defined values in weeks t-3..t for (vuln_count, fix_rate).

    Falls back to the last known value when the 4 weeks have none.
    """
    last4 = slice(max(0, t - 4), t)
    out = []
    for series, carried in [(panel.target_vuln, panel.vuln_carried), (panel.target_fix, panel.fix_carried)]:
        values = series[d, last4]
        out.append(np.nanmean(values) if (~np.isnan(values)).any() else carried[d, t - 1])
    return np.array(out)


def make_windows(panel, window, horizon, origins, require_targets=True):
    """Slide over each developer: inputs weeks t-L+1..t, targets weeks t+1..t+H.

    With require_targets=False, origins whose target weeks lie beyond the data
    are kept with fully masked targets (used for the future forecast).
    """
    n_dev, n_weeks, _ = panel.inputs.shape
    X, Y, base, dev, org = [], [], [], [], []
    for d in range(n_dev):
        for t in origins:
            if t < window or (require_targets and t + horizon > n_weeks):
                continue
            X.append(panel.inputs[d, t - window:t])
            pad = np.full(max(0, t + horizon - n_weeks), np.nan)
            Y.append(np.concatenate([panel.target_vuln[d, t:t + horizon], pad,
                                     panel.target_fix[d, t:t + horizon], pad]))
            base.append(np.repeat(mean4_level(panel, d, t), horizon))
            dev.append(d)
            org.append(t)
    Y = np.array(Y, dtype=float)
    M = (~np.isnan(Y)).astype(float)
    return Windows(np.array(X, dtype=float), np.nan_to_num(Y), M, np.array(base, dtype=float),
                   np.array(dev), np.array(org))


def split_origins(cfg, window, n_weeks):
    """Origins for train / validation / test, chosen by target week (see module docstring)."""
    h = cfg["forecast"]["horizon"]
    s = cfg["forecast"]["split"]
    train = [t for t in range(window, n_weeks - h + 1) if t + h <= s["train_max_target_week"]]
    return train, list(s["val_origins"]), list(s["test_origins"])


def target_weeks(origins, horizon):
    return sorted({t + k for t in origins for k in range(1, horizon + 1)})


class Standardiser:
    """z = (x - mean) / sd with mean and sd taken from TRAIN data only.

    target_mode decides what the network learns:
      raw:      the targets themselves (stats from train-period weeks);
      residual: target minus its 4-week mean at the origin (stats from the
                residuals of the train windows). The final prediction adds the
                4-week mean back, so the network only has to learn the change.
    """

    def __init__(self, panel, stats_max_week, horizon, target_mode="raw", train_w=None):
        w = stats_max_week
        self.mode, self.horizon = target_mode, horizon
        x = panel.inputs[:, :w].reshape(-1, panel.inputs.shape[-1])
        self.x_mean, self.x_sd = x.mean(0), x.std(0)
        self.x_sd[self.x_sd == 0] = 1.0
        if target_mode == "raw":
            tv, tf = panel.target_vuln[:, :w], panel.target_fix[:, :w]
            stats = [(np.nanmean(tv), np.nanstd(tv)), (np.nanmean(tf), np.nanstd(tf))]
        else:
            resid = train_w.Y - train_w.base
            stats = []
            for ti in range(2):
                cols = slice(ti * horizon, (ti + 1) * horizon)
                r = resid[:, cols][train_w.M[:, cols].astype(bool)]
                stats.append((r.mean(), r.std()))
        self.y_mean = np.repeat([m for m, _ in stats], horizon)
        self.y_sd = np.repeat([s for _, s in stats], horizon)

    def x(self, X):
        return (X - self.x_mean) / self.x_sd

    def _offset(self, w):
        return w.base if self.mode == "residual" else 0.0

    def target(self, w):
        """Standardised training target for windows w."""
        return (w.Y - self._offset(w) - self.y_mean) / self.y_sd

    def prediction(self, Z, w):
        """Network output -> prediction in original units, clipped to valid ranges."""
        return clip_predictions(Z * self.y_sd + self.y_mean + self._offset(w), self.horizon)


def common_scale_loss(P, w, raw_std, delta):
    """Masked Huber of final predictions, standardised with the RAW train statistics.

    Raw and residual models standardise their targets differently, so their
    own training losses cannot be compared. This puts every candidate on one
    scale; it is the score used for all model selection on validation.
    """
    zp = (P - raw_std.y_mean) / raw_std.y_sd
    zy = (w.Y - raw_std.y_mean) / raw_std.y_sd
    e = np.abs(zp - zy)
    huber = np.where(e <= delta, 0.5 * e ** 2, delta * (e - 0.5 * delta))
    return float((huber * w.M).sum() / max(w.M.sum(), 1.0))


def clip_predictions(P, horizon):
    P = P.copy()
    P[:, :horizon] = np.clip(P[:, :horizon], 0, None)
    P[:, horizon:] = np.clip(P[:, horizon:], 0, 1)
    return P


# ---------------------------------------------------------------- model

class Forecaster(nn.Module):
    """1-layer GRU/LSTM -> last hidden state -> dropout -> linear head (2H outputs)."""

    def __init__(self, n_inputs, hidden, dropout, cell, n_outputs):
        super().__init__()
        rnn = {"gru": nn.GRU, "lstm": nn.LSTM}[cell]
        self.rnn = rnn(n_inputs, hidden, num_layers=1, batch_first=True)
        self.dropout = nn.Dropout(dropout)  # nn.GRU's own dropout only acts between layers
        self.head = nn.Linear(hidden, n_outputs)

    def forward(self, x):
        out, _ = self.rnn(x)
        return self.head(self.dropout(out[:, -1]))


def masked_huber(pred, target, mask, delta):
    """Huber loss averaged over valid targets only. Masked entries contribute 0.

    Huber is squared error for small errors and absolute error for large ones,
    so a few weeks with very high counts do not dominate training.
    """
    loss = F.huber_loss(pred, target, reduction="none", delta=delta)
    return (loss * mask).sum() / mask.sum().clamp(min=1.0)


def _tensors(w, std):
    return (torch.tensor(std.x(w.X), dtype=torch.float32),
            torch.tensor(np.nan_to_num(std.target(w)) * w.M, dtype=torch.float32),
            torch.tensor(w.M, dtype=torch.float32))


def steps_per_epoch(n_windows, batch_size):
    return int(np.ceil(n_windows / batch_size))


def train_model(train_w, std, cell, hidden, dropout, tcfg, seed, val_w=None, max_steps=None):
    """Train with AdamW and gradient clipping.

    With val_w: early stopping on validation loss (patience), restoring the best
    weights. Without it: train for exactly max_steps gradient steps (deployment
    refit). Steps, not epochs, are fixed because the refit has more windows per
    epoch; the same number of epochs would mean many more updates.
    Returns (model, best_epoch, best_val_loss).
    """
    torch.manual_seed(seed)
    Xt, Yt, Mt = _tensors(train_w, std)
    model = Forecaster(Xt.shape[-1], hidden, dropout, cell, Yt.shape[-1])
    opt = torch.optim.AdamW(model.parameters(), lr=tcfg["lr"], weight_decay=tcfg["weight_decay"])
    gen = torch.Generator().manual_seed(seed)
    val = _tensors(val_w, std) if val_w is not None else None

    best_loss, best_state, best_epoch, wait, steps = float("inf"), None, 0, 0, 0
    for epoch in range(1, tcfg["max_epochs"] + 1):
        model.train()
        for idx in torch.randperm(len(Xt), generator=gen).split(tcfg["batch_size"]):
            loss = masked_huber(model(Xt[idx]), Yt[idx], Mt[idx], tcfg["huber_delta"])
            opt.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), tcfg["grad_clip"])
            opt.step()
            steps += 1
            if max_steps is not None and steps >= max_steps:
                return model, epoch, float("nan")
        if val is None:
            continue
        model.eval()
        with torch.no_grad():
            vloss = masked_huber(model(val[0]), val[1], val[2], tcfg["huber_delta"]).item()
        if vloss < best_loss - 1e-6:
            best_loss, best_state, best_epoch, wait = vloss, copy.deepcopy(model.state_dict()), epoch, 0
        else:
            wait += 1
            if wait >= tcfg["patience"]:
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    return model, best_epoch, best_loss


def predict(model, w, std):
    model.eval()
    with torch.no_grad():
        Z = model(torch.tensor(std.x(w.X), dtype=torch.float32)).numpy()
    return std.prediction(Z, w)


# ---------------------------------------------------------------- baselines

def _line_forecast(weeks, values, future_weeks):
    mask = ~np.isnan(values)
    if mask.sum() < 2:
        return None
    slope, intercept = np.polyfit(weeks[mask], values[mask], 1)
    return intercept + slope * np.asarray(future_weeks, dtype=float)


def baseline_predictions(panel, windows, window, horizon):
    """naive, mean4 and linear predictions for every window, clipped to valid ranges."""
    preds = {"naive": [], "mean4": [], "linear": []}
    for d, t in zip(windows.dev, windows.origin):
        naive = np.array([panel.vuln_carried[d, t - 1], panel.fix_carried[d, t - 1]])
        mean4 = mean4_level(panel, d, t)
        weeks = np.arange(t - window + 1, t + 1, dtype=float)
        future = np.arange(t + 1, t + horizon + 1)
        linear = []
        for series, fallback in [(panel.target_vuln, naive[0]), (panel.target_fix, naive[1])]:
            line = _line_forecast(weeks, series[d, t - window:t], future)
            linear.append(line if line is not None else np.full(horizon, fallback))
        preds["naive"].append(np.repeat(naive, horizon))
        preds["mean4"].append(np.repeat(mean4, horizon))
        preds["linear"].append(np.concatenate(linear))
    return {k: clip_predictions(np.array(v), horizon) for k, v in preds.items()}


# ---------------------------------------------------------------- metrics

def smape(actual, pred):
    """Symmetric MAPE in percent: mean of 2|y - yhat| / (|y| + |yhat|), 0/0 counted as 0.

    Plain MAPE divides by the actual value |y|. Weekly counts are often 0, which
    makes MAPE infinite (or undefined), so one zero week would wreck the score.
    sMAPE divides by the average size of actual and prediction instead; it is
    bounded in [0, 200] and only undefined when both are 0, which is a perfect
    prediction and is counted as 0 error.
    """
    actual, pred = np.asarray(actual, float), np.asarray(pred, float)
    denom = np.abs(actual) + np.abs(pred)
    ratio = np.divide(2 * np.abs(actual - pred), denom, out=np.zeros_like(denom), where=denom > 0)
    return float(100 * ratio.mean()) if len(ratio) else float("nan")


def error_metrics(actual, pred):
    e = np.asarray(pred, float) - np.asarray(actual, float)
    return {"mae": float(np.abs(e).mean()), "rmse": float(np.sqrt((e ** 2).mean())), "smape": smape(actual, pred)}


def metric_rows(Y, M, P, horizon, target_names):
    """Metrics per target for all horizons together ("all") and for each horizon h."""
    rows = []
    for ti, name in enumerate(target_names):
        cols = list(range(ti * horizon, (ti + 1) * horizon))
        groups = [("all", cols)] + [(h + 1, [c]) for h, c in enumerate(cols)]
        for label, cs in groups:
            valid = M[:, cs].astype(bool)
            rows.append({"target": TARGET_NAMES[name], "horizon": label,
                         **error_metrics(Y[:, cs][valid], P[:, cs][valid])})
    return rows


def developer_abs_errors(Y, M, P, dev, horizon, target_index):
    """Mean absolute error per developer for one target (over all its valid test targets)."""
    cols = slice(target_index * horizon, (target_index + 1) * horizon)
    err = np.abs(P[:, cols] - Y[:, cols])
    valid = M[:, cols]
    out = {}
    for d in np.unique(dev):
        rows = dev == d
        if valid[rows].sum() > 0:
            out[d] = (err[rows] * valid[rows]).sum() / valid[rows].sum()
    return out


def wilcoxon_rows(model_name, P_model, baselines, Y, M, dev, horizon, target_names):
    """Paired Wilcoxon signed-rank test across developers on per-developer MAE.

    Aggregating to one error per developer first avoids treating the several
    windows of the same developer as independent observations.
    """
    rows = []
    for ti, name in enumerate(target_names):
        m_err = developer_abs_errors(Y, M, P_model, dev, horizon, ti)
        for b_name, P_b in baselines.items():
            b_err = developer_abs_errors(Y, M, P_b, dev, horizon, ti)
            devs = sorted(set(m_err) & set(b_err))
            diff = np.array([m_err[d] - b_err[d] for d in devs])
            p = float(wilcoxon(diff).pvalue) if np.any(diff != 0) else 1.0
            rows.append({"model": model_name, "baseline": b_name, "target": TARGET_NAMES[name],
                         "nDevelopers": len(devs), "medianDiff": float(np.median(diff)),
                         "modelBetterShare": float(np.mean(diff < 0)), "pValue": p})
    return rows


def archetype_rows(preds, Y, M, dev, panel, archetypes, horizon, target_names):
    """MAE by simulated archetype. Analysis only: archetype is never a model input."""
    rows = []
    arch_of = np.array([archetypes[panel.dev_ids[d]] for d in dev])
    for model_name, P in preds.items():
        for arch in sorted(set(arch_of)):
            sel = arch_of == arch
            for ti, name in enumerate(target_names):
                cols = slice(ti * horizon, (ti + 1) * horizon)
                valid = M[sel, cols].astype(bool)
                err = np.abs(P[sel, cols] - Y[sel, cols])[valid]
                rows.append({"archetype": arch, "model": model_name, "target": TARGET_NAMES[name],
                             "mae": float(err.mean()), "nDevelopers": int(len(set(dev[sel])))})
    return rows


def _mean_std(values):
    return {"mean": float(np.mean(values)), "std": float(np.std(values))}


# ---------------------------------------------------------------- pipeline

def tune(panel, raw_std, cfg, cell, mode, grid, tcfg, n_weeks, log):
    """Grid search scored on VALIDATION only (mean over tuning seeds). Test windows are never built here.

    The score is common_scale_loss, so raw and residual candidates are comparable.
    """
    h = cfg["forecast"]["horizon"]
    stats_week = cfg["forecast"]["split"]["train_max_target_week"]
    delta = tcfg["huber_delta"]
    best = None
    for hidden, window, dropout in grid:
        train_o, val_o, _ = split_origins(cfg, window, n_weeks)
        tr, va = make_windows(panel, window, h, train_o), make_windows(panel, window, h, val_o)
        std = Standardiser(panel, stats_week, h, mode, tr)
        scores, epochs = [], []
        for seed in tcfg["tuning_seeds"]:
            model, ep, _ = train_model(tr, std, cell, hidden, dropout, tcfg, seed, val_w=va)
            scores.append(common_scale_loss(predict(model, va, std), va, raw_std, delta))
            epochs.append(ep)
        row = {"cell": cell, "target_mode": mode, "hidden": hidden, "window": window, "dropout": dropout,
               "val_score_mean": float(np.mean(scores)), "val_score_std": float(np.std(scores)),
               "best_epoch_mean": float(np.mean(epochs)), "n_train": len(tr.X), "n_val": len(va.X)}
        log.append(row)
        print(f"  tune {cell}/{mode} hidden={hidden} L={window} dropout={dropout}: "
              f"val {row['val_score_mean']:.4f} +/- {row['val_score_std']:.4f}")
        if best is None or row["val_score_mean"] < best["val_score_mean"]:
            best = row
    return best


def run(quick=False):
    cfg = load_config()
    fc = cfg["forecast"]
    tcfg = dict(fc["training"])
    if quick:
        tcfg.update(max_epochs=fc["quick"]["max_epochs"], patience=fc["quick"]["patience"],
                    seeds=fc["quick"]["seeds"], tuning_seeds=fc["quick"]["seeds"])
        grid = [(fc["model"]["hidden"], fc["window"], fc["model"]["dropout"])]
    else:
        g = fc["grid"]
        grid = list(itertools.product(g["hidden"], g["window"], g["dropout"]))

    h, targets = fc["horizon"], fc["targets"]
    n_weeks = cfg["study"]["n_weeks"]
    stats_week = fc["split"]["train_max_target_week"]
    dw = pd.read_csv(resolve(cfg["paths"]["developer_weeks"]))
    archetypes = pd.read_csv(resolve(cfg["paths"]["developers"])).set_index("developerId")["archetype"].to_dict()

    panel = build_panel(dw, cfg, stats_week)
    raw_std = Standardiser(panel, stats_week, h, "raw")

    # 1. Tune every (cell, target mode) variant on validation
    tuning_log, selected = [], {}
    for cell in fc["model"]["cells"]:
        for mode in fc["model"]["target_modes"]:
            selected[f"{cell}_{mode}"] = tune(panel, raw_std, cfg, cell, mode, grid, tcfg, n_weeks, tuning_log)

    # 2. Final models: several seeds per variant with the selected settings, evaluated once on test
    _, _, test_o = split_origins(cfg, fc["window"], n_weeks)
    test_ref = make_windows(panel, fc["window"], h, test_o)
    Y, M = test_ref.Y, test_ref.M
    baselines = baseline_predictions(panel, test_ref, fc["window"], h)

    metrics, ensembles, seed_preds, best_epochs = [], {}, {}, {}
    for name, sel in selected.items():
        L = sel["window"]
        train_o, val_o, test_o = split_origins(cfg, L, n_weeks)
        tr, va, te = (make_windows(panel, L, h, o) for o in (train_o, val_o, test_o))
        assert np.array_equal(te.dev, test_ref.dev) and np.array_equal(te.origin, test_ref.origin)
        std = Standardiser(panel, stats_week, h, sel["target_mode"], tr)
        per_seed, preds, eps = [], [], []
        for seed in tcfg["seeds"]:
            model, ep, _ = train_model(tr, std, sel["cell"], sel["hidden"], sel["dropout"], tcfg, seed, val_w=va)
            P = predict(model, te, std)
            preds.append(P)
            eps.append(ep)
            per_seed.append(metric_rows(Y, M, P, h, targets))
        for i, row in enumerate(per_seed[0]):
            metrics.append({"model": name, "target": row["target"], "horizon": row["horizon"],
                            **{k: _mean_std([s[i][k] for s in per_seed]) for k in ("mae", "rmse", "smape")}})
        seed_preds[name] = np.stack(preds)
        ensembles[name] = seed_preds[name].mean(0)
        best_epochs[name] = eps

    ens = {f"{n}_ensemble": P for n, P in ensembles.items()}
    for name, P in {**ens, **baselines}.items():
        for row in metric_rows(Y, M, P, h, targets):
            metrics.append({"model": name, "target": row["target"], "horizon": row["horizon"],
                            **{k: {"mean": row[k], "std": 0.0} for k in ("mae", "rmse", "smape")}})

    wil = []
    for name, P in ens.items():
        wil += wilcoxon_rows(name, P, baselines, Y, M, test_ref.dev, h, targets)
    arch = archetype_rows({**ens, **baselines}, Y, M, test_ref.dev, panel, archetypes, h, targets)

    # 3. Deployment: the variant with the best VALIDATION score is refit on all data
    #    for the same number of gradient steps it needed on validation, then forecasts weeks 17-18.
    deployed = min(selected, key=lambda n: selected[n]["val_score_mean"])
    sel = selected[deployed]
    L = sel["window"]
    n_train = len(make_windows(panel, L, h, split_origins(cfg, L, n_weeks)[0]).X)
    fixed_steps = int(np.median([e * steps_per_epoch(n_train, tcfg["batch_size"]) for e in best_epochs[deployed]]))
    panel_all = build_panel(dw, cfg, n_weeks)
    all_w = make_windows(panel_all, L, h, range(L, n_weeks - h + 1))
    std_all = Standardiser(panel_all, n_weeks, h, sel["target_mode"], all_w)
    future_w = make_windows(panel_all, L, h, [n_weeks], require_targets=False)
    future = np.stack([
        predict(train_model(all_w, std_all, sel["cell"], sel["hidden"], sel["dropout"], tcfg, seed,
                            max_steps=fixed_steps)[0], future_w, std_all)
        for seed in tcfg["seeds"]])

    # 4. Write outputs
    split_info = {}
    for split, origins in zip(("train", "validation", "test"), split_origins(cfg, fc["window"], n_weeks)):
        split_info[split] = {"origins": origins, "targetWeeks": target_weeks(origins, h)}
    metrics_out = {
        "meta": {"dataSource": "simulated", "disclaimer": SIMULATED_NOTE, "quick": quick,
                 "seeds": tcfg["seeds"], "horizon": h, "baselineWindow": fc["window"],
                 "split": split_info, "nTestWindows": int(len(Y)),
                 "nTestTargets": {TARGET_NAMES[t]: int(M[:, i * h:(i + 1) * h].sum()) for i, t in enumerate(targets)},
                 "selectionScore": "validation masked Huber on the raw-standardised scale (common to raw and residual)",
                 "residualNote": RESIDUAL_NOTE},
        "selected": {n: {"cell": s["cell"], "targetMode": s["target_mode"], "hidden": s["hidden"],
                         "window": s["window"], "dropout": s["dropout"], "valScore": s["val_score_mean"],
                         "bestEpochs": best_epochs[n]}
                     for n, s in selected.items()},
        "deployed": deployed, "deploymentSteps": fixed_steps,
        "metrics": metrics, "wilcoxon": wil,
        "archetypeMaeNote": ARCHETYPE_NOTE, "archetypeMae": arch,
    }
    _write_json(resolve(fc["outputs"]["metrics"]), metrics_out)
    _write_json(resolve(fc["outputs"]["forecasts"]),
                _forecasts_json(panel, dw, test_ref, Y, M, ensembles, seed_preds[deployed], baselines,
                                future, deployed, sel, h, n_weeks))
    with open(resolve(fc["outputs"]["tuning"]), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(tuning_log[0].keys()))
        writer.writeheader()
        writer.writerows(tuning_log)

    _print_summary(metrics_out)
    return metrics_out


def _forecasts_json(panel, dw, test_w, Y, M, ensembles, deployed_seed_preds, baselines,
                    future, deployed, sel, h, n_weeks):
    def num(x):
        return None if x is None or (isinstance(x, float) and np.isnan(x)) else round(float(x), 4)

    developers = []
    dw = dw.sort_values(["developer_id", "week"])
    for d, dev_id in enumerate(panel.dev_ids):
        hist = dw[dw["developer_id"] == dev_id]
        test = []
        for i in np.where(test_w.dev == d)[0]:
            t = int(test_w.origin[i])
            for ti, name in enumerate(("vulnCount", "fixRate")):
                for k in range(h):
                    c = ti * h + k
                    rec = {"originWeek": t, "week": t + k + 1, "horizon": k + 1, "target": name,
                           "actual": num(Y[i, c]) if M[i, c] else None}
                    rec.update({cell: num(P[i, c]) for cell, P in ensembles.items()})
                    rec["band"] = {"low": num(deployed_seed_preds[:, i, c].min()),
                                   "high": num(deployed_seed_preds[:, i, c].max())}
                    rec.update({b: num(P[i, c]) for b, P in baselines.items()})
                    test.append(rec)
        fut = []
        for k in range(h):
            fut.append({"week": n_weeks + k + 1, "horizon": k + 1, **{
                name: {"mean": num(future[:, d, ti * h + k].mean()),
                       "low": num(future[:, d, ti * h + k].min()),
                       "high": num(future[:, d, ti * h + k].max())}
                for ti, name in enumerate(("vulnCount", "fixRate"))}})
        developers.append({
            "developerId": dev_id,
            "history": [{"week": int(r.week), "vulnCount": int(r.vuln_count), "fixRate": num(r.fix_rate),
                         "active": bool(r.active)} for r in hist.itertuples()],
            "test": test,
            "future": fut,
        })
    return {"meta": {"dataSource": "simulated", "disclaimer": SIMULATED_NOTE, "deployed": deployed,
                     "window": sel["window"], "horizon": h, "bandNote": BAND_NOTE},
            "developers": developers}


def _write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)


def _print_summary(out):
    print("\nTest metrics (all horizons), SIMULATED data:")
    print(f"{'model':22s} {'target':10s} {'MAE':>16s} {'RMSE':>16s} {'sMAPE':>16s}")
    for r in out["metrics"]:
        if r["horizon"] == "all":
            cells = [f"{r[k]['mean']:.3f} +/- {r[k]['std']:.3f}" for k in ("mae", "rmse", "smape")]
            print(f"{r['model']:22s} {r['target']:10s} " + " ".join(f"{c:>16s}" for c in cells))
    print("\nWilcoxon (per-developer MAE, model - baseline):")
    for r in out["wilcoxon"]:
        print(f"  {r['model']:22s} vs {r['baseline']:6s} {r['target']:9s} "
              f"median diff {r['medianDiff']:+.3f}  p={r['pValue']:.4f}")


def main():
    parser = argparse.ArgumentParser(description="Phase 2 forecasting (simulated data).")
    parser.add_argument("--quick", action="store_true", help="1 seed, few epochs, default settings only")
    run(quick=parser.parse_args().quick)


if __name__ == "__main__":
    main()
