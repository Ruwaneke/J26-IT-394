"""Phase 6: research summary report generated from outputs/analytics.json.

Writes outputs/research_summary.md and outputs/research_summary.html with
figures in outputs/figures/ (PNG, 200 dpi, black-and-white friendly).

The report is built once as a list of blocks (heading, paragraph, bullets,
table, figure) and rendered to both Markdown and HTML, so the two never
disagree. Every comparison sentence is generated from the verdicts in the JSON,
using the same rules as export.py:
- forecasting: beats = Wilcoxon p < 0.05 and lower median per-developer error;
- classification: beats = the paired bootstrap 95% CI of the macro-F1 difference
  lies entirely above 0.
A "tie" is never described as a win. tests/test_report.py checks this.
"""

import html
import json
from datetime import datetime, timezone

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from .config import load_config, resolve  # noqa: E402
from .export import forecast_verdict, interval_verdict  # noqa: E402

BASELINE_WORDS = {
    "naive": "the naive last value", "mean4": "the 4-week mean", "linear": "the linear trend",
    "logreg": "logistic regression", "persistence": "persistence", "fix_rate_rule": "the static fix-rate rule",
    "majority": "the majority class",
}
TABLE_NAMES = {
    "naive": "Naive last value", "mean4": "4-week mean", "linear": "Linear trend",
    "xgboost": "XGBoost", "logreg": "Logistic regression", "persistence": "Persistence",
    "fix_rate_rule": "Fix-rate rule", "majority": "Majority class",
}
TARGET_WORDS = {"vulnCount": "findings per week", "fixRate": "fix rate"}
BY_CONSTRUCTION = {
    frozenset({"fix_rate", "ignore_rate"}): "fix and ignore rates are shares of the same findings",
    frozenset({"severity_weighted_load", "vuln_count"}): "load is a severity-weighted count of the same findings",
}


def model_name(name):
    """gru_raw_ensemble -> 'GRU raw (seed ensemble)'."""
    if name in TABLE_NAMES:
        return TABLE_NAMES[name]
    ensemble = name.endswith("_ensemble")
    base = name.removesuffix("_ensemble")
    cell, _, mode = base.partition("_")
    label = f"{cell.upper()} {mode}".strip()
    return f"{label} (seed ensemble)" if ensemble else label


def f3(x):
    return "–" if x is None else f"{x:.3f}"


def p_text(p):
    return "–" if p is None else ("< 0.001" if p < 0.001 else f"{p:.3f}")


def join_words(items):
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


# ---------------------------------------------------------------- verdict sentences

def forecast_claims(wilcoxon, model):
    """{baseline: {target: verdict}} for one model."""
    out = {}
    for r in wilcoxon:
        if r["model"] == model:
            out.setdefault(r["baseline"], {})[r["target"]] = forecast_verdict(r)
    return out


def forecast_sentence(wilcoxon, model, subject):
    """E.g. 'The deployed forecaster (GRU raw) beats the naive last value and the linear trend on both targets, and ties the 4-week mean on both targets.'"""
    claims = forecast_claims(wilcoxon, model)
    groups, mixed = {"beats": [], "ties": [], "worse": []}, []
    for baseline, by_target in claims.items():
        verdicts = set(by_target.values())
        if len(verdicts) == 1:
            groups[verdicts.pop()].append(BASELINE_WORDS[baseline])
        else:
            mixed.append("against " + BASELINE_WORDS[baseline] + " it " + " but ".join(
                f"{v} on {TARGET_WORDS[t]}" for t, v in by_target.items()))
    parts = []
    if groups["beats"]:
        parts.append(f"beats {join_words(groups['beats'])} on both targets")
    if groups["ties"]:
        parts.append(f"ties {join_words(groups['ties'])} on both targets")
    if groups["worse"]:
        parts.append(f"is worse than {join_words(groups['worse'])} on both targets")
    text = f"{subject} " + ", and ".join(parts)
    if mixed:
        text += "; " + "; ".join(mixed)
    return text + "."


def classifier_sentence(significance):
    """E.g. 'XGBoost beats the static fix-rate rule, logistic regression and the majority class, and ties persistence.'"""
    groups = {"beats": [], "ties": [], "worse": []}
    for s in significance:
        d = s["bootstrapMacroF1Diff"]
        groups[interval_verdict(d)].append(BASELINE_WORDS[s["baseline"]])
    parts = []
    if groups["beats"]:
        parts.append(f"beats {join_words(groups['beats'])}")
    if groups["ties"]:
        parts.append(f"ties {join_words(groups['ties'])}")
    if groups["worse"]:
        parts.append(f"is worse than {join_words(groups['worse'])}")
    return "In repeated grouped cross-validation, XGBoost " + ", and ".join(parts) + " on macro F1."


def key_findings(a):
    fe, re_ = a["forecastEvaluation"], a["riskEvaluation"]
    deployed = fe["deployed"]
    ens = f"{deployed}_ensemble"
    findings = [
        "All results describe SIMULATED developers generated from the assumptions listed in this report, "
        "not real developers.",
        forecast_sentence(fe["wilcoxon"], ens, f"The deployed forecaster ({model_name(deployed)}, chosen on validation)"),
    ]
    for name in sorted(n for n in fe["selected"] if n.endswith("_residual")):
        findings.append(forecast_sentence(fe["wilcoxon"], f"{name}_ensemble",
                                          f"The post-hoc residual variant {model_name(name)}"))
    findings.append(classifier_sentence(re_["significance"]))

    mean4_ties = all(v != "beats" for v in forecast_claims(fe["wilcoxon"], ens).get("mean4", {}).values())
    persistence = next(s for s in re_["significance"] if s["baseline"] == "persistence")
    persist_ties = interval_verdict(persistence["bootstrapMacroF1Diff"]) != "beats"
    if mean4_ties and persist_ties:
        top = re_["featureImportance"][0]["feature"]
        findings.append("Recent behaviour is the strongest predictor on this data: neither model is reliably better than a "
                        "baseline that repeats the last 4 weeks (the 4-week mean for forecasting, persistence for "
                        f"risk). The classifier's most important feature is {top}.")
    else:
        findings.append("At least one model beats a recent-behaviour baseline; see the result tables for the size "
                        "of the gain.")
    findings.append("Two variants were added after the first results were seen (post-hoc): the residual forecasting "
                    "mode and the extra classifier features (severity-weighted ignore rate and past risk score). "
                    "Both were selected on validation or training-fold data only, but they are still post-hoc.")
    sig = [p for p in a["correlations"]["developer"]["pairs"] if p["pearson"]["significant"]]
    built_in = sum(frozenset({p["x"], p["y"]}) in BY_CONSTRUCTION for p in sig)
    findings.append(f"At developer level, {len(sig)} of {a['correlations']['developer']['nTests']} metric pairs remain "
                    f"significant after Benjamini-Hochberg correction; {built_in} of them are partly true by "
                    "construction.")
    return findings


# ---------------------------------------------------------------- figures

def _style():
    plt.rcParams.update({"font.size": 9, "axes.grid": True, "grid.color": "#cccccc", "grid.linewidth": 0.5,
                         "axes.spines.top": False, "axes.spines.right": False})


def figure_team_trend(a, path, dpi):
    team = a["trends"]["team"]
    weeks = [w["week"] for w in team]
    fig, ax = plt.subplots(figsize=(7, 3.4))
    ax.bar(weeks, [w["vulnCount"] for w in team], color="#bbbbbb", edgecolor="black", linewidth=0.5,
           label="Findings per week")
    ax.plot(weeks, [w["vulnCountMa4"] for w in team], color="black", linewidth=1.8, label="4-week moving average")
    ax.set_xlabel("Study week")
    ax.set_ylabel("Findings (count per week)")
    ax2 = ax.twinx()
    ax2.plot(weeks, [100 * w["fixRate"] for w in team], color="black", linestyle="--", marker="o", markersize=3,
             label="Fix rate")
    ax2.set_ylabel("Fix rate (%)")
    ax2.set_ylim(0, 100)
    ax2.grid(False)
    handles = ax.get_legend_handles_labels()[0] + ax2.get_legend_handles_labels()[0]
    ax.legend(handles, [h.get_label() for h in handles], loc="lower right", fontsize=8)
    ax.set_title("Team weekly findings and fix rate (simulated)")
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)


def figure_forecast_mae(a, path, dpi):
    fe = a["forecastEvaluation"]
    models = [f"{fe['deployed']}_ensemble", "naive", "mean4", "linear"]
    hatches = ["", "//", "..", "xx"]
    fig, axes = plt.subplots(1, 2, figsize=(7, 3.2))
    for ax, target, unit in zip(axes, ("vulnCount", "fixRate"), ("findings per week", "proportion")):
        values = [next(m["mae"]["mean"] for m in fe["metrics"]
                       if m["model"] == model and m["target"] == target and m["horizon"] == "all") for model in models]
        for i, (v, h) in enumerate(zip(values, hatches)):
            ax.bar(i, v, color="#dddddd" if i == 0 else "white", edgecolor="black", hatch=h)
            ax.text(i, v, f"{v:.3f}", ha="center", va="bottom", fontsize=7)
        ax.set_xticks(range(len(models)), [model_name(m).replace(" (seed ensemble)", "") for m in models],
                      rotation=20, ha="right")
        ax.set_ylabel(f"MAE ({unit})")
        ax.set_title(f"Test MAE: {TARGET_WORDS[target]}")
    fig.suptitle("Forecasting error, test weeks 13-16 (lower is better)", fontsize=9)
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)


def figure_classifier(a, path, dpi):
    rows = a["riskEvaluation"]["headline"]
    fig, ax = plt.subplots(figsize=(7, 3))
    y = np.arange(len(rows))[::-1]
    means = [r["macroF1"]["mean"] for r in rows]
    err = [[r["macroF1"]["mean"] - r["macroF1"]["ciLow"] for r in rows],
           [r["macroF1"]["ciHigh"] - r["macroF1"]["mean"] for r in rows]]
    ax.errorbar(means, y, xerr=err, fmt="o", color="black", ecolor="black", capsize=4)
    ax.set_yticks(y, [TABLE_NAMES[r["model"]] for r in rows])
    ax.set_xlabel("Macro F1 (0-1), mean over CV repeats with 95% developer-bootstrap CI")
    ax.set_xlim(0, 1)
    ax.set_title("Risk classification, repeated grouped CV (higher is better)")
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)


def figure_correlations(a, path, dpi):
    level = a["correlations"]["developer"]
    labels = [a["correlations"]["variableLabels"][v] for v in level["variables"]]
    r = np.array([[np.nan if v is None else v for v in row] for row in level["matrices"]["pearson"]["r"]], dtype=float)
    sig = level["matrices"]["pearson"]["significant"]
    fig, ax = plt.subplots(figsize=(6.4, 5.4))
    im = ax.imshow(np.abs(r), cmap="Greys", vmin=0, vmax=1)
    for i in range(len(labels)):
        for j in range(len(labels)):
            if i == j:
                continue
            text = f"{r[i, j]:+.2f}" + ("*" if sig[i][j] else "")
            ax.text(j, i, text, ha="center", va="center", fontsize=7,
                    color="white" if abs(r[i, j]) > 0.55 else "black")
    ax.set_xticks(range(len(labels)), labels, rotation=40, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    ax.grid(False)
    cbar = fig.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label("|Pearson r| (strength, 0-1)")
    ax.set_title("Developer-level Pearson r (sign in cell; * = significant after BH)", fontsize=9)
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)


def figure_risk_bands(a, path, dpi):
    counts = a["overview"]["riskBandCounts"]
    fig, ax = plt.subplots(figsize=(4.5, 3))
    bands = ["LOW", "MEDIUM", "HIGH"]
    for i, (b, h) in enumerate(zip(bands, ["", "//", "xx"])):
        ax.bar(i, counts[b], color="white", edgecolor="black", hatch=h)
        ax.text(i, counts[b], str(counts[b]), ha="center", va="bottom")
    ax.set_xticks(range(3), bands)
    ax.set_xlabel("Research risk profile band (predicted for weeks 17-20)")
    ax.set_ylabel("Developers (count)")
    ax.set_title("Risk profile bands at week 16 (simulated)", fontsize=9)
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)


FIGURES = [
    ("team_trend.png", figure_team_trend, "Team weekly findings (bars), 4-week moving average and fix rate."),
    ("forecast_mae.png", figure_forecast_mae, "Test MAE of the deployed forecaster and the three baselines."),
    ("classifier_f1.png", figure_classifier, "Macro F1 with 95% CIs from repeated grouped cross-validation."),
    ("correlation_heatmap.png", figure_correlations, "Developer-level Pearson correlations; * marks BH-significant pairs."),
    ("risk_bands.png", figure_risk_bands, "Number of developers in each research risk profile band."),
]


# ---------------------------------------------------------------- document

def build_blocks(a, cfg, figure_dir_name):
    meta, ov, fe, re_ = a["meta"], a["overview"], a["forecastEvaluation"], a["riskEvaluation"]
    sim, fc, rc = cfg["simulation"], cfg["forecast"], cfg["risk"]
    B = []
    B.append(("h1", "Sentinel Component 4: research summary"))
    B.append(("note", f"SIMULATED DATA. {meta['disclaimer']} Every number in this report describes the simulator's "
                      "assumptions, not real developers."))
    B.append(("p", f"Generated {meta['generatedAt']} from analytics.json (seed {meta['seed']}, "
                   f"{meta['nDevelopers']} developers, {meta['nWeeks']} weeks from {meta['studyStart']})."))

    B.append(("h2", "1. Purpose and scope"))
    B.append(("p", "Sentinel is a four-component system. Component 1 detects vulnerabilities in the editor. "
                   "Component 2 tracks how developers respond. Component 3 adapts the feedback. Component 4 (this "
                   "report) analyses the behaviour data. It asks whether developers' secure-coding behaviour "
                   "changes over time, whether it can be forecast, whether a developer's near-future behaviour can be "
                   "profiled, which behaviour metrics move together, and what simple rules would recommend."))

    B.append(("h2", "2. Data (simulated)"))
    B.append(("p", "Components 1-3 do not produce data yet, so a seeded simulator generates security events with the "
                   "same schema that Component 2 will use. The results describe these assumptions, not real people."))
    mix = ", ".join(f"{k} {int(round(v * sim['n_developers']))}" for k, v in sim["archetype_mix"].items())
    B.append(("ul", [
        f"{sim['n_developers']} developers over {cfg['study']['n_weeks']} weeks; archetypes (hidden ground truth, "
        f"never a model input): {mix}.",
        f"Each week a developer is inactive with probability {sim['p_inactive_week']}; active weeks have "
        f"1 + Poisson({sim['sessions_per_week_mean'] - 1:g}) sessions.",
        f"Detections per session ~ Poisson(lambda); lambda has a per-developer base (median {sim['base_rate_median']}) "
        f"that falls by up to {int(sim['rate_change'] * 100)}% for improving and rises for worsening developers; "
        f"erratic developers follow a mean-reverting AR(1) walk (phi {sim['erratic_ar_phi']}).",
        "Fix propensity, ignored share, response time (lognormal) and repeat propensity move linearly over the study "
        "for each archetype (for example, fix propensity 0.45 to 0.85 for improving and 0.60 to 0.30 for worsening).",
        f"Each developer works on {sim['working_set_size'][0]}-{sim['working_set_size'][1]} files with uneven usage; a "
        "repeat is the same (type, file) flagged within the previous 4 weeks.",
        "Vulnerability types SQL injection, XSS, hard-coded secrets and command injection, with type-dependent severity; "
        "false-positive rate per developer ~ Beta(2, 28).",
        f"Result: {ov['totalEvents']:,} detections in {ov['totalSessions']:,} sessions; pooled fix rate "
        f"{100 * ov['fixRate']:.0f}%, ignore rate {100 * ov['ignoreRate']:.0f}%.",
    ]))
    B.append(("fig", f"{figure_dir_name}/team_trend.png", FIGURES[0][2]))

    B.append(("h2", "3. Methods"))
    B.append(("ul", [
        "Weekly features per developer: findings, fix/ignore/false-positive rates, response time, repeats, "
        "severity-weighted load, per-type counts and findings per session. Undefined rates are left empty, never 0.",
        "Trend analysis: 4-week moving averages, week-over-week change and least-squares slopes; team rates are pooled.",
        f"Forecasting: a pooled 1-layer GRU and LSTM read the last {fc['window']} weeks of 7 inputs and predict findings "
        f"and fix rate {fc['horizon']} weeks ahead. Masked Huber loss, AdamW, early stopping, {len(fe['seeds'])} seeds "
        "(mean ± std; the test predictions are the seed mean).",
        "Forecasting baselines: naive last value, 4-week mean and a per-developer linear trend.",
        f"Chronological split by target week: train targets ≤ week {fc['split']['train_max_target_week']}, validation "
        f"targets weeks {min(fe['split']['validation']['targetWeeks'])}-{max(fe['split']['validation']['targetWeeks'])}, "
        f"test targets weeks {min(fe['split']['test']['targetWeeks'])}-{max(fe['split']['test']['targetWeeks'])}. "
        "Standardisation uses training data only; tuning uses validation only.",
        "Forecast metrics: MAE, RMSE and sMAPE (sMAPE is used because plain MAPE is undefined for zero counts). "
        "Significance: paired Wilcoxon signed-rank test on per-developer MAE.",
        f"Risk label: the developer's FUTURE risk score over weeks t+1 to t+4 (0.4 severity-weighted ignore rate + "
        "0.3 (1 - fix rate) + 0.2 repeat rate + 0.1 log response time, the last two min-max scaled), banded at the "
        f"frozen thresholds {rc['thresholds']['medium']} and {rc['thresholds']['high']}. Features use weeks ≤ t only.",
        "Risk models: XGBoost with balanced class weights, against four baselines: majority class, static fix-rate rule, "
        "persistence (the same score on the last 4 weeks) and logistic regression.",
        f"Validation: configuration chosen by GroupKFold on training developers; headline = {re_['headlineMethod']}. "
        "Main significance test: paired developer-level bootstrap of the macro-F1 difference.",
        "Correlation: Pearson and Spearman at developer level (per-developer means over active weeks, n = "
        f"{meta['nDevelopers']}) to avoid pseudo-replication, with Fisher-z CIs and Benjamini-Hochberg correction.",
        f"Recommendations: {len(a['recommendations']['rules'])} configurable rules on the risk band, forecast direction, "
        "the developer's own recent metrics and dominant vulnerability type; up to 3 per developer.",
    ]))

    B.append(("h2", "4. Results"))
    B.append(("h3", "4.1 Forecasting (test weeks 13-16)"))
    B.append(("p", fe["residualNote"] + " Variant rows show mean ± std over seeds; ensemble and baseline rows are single values."))
    rows = []
    models = list(dict.fromkeys(m["model"] for m in fe["metrics"] if m["horizon"] == "all"))
    for model in models:
        cells = [model_name(model) + (" (deployed)" if model == fe["deployed"] else "")
                 + (" (post-hoc)" if model.endswith("residual") else "")]
        for target in ("vulnCount", "fixRate"):
            m = next(x for x in fe["metrics"] if x["model"] == model and x["target"] == target and x["horizon"] == "all")
            for key, digits in (("mae", 3), ("rmse", 3), ("smape", 1)):
                mean, std = m[key]["mean"], m[key]["std"]
                cells.append(f"{mean:.{digits}f}" + (f" ± {std:.{digits}f}" if std else ""))
        rows.append(cells)
    B.append(("table", ["Model", "MAE findings", "RMSE findings", "sMAPE findings (%)", "MAE fix rate",
                        "RMSE fix rate", "sMAPE fix rate (%)"], rows))
    B.append(("fig", f"{figure_dir_name}/forecast_mae.png", FIGURES[1][2]))
    B.append(("p", "Wilcoxon signed-rank tests on per-developer MAE (model minus baseline; negative = model better)."))
    B.append(("table", ["Model", "Baseline", "Target", "Median difference", "p", "Verdict"],
              [[model_name(w["model"]), TABLE_NAMES[w["baseline"]], TARGET_WORDS[w["target"]], f3(w["medianDiff"]),
                p_text(w["pValue"]), forecast_verdict(w)] for w in fe["wilcoxon"]]))

    B.append(("h3", "4.2 Risk classification"))
    balance = re_["classBalance"]["all"]
    B.append(("p", f"{re_['headlineMethod']}. Class balance: {balance['LOW']} LOW, {balance['MEDIUM']} MEDIUM, "
                   f"{balance['HIGH']} HIGH rows. {re_['postHocNote']}"))
    B.append(("table", ["Model", "Macro F1 (mean ± std)", "95% CI", "Accuracy", "HIGH recall"],
              [[TABLE_NAMES[h["model"]], f"{h['macroF1']['mean']:.3f} ± {h['macroF1']['std']:.3f}",
                f"[{h['macroF1']['ciLow']:.3f}, {h['macroF1']['ciHigh']:.3f}]", f3(h["accuracy"]["mean"]),
                f3(h["recallHigh"]["mean"])] for h in re_["headline"]]))
    B.append(("table", ["XGBoost vs", "Macro-F1 difference", "95% CI", "P(XGBoost better)", "Verdict",
                        "McNemar p (secondary)"],
              [[TABLE_NAMES[s["baseline"]], f"{s['bootstrapMacroF1Diff']['meanDiff']:+.3f}",
                f"[{s['bootstrapMacroF1Diff']['ciLow']:+.3f}, {s['bootstrapMacroF1Diff']['ciHigh']:+.3f}]",
                f"{s['bootstrapMacroF1Diff']['xgbBetterShare']:.2f}", interval_verdict(s["bootstrapMacroF1Diff"]),
                p_text(s["mcnemarRepeat1"]["pValue"])] for s in re_["significance"]]))
    B.append(("p", re_["significance"][0]["mcnemarRepeat1"]["note"]))
    B.append(("fig", f"{figure_dir_name}/classifier_f1.png", FIGURES[2][2]))
    r1 = re_["round1"]
    B.append(("p", f"Round 1 (12 held-out developers): {r1['note']}"))
    B.append(("table", ["Model", "Macro F1, original features", "Macro F1, extended features (post-hoc)"],
              [[TABLE_NAMES[r["model"]], f3(r["macroF1"]),
                f3(next(x["macroF1"] for x in r1["extendedFeatures"] if x["model"] == r["model"]))]
               for r in r1["originalFeatures"]]))
    B.append(("p", "Global importance (mean |SHAP|), top 5: "
                   + ", ".join(f"{f['feature']} ({f['meanAbsShap']:.3f})" for f in re_["featureImportance"][:5])
                   + ". " + re_["featureImportanceNote"]))
    B.append(("fig", f"{figure_dir_name}/risk_bands.png", FIGURES[4][2]))

    B.append(("h3", "4.3 Correlations (developer level)"))
    labels = a["correlations"]["variableLabels"]
    dev = a["correlations"]["developer"]
    sig = sorted((p for p in dev["pairs"] if p["pearson"]["significant"] or p["spearman"]["significant"]),
                 key=lambda p: -abs(p["pearson"]["r"]))
    B.append(("p", f"{len(sig)} of {dev['nTests']} pairs are significant after Benjamini-Hochberg correction "
                   f"(alpha {dev['alpha']}). Pairs marked 'yes' are partly true by construction."))
    B.append(("table", ["Pair", "Pearson r [95% CI]", "p (BH)", "Spearman rho", "p (BH)", "By construction"],
              [[f"{labels[p['x']]} ~ {labels[p['y']]}",
                f"{p['pearson']['r']:+.2f} [{p['pearson']['ci'][0]:+.2f}, {p['pearson']['ci'][1]:+.2f}]",
                p_text(p["pearson"]["pAdj"]), f"{p['spearman']['r']:+.2f}", p_text(p["spearman"]["pAdj"]),
                ("yes: " + BY_CONSTRUCTION[frozenset({p['x'], p['y']})]) if frozenset({p["x"], p["y"]}) in BY_CONSTRUCTION else "no"]
               for p in sig]))
    B.append(("fig", f"{figure_dir_name}/correlation_heatmap.png", FIGURES[3][2]))

    B.append(("h2", "5. Key findings"))
    B.append(("ul", key_findings(a)))

    B.append(("h2", "6. Limitations"))
    B.append(("ul", [
        "Simulated data: the archetypes and linear trajectories are design assumptions, so models partly recover the "
        "simulator's own rules. Real behaviour may be non-linear and driven by the feedback itself.",
        f"Small sample: {meta['nDevelopers']} developers and {meta['nWeeks']} weeks; few training windows for a neural "
        "model and wide confidence intervals.",
        "Post-hoc variants (residual forecasting, extra classifier features) were added after first results were seen.",
        "The risk label is a designed formula with frozen constants and thresholds set from round-1 training "
        "developers; some of them fall in test folds of the repeated CV.",
        "The forecast band is a seed spread, not a calibrated confidence interval.",
        "Correlations across developers do not show causes within a developer; some pairs are related by construction.",
        "Recommendation thresholds are design choices, not fitted values.",
    ]))

    B.append(("h2", "7. Future work"))
    B.append(("ul", [
        "Use real data: Sentinel's stored vulnerability records and Component 2's behaviour events, via an ingest "
        "adapter that maps them onto the Component 4 event schema (outcome actions, detectedAt, sessions).",
        "Run a longer study with more developers so trends and models can be tested with adequate power.",
        "Integrate the dashboard into the Sentinel extension instead of running it as a separate extension.",
        "Calibrate the risk thresholds and recommendation rules with expert (security lead or supervisor) input.",
    ]))
    return B


def to_markdown(blocks):
    out = []
    for b in blocks:
        kind = b[0]
        if kind == "h1":
            out.append(f"# {b[1]}\n")
        elif kind == "h2":
            out.append(f"## {b[1]}\n")
        elif kind == "h3":
            out.append(f"### {b[1]}\n")
        elif kind == "note":
            out.append(f"> **{b[1]}**\n")
        elif kind == "p":
            out.append(f"{b[1]}\n")
        elif kind == "ul":
            out.append("\n".join(f"- {item}" for item in b[1]) + "\n")
        elif kind == "table":
            head, rows = b[1], b[2]
            lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
            lines += ["| " + " | ".join(str(c).replace("|", "\\|") for c in row) + " |" for row in rows]
            out.append("\n".join(lines) + "\n")
        elif kind == "fig":
            out.append(f"![{b[2]}]({b[1]})\n\n*{b[2]}*\n")
    return "\n".join(out)


def to_html(blocks, title):
    e = html.escape
    body = []
    for b in blocks:
        kind = b[0]
        if kind in ("h1", "h2", "h3"):
            body.append(f"<{kind}>{e(b[1])}</{kind}>")
        elif kind == "note":
            body.append(f'<p class="note"><strong>{e(b[1])}</strong></p>')
        elif kind == "p":
            body.append(f"<p>{e(b[1])}</p>")
        elif kind == "ul":
            body.append("<ul>" + "".join(f"<li>{e(i)}</li>" for i in b[1]) + "</ul>")
        elif kind == "table":
            head = "".join(f"<th>{e(h)}</th>" for h in b[1])
            rows = "".join("<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in r) + "</tr>" for r in b[2])
            body.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
        elif kind == "fig":
            body.append(f'<figure><img src="{e(b[1])}" alt="{e(b[2])}"><figcaption>{e(b[2])}</figcaption></figure>')
    css = ("body{font-family:Georgia,'Times New Roman',serif;max-width:900px;margin:2em auto;padding:0 1em;"
           "color:#111;line-height:1.45}table{border-collapse:collapse;margin:1em 0;font-size:0.9em}"
           "th,td{border:1px solid #888;padding:4px 8px;text-align:left;vertical-align:top}th{background:#eee}"
           ".note{border:2px solid #000;padding:8px}figure{margin:1em 0}img{max-width:100%}"
           "figcaption{font-style:italic;font-size:0.9em}")
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>{e(title)}</title>'
            f"<style>{css}</style></head><body>\n" + "\n".join(body) + "\n</body></html>\n")


def run():
    cfg = load_config()
    rp = cfg["report"]
    with open(resolve(cfg["export"]["output"]), encoding="utf-8") as f:
        a = json.load(f)
    fig_dir = resolve(rp["figures"])
    fig_dir.mkdir(parents=True, exist_ok=True)
    _style()
    for name, fn, _ in FIGURES:
        fn(a, fig_dir / name, rp["dpi"])
    blocks = build_blocks(a, cfg, fig_dir.name)
    md_path, html_path = resolve(rp["markdown"]), resolve(rp["html"])
    md_path.write_text(to_markdown(blocks), encoding="utf-8")
    html_path.write_text(to_html(blocks, "Sentinel Component 4 research summary"), encoding="utf-8")
    print(f"Wrote {md_path}, {html_path} and {len(FIGURES)} figures in {fig_dir} "
          f"({datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC)")
    for finding in key_findings(a):
        print(f"- {finding}")


def main():
    run()


if __name__ == "__main__":
    main()
