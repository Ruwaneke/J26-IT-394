"""Phase 4: assemble every pipeline output into ONE contract file, outputs/analytics.json.

The dashboard reads only this file. It is validated against
analytics.schema.json by a test. A 20-developer sample of the same shape is
written to frontend/public/sample-analytics.json so the frontend can run
without the pipeline.

keyFindings are generated from the computed results (verdicts from the
significance tests), not written by hand, so they always match the numbers.
Verdict rules:
- forecasting: "beats" if Wilcoxon p < 0.05 and the median per-developer error
  difference is negative; "worse" if p < 0.05 and positive; otherwise "ties".
- risk: "beats" if the 95% CI of the paired bootstrap difference in macro F1
  is entirely above 0, "worse" if entirely below 0, otherwise "ties".
"""

import argparse
import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from .config import load_config, resolve

SCHEMA_VERSION = "1.0.0"
SIMULATED_NOTE = "Simulated data generated from stated assumptions; not real developer data."
BASELINE_NAMES = {"naive": "naive last value", "mean4": "4-week mean", "linear": "linear trend",
                  "logreg": "logistic regression", "persistence": "persistence (last 4 weeks' score)",
                  "fix_rate_rule": "fix-rate rule", "majority": "majority class"}
TARGET_WORDS = {"vulnCount": "findings per week", "fixRate": "fix rate"}


def clean(obj):
    """Recursively turn NaN/inf and numpy scalars into JSON-safe values."""
    if isinstance(obj, dict):
        return {str(k): clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [clean(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating, float)):
        return None if not np.isfinite(obj) else float(obj)
    if isinstance(obj, np.bool_):
        return bool(obj)
    return obj


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _num(x, digits=4):
    return None if x is None or (isinstance(x, float) and np.isnan(x)) else round(float(x), digits)


# ---------------------------------------------------------------- sections

def overview(dw, risk, recs, dev_trends):
    v = dw["vuln_count"].sum()
    return {
        "nWeeks": int(dw["week"].max()),
        "totalEvents": int(v),
        "totalSessions": int(dw["n_sessions"].sum()),
        "activeDevelopers": int(dw.groupby("developer_id")["active"].any().sum()),
        "fixRate": float(dw["n_fixed"].sum() / v),
        "ignoreRate": float(dw["n_ignored"].sum() / v),
        "falsePositiveRate": float(dw["n_false_positive"].sum() / v),
        "avgResponseTimeSec": float((dw["avg_response_time"].fillna(0) * dw["vuln_count"]).sum() / v),
        "introRatePerSession": float(v / dw["n_sessions"].sum()),
        "riskBandCounts": {b: sum(d["band"] == b for d in risk["developers"]) for b in ("LOW", "MEDIUM", "HIGH")},
        "priorityCounts": {str(p): sum(d["priority"] == p for d in recs["developers"]) for p in (1, 2, 3)},
        "trendDirections": {k: int(c) for k, c in dev_trends["direction"].value_counts().items()},
    }


def team_trends(team, cfg):
    rows = []
    for r in team.itertuples():
        rows.append({
            "week": int(r.week), "vulnCount": int(r.vuln_count), "activeDevelopers": int(r.active_developers),
            "sessions": int(r.n_sessions), "fixRate": _num(r.fix_rate), "ignoreRate": _num(r.ignore_rate),
            "falsePositiveRate": _num(r.false_positive_rate), "avgResponseTime": _num(r.avg_response_time, 1),
            "severityWeightedLoad": int(r.severity_weighted_load), "repeatCount": int(r.repeat_count),
            "introRatePerSession": _num(r.intro_rate_per_session), "vulnCountMa4": _num(r.vuln_count_ma4, 2),
            "fixRateMa4": _num(r.fix_rate_ma4), "vulnCountWow": _num(r.vuln_count_wow, 2),
            "byType": {v: int(getattr(r, f"count_{v.lower()}")) for v in cfg["vulnerability_types"]},
        })
    return rows


def developer_trends(dwt, summary):
    s = summary.set_index("developer_id")
    out = []
    for dev, g in dwt.sort_values(["developer_id", "week"]).groupby("developer_id"):
        out.append({
            "developerId": dev,
            "introRateSlope": _num(s.loc[dev, "intro_rate_slope"]), "fixRateSlope": _num(s.loc[dev, "fix_rate_slope"]),
            "direction": s.loc[dev, "direction"], "activeWeeks": int(s.loc[dev, "active_weeks"]),
            "weeks": [{"week": int(r.week), "active": bool(r.active), "vulnCount": int(r.vuln_count),
                       "fixRate": _num(r.fix_rate), "introRatePerSession": _num(r.intro_rate_per_session),
                       "vulnCountMa4": _num(r.vuln_count_ma4, 2), "vulnCountSlope4": _num(r.vuln_count_slope4)}
                      for r in g.itertuples()],
        })
    return out


# ---------------------------------------------------------------- key findings

def forecast_verdict(row, alpha=0.05):
    if row["pValue"] < alpha:
        return "beats" if row["medianDiff"] < 0 else "worse"
    return "ties"


def interval_verdict(diff):
    return "beats" if diff["ciLow"] > 0 else "worse" if diff["ciHigh"] < 0 else "ties"


def _forecast_sentence(model, label, wilcoxon):
    rows = [r for r in wilcoxon if r["model"] == f"{model}_ensemble"]
    parts = []
    for b in ("naive", "linear", "mean4"):
        verdicts = {r["target"]: (forecast_verdict(r), r["pValue"]) for r in rows if r["baseline"] == b}
        if len({v for v, _ in verdicts.values()}) == 1:
            v = next(iter(verdicts.values()))[0]
            ps = ", ".join(f"{TARGET_WORDS[t]} p = {p:.3g}" for t, (_, p) in verdicts.items())
            parts.append(f"{v} the {BASELINE_NAMES[b]} on both targets ({ps})")
        else:
            parts.append(f"against the {BASELINE_NAMES[b]}: " + "; ".join(
                f"{v} on {TARGET_WORDS[t]} (p = {p:.3g})" for t, (v, p) in verdicts.items()))
    return f"{label} " + "; ".join(parts) + "."


def key_findings(fm, rm, corr):
    """Plain statements derived from the computed results."""
    findings = [{"topic": "data", "text": "All results come from SIMULATED data generated from stated assumptions "
                                          "(60 developers, 16 weeks). They are not findings about real developers."}]
    deployed = fm["deployed"]
    findings.append({"topic": "forecast", "text": _forecast_sentence(
        deployed, f"Forecasting: the deployed model ({deployed}, chosen on validation)", fm["wilcoxon"])})
    residual = min((n for n in fm["selected"] if n.endswith("_residual")), key=lambda n: fm["selected"][n]["valScore"])
    findings.append({"topic": "forecast", "text": _forecast_sentence(
        residual, f"The residual variant ({residual}, added post-hoc after the first test results)", fm["wilcoxon"])})

    risk_parts = []
    for s in rm["significance"]:
        d = s["bootstrapMacroF1Diff"]
        risk_parts.append(f"{interval_verdict(d)} {BASELINE_NAMES[s['baseline']]} "
                          f"(macro-F1 difference {d['meanDiff']:+.3f}, 95% CI [{d['ciLow']:+.3f}, {d['ciHigh']:+.3f}])")
    findings.append({"topic": "risk", "text": "Risk classification (repeated grouped CV over all developers): XGBoost "
                                              + "; ".join(risk_parts) + "."})

    mean4_ties = all(forecast_verdict(r) != "beats" for r in fm["wilcoxon"]
                     if r["model"] == f"{deployed}_ensemble" and r["baseline"] == "mean4")
    persistence = next(s for s in rm["significance"] if s["baseline"] == "persistence")
    persist_ties = interval_verdict(persistence["bootstrapMacroF1Diff"]) != "beats"
    top = rm["featureImportance"][0]["feature"]
    if mean4_ties and persist_ties:
        text = ("Recent behaviour is the strongest predictor: no model reliably beats a baseline that simply repeats the "
                "last 4 weeks (the 4-week mean for forecasting, persistence for risk)")
        text += f", and the classifier's most important feature is {top}." if top.startswith("past_score") else "."
    else:
        text = ("At least one model beats the recent-behaviour baselines (4-week mean or persistence); see the "
                "evaluation sections for the size of the gain.")
    findings.append({"topic": "summary", "text": text})

    r1 = {r["model"]: r["macroF1"] for r in rm["round1"]["originalFeatures"]}
    findings.append({"topic": "risk", "text": f"Round 1 (12 held-out developers, already seen): persistence macro F1 "
                                              f"{r1['persistence']:.2f} vs XGBoost {r1['xgboost']:.2f} with the original "
                                              f"features. The extended features were added post-hoc."})

    sig = [p for p in corr["developer"]["pairs"] if p["pearson"]["significant"]]
    sig.sort(key=lambda p: -abs(p["pearson"]["r"]))
    labels = corr["meta"]["variableLabels"]
    listed = ", ".join(f"{labels[p['x']]} ~ {labels[p['y']]} (r = {p['pearson']['r']:+.2f})" for p in sig[:4])
    findings.append({"topic": "correlation", "text": (
        f"At developer level, {len(sig)} of {corr['developer']['nTests']} pairs remain significant after "
        f"Benjamini-Hochberg correction (Pearson). Strongest: {listed}. Some pairs are related by construction: fix and "
        f"ignore rates are shares of the same findings, and severity-weighted load is a weighted count of findings.")})
    return findings


# ---------------------------------------------------------------- assembly

def build(cfg):
    p = cfg["paths"]
    dw = pd.read_csv(resolve(p["developer_weeks"]))
    dwt = pd.read_csv(resolve(p["developer_week_trends"]))
    summary = pd.read_csv(resolve(p["developer_trends"]))
    team = pd.read_csv(resolve(p["team_weeks"]))
    forecasts = _load(resolve(cfg["forecast"]["outputs"]["forecasts"]))
    fm = _load(resolve(cfg["forecast"]["outputs"]["metrics"]))
    risk = _load(resolve(cfg["risk"]["outputs"]["risk"]))
    rm = _load(resolve(cfg["risk"]["outputs"]["metrics"]))
    corr = _load(resolve(cfg["correlation"]["output"]))
    recs = _load(resolve(cfg["recommend"]["output"]))

    return clean({
        "meta": {"schemaVersion": SCHEMA_VERSION, "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "dataSource": "simulated", "disclaimer": SIMULATED_NOTE, "seed": cfg["seed"],
                 "nDevelopers": int(dw["developer_id"].nunique()), "nWeeks": cfg["study"]["n_weeks"],
                 "studyStart": cfg["study"]["start_date"],
                 "quick": bool(fm["meta"]["quick"] or rm["meta"]["quick"])},
        "overview": overview(dw, risk, recs, summary),
        "trends": {"team": team_trends(team, cfg), "developers": developer_trends(dwt, summary)},
        "forecast": {**{k: forecasts["meta"][k] for k in ("deployed", "window", "horizon", "bandNote")},
                     "developers": forecasts["developers"]},
        "forecastEvaluation": {
            "split": fm["meta"]["split"], "seeds": fm["meta"]["seeds"], "nTestWindows": fm["meta"]["nTestWindows"],
            "nTestTargets": fm["meta"]["nTestTargets"], "selectionScore": fm["meta"]["selectionScore"],
            "residualNote": fm["meta"]["residualNote"], "selected": fm["selected"], "deployed": fm["deployed"],
            "deploymentSteps": fm["deploymentSteps"], "metrics": fm["metrics"], "wilcoxon": fm["wilcoxon"],
            "archetypeMaeNote": fm["archetypeMaeNote"], "archetypeMae": fm["archetypeMae"]},
        "risk": {**{k: risk["meta"][k] for k in ("framing", "thresholds", "scoredAtWeek", "predictsWeeks",
                                                 "driversNote", "scoreHistoryNote")},
                 "developers": risk["developers"]},
        "riskEvaluation": {
            "headlineMethod": rm["meta"]["headlineMethod"], "postHocNote": rm["meta"]["postHocNote"],
            "scoreWeights": rm["meta"]["scoreWeights"], "labelNormaliser": rm["meta"]["labelNormaliser"],
            "featureSets": rm["meta"]["featureSets"], "classBalance": rm["classBalance"], "selected": rm["selected"],
            "headline": rm["headline"], "significance": rm["significance"], "round1": rm["round1"],
            "featureImportance": rm["featureImportance"], "featureImportanceNote": rm["featureImportanceNote"]},
        "correlations": {"variableLabels": corr["meta"]["variableLabels"], "developer": corr["developer"],
                         "week": corr["week"]},
        "recommendations": {"framing": recs["meta"]["framing"], "rules": recs["meta"]["rules"],
                            "developers": recs["developers"]},
        "keyFindings": key_findings(fm, rm, corr),
    })


def sample(analytics, n):
    """Same shape, per-developer sections cut to the first n developers."""
    keep = sorted(d["developerId"] for d in analytics["trends"]["developers"])[:n]
    out = json.loads(json.dumps(analytics))
    for section in (out["trends"], out["forecast"], out["risk"], out["recommendations"]):
        section["developers"] = [d for d in section["developers"] if d["developerId"] in keep]
    out["meta"]["sample"] = {"nDevelopersIncluded": len(keep),
                             "note": "Per-developer sections are cut to this many developers; team trends, overview "
                                     "and evaluation sections cover all developers."}
    return out


def write_json(path, obj, compact=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        if compact:
            json.dump(obj, f, separators=(",", ":"), allow_nan=False)
        else:
            json.dump(obj, f, indent=1, allow_nan=False)


def run(write_sample=True):
    cfg = load_config()
    ec = cfg["export"]
    analytics = build(cfg)
    write_json(resolve(ec["output"]), analytics)
    print(f"Wrote {resolve(ec['output'])} ({resolve(ec['output']).stat().st_size // 1024} KB)")
    if write_sample:
        path = resolve(ec["sample_output"])
        write_json(path, sample(analytics, ec["sample_developers"]), compact=True)
        size_kb = path.stat().st_size / 1024
        print(f"Wrote {path} ({size_kb:.0f} KB, {ec['sample_developers']} developers)")
        if size_kb > ec["sample_max_kb"]:
            raise SystemExit(f"Sample is {size_kb:.0f} KB, above the {ec['sample_max_kb']} KB limit")
    for f in analytics["keyFindings"]:
        print(f"- [{f['topic']}] {f['text']}")
    return analytics


def main():
    parser = argparse.ArgumentParser(description="Build outputs/analytics.json (simulated data).")
    parser.add_argument("--no-sample", action="store_true", help="do not rewrite the frontend sample")
    run(write_sample=not parser.parse_args().no_sample)


if __name__ == "__main__":
    main()
