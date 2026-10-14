"""Phase 4: rule-based recommendations per developer.

Rules live in config.yaml so they can be read, changed and defended without
touching code. Each rule has an id, a priority (1 = most urgent, 3 = least),
a list of conditions that must ALL hold, and a plain-language template.
Conditions are structured data ({field, op, value}), never evaluated as
code. A condition on a missing value (for example no findings in the last 4
weeks) is false, so a rule never fires on data that does not exist.

Inputs per developer (all from earlier pipeline steps):
- risk_band: the research risk profile band at the last week (risk.json)
- forecast_vuln_direction / forecast_fix_direction: up / down / flat. The
  deployed forecast for weeks 17-18 is compared with the developer's own
  recent mean (weeks 13-16), with a tolerance from config.
- own measured metrics for the last 4 weeks: ignore rate, fix rate, repeat
  rate, average response time
- dominant_type: the most frequent vulnerability type in the last 4 weeks

Output per developer: priority (the most urgent fired rule; 3 if only the
fallback fires), up to 3 recommendations ordered by priority, and the ids of
every rule that fired. Wording describes a research risk profile based on
measured behaviour, never a judgment of the person.
"""

import json

import numpy as np
import pandas as pd

from .config import load_config, resolve
from .features import type_column
from .risk import cut, developer_arrays, window_stats

SIMULATED_NOTE = "Simulated data generated from stated assumptions; not real developer data."
FRAMING = "Research risk profile based on measured behaviour; not a judgment of the person."


def _missing(v):
    return v is None or (isinstance(v, float) and np.isnan(v))


def condition_holds(cond, inputs):
    """Evaluate one structured condition. Missing values make every condition false."""
    value = inputs.get(cond["field"])
    op = cond["op"]
    if op == "exists":
        return not _missing(value)
    if _missing(value):
        return False
    target = cond.get("value")
    return {
        "eq": lambda: value == target,
        "ne": lambda: value != target,
        "in": lambda: value in target,
        "gt": lambda: value > target,
        "gte": lambda: value >= target,
        "lt": lambda: value < target,
        "lte": lambda: value <= target,
    }[op]()


def direction(forecast, recent, tolerance):
    """up / down / flat, or None when either value is missing."""
    if _missing(forecast) or _missing(recent):
        return None
    if abs(forecast - recent) <= tolerance:
        return "flat"
    return "up" if forecast > recent else "down"


def template_fields(inputs, rc):
    """Formatted values the rule templates can use."""
    def pct(v):
        return "n/a" if _missing(v) else f"{100 * v:.0f}%"

    def num(v):
        return "n/a" if _missing(v) else f"{v:.1f}"

    dom = inputs.get("dominant_type")
    return {
        "risk_band": inputs.get("risk_band"),
        "ignore_rate_pct": pct(inputs.get("ignore_rate")),
        "fix_rate_pct": pct(inputs.get("fix_rate")),
        "repeat_rate_pct": pct(inputs.get("repeat_rate")),
        "response_time_min": num(None if _missing(inputs.get("response_time_sec")) else inputs["response_time_sec"] / 60),
        "recent_vuln": num(inputs.get("recent_vuln")),
        "forecast_vuln": num(inputs.get("forecast_vuln")),
        "recent_fix_pct": pct(inputs.get("recent_fix")),
        "forecast_fix_pct": pct(inputs.get("forecast_fix")),
        "dominant_type_label": rc["type_labels"].get(dom, "n/a") if dom else "n/a",
        "type_tip": rc["type_tips"].get(dom, "") if dom else "",
    }


def recommend(inputs, rc):
    """Apply every rule; return priority, up to max recommendations, and all fired rule ids."""
    fired = [r for r in rc["rules"] if all(condition_holds(c, inputs) for c in r["when"])]
    fields = template_fields(inputs, rc)
    if not fired:
        fb = rc["fallback"]
        return {"priority": fb["priority"], "firedRules": [fb["id"]],
                "recommendations": [{"ruleId": fb["id"], "priority": fb["priority"], "text": fb["text"]}]}
    chosen = sorted(fired, key=lambda r: r["priority"])[:rc["max_recommendations"]]   # stable: config order breaks ties
    return {"priority": min(r["priority"] for r in fired),
            "firedRules": [r["id"] for r in fired],
            "recommendations": [{"ruleId": r["id"], "priority": r["priority"], "text": r["text"].format(**fields)}
                                for r in chosen]}


def developer_inputs(arrays, risk_dev, forecast_dev, cfg):
    """Assemble the rule inputs for one developer from earlier pipeline outputs."""
    rc = cfg["recommend"]
    tol = rc["direction_tolerance"]
    n_weeks = cfg["study"]["n_weeks"]
    first = n_weeks - rc["recent_weeks"] + 1
    a = cut(arrays, n_weeks)
    recent = window_stats(a, first, n_weeks)

    hist = [h for h in forecast_dev["history"] if h["week"] >= first]
    active_counts = [h["vulnCount"] for h in hist if h["active"]]
    fix_values = [h["fixRate"] for h in hist if h["fixRate"] is not None]
    recent_vuln = float(np.mean(active_counts)) if active_counts else None
    recent_fix = float(np.mean(fix_values)) if fix_values else None
    forecast_vuln = float(np.mean([f["vulnCount"]["mean"] for f in forecast_dev["future"]]))
    forecast_fix = float(np.mean([f["fixRate"]["mean"] for f in forecast_dev["future"]]))
    vuln_tol = None if recent_vuln is None else max(tol["vuln_count_relative"] * recent_vuln, tol["vuln_count_min_abs"])

    type_counts = {v: a[type_column(v)][first - 1:].sum() for v in cfg["vulnerability_types"]}
    dominant = max(type_counts, key=type_counts.get) if sum(type_counts.values()) > 0 else None

    return {
        "risk_band": risk_dev["band"],
        "forecast_vuln_direction": direction(forecast_vuln, recent_vuln, vuln_tol),
        "forecast_fix_direction": direction(forecast_fix, recent_fix, tol["fix_rate_abs"]),
        "recent_vuln": recent_vuln, "forecast_vuln": forecast_vuln,
        "recent_fix": recent_fix, "forecast_fix": forecast_fix,
        "ignore_rate": recent["ignore_rate"], "fix_rate": recent["fix_rate"],
        "repeat_rate": recent["repeat_rate"], "response_time_sec": recent["response_time_sec"],
        "dominant_type": dominant,
    }


def run():
    cfg = load_config()
    rc = cfg["recommend"]
    dw = pd.read_csv(resolve(cfg["paths"]["developer_weeks"]))
    arrays = developer_arrays(dw, cfg)
    with open(resolve(cfg["risk"]["outputs"]["risk"]), encoding="utf-8") as f:
        risk = {d["developerId"]: d for d in json.load(f)["developers"]}
    with open(resolve(cfg["forecast"]["outputs"]["forecasts"]), encoding="utf-8") as f:
        forecasts = {d["developerId"]: d for d in json.load(f)["developers"]}

    developers = []
    for dev in sorted(arrays):
        inputs = developer_inputs(arrays[dev], risk[dev], forecasts[dev], cfg)
        clean = {k: (None if _missing(v) else round(v, 4) if isinstance(v, float) else v) for k, v in inputs.items()}
        developers.append({"developerId": dev, **recommend(inputs, rc), "inputs": clean})

    out = {"meta": {"dataSource": "simulated", "disclaimer": SIMULATED_NOTE, "framing": FRAMING,
                    "rules": [{"id": r["id"], "priority": r["priority"], "when": r["when"]} for r in rc["rules"]],
                    "fallback": rc["fallback"]["id"]},
           "developers": developers}
    path = resolve(rc["output"])
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    counts = pd.Series([r for d in developers for r in d["firedRules"]]).value_counts().sort_index()
    print("Rules fired:", counts.to_dict())
    print("Priority counts:", pd.Series([d["priority"] for d in developers]).value_counts().sort_index().to_dict())
    return out


def main():
    run()


if __name__ == "__main__":
    main()
