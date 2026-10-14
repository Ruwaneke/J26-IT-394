"""Phase 4: correlations between developer behaviour metrics (statistics only, no ML).

Levels
------
- Developer level (MAIN): one value per developer = mean of the weekly values
  over that developer's ACTIVE weeks (rates skip weeks with no findings).
  60 developers -> n = 60 independent observations. Correlating all 960
  developer-weeks instead would count each developer up to 16 times
  (pseudo-replication), make n look 16x larger and give p-values that are far
  too small.
- Developer-week level (SECONDARY): active developer-weeks, pairwise complete.
  Reported for completeness with a repeated-measures warning.

Methods
-------
- Pearson r measures linear association. 95% CI by the Fisher z transform:
  z = atanh(r), se = 1 / sqrt(n - 3), CI = tanh(z +/- 1.96 se).
- Spearman rho is Pearson on ranks: monotonic association, robust to outliers
  and skew (response times and counts are skewed). Its CI uses the same
  transform with se = sqrt(1.06 / (n - 3)) (Fieller, Hartley and Pearson, 1957).
- Benjamini-Hochberg correction controls the false discovery rate across
  the 21 variable pairs tested within each (level, method). With 21 tests at
  alpha = 0.05, about one "significant" result is expected by chance alone if
  nothing is related. Raw and adjusted p-values are both reported.
"""

import itertools
import json

import numpy as np
import pandas as pd
from scipy.stats import pearsonr, spearmanr

from .config import load_config, resolve

SIMULATED_NOTE = "Simulated data generated from stated assumptions; not real developer data."
WEEK_NOTE = ("Secondary analysis: developer-weeks are repeated measures of the same 60 developers, "
             "so they are not independent and these p-values are optimistic. Use the developer level for inference.")
SE_FACTOR = {"pearson": 1.0, "spearman": 1.06}


def add_repeat_rate(dw):
    out = dw.copy()
    out["repeat_rate"] = (out["repeat_count"] / out["vuln_count"]).where(out["vuln_count"] > 0)
    return out


def developer_means(dw, variables):
    """Mean of each variable over each developer's active weeks (NaN weeks skipped)."""
    active = add_repeat_rate(dw)
    active = active[active["active"].astype(bool)]
    return active.groupby("developer_id")[variables].mean()


def week_rows(dw, variables):
    active = add_repeat_rate(dw)
    return active.loc[active["active"].astype(bool), variables]


def fisher_ci(r, n, method, z_crit=1.959964):
    """95% CI for a correlation via the Fisher z transform."""
    if n <= 3 or np.isnan(r):
        return [None, None]
    r = float(np.clip(r, -0.999999, 0.999999))
    se = np.sqrt(SE_FACTOR[method] / (n - 3))
    z = np.arctanh(r)
    return [float(np.tanh(z - z_crit * se)), float(np.tanh(z + z_crit * se))]


def bh_adjust(pvalues):
    """Benjamini-Hochberg adjusted p-values (step-up, monotone, capped at 1). NaN stays NaN."""
    p = np.asarray(pvalues, dtype=float)
    out = np.full(len(p), np.nan)
    ok = ~np.isnan(p)
    m = ok.sum()
    if m == 0:
        return out
    order = np.argsort(p[ok])
    ranked = p[ok][order] * m / np.arange(1, m + 1)
    adjusted = np.minimum.accumulate(ranked[::-1])[::-1]
    result = np.empty(m)
    result[order] = np.minimum(adjusted, 1.0)
    out[ok] = result
    return out


def correlate(df, variables, alpha=0.05):
    """Pearson and Spearman for every pair of variables, with CIs, raw and BH-adjusted p-values."""
    pairs = []
    for x, y in itertools.combinations(variables, 2):
        sub = df[[x, y]].dropna()
        n = len(sub)
        row = {"x": x, "y": y, "n": n}
        for method, fn in (("pearson", pearsonr), ("spearman", spearmanr)):
            if n > 3 and sub[x].std() > 0 and sub[y].std() > 0:
                res = fn(sub[x], sub[y])
                r, p = float(res.statistic), float(res.pvalue)
            else:
                r, p = np.nan, np.nan
            row[method] = {"r": r, "p": p, "ci": fisher_ci(r, n, method)}
        pairs.append(row)

    for method in ("pearson", "spearman"):
        adjusted = bh_adjust([pr[method]["p"] for pr in pairs])
        for pr, pa in zip(pairs, adjusted):
            pr[method]["pAdj"] = float(pa)
            pr[method]["significant"] = bool(pa < alpha) if not np.isnan(pa) else False

    k = len(variables)
    index = {v: i for i, v in enumerate(variables)}
    matrices = {}
    for method in ("pearson", "spearman"):
        r_m = [[1.0 if i == j else None for j in range(k)] for i in range(k)]
        p_m = [[None] * k for _ in range(k)]
        s_m = [[False] * k for _ in range(k)]
        for pr in pairs:
            i, j = index[pr["x"]], index[pr["y"]]
            for a, b in ((i, j), (j, i)):
                r_m[a][b] = pr[method]["r"]
                p_m[a][b] = pr[method]["pAdj"]
                s_m[a][b] = pr[method]["significant"]
        matrices[method] = {"r": r_m, "pAdj": p_m, "significant": s_m}
    return {"variables": variables, "alpha": alpha, "correction": "benjamini-hochberg",
            "nTests": len(pairs), "pairs": pairs, "matrices": matrices}


def run():
    cfg = load_config()
    cc = cfg["correlation"]
    dw = pd.read_csv(resolve(cfg["paths"]["developer_weeks"]))
    variables = cc["variables"]
    dev_level = correlate(developer_means(dw, variables), variables, cc["alpha"])
    week_level = correlate(week_rows(dw, variables), variables, cc["alpha"])
    out = {
        "meta": {"dataSource": "simulated", "disclaimer": SIMULATED_NOTE,
                 "variableLabels": cc["labels"],
                 "bhFamily": "the pairs tested within each level and method"},
        "developer": {**dev_level, "level": "developer", "note": "Main analysis: per-developer means over active weeks."},
        "week": {**week_level, "level": "developer-week", "note": WEEK_NOTE},
    }
    path = resolve(cc["output"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_clean(out), f, indent=1)

    print(f"Developer level (n = {dev_level['pairs'][0]['n']}): pairs significant after BH")
    for pr in dev_level["pairs"]:
        flags = [m for m in ("pearson", "spearman") if pr[m]["significant"]]
        if flags:
            print(f"  {pr['x']:22s} ~ {pr['y']:22s} r={pr['pearson']['r']:+.2f} (pAdj {pr['pearson']['pAdj']:.4f})"
                  f"  rho={pr['spearman']['r']:+.2f} (pAdj {pr['spearman']['pAdj']:.4f})")
    n_sig_week = sum(pr["pearson"]["significant"] for pr in week_level["pairs"])
    print(f"Developer-week level: {n_sig_week}/{len(week_level['pairs'])} Pearson pairs significant (repeated measures; optimistic)")
    return out


def _clean(obj):
    """Replace NaN with None so the file is valid JSON."""
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, float) and np.isnan(obj):
        return None
    return obj


def main():
    run()


if __name__ == "__main__":
    main()
