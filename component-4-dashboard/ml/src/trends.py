"""Weekly trend analysis on the developer-week feature table.

Outputs
-------
1. developer_week_trends: each developer-week row plus
   - 4-week trailing moving averages (vuln_count, fix_rate, intro rate)
   - week-over-week change (absolute for counts, percentage points for rates;
     percent change is avoided because it is undefined when last week was 0)
   - rolling 4-week OLS slope of vuln_count and intro rate (units per week)
2. developer_trends: one row per developer with the OLS slope of intro rate per
   session and fix rate over the whole study, and a direction label
   (improving / stable / worsening) from the intro-rate slope.
3. team_weeks: team totals per week. Team rates are POOLED
   (total fixed / total detections), not the mean of developer rates, so a
   developer with 1 detection does not count as much as one with 30.

Design choices
--------------
- Moving averages use min_periods=1, so early weeks average whatever weeks
  exist so far (week 1 = its own value). NaN weeks are skipped.
- Rolling slopes need at least 3 non-missing points in the 4-week window;
  fewer points give a slope that is mostly noise, so it is left NaN.
"""

import numpy as np
import pandas as pd

from .config import load_config, resolve
from .features import type_column


def ols_slope(y, x=None):
    """Least-squares slope of y on x, ignoring NaN. Returns NaN with < 2 points."""
    y = np.asarray(y, dtype=float)
    x = np.arange(len(y), dtype=float) if x is None else np.asarray(x, dtype=float)
    mask = ~np.isnan(y)
    if mask.sum() < 2:
        return np.nan
    xm, ym = x[mask], y[mask]
    return float(np.sum((xm - xm.mean()) * (ym - ym.mean())) / np.sum((xm - xm.mean()) ** 2))


def rolling_slope(series, window, min_points):
    def slope(values):
        return ols_slope(values) if np.sum(~np.isnan(values)) >= min_points else np.nan
    return series.rolling(window, min_periods=1).apply(slope, raw=True)


def add_developer_trends(dw, cfg):
    t = cfg["trends"]
    ma, sw, mp = t["moving_average_window"], t["slope_window"], t["slope_min_points"]
    df = dw.sort_values(["developer_id", "week"]).copy()
    g = df.groupby("developer_id", group_keys=False)

    for col, short in [("vuln_count", "vuln_count"), ("fix_rate", "fix_rate"),
                       ("intro_rate_per_session", "intro_rate")]:
        df[f"{short}_ma4"] = g[col].transform(lambda s: s.rolling(ma, min_periods=1).mean())
    df["vuln_count_wow"] = g["vuln_count"].diff()
    df["fix_rate_wow"] = g["fix_rate"].diff()
    df["vuln_count_slope4"] = g["vuln_count"].transform(lambda s: rolling_slope(s, sw, mp))
    df["intro_rate_slope4"] = g["intro_rate_per_session"].transform(lambda s: rolling_slope(s, sw, mp))
    return df.reset_index(drop=True)


def developer_summary(dw, cfg):
    threshold = cfg["trends"]["direction_threshold"]
    rows = []
    for dev, d in dw.sort_values("week").groupby("developer_id"):
        intro_slope = ols_slope(d["intro_rate_per_session"], d["week"])
        if np.isnan(intro_slope) or abs(intro_slope) < threshold:
            direction = "stable"
        else:
            direction = "improving" if intro_slope < 0 else "worsening"
        rows.append({
            "developer_id": dev,
            "intro_rate_slope": intro_slope,
            "fix_rate_slope": ols_slope(d["fix_rate"], d["week"]),
            "direction": direction,
            "active_weeks": int(d["active"].sum()),
            "total_vulns": int(d["vuln_count"].sum()),
            "fix_rate": d["n_fixed"].sum() / max(d["vuln_count"].sum(), 1),
            "intro_rate_per_session": d["vuln_count"].sum() / max(d["n_sessions"].sum(), 1),
        })
    return pd.DataFrame(rows)


def team_weekly(dw, cfg):
    type_cols = [type_column(v) for v in cfg["vulnerability_types"]]
    sums = ["vuln_count", "n_fixed", "n_ignored", "n_false_positive", "n_dismissed",
            "n_sessions", "repeat_count", "severity_weighted_load", *type_cols]
    df = dw.copy()
    df["response_time_total"] = df["avg_response_time"].fillna(0) * df["vuln_count"]

    team = df.groupby("week")[sums + ["response_time_total"]].sum()
    team["active_developers"] = df.groupby("week")["active"].sum()
    v = team["vuln_count"].replace(0, np.nan)
    team["fix_rate"] = team["n_fixed"] / v
    team["ignore_rate"] = team["n_ignored"] / v
    team["false_positive_rate"] = team["n_false_positive"] / v
    team["avg_response_time"] = team["response_time_total"] / v
    team["intro_rate_per_session"] = team["vuln_count"] / team["n_sessions"].replace(0, np.nan)
    team = team.drop(columns="response_time_total")

    ma = cfg["trends"]["moving_average_window"]
    team["vuln_count_ma4"] = team["vuln_count"].rolling(ma, min_periods=1).mean()
    team["fix_rate_ma4"] = team["fix_rate"].rolling(ma, min_periods=1).mean()
    team["vuln_count_wow"] = team["vuln_count"].diff()
    team["fix_rate_wow"] = team["fix_rate"].diff()
    return team.reset_index()


def main():
    cfg = load_config()
    dw = pd.read_csv(resolve(cfg["paths"]["developer_weeks"]))

    dwt = add_developer_trends(dw, cfg)
    summary = developer_summary(dw, cfg)
    team = team_weekly(dw, cfg)

    dwt.to_csv(resolve(cfg["paths"]["developer_week_trends"]), index=False)
    summary.to_csv(resolve(cfg["paths"]["developer_trends"]), index=False)
    team.to_csv(resolve(cfg["paths"]["team_weeks"]), index=False)

    first, last = team.iloc[0], team.iloc[-1]
    print(f"Team week 1 -> {int(last['week'])}: intro rate/session "
          f"{first['intro_rate_per_session']:.2f} -> {last['intro_rate_per_session']:.2f}, "
          f"fix rate {first['fix_rate']:.2f} -> {last['fix_rate']:.2f}")
    print("Developer directions:", summary["direction"].value_counts().to_dict())


if __name__ == "__main__":
    main()
