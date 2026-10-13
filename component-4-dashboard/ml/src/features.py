"""Build one feature row per developer per week from raw security events.

Design choices
--------------
- Full grid: every developer gets a row for every study week, even weeks with
  no activity. Missing weeks are information (inactivity), and later models
  need equal-length sequences.
- Rates are NaN when undefined. A week with zero detections has no fix rate;
  writing 0 would wrongly say "fixed nothing". Counts are 0 in that case.
- Rates are per event in that week: fix_rate = fixed / detections.
- repeat_count counts events whose (vulnerability type, file) pair was also
  flagged for the same developer in any of the previous 4 weeks. It measures
  "the same mistake keeps coming back in the same place". Same-week repeats do
  not count, so the first detection of a new pair is never a repeat.
- repeat_type_rate (secondary) is the share of the week's events whose type
  alone was seen in the previous 2 weeks. With only 4 types this is close to
  saturated (most types are always "recent"), which is why repeat_count uses
  the narrower (type, file) key.
- severity_weighted_load = sum of severity weights (LOW=1, MEDIUM=2, HIGH=3),
  so one HIGH detection weighs as much as three LOW ones.
- intro_rate_per_session = detections / sessions. Sessions come from
  sessions.jsonl when available. If not, only sessions that appear in events
  can be counted, which hides clean sessions and biases the rate upward; a
  warning is printed in that case.
"""

import warnings

import numpy as np
import pandas as pd

from .config import load_config, resolve

ACTION_COLUMNS = {
    "FIXED": "n_fixed",
    "IGNORED": "n_ignored",
    "FALSE_POSITIVE": "n_false_positive",
    "DISMISSED": "n_dismissed",
}


def type_column(vtype):
    return f"count_{vtype.lower()}"


def load_jsonl(path):
    return pd.read_json(path, lines=True, dtype=False)


def week_index(timestamps, start_date):
    """1-based study week: floor((timestamp - start) / 7 days) + 1."""
    start = pd.Timestamp(start_date, tz="UTC")
    ts = pd.to_datetime(timestamps, utc=True)
    return ((ts - start).dt.days // 7 + 1).astype(int)


def _repeat_flags(ev, key_columns, lookback):
    """True for each event whose key (e.g. type and file) was seen by that developer in the previous `lookback` weeks."""
    keys = list(zip(*(ev[c] for c in key_columns)))
    seen = set(zip(ev["developerId"], ev["week"], keys))
    return np.array([
        any((dev, week - k, key) in seen for k in range(1, lookback + 1))
        for dev, week, key in zip(ev["developerId"], ev["week"], keys)
    ], dtype=bool)


def build_developer_weeks(events, cfg, sessions=None):
    """Return a DataFrame with one row per (developer_id, week) for weeks 1..n_weeks."""
    n_weeks = cfg["study"]["n_weeks"]
    start = cfg["study"]["start_date"]
    vtypes = cfg["vulnerability_types"]
    weights = cfg["severity_weights"]

    ev = events.copy()
    ev["week"] = week_index(ev["detectedAt"], start)
    ev = ev[(ev["week"] >= 1) & (ev["week"] <= n_weeks)]
    ev["is_repeat"] = _repeat_flags(ev, ["vulnerabilityType", "fileName"], cfg["features"]["repeat_lookback_weeks"])
    ev["is_type_repeat"] = _repeat_flags(ev, ["vulnerabilityType"], cfg["features"]["repeat_type_lookback_weeks"])
    ev["severity_weight"] = ev["severity"].map(weights)

    developers = set(ev["developerId"])
    if sessions is not None:
        ses = sessions.copy()
        ses["week"] = week_index(ses["startedAt"], start)
        ses = ses[(ses["week"] >= 1) & (ses["week"] <= n_weeks)]
        developers |= set(ses["developerId"])
    else:
        warnings.warn("No sessions file: counting only sessions with detections, "
                      "so intro_rate_per_session is biased upward.")
        ses = ev[["developerId", "sessionId", "week"]]

    grid = pd.MultiIndex.from_product([sorted(developers), range(1, n_weeks + 1)],
                                      names=["developerId", "week"])
    g = ev.groupby(["developerId", "week"])

    out = pd.DataFrame(index=grid)
    out["n_sessions"] = ses.groupby(["developerId", "week"])["sessionId"].nunique()
    out["vuln_count"] = g.size()
    actions = ev.pivot_table(index=["developerId", "week"], columns="action",
                             values="eventId", aggfunc="count")
    for action, col in ACTION_COLUMNS.items():
        out[col] = actions[action] if action in actions else 0
    out["avg_response_time"] = g["responseTime"].mean()
    out["repeat_count"] = g["is_repeat"].sum()
    out["n_type_repeats"] = g["is_type_repeat"].sum()
    out["severity_weighted_load"] = g["severity_weight"].sum()
    types = ev.pivot_table(index=["developerId", "week"], columns="vulnerabilityType",
                           values="eventId", aggfunc="count")
    for vtype in vtypes:
        out[type_column(vtype)] = types[vtype] if vtype in types else 0

    count_cols = ["n_sessions", "vuln_count", *ACTION_COLUMNS.values(), "repeat_count", "n_type_repeats",
                  "severity_weighted_load", *(type_column(v) for v in vtypes)]
    out[count_cols] = out[count_cols].fillna(0).astype(int)

    has_events = out["vuln_count"] > 0
    out["repeat_type_rate"] = (out.pop("n_type_repeats") / out["vuln_count"]).where(has_events)
    out["fix_rate"] = (out["n_fixed"] / out["vuln_count"]).where(has_events)
    out["ignore_rate"] = (out["n_ignored"] / out["vuln_count"]).where(has_events)
    out["false_positive_rate"] = (out["n_false_positive"] / out["vuln_count"]).where(has_events)
    out["intro_rate_per_session"] = (out["vuln_count"] / out["n_sessions"]).where(out["n_sessions"] > 0)
    out["active"] = out["n_sessions"] > 0

    out = out.reset_index().rename(columns={"developerId": "developer_id"})
    return out


def main():
    cfg = load_config()
    events = load_jsonl(resolve(cfg["paths"]["events"]))
    sessions_path = resolve(cfg["paths"]["sessions"])
    sessions = load_jsonl(sessions_path) if sessions_path.exists() else None

    dw = build_developer_weeks(events, cfg, sessions)
    path = resolve(cfg["paths"]["developer_weeks"])
    path.parent.mkdir(parents=True, exist_ok=True)
    dw.to_csv(path, index=False)
    print(f"Wrote {len(dw)} developer-week rows ({dw['active'].mean():.1%} active) to {path}")


if __name__ == "__main__":
    main()
