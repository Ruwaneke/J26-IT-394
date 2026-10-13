import math

import pandas as pd
import pytest

from src.features import build_developer_weeks, week_index


def row(df, dev, week):
    return df[(df["developer_id"] == dev) & (df["week"] == week)].iloc[0]


def test_week_index_boundaries():
    weeks = week_index(pd.Series(["2026-06-01T00:00:00Z", "2026-06-07T23:59:59Z",
                                  "2026-06-08T00:00:00Z"]), "2026-06-01")
    assert list(weeks) == [1, 1, 2]


def test_full_grid(tiny_events, tiny_sessions, tiny_cfg):
    dw = build_developer_weeks(tiny_events, tiny_cfg, tiny_sessions)
    assert len(dw) == 2 * 3


def test_week_with_events(tiny_events, tiny_sessions, tiny_cfg):
    r = row(build_developer_weeks(tiny_events, tiny_cfg, tiny_sessions), "DEV_A", 1)
    assert r["vuln_count"] == 3
    assert (r["n_fixed"], r["n_ignored"], r["n_false_positive"], r["n_dismissed"]) == (1, 1, 1, 0)
    assert r["fix_rate"] == pytest.approx(1 / 3)
    assert r["ignore_rate"] == pytest.approx(1 / 3)
    assert r["false_positive_rate"] == pytest.approx(1 / 3)
    assert r["avg_response_time"] == pytest.approx(50.0)
    assert r["severity_weighted_load"] == 3 + 1 + 2
    assert r["count_sql_injection"] == 2 and r["count_xss"] == 1
    assert r["repeat_count"] == 0          # same-week repeats do not count
    assert r["repeat_type_rate"] == 0.0
    assert r["n_sessions"] == 2
    assert r["intro_rate_per_session"] == pytest.approx(1.5)


def test_clean_session_week(tiny_events, tiny_sessions, tiny_cfg):
    r = row(build_developer_weeks(tiny_events, tiny_cfg, tiny_sessions), "DEV_A", 2)
    assert r["vuln_count"] == 0
    assert r["n_sessions"] == 1 and bool(r["active"])
    assert r["intro_rate_per_session"] == 0.0
    assert math.isnan(r["fix_rate"])


def test_repeat_within_lookback(tiny_events, tiny_sessions, tiny_cfg):
    r = row(build_developer_weeks(tiny_events, tiny_cfg, tiny_sessions), "DEV_A", 3)
    assert r["vuln_count"] == 3
    assert r["repeat_count"] == 1          # only (SQLi, a.py) was flagged before
    assert r["repeat_type_rate"] == pytest.approx(2 / 3)   # both SQLi events repeat the type
    assert r["fix_rate"] == pytest.approx(1 / 3)
    assert r["avg_response_time"] == pytest.approx(100.0)
    assert r["intro_rate_per_session"] == pytest.approx(3.0)


def test_repeat_outside_lookback_does_not_count(tiny_events, tiny_sessions, tiny_cfg):
    tiny_cfg["features"]["repeat_lookback_weeks"] = 1
    tiny_cfg["features"]["repeat_type_lookback_weeks"] = 1
    r = row(build_developer_weeks(tiny_events, tiny_cfg, tiny_sessions), "DEV_A", 3)
    assert r["repeat_count"] == 0          # week 1 is 2 weeks back
    assert r["repeat_type_rate"] == 0.0


def test_inactive_week(tiny_events, tiny_sessions, tiny_cfg):
    r = row(build_developer_weeks(tiny_events, tiny_cfg, tiny_sessions), "DEV_B", 1)
    assert r["vuln_count"] == 0 and r["n_sessions"] == 0
    assert not bool(r["active"])
    assert math.isnan(r["intro_rate_per_session"])


def test_without_sessions_file_warns_and_hides_clean_sessions(tiny_events, tiny_cfg):
    with pytest.warns(UserWarning):
        dw = build_developer_weeks(tiny_events, tiny_cfg)
    r = row(dw, "DEV_A", 2)
    assert r["n_sessions"] == 0
    assert math.isnan(r["intro_rate_per_session"])
