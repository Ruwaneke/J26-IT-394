import math

import numpy as np
import pandas as pd
import pytest

from src.features import build_developer_weeks
from src.trends import add_developer_trends, developer_summary, ols_slope, team_weekly


def test_ols_slope():
    assert ols_slope([1, 2, 3, 4]) == pytest.approx(1.0)
    assert ols_slope([1, np.nan, 3]) == pytest.approx(1.0)
    assert math.isnan(ols_slope([np.nan, 5]))


def test_moving_average_wow_and_rolling_slope(cfg):
    dw = pd.DataFrame({
        "developer_id": ["D"] * 4, "week": [1, 2, 3, 4],
        "vuln_count": [4, 0, 2, 6],
        "fix_rate": [0.5, np.nan, 1.0, 0.5],
        "intro_rate_per_session": [2.0, 0.0, 1.0, 3.0],
    })
    t = add_developer_trends(dw, cfg)
    assert list(t["vuln_count_ma4"]) == [4, 2, 2, 3]
    assert list(t["fix_rate_ma4"]) == pytest.approx([0.5, 0.5, 0.75, 2 / 3])   # NaN week skipped
    assert t["vuln_count_wow"].tolist()[1:] == [-4, 2, 4]
    slopes = t["vuln_count_slope4"].tolist()
    assert math.isnan(slopes[0]) and math.isnan(slopes[1])                     # < 3 points
    assert slopes[2] == pytest.approx(-1.0)
    assert slopes[3] == pytest.approx(0.8)


def test_developer_direction(cfg):
    weeks = list(range(1, 9))
    dw = pd.DataFrame({
        "developer_id": ["UP"] * 8 + ["DOWN"] * 8, "week": weeks * 2,
        "intro_rate_per_session": [1 + 0.2 * w for w in weeks] + [3 - 0.2 * w for w in weeks],
        "fix_rate": [0.5] * 16, "active": [True] * 16,
        "vuln_count": [5] * 16, "n_fixed": [2] * 16, "n_sessions": [4] * 16,
    })
    s = developer_summary(dw, cfg).set_index("developer_id")
    assert s.loc["UP", "direction"] == "worsening"
    assert s.loc["DOWN", "direction"] == "improving"


def test_team_rates_are_pooled(tiny_events, tiny_sessions, tiny_cfg):
    team = team_weekly(build_developer_weeks(tiny_events, tiny_cfg, tiny_sessions), tiny_cfg)
    w1 = team[team["week"] == 1].iloc[0]
    assert w1["vuln_count"] == 3
    assert w1["fix_rate"] == pytest.approx(1 / 3)
    w2 = team[team["week"] == 2].iloc[0]
    # DEV_A: 0 events in 1 session, DEV_B: 1 fixed event in 1 session
    assert w2["fix_rate"] == pytest.approx(1.0)
    assert w2["intro_rate_per_session"] == pytest.approx(0.5)
    assert w2["active_developers"] == 2
    w3 = team[team["week"] == 3].iloc[0]
    assert w3["avg_response_time"] == pytest.approx(100.0)
