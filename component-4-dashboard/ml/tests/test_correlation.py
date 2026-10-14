import numpy as np
import pandas as pd
import pytest
from scipy.stats import pearsonr

from src.correlation import bh_adjust, correlate, developer_means, fisher_ci


def tiny():
    """Known relations: b = 2a + 1 (r = +1), c = reversed a (r = -1), d alternates (r near 0)."""
    a = np.arange(1, 11, dtype=float)
    return pd.DataFrame({"a": a, "b": 2 * a + 1, "c": a[::-1], "d": [1, -1] * 5})


def pair(result, x, y):
    return next(p for p in result["pairs"] if {p["x"], p["y"]} == {x, y})


def test_known_correlations():
    res = correlate(tiny(), ["a", "b", "c", "d"])
    assert pair(res, "a", "b")["pearson"]["r"] == pytest.approx(1.0)
    assert pair(res, "a", "c")["spearman"]["r"] == pytest.approx(-1.0)
    assert abs(pair(res, "a", "d")["pearson"]["r"]) < 0.2
    assert pair(res, "a", "b")["pearson"]["significant"]
    assert not pair(res, "a", "d")["pearson"]["significant"]
    assert res["nTests"] == 6


def test_matrices_are_symmetric_with_unit_diagonal():
    res = correlate(tiny(), ["a", "b", "c", "d"])
    r = res["matrices"]["pearson"]["r"]
    assert all(r[i][i] == 1.0 for i in range(4))
    assert r[0][2] == r[2][0] == pytest.approx(-1.0)
    assert res["matrices"]["pearson"]["significant"][0][1] is True


def test_fisher_ci_matches_formula_and_contains_r():
    rng = np.random.default_rng(1)
    x = rng.normal(size=30)
    y = x + rng.normal(size=30)
    r = pearsonr(x, y).statistic
    lo, hi = fisher_ci(r, 30, "pearson")
    z, se = np.arctanh(r), 1 / np.sqrt(27)
    assert lo == pytest.approx(np.tanh(z - 1.959964 * se))
    assert hi == pytest.approx(np.tanh(z + 1.959964 * se))
    assert lo < r < hi
    s_lo, s_hi = fisher_ci(r, 30, "spearman")
    assert s_lo < lo and s_hi > hi           # Spearman CI is wider (se factor 1.06)


def test_bh_adjust_known_example():
    p = [0.01, 0.04, 0.03, 0.005]
    # sorted: 0.005, 0.01, 0.03, 0.04 -> *4/rank: 0.02, 0.02, 0.04, 0.04
    assert bh_adjust(p) == pytest.approx([0.02, 0.04, 0.04, 0.02])
    assert np.isnan(bh_adjust([np.nan, 0.01])[0])
    assert bh_adjust([0.9, 0.95]).max() <= 1.0


def test_developer_means_use_active_weeks_only():
    dw = pd.DataFrame({
        "developer_id": ["A", "A", "A", "B"], "week": [1, 2, 3, 1],
        "active": [True, False, True, True],
        "fix_rate": [0.2, np.nan, 0.6, 0.5], "vuln_count": [4, 0, 2, 1], "repeat_count": [2, 0, 0, 1],
    })
    m = developer_means(dw, ["fix_rate", "vuln_count", "repeat_rate"])
    assert m.loc["A", "vuln_count"] == pytest.approx(3.0)       # inactive week 2 excluded
    assert m.loc["A", "fix_rate"] == pytest.approx(0.4)
    assert m.loc["A", "repeat_rate"] == pytest.approx(0.25)     # mean of 0.5 and 0.0
