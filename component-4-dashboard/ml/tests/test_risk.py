import numpy as np
import pandas as pd
import pytest
from sklearn.model_selection import GroupKFold

from src.features import build_developer_weeks
from sklearn.metrics import f1_score

from src.risk import (PAST_SCORE_FEATURES, Normaliser, build_rows, design, developer_arrays, feature_columns,
                      feature_sets, features_at, fix_rate_rule, holdout_split, macro_f1, measured_drivers,
                      risk_score, score_components, to_band)

WEIGHTS = {"severity_weighted_ignore_rate": 0.4, "one_minus_fix_rate": 0.3,
           "normalised_repeat_rate": 0.2, "normalised_log_response_time": 0.1}
from src.simulate import simulate


@pytest.fixture(scope="module")
def sim_dw():
    from src.config import load_config
    cfg = load_config()
    cfg["simulation"]["n_developers"] = 20
    events, sessions, profiles = simulate(cfg)
    dw = build_developer_weeks(pd.DataFrame(events), cfg, pd.DataFrame(sessions))
    return cfg, dw, {p["developerId"]: p["archetype"] for p in profiles}


def _same(a, b):
    return all((np.isnan(a[k]) and np.isnan(b[k])) or a[k] == pytest.approx(b[k]) for k in a)


def test_features_use_only_weeks_up_to_t(sim_dw):
    cfg, dw, _ = sim_dw
    arrays = developer_arrays(dw, cfg)
    a = arrays["DEV001"]
    t = 8
    before = features_at(a, t, cfg["vulnerability_types"])
    tampered = {k: np.concatenate([v[:t], v[t:] * 0 + 999.0]) for k, v in a.items()}
    assert _same(before, features_at(tampered, t, cfg["vulnerability_types"]))


def test_label_uses_only_weeks_t_plus_1_to_t_plus_4(sim_dw):
    cfg, dw, _ = sim_dw
    arrays = developer_arrays(dw, cfg)
    dev, t = "DEV002", 8
    label_cols = [c for c in build_rows({dev: arrays[dev]}, [t], cfg).columns if c.startswith("label_")]
    base = build_rows({dev: arrays[dev]}, [t], cfg)[label_cols].iloc[0]

    outside = {k: v.copy() for k, v in arrays[dev].items()}
    for v in outside.values():
        v[:t] = 7.0          # weeks <= t
        v[t + 4:] = 7.0      # weeks > t+4
    assert np.allclose(build_rows({dev: outside}, [t], cfg)[label_cols].iloc[0], base, equal_nan=True)

    inside = {k: v.copy() for k, v in arrays[dev].items()}
    inside["n_fixed"][t + 1] = 0.0       # week t+2
    inside["vuln_count"][t + 1] += 5.0
    assert not np.allclose(build_rows({dev: inside}, [t], cfg)[label_cols].iloc[0], base, equal_nan=True)


def test_no_developer_in_both_train_and_test(sim_dw):
    cfg, dw, archetypes = sim_dw
    devs = sorted(dw["developer_id"].unique())
    train, test = holdout_split(devs, archetypes, 4, seed=42)
    assert not set(train) & set(test)
    assert sorted(train + test) == devs

    rows = build_rows({d: a for d, a in developer_arrays(dw, cfg).items() if d in train}, [6, 7, 8], cfg)
    seen_in_val = []
    for tr, va in GroupKFold(n_splits=4).split(rows, groups=rows["developer_id"]):
        assert not set(rows["developer_id"].iloc[tr]) & set(rows["developer_id"].iloc[va])
        seen_in_val += sorted(set(rows["developer_id"].iloc[va]))
    assert sorted(seen_in_val) == sorted(train)


def test_past_score_inputs_use_only_weeks_up_to_t(sim_dw):
    cfg, dw, _ = sim_dw
    a = developer_arrays(dw, cfg)["DEV003"]
    t = 9
    cols = [c for c in build_rows({"D": a}, [t], cfg).columns if c.startswith(("persist_", "history_"))]
    before = build_rows({"D": a}, [t], cfg)[cols].iloc[0]
    tampered = {k: np.concatenate([v[:t], v[t:] * 0 + 50.0]) for k, v in a.items()}
    assert np.allclose(build_rows({"D": tampered}, [t], cfg)[cols].iloc[0], before, equal_nan=True)


def test_feature_sets(sim_dw):
    cfg, dw, _ = sim_dw
    rows = build_rows(developer_arrays(dw, cfg), [6], cfg)
    sets = feature_sets(rows)
    n_types = len(cfg["vulnerability_types"])
    assert len(sets["original"]) == 8 * 3 + n_types + 2
    assert len(sets["extended"]) == 9 * 3 + n_types + 2 + 2
    assert set(sets["original"]) < set(sets["extended"])
    for cols in sets.values():
        assert not [c for c in cols if "archetype" in c or c.startswith(("label_", "persist_", "history_"))]


def test_past_score_features_use_the_given_normaliser(sim_dw):
    cfg, dw, _ = sim_dw
    rows = build_rows(developer_arrays(dw, cfg), [8], cfg).dropna(subset=["persist_fix_rate"])
    cols = feature_columns(rows) + PAST_SCORE_FEATURES
    wide = Normaliser([{"repeat_rate": 0.0, "log_response_time": 0.0}, {"repeat_rate": 1.0, "log_response_time": 10.0}])
    narrow = Normaliser([{"repeat_rate": 0.4, "log_response_time": 5.0}, {"repeat_rate": 0.5, "log_response_time": 5.5}])
    a, b = design(rows, cols, wide, WEIGHTS), design(rows, cols, narrow, WEIGHTS)
    assert not np.allclose(a["past_score_last4"], b["past_score_last4"])
    first = rows.iloc[0]
    comp = {k: first[f"persist_{k}"] for k in ("severity_weighted_ignore_rate", "fix_rate", "repeat_rate", "log_response_time")}
    assert a["past_score_last4"].iloc[0] == pytest.approx(risk_score(comp, wide, WEIGHTS))


def test_macro_f1_matches_sklearn():
    rng = np.random.default_rng(0)
    for _ in range(20):
        y, p = rng.integers(0, 3, 40), rng.integers(0, 3, 40)
        assert macro_f1(y, p) == pytest.approx(f1_score(y, p, labels=[0, 1, 2], average="macro", zero_division=0))
    assert macro_f1(np.array([0, 0]), np.array([0, 0])) == pytest.approx(1 / 3)   # absent classes score 0


def test_risk_score_and_bands():
    norm = Normaliser([{"repeat_rate": 0.0, "log_response_time": 4.0},
                       {"repeat_rate": 0.5, "log_response_time": 6.0}])
    weights = {"severity_weighted_ignore_rate": 0.4, "one_minus_fix_rate": 0.3,
               "normalised_repeat_rate": 0.2, "normalised_log_response_time": 0.1}
    comp = {"severity_weighted_ignore_rate": 0.5, "fix_rate": 0.6, "repeat_rate": 0.25, "log_response_time": 7.0}
    # 0.4*0.5 + 0.3*0.4 + 0.2*0.5 + 0.1*1.0 (clipped)
    assert risk_score(comp, norm, weights) == pytest.approx(0.52)
    assert np.isnan(risk_score({**comp, "fix_rate": np.nan}, norm, weights))
    thr = {"medium": 0.3, "high": 0.5}
    assert [to_band(s, thr) for s in (0.1, 0.3, 0.49, 0.5)] == [0, 1, 1, 2]


def test_score_components_pool_the_window():
    a = {"vuln_count": np.array([2.0, 2.0]), "n_fixed": np.array([2.0, 0.0]), "n_ignored": np.array([0.0, 2.0]),
         "n_false_positive": np.zeros(2), "repeat_count": np.array([0.0, 1.0]),
         "severity_weighted_load": np.array([6.0, 2.0]), "ignored_severity_load": np.array([0.0, 2.0]),
         "n_high_severity": np.array([2.0, 0.0]), "response_total": np.array([200.0, 200.0]),
         "active": np.ones(2)}
    c = score_components(a, 1, 2)
    assert c["fix_rate"] == pytest.approx(0.5)
    assert c["severity_weighted_ignore_rate"] == pytest.approx(2 / 8)
    assert c["repeat_rate"] == pytest.approx(0.25)
    assert c["log_response_time"] == pytest.approx(np.log1p(100.0))


def test_fix_rate_rule():
    rule = {"high_below": 0.5, "medium_below": 0.75}
    assert [fix_rate_rule(f, rule) for f in (0.2, 0.5, 0.74, 0.75, np.nan)] == [2, 1, 1, 0, 0]


def _arrays(fixed, ignored, sw_ignored, repeats, response_total, vuln=10.0, weeks=4):
    rep = lambda x: np.full(weeks, float(x))
    return {"vuln_count": rep(vuln), "n_fixed": rep(fixed), "n_ignored": rep(ignored), "n_false_positive": rep(0),
            "repeat_count": rep(repeats), "severity_weighted_load": rep(20), "ignored_severity_load": rep(sw_ignored),
            "n_high_severity": rep(3), "response_total": rep(response_total), "active": rep(1)}


def test_drivers_come_from_measured_metrics():
    reference = {"severity_weighted_ignore_rate": (0.2, 0.1), "fix_rate": (0.6, 0.2), "repeat_rate": (0.4, 0.2),
                 "response_time_sec": (400.0, 200.0), "vuln_count": (10.0, 4.0)}
    risky = _arrays(fixed=2, ignored=6, sw_ignored=12, repeats=4, response_total=4000)  # fix 20%, sw-ignore 60%
    drivers = measured_drivers(risky, 4, reference, "HIGH", 3)
    assert [d["metric"] for d in drivers] == ["severity_weighted_ignore_rate", "fix_rate"]
    assert drivers[0]["value"] == pytest.approx(0.6) and drivers[0]["direction"] == "worse"
    assert drivers[0]["text"] == "Severity-weighted ignore rate 60% in weeks 1-4 (above the study median of 20%)"

    careful = _arrays(fixed=9, ignored=0, sw_ignored=0, repeats=1, response_total=2000)
    low = measured_drivers(careful, 4, reference, "LOW", 3)
    assert {d["metric"] for d in low} == {"severity_weighted_ignore_rate", "fix_rate", "repeat_rate"}
    assert all(d["direction"] == "better" for d in low)
