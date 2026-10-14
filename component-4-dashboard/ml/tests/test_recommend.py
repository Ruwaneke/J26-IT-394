import numpy as np
import pytest

from src.recommend import condition_holds, direction, recommend

NEUTRAL = {
    "risk_band": "MEDIUM", "forecast_vuln_direction": "flat", "forecast_fix_direction": "flat",
    "recent_vuln": 4.0, "forecast_vuln": 4.0, "recent_fix": 0.6, "forecast_fix": 0.6,
    "ignore_rate": 0.1, "fix_rate": 0.7, "repeat_rate": 0.2, "response_time_sec": 300.0, "dominant_type": None,
}

# rule id -> (changes that make it fire, changes that keep it silent)
CASES = {
    "R1": ({"risk_band": "HIGH", "ignore_rate": 0.4}, {"risk_band": "MEDIUM", "ignore_rate": 0.4}),
    "R2": ({"fix_rate": 0.3}, {"fix_rate": 0.3, "risk_band": "LOW"}),
    "R3": ({"repeat_rate": 0.6}, {"repeat_rate": 0.49}),
    "R4": ({"forecast_vuln_direction": "up", "forecast_vuln": 6.0}, {"forecast_vuln_direction": "down"}),
    "R5": ({"forecast_fix_direction": "down", "forecast_fix": 0.4}, {"forecast_fix_direction": "down", "risk_band": "LOW"}),
    "R6": ({"response_time_sec": 1200.0}, {"response_time_sec": 600.0}),
    "R7": ({"dominant_type": "XSS"}, {"dominant_type": "XSS", "risk_band": "LOW"}),
    "R8": ({"risk_band": "LOW", "forecast_vuln_direction": "down"}, {"risk_band": "LOW", "forecast_vuln_direction": "up"}),
}


@pytest.fixture
def rc(cfg):
    return dict(cfg["recommend"], max_recommendations=10)


def test_every_configured_rule_has_a_case(rc):
    assert {r["id"] for r in rc["rules"]} == set(CASES)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_and_does_not_fire(rc, rule_id):
    fire, silent = CASES[rule_id]
    assert rule_id in recommend({**NEUTRAL, **fire}, rc)["firedRules"]
    assert rule_id not in recommend({**NEUTRAL, **silent}, rc)["firedRules"]


def test_neutral_input_gets_only_the_fallback(rc):
    out = recommend(NEUTRAL, rc)
    assert out["firedRules"] == ["R0"] and out["priority"] == 3


def test_priority_order_cap_and_text(cfg):
    rc = cfg["recommend"]
    out = recommend({**NEUTRAL, "risk_band": "HIGH", "ignore_rate": 0.42, "fix_rate": 0.3, "repeat_rate": 0.6,
                     "response_time_sec": 1500.0, "dominant_type": "SQL_INJECTION"}, rc)
    assert out["priority"] == 1
    assert len(out["recommendations"]) == 3
    assert [r["priority"] for r in out["recommendations"]] == sorted(r["priority"] for r in out["recommendations"])
    assert out["recommendations"][0]["text"].startswith("Research risk profile based on measured behaviour: HIGH. 42%")
    assert {"R1", "R2", "R3", "R6", "R7"} <= set(out["firedRules"])


def test_missing_values_never_fire():
    assert not condition_holds({"field": "fix_rate", "op": "lt", "value": 0.5}, {"fix_rate": np.nan})
    assert not condition_holds({"field": "dominant_type", "op": "exists"}, {"dominant_type": None})
    assert condition_holds({"field": "risk_band", "op": "in", "value": ["MEDIUM", "HIGH"]}, {"risk_band": "HIGH"})


def test_direction_with_tolerance():
    assert direction(5.4, 5.0, 0.5) == "flat"
    assert direction(5.6, 5.0, 0.5) == "up"
    assert direction(0.40, 0.50, 0.05) == "down"
    assert direction(None, 0.5, 0.05) is None
