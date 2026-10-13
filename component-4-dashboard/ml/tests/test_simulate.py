from datetime import datetime

import pytest

from src.simulate import ACTIONS, SEVERITIES, simulate


@pytest.fixture
def small_cfg(cfg):
    cfg["simulation"]["n_developers"] = 8
    cfg["study"]["n_weeks"] = 5
    return cfg


def test_same_seed_gives_identical_output(small_cfg):
    assert simulate(small_cfg, seed=7) == simulate(small_cfg, seed=7)


def test_different_seed_gives_different_output(small_cfg):
    assert simulate(small_cfg, seed=7)[0] != simulate(small_cfg, seed=8)[0]


def test_events_follow_schema(small_cfg):
    events, sessions, profiles = simulate(small_cfg)
    session_ids = {s["sessionId"] for s in sessions}
    start = datetime.fromisoformat(small_cfg["study"]["start_date"])
    assert events
    for e in events:
        assert e["vulnerabilityType"] in small_cfg["vulnerability_types"]
        assert e["severity"] in SEVERITIES
        assert e["action"] in ACTIONS
        assert 0.0 <= e["confidence"] <= 1.0
        assert e["responseTime"] >= 1.0
        assert (e["fixedAt"] is not None) == (e["action"] == "FIXED")
        assert e["sessionId"] in session_ids
        detected = datetime.fromisoformat(e["detectedAt"].rstrip("Z"))
        assert 0 <= (detected - start).days < 7 * small_cfg["study"]["n_weeks"]
    assert len({e["eventId"] for e in events}) == len(events)
    assert len(profiles) == 8


def test_working_set_files(small_cfg):
    events, _, profiles = simulate(small_cfg)
    lo, hi = small_cfg["simulation"]["working_set_size"]
    for p in profiles:
        files = {e["fileName"] for e in events if e["developerId"] == p["developerId"]}
        assert lo <= p["workingSetSize"] <= hi
        assert len(files) <= p["workingSetSize"]
        assert files <= set(small_cfg["simulation"]["file_pool"])


def test_archetype_counts_follow_mix(cfg):
    _, _, profiles = simulate(cfg)
    counts = {a: sum(p["archetype"] == a for p in profiles) for a in cfg["simulation"]["archetype_mix"]}
    assert counts == {"improving": 18, "stagnant": 18, "worsening": 12, "erratic": 12}
