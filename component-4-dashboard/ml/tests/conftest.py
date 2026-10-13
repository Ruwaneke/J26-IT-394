import copy

import pandas as pd
import pytest

from src.config import load_config


@pytest.fixture
def cfg():
    return copy.deepcopy(load_config())


@pytest.fixture
def tiny_cfg(cfg):
    cfg["study"]["start_date"] = "2026-06-01"
    cfg["study"]["n_weeks"] = 3
    cfg["features"]["repeat_lookback_weeks"] = 4
    cfg["features"]["repeat_type_lookback_weeks"] = 2
    return cfg


def _event(eid, dev, session, vtype, file_name, severity, detected, action, rt):
    return {"eventId": eid, "developerId": dev, "sessionId": session,
            "vulnerabilityType": vtype, "severity": severity, "confidence": 0.9,
            "fileName": file_name, "lineNumber": 1, "detectedAt": detected,
            "action": action, "fixedAt": None, "responseTime": rt}


@pytest.fixture
def tiny_events():
    """Hand-made events. Week 1 = 1-7 Jun, week 2 = 8-14 Jun, week 3 = 15-21 Jun 2026."""
    return pd.DataFrame([
        # DEV_A week 1: two sessions, three events
        _event("e1", "DEV_A", "S1", "SQL_INJECTION", "a.py", "HIGH", "2026-06-01T10:00:00Z", "FIXED", 100),
        _event("e2", "DEV_A", "S1", "XSS", "a.py", "LOW", "2026-06-01T10:30:00Z", "IGNORED", 20),
        _event("e3", "DEV_A", "S2", "SQL_INJECTION", "a.py", "MEDIUM", "2026-06-03T09:00:00Z", "FALSE_POSITIVE", 30),
        # DEV_A week 2: one clean session (only in sessions file)
        # DEV_A week 3: SQLi in a.py repeats week 1 (pair repeat);
        # SQLi in b.py is a type repeat only; command injection is new
        _event("e4", "DEV_A", "S4", "SQL_INJECTION", "a.py", "HIGH", "2026-06-15T11:00:00Z", "DISMISSED", 50),
        _event("e5", "DEV_A", "S4", "COMMAND_INJECTION", "c.py", "HIGH", "2026-06-15T11:10:00Z", "FIXED", 150),
        _event("e7", "DEV_A", "S4", "SQL_INJECTION", "b.py", "LOW", "2026-06-15T11:20:00Z", "IGNORED", 100),
        # DEV_B week 2 only
        _event("e6", "DEV_B", "S5", "XSS", "a.py", "MEDIUM", "2026-06-09T14:00:00Z", "FIXED", 60),
    ])


@pytest.fixture
def tiny_sessions():
    return pd.DataFrame([
        {"sessionId": "S1", "developerId": "DEV_A", "startedAt": "2026-06-01T09:55:00Z"},
        {"sessionId": "S2", "developerId": "DEV_A", "startedAt": "2026-06-03T08:55:00Z"},
        {"sessionId": "S3", "developerId": "DEV_A", "startedAt": "2026-06-10T09:00:00Z"},
        {"sessionId": "S4", "developerId": "DEV_A", "startedAt": "2026-06-15T10:55:00Z"},
        {"sessionId": "S5", "developerId": "DEV_B", "startedAt": "2026-06-09T13:55:00Z"},
    ])
