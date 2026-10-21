"""Generate the Component 3 escalation scenario set.

Expected levels come from the rubric below, which is written independently of
the scoring engine. Do not tune the rubric to match the engine: the point of
the scenario set is to measure how often the engine agrees with it.

Usage (from component-3-feedback-engine/):
    python tools/generate_scenarios.py
Writes src/test/resources/scenarios/scenarios.json.
"""

import json
from pathlib import Path

WINDOW_DAYS = 30
RECENT_DAYS = 14

CWES = [
    # key, cwe, typical, lower, higher severity
    ("SQLI", "CWE-89", "HIGH", "MEDIUM", "CRITICAL"),
    ("XSS", "CWE-79", "MEDIUM", "LOW", "HIGH"),
    ("SECRET", "CWE-798", "HIGH", "MEDIUM", "CRITICAL"),
    ("VALID", "CWE-20", "LOW", "INFO", "MEDIUM"),
]

# Timelines are lists of (event, days_ago) for earlier occurrences of the same CWE.
# REPEAT means the issue was reintroduced after an earlier warning.
SITUATIONS = [
    ("first-time", "typical", "First occurrence, no history", []),
    ("first-time-lower", "lower", "First occurrence of a less severe finding", []),
    ("first-time-higher", "higher", "First occurrence of a more severe finding", []),
    ("one-earlier-fixed", "typical", "One earlier occurrence, fixed 6 days ago",
     [("FIX", 6)]),
    ("repeated-but-fixed", "typical", "Reintroduced 3 times this month, fixed each time",
     [("FIX", 24), ("REPEAT", 16), ("FIX", 16), ("REPEAT", 8), ("FIX", 8), ("REPEAT", 3), ("FIX", 3)]),
    ("repeated-ignored-twice", "typical", "Reintroduced 3 times, 2 warnings ignored",
     [("IGNORE", 26), ("REPEAT", 18), ("IGNORE", 18), ("REPEAT", 9), ("FIX", 9), ("REPEAT", 2)]),
    ("persistent-ignorer", "typical", "Reintroduced 3 times, 3 warnings ignored",
     [("IGNORE", 27), ("REPEAT", 19), ("IGNORE", 19), ("REPEAT", 9), ("IGNORE", 9), ("REPEAT", 2)]),
    ("mastered", "typical", "Five fixes over three months, nothing ignored",
     [("FIX", 80), ("FIX", 62), ("FIX", 45), ("FIX", 28), ("FIX", 12)]),
    ("improving", "typical", "Ignored warnings two months ago, three fixes this month",
     [("IGNORE", 60), ("IGNORE", 50), ("REPEAT", 40), ("FIX", 25), ("FIX", 15), ("FIX", 5)]),
    ("fix-reopened", "typical", "Two fixes this month did not hold",
     [("FIX", 20), ("REOPEN", 14), ("FIX", 14), ("REOPEN", 4)]),
    ("old-history-only", "typical", "Ignored and repeated, but over two months ago",
     [("IGNORE", 75), ("REPEAT", 70), ("IGNORE", 70), ("REPEAT", 60), ("IGNORE", 60)]),
    ("mastered-recent-ignore", "typical", "Long fix record, one warning ignored 5 days ago",
     [("FIX", 70), ("FIX", 50), ("FIX", 35), ("FIX", 20), ("IGNORE", 5)]),
]

BASE_LEVEL = {"INFO": 1, "LOW": 1, "MEDIUM": 2, "HIGH": 2, "CRITICAL": 2}


def history(timeline):
    def count(kind):
        return sum(1 for event, days in timeline if event == kind and days <= WINDOW_DAYS)

    return {
        "repeats30d": count("REPEAT"),
        "ignored30d": count("IGNORE"),
        "fixed30d": count("FIX"),
        "reopened30d": count("REOPEN"),
        "lastSimilarDaysAgo": min((days for _, days in timeline), default=None),
    }


def expected_level(cwe, severity, timeline, h):
    """The rubric. Returns (level, rationale)."""
    level = BASE_LEVEL[severity]
    notes = [f"{severity} base L{level}"]

    recent = h["lastSimilarDaysAgo"] is not None and h["lastSimilarDaysAgo"] <= RECENT_DAYS
    total_fixes = sum(1 for event, _ in timeline if event == "FIX")

    if h["repeats30d"] >= 3 and h["ignored30d"] >= 3:
        level += 2
        notes.append("persistent repeat-and-ignore pattern +2")
    elif (h["repeats30d"] >= 2 and recent) or h["ignored30d"] >= 2 or h["reopened30d"] >= 2:
        level += 1
        notes.append("concerning pattern (repeats, ignores or reopens) +1")
    elif (total_fixes >= 3 and h["ignored30d"] == 0 and h["reopened30d"] == 0
          and h["repeats30d"] <= 1):
        level -= 1
        notes.append("demonstrated mastery -1")

    level = max(1, min(4, level))
    if cwe == "CWE-798" and level < 3:
        level = 3
        notes.append("hardcoded secret floor L3")
    if severity == "CRITICAL" and level < 2:
        level = 2
        notes.append("critical floor L2")
    return level, "; ".join(notes)


def main():
    scenarios = []
    for cwe_index, (key, cwe, typical, lower, higher) in enumerate(CWES):
        severities = {"typical": typical, "lower": lower, "higher": higher}
        for situation_index, (name, severity_kind, description, timeline) in enumerate(SITUATIONS, 1):
            severity = severities[severity_kind]
            h = history(timeline)
            level, rationale = expected_level(cwe, severity, timeline, h)
            scenarios.append({
                "id": f"{key}-{situation_index:02d}",
                "set": "heldout" if (situation_index + cwe_index) % 3 == 0 else "tuning",
                "situation": name,
                "description": description,
                "event": {"cwe": cwe, "severity": severity},
                "history": h,
                "skillEvents": [{"type": event, "daysAgo": days} for event, days in timeline],
                "expectedLevel": level,
                "rationale": rationale,
            })

    out = Path(__file__).resolve().parent.parent / "src/test/resources/scenarios/scenarios.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(scenarios, indent=2) + "\n", encoding="utf-8")
    heldout = sum(1 for s in scenarios if s["set"] == "heldout")
    print(f"Wrote {len(scenarios)} scenarios ({len(scenarios) - heldout} tuning, {heldout} held-out) to {out}")


if __name__ == "__main__":
    main()
