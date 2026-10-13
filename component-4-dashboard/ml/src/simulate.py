"""Generate SIMULATED security events for Component 4.

Components 1-3 do not produce data yet, so this module creates synthetic events
that follow the team event schema. The output is NOT real developer data: every
behaviour comes from the assumptions in config.yaml (explained in ml/README.md).

How it works
------------
1. Each developer gets an archetype (improving, stagnant, worsening, erratic).
2. The archetype defines *latent trajectories* over the study, written as a
   function of study progress t in [0, 1]:
     - vulnerability rate per session  lambda(t)
     - fix propensity                  p_fix(t)
     - share of non-fixes that are ignored (the rest are dismissed)
     - median response time (lognormal)
     - repeat propensity (re-using a (type, file) pair flagged in the previous 4 weeks)
   Improving/worsening move linearly between a start and end value; stagnant
   stays flat; erratic adds a random walk so its direction is unpredictable.
3. Each week: the developer may be inactive; otherwise they have a number of
   sessions, each session has Poisson(lambda) detections, and each detection
   gets a type, file, severity, confidence, action and response time.
   Each developer works on a fixed working set of 6-12 files with uneven usage.

Randomness uses one numpy SeedSequence: each developer gets its own child
generator, so the output is identical for the same seed and config.
"""

import argparse
import csv
import json
import uuid
from datetime import datetime, timedelta, timezone

import numpy as np

from .config import load_config, resolve

ARCHETYPES = ["improving", "stagnant", "worsening", "erratic"]
ACTIONS = ["FIXED", "FALSE_POSITIVE", "IGNORED", "DISMISSED"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH"]


def _linear(start_end, t):
    """Straight line from start (t=0) to end (t=1)."""
    start, end = start_end
    return start + (end - start) * t


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def assign_archetypes(n, mix, rng):
    """Give exact archetype counts from the configured mix, then shuffle.

    Exact counts (e.g. 18/18/12/12 for 60 developers) keep every run balanced,
    instead of letting random sampling under-represent a group.
    """
    counts = [int(round(mix[a] * n)) for a in ARCHETYPES]
    counts[0] += n - sum(counts)
    labels = [a for a, c in zip(ARCHETYPES, counts) for _ in range(c)]
    rng.shuffle(labels)
    return labels


def developer_trajectories(archetype, sim, n_weeks, rng):
    """Return per-week latent parameters for one developer as numpy arrays."""
    t = np.linspace(0.0, 1.0, n_weeks)
    erratic = archetype == "erratic"

    def walk(sd):
        """Mean-reverting AR(1) walk starting at 0, used only for erratic developers.

        x_w = phi * x_{w-1} + noise. With phi < 1 the walk keeps pulling back
        toward 0, so erratic developers swing up and down instead of drifting
        without bound (a pure random walk produced unrealistic 20x rates).
        """
        phi = sim["erratic_ar_phi"]
        x = np.zeros(n_weeks)
        for i in range(1, n_weeks):
            x[i] = phi * x[i - 1] + rng.normal(0, sd)
        return x

    base = sim["base_rate_median"] * np.exp(rng.normal(0, sim["base_rate_sigma"]))
    change = sim["rate_change"]
    shape = {
        "improving": 1 - change * t,
        "worsening": 1 + change * t,
    }.get(archetype, np.ones(n_weeks))
    if erratic:
        shape = np.exp(walk(sim["erratic_walk_sigma"]))
    weekly_noise = np.exp(rng.normal(0, sim["weekly_rate_noise_sigma"], n_weeks))
    rate = np.clip(base * shape * weekly_noise, 0.05, None)

    fp_rate = rng.beta(*sim["false_positive_rate_beta"])
    p_fix = _linear(sim["fix_propensity"][archetype], t) + rng.normal(0, sim["fix_jitter_sd"])
    if erratic:
        p_fix = p_fix + walk(sim["erratic_fix_walk_sd"])
    p_fix = np.clip(p_fix, 0.02, 0.98 - fp_rate)

    ignore_share = np.clip(_linear(sim["ignore_share"][archetype], t), 0.05, 0.95)

    response_median = _linear(sim["response_median_sec"][archetype], t)
    if erratic:
        response_median = response_median * np.exp(rng.normal(0, sim["erratic_walk_sigma"], n_weeks))

    repeat = _linear(sim["repeat_propensity"][archetype], t)
    if erratic:
        repeat = repeat + walk(sim["erratic_fix_walk_sd"])
    repeat = np.clip(repeat, 0.0, 0.95)

    types = list(sim["type_mix"].keys())
    alpha = np.array([sim["type_mix"][k] for k in types]) * sim["type_mix_concentration"]
    type_mix = rng.dirichlet(alpha)

    lo, hi = sim["working_set_size"]
    files = [str(f) for f in rng.choice(sim["file_pool"], size=int(rng.integers(lo, hi + 1)), replace=False)]
    file_weights = rng.dirichlet(np.full(len(files), sim["file_usage_concentration"]))

    return {
        "files": files,
        "file_weights": file_weights,
        "base_rate": base,
        "rate": rate,
        "fp_rate": fp_rate,
        "p_fix": p_fix,
        "ignore_share": ignore_share,
        "response_median": response_median,
        "repeat": repeat,
        "types": types,
        "type_mix": type_mix,
    }


def simulate_developer(dev_id, archetype, cfg, rng):
    """Simulate all sessions and events for one developer."""
    sim = cfg["simulation"]
    n_weeks = cfg["study"]["n_weeks"]
    lookback = cfg["features"]["repeat_lookback_weeks"]
    start = datetime.fromisoformat(cfg["study"]["start_date"]).replace(tzinfo=timezone.utc)
    traj = developer_trajectories(archetype, sim, n_weeks, rng)

    events, sessions = [], []
    pairs_by_week = {}  # week -> set of (type, file) pairs flagged that week (for repeats)

    def fresh_pair(recent):
        """Draw a (type, file) from the developer's type mix and file usage, avoiding recent pairs.

        A detection that is not a repeat should, by definition, not hit a pair
        flagged in the lookback window. Rejection sampling keeps the measured
        repeat rate close to the latent repeat propensity.
        """
        for _ in range(sim["fresh_pair_max_tries"]):
            pair = (str(rng.choice(traj["types"], p=traj["type_mix"])),
                    str(rng.choice(traj["files"], p=traj["file_weights"])))
            if pair not in recent:
                break
        return pair

    for w in range(n_weeks):
        week_no = w + 1
        pairs_by_week[week_no] = set()
        if rng.random() < sim["p_inactive_week"]:
            continue

        n_sessions = 1 + rng.poisson(sim["sessions_per_week_mean"] - 1)
        week_start = start + timedelta(weeks=w)
        session_starts = sorted(
            week_start
            + timedelta(days=int(rng.integers(0, 5)))
            + timedelta(hours=float(rng.uniform(sim["workday_start_hour"], sim["workday_end_hour"] - 2)))
            for _ in range(n_sessions)
        )
        recent = set().union(*(pairs_by_week.get(week_no - k, set()) for k in range(1, lookback + 1)))

        for s_idx, s_start in enumerate(session_starts, start=1):
            session_id = f"SESSION-{dev_id}-W{week_no:02d}-{s_idx}"
            sessions.append({"sessionId": session_id, "developerId": dev_id, "startedAt": _iso(s_start)})

            for _ in range(rng.poisson(traj["rate"][w])):
                if recent and rng.random() < traj["repeat"][w]:
                    ordered = sorted(recent)
                    vtype, file_name = ordered[int(rng.integers(len(ordered)))]
                else:
                    vtype, file_name = fresh_pair(recent)
                pairs_by_week[week_no].add((vtype, file_name))

                severity = str(rng.choice(SEVERITIES, p=sim["severity_by_type"][vtype]))
                confidence = float(np.clip(rng.beta(*sim["confidence_beta"][severity]), 0.0, 1.0))

                p_fix, p_fp = traj["p_fix"][w], traj["fp_rate"]
                rest = 1.0 - p_fix - p_fp
                p_ignore = rest * traj["ignore_share"][w]
                action = str(rng.choice(ACTIONS, p=[p_fix, p_fp, p_ignore, rest - p_ignore]))

                median = traj["response_median"][w]
                if action != "FIXED":
                    median *= sim["quick_action_factor"]
                response = max(1.0, float(rng.lognormal(np.log(median), sim["response_sigma"])))

                detected = s_start + timedelta(seconds=float(rng.uniform(0, 2 * 3600)))
                detected = detected.replace(microsecond=0)
                events.append({
                    "eventId": str(uuid.UUID(bytes=rng.bytes(16), version=4)),
                    "developerId": dev_id,
                    "sessionId": session_id,
                    "vulnerabilityType": vtype,
                    "severity": severity,
                    "confidence": round(confidence, 3),
                    "fileName": file_name,
                    "lineNumber": int(rng.integers(1, sim["max_line_number"] + 1)),
                    "detectedAt": _iso(detected),
                    "action": action,
                    "fixedAt": _iso(detected + timedelta(seconds=response)) if action == "FIXED" else None,
                    "responseTime": round(response, 1),
                })

    profile = {
        "developerId": dev_id,
        "archetype": archetype,
        "baseRate": round(traj["base_rate"], 4),
        "falsePositiveRate": round(traj["fp_rate"], 4),
        "workingSetSize": len(traj["files"]),
    }
    return events, sessions, profile


def simulate(cfg, seed=None):
    """Run the full simulation. Returns (events, sessions, developer_profiles)."""
    seed = cfg["seed"] if seed is None else seed
    n_dev = cfg["simulation"]["n_developers"]
    children = np.random.SeedSequence(seed).spawn(n_dev + 1)
    archetypes = assign_archetypes(n_dev, cfg["simulation"]["archetype_mix"], np.random.default_rng(children[0]))

    events, sessions, profiles = [], [], []
    for i in range(n_dev):
        dev_id = f"DEV{i + 1:03d}"
        e, s, p = simulate_developer(dev_id, archetypes[i], cfg, np.random.default_rng(children[i + 1]))
        events += e
        sessions += s
        profiles.append(p)

    events.sort(key=lambda e: (e["detectedAt"], e["developerId"], e["eventId"]))
    sessions.sort(key=lambda s: (s["startedAt"], s["developerId"], s["sessionId"]))
    return events, sessions, profiles


def _write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Generate simulated security events.")
    parser.add_argument("--seed", type=int, default=None, help="override the seed in config.yaml")
    args = parser.parse_args()

    cfg = load_config()
    events, sessions, profiles = simulate(cfg, seed=args.seed)

    _write_jsonl(resolve(cfg["paths"]["events"]), events)
    _write_jsonl(resolve(cfg["paths"]["sessions"]), sessions)
    with open(resolve(cfg["paths"]["developers"]), "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(profiles[0].keys()))
        writer.writeheader()
        writer.writerows(profiles)

    counts = {a: sum(p["archetype"] == a for p in profiles) for a in ARCHETYPES}
    seed = cfg["seed"] if args.seed is None else args.seed
    print(f"SIMULATED data (seed={seed}): "
          f"{len(events)} events, {len(sessions)} sessions, {len(profiles)} developers {counts}")


if __name__ == "__main__":
    main()
