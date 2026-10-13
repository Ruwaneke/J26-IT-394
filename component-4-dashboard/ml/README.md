# Component 4 ML pipeline

> **All data here is SIMULATED.** Components 1-3 are not producing events yet,
> so `src/simulate.py` generates synthetic events from the assumptions below.
> No result from this pipeline describes real developers. When Component 2 is
> ready, its events replace `data/raw/events.jsonl` (same schema) and the rest
> of the pipeline runs unchanged.

## Setup (Windows, Python 3.12)

```bash
cd component-4-dashboard/ml
py -3.12 -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
```

On macOS/Linux use `python3.12 -m venv .venv` and `.venv/bin/python`.

## Run

```bash
.venv/Scripts/python -m src.simulate     # data/raw/events.jsonl, sessions.jsonl, developers.csv
.venv/Scripts/python -m src.features     # data/processed/developer_weeks.csv
.venv/Scripts/python -m src.trends       # developer_week_trends.csv, developer_trends.csv, team_weeks.csv
.venv/Scripts/python -m pytest           # tests
```

`python -m src.simulate --seed 7` overrides the seed. All other parameters are
in `config.yaml`.

## Pipeline so far

| Step | Module | Output |
|---|---|---|
| Simulate events | `simulate.py` | `data/raw/events.jsonl`, `sessions.jsonl`, `developers.csv` |
| Developer-week features | `features.py` | `data/processed/developer_weeks.csv` |
| Trends | `trends.py` | `developer_week_trends.csv`, `developer_trends.csv`, `team_weeks.csv` |

### Features (one row per developer per week, weeks 1-16)

| Feature | Definition |
|---|---|
| `vuln_count` | detections in the week |
| `fix_rate`, `ignore_rate`, `false_positive_rate` | share of the week's detections with that action (NaN if no detections) |
| `avg_response_time` | mean seconds from detection to action |
| `repeat_count` | detections whose type was also detected for that developer in the previous 2 weeks |
| `severity_weighted_load` | sum of severity weights, LOW=1, MEDIUM=2, HIGH=3 |
| `count_<type>` | detections per vulnerability type |
| `n_sessions`, `active` | sessions in the week; active = at least one session |
| `intro_rate_per_session` | `vuln_count / n_sessions` (NaN if no sessions) |

### Trends

- 4-week trailing moving averages (early weeks average the weeks available so far).
- Week-over-week change: absolute for counts, percentage points for rates. Percent
  change is not used because it is undefined after a zero week.
- Rolling 4-week OLS slope (needs at least 3 non-missing weeks).
- Per developer: OLS slope of intro rate per session over the study. Below
  -0.02/week = improving, above +0.02 = worsening, otherwise stable.
- Team: weekly totals with **pooled** rates (total fixed / total detections).

## Simulator assumptions

Every number below is in `config.yaml`. The values were chosen to be plausible
and to give the later models a clear but noisy signal. They are not
calibrated against real data, because no real data exists yet.

**Population and time.** 60 developers, 16 weeks starting Monday 1 June 2026,
seed 42. Archetypes are assigned with exact counts from the mix:
30% improving (18), 30% stagnant (18), 20% worsening (12), 20% erratic (12).

**Latent trajectories.** Each archetype defines how a developer's behaviour
changes with study progress `t` (0 at week 1, 1 at week 16):

| Trajectory | Improving | Stagnant | Worsening | Erratic |
|---|---|---|---|---|
| Detections per session `lambda` | base x (1 - 0.6t) | base | base x (1 + 0.6t) | base x exp(AR(1) walk) |
| Fix propensity | 0.45 → 0.85 | 0.55 | 0.60 → 0.30 | 0.55 + AR(1) walk |
| Ignored share of non-fixes | 0.55 → 0.35 | 0.50 | 0.45 → 0.75 | 0.50 |
| Median response time (s) | 600 → 240 | 450 | 300 → 900 | 450 x weekly lognormal noise |
| Repeat propensity | 0.50 → 0.20 | 0.40 | 0.35 → 0.65 | 0.40 + AR(1) walk |

- **Base rate:** per developer, lognormal with median 1.2 detections per
  session and log-sd 0.35, so some developers are naturally more error-prone.
- **Weekly noise:** `lambda` is multiplied by lognormal noise (log-sd 0.25) each week.
- **Erratic developers** use a mean-reverting AR(1) walk (phi = 0.7) instead of
  a straight line. A pure random walk drifted to unrealistic 20x rates. AR(1)
  keeps them volatile but bounded.
- **Fix propensity** gets a fixed per-developer offset (sd 0.06) and is clipped
  to [0.02, 0.98 - false-positive rate].
- **False positives:** each developer has a fixed FP rate ~ Beta(2, 28) (mean
  about 6.7%). This is treated as a property of the code the developer works on,
  not of their behaviour.

**Activity.** Each week a developer is inactive with probability 0.08. Active
weeks have `1 + Poisson(3)` sessions on random weekdays between 09:00 and
16:00 UTC. Sessions with no detections are still written to `sessions.jsonl`.

**Each detection.**
- Count per session ~ Poisson(`lambda` for that week).
- Type: with the repeat propensity, a type seen in the previous 2 weeks is
  reused. Otherwise the type is drawn from the developer's own type mix (a
  Dirichlet around the global mix SQLi 35%, XSS 30%, secrets 20%, command
  injection 15%, concentration 8).
- Severity depends on type (for example, command injection is 70% HIGH and XSS
  is 30% HIGH). See `severity_by_type`.
- Confidence ~ Beta by severity (higher severity means higher confidence).
- Action probabilities: FIXED = fix propensity, FALSE_POSITIVE = FP rate, and
  the remainder is split between IGNORED and DISMISSED by the ignored share.
- Response time ~ lognormal(median, log-sd 0.8). Non-fix actions use 0.3x the
  median, because dismissing a warning is faster than fixing code.
- `fixedAt = detectedAt + responseTime` only for FIXED.
- File name comes from a small per-type list, and the line number is uniform in 1-400.

**Ground truth.** `developers.csv` stores each developer's archetype. It is used
only for sanity checks and must never be a model input.

## Known limitations

- **`repeat_count` is close to saturated.** With 4 types and about 10
  detections per developer over 2 weeks, roughly 86% of detections count as
  repeats. The feature therefore mostly tracks `vuln_count`. A narrower key,
  such as same type in the same file, would separate developers better.
  *Open decision.*
- Trajectories are linear (or AR(1)). Real learning curves are likely to be
  non-linear and partly driven by the feedback itself, which the simulator
  does not model.
- Developers are independent. There are no team or project effects.
- `sessions.jsonl` is an optional input proposed to Component 2; it is not yet part of the Component 1/2 contract.
