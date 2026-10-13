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
.venv/Scripts/python -m src.forecast     # outputs/forecast_metrics.json, forecasts.json (see Forecasting)
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
| `repeat_count` | detections whose (type, file) pair was also flagged for that developer in the previous 4 weeks |
| `repeat_type_rate` | secondary: share of detections whose type alone was seen in the previous 2 weeks (NaN if no detections) |
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

## Forecasting (Phase 2)

```bash
.venv/Scripts/python -m src.forecast --quick   # smoke test: 1 seed, 20 epochs, default settings (~25 s)
.venv/Scripts/python -m src.forecast           # full: grid search, 5 seeds, both cells (~1.5 min on CPU)
.venv/Scripts/python -m pytest tests/test_forecast.py tests/test_gru_numpy_matches_torch.py
```

Run `simulate`, `features` and `trends` first. Outputs (not committed):

| File | Contents |
|---|---|
| `outputs/forecast_metrics.json` | selected settings, test metrics (mean ± std over seeds), per-horizon metrics, Wilcoxon tests, MAE by archetype |
| `outputs/forecasts.json` | per developer: weekly history, test-period predicted vs actual, forecast for weeks 17-18 with seed spread |
| `outputs/forecast_tuning.csv` | every grid configuration and its validation loss |

**Task.** From the last L weeks (default 4) of 7 inputs (`vuln_count`,
`fix_rate`, `ignore_rate`, `log1p(avg_response_time)`, `repeat_count`,
`severity_weighted_load`, `active`), predict `vuln_count` and `fix_rate` for the
next 2 weeks: 4 outputs, predicted directly. One model is pooled across all
developers.

**Split (chronological by target week).** Train uses origins 4-7 (targets in
weeks 5-9). Validation uses origins 9-10 (targets 10-12). Test uses origins
12-14 (targets 13-16). Standardisation uses weeks 1-9 only, tuning uses
validation only, and the test set is used once.

**Missing weeks.** Undefined inputs carry the last known value forward,
alongside the `active` flag. Inactive target weeks are masked out of the loss
and the metrics. `fix_rate` targets are also masked in weeks with zero
detections.

**Model.** A 1-layer GRU or LSTM, then dropout, then a linear head. It trains
with masked Huber loss, AdamW (lr 0.003, weight decay 1e-4), gradient clipping
at 1.0, and early stopping on validation loss (patience 30). The grid covers
hidden {16, 32, 64} × L {3, 4} × dropout {0.1, 0.3}, scored on mean validation
loss over 3 seeds. The final model trains with 5 seeds, and the test
predictions are the mean of those seeds. Count outputs are clipped to ≥ 0, and
`fix_rate` outputs to [0, 1].

**Baselines.** Naive last value, mean of the last 4 weeks, and a per-developer
linear trend over the window, all clipped.

**Metrics.** MAE, RMSE and sMAPE (0/0 counts as 0; plain MAPE is undefined
when the actual count is 0), per target and per horizon. Significance uses a
paired Wilcoxon signed-rank test on per-developer MAE.

**Deployment forecast.** The cell with the better validation loss is refit on
all windows with targets up to week 16, using a fixed epoch count (the median
best epoch from validation). It forecasts weeks 17-18 from weeks 13-16. The
band is the min-max spread across 5 seeds. It is a *seed spread, not a
calibrated confidence interval*.

### Results (simulated data, seed 42)

Test set: 180 windows, 338 valid `vuln_count` targets and 298 valid `fix_rate` targets.

| Model | vuln_count MAE | vuln_count sMAPE | fix_rate MAE | fix_rate sMAPE |
|---|---|---|---|---|
| GRU (h=32, L=4, d=0.1), 5 seeds | 3.763 ± 0.030 | 77.1 ± 0.3 | 0.250 ± 0.001 | 51.3 ± 0.2 |
| LSTM (h=64, L=4, d=0.1), 5 seeds | 3.734 ± 0.020 | 76.5 ± 0.3 | 0.252 ± 0.001 | 51.6 ± 0.2 |
| Naive last value | 4.533 | 94.2 | 0.289 | 64.0 |
| 4-week mean | 3.749 | 78.1 | 0.253 | 54.7 |
| Linear trend | 5.336 | 111.3 | 0.323 | 72.6 |

The recurrent models beat the naive and linear baselines significantly
(Wilcoxon p < 0.05 for both targets). They do **not** beat the 4-week mean
(p ≥ 0.09). Treat this as an honest negative result: on this data, most of the
predictable signal is the developer's recent level. See `forecast_metrics.json`
for per-horizon and per-archetype results.

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
- Type and file: with the repeat propensity, a (type, file) pair flagged for
  this developer in the previous 4 weeks is reused (chosen uniformly). Otherwise
  a fresh pair is drawn: the type from the developer's own type mix (a Dirichlet
  around the global mix SQLi 35%, XSS 30%, secrets 20%, command injection 15%,
  concentration 8) and the file from their working set. Fresh draws reject
  recently flagged pairs (up to 20 tries), so a "fresh" detection is not a
  hidden repeat and the measured repeat rate follows the latent propensity.
- Severity depends on type (for example, command injection is 70% HIGH and XSS
  is 30% HIGH). See `severity_by_type`.
- Confidence ~ Beta by severity (higher severity means higher confidence).
- Action probabilities: FIXED = fix propensity, FALSE_POSITIVE = FP rate, and
  the remainder is split between IGNORED and DISMISSED by the ignored share.
- Response time ~ lognormal(median, log-sd 0.8). Non-fix actions use 0.3x the
  median, because dismissing a warning is faster than fixing code.
- `fixedAt = detectedAt + responseTime` only for FIXED.
- Line number is uniform in 1-400.

**Working set.** Each developer works on 6-12 files (uniform) drawn from a pool
of 26 file names. Usage across those files is uneven, with weights from
Dirichlet(0.6). An alpha below 1 makes a few "hot" files take most detections,
as in real projects where some modules are edited far more often.

**Ground truth.** `developers.csv` stores each developer's archetype. It is used
only for sanity checks and must never be a model input.

## Known limitations

- **Why `repeat_count` uses (type, file).** A type-only definition (2-week
  lookback) was nearly saturated. With 4 types, 86% of detections counted as
  repeats, and the Pearson correlation with `vuln_count` was 0.94. The
  (type, file) key over 4 weeks gives a 43% repeat share and r = 0.83. The raw
  count still grows with volume, but the repeat *rate*
  (`repeat_count / vuln_count`) has r = 0.13 with `vuln_count`, so use the rate
  when volume should not matter. The archetype signal is now visible:
  worsening developers go from 41% to 64% repeats between the two halves of the
  study, and improving developers from 38% to 29%. Weeks 1-4 have fewer
  possible repeats because the lookback window is still filling.
- Trajectories are linear (or AR(1)). Real learning curves are likely to be
  non-linear and partly driven by the feedback itself, which the simulator
  does not model.
- Developers are independent. There are no team or project effects.
- `sessions.jsonl` is an optional input proposed to Component 2; it is not yet part of the Component 1/2 contract.
