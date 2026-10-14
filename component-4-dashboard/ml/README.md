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

One command runs everything:

```bash
.venv/Scripts/python -m src.pipeline           # full run, about 5 minutes on CPU
.venv/Scripts/python -m src.pipeline --quick   # smoke test, under 1 minute (quick forecast and risk settings)
.venv/Scripts/python -m pytest                 # all tests
```

Each step can also be run on its own, in this order:

```bash
.venv/Scripts/python -m src.simulate      # data/raw/events.jsonl, sessions.jsonl, developers.csv
.venv/Scripts/python -m src.features      # data/processed/developer_weeks.csv
.venv/Scripts/python -m src.trends        # developer_week_trends.csv, developer_trends.csv, team_weeks.csv
.venv/Scripts/python -m src.forecast      # outputs/forecast_metrics.json, forecasts.json
.venv/Scripts/python -m src.risk          # outputs/risk_metrics.json, risk.json
.venv/Scripts/python -m src.correlation   # outputs/correlations.json
.venv/Scripts/python -m src.recommend     # outputs/recommendations.json
.venv/Scripts/python -m src.export        # outputs/analytics.json + frontend/public/sample-analytics.json
```

`python -m src.simulate --seed 7` overrides the seed. All other parameters are
in `config.yaml`.

## Pipeline

| Step | Module | Output |
|---|---|---|
| Simulate events | `simulate.py` | `data/raw/events.jsonl`, `sessions.jsonl`, `developers.csv` |
| Developer-week features | `features.py` | `data/processed/developer_weeks.csv` |
| Trends | `trends.py` | `developer_week_trends.csv`, `developer_trends.csv`, `team_weeks.csv` |
| Forecasting | `forecast.py` | `outputs/forecast_metrics.json`, `forecasts.json`, `forecast_tuning.csv` |
| Risk classification | `risk.py` | `outputs/risk_metrics.json`, `risk.json`, `risk_tuning.csv` |
| Correlation | `correlation.py` | `outputs/correlations.json` |
| Recommendations | `recommend.py` | `outputs/recommendations.json` |
| Export | `export.py` | `outputs/analytics.json` (the single contract file), `../frontend/public/sample-analytics.json` |

Everything under `data/` and `outputs/` is generated and not committed. The
only committed output is the 20-developer sample for the frontend.

### Features (one row per developer per week, weeks 1-16)

| Feature | Definition |
|---|---|
| `vuln_count` | detections in the week |
| `fix_rate`, `ignore_rate`, `false_positive_rate` | share of the week's detections with that action (NaN if no detections) |
| `avg_response_time` | mean seconds from detection to action |
| `repeat_count` | detections whose (type, file) pair was also flagged for that developer in the previous 4 weeks |
| `repeat_type_rate` | secondary: share of detections whose type alone was seen in the previous 2 weeks (NaN if no detections) |
| `severity_weighted_load` | sum of severity weights, LOW=1, MEDIUM=2, HIGH=3 |
| `ignored_severity_load` | the same sum over IGNORED detections only (numerator of the severity-weighted ignore rate) |
| `n_high_severity` | HIGH detections |
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
.venv/Scripts/python -m src.forecast --quick   # smoke test: 1 seed, 20 epochs, default settings (~40 s)
.venv/Scripts/python -m src.forecast           # full: grid search, 5 seeds, 4 variants (~3 min on CPU)
.venv/Scripts/python -m pytest tests/test_forecast.py tests/test_gru_numpy_matches_torch.py
```

Run `simulate`, `features` and `trends` first. Outputs (not committed):

| File | Contents |
|---|---|
| `outputs/forecast_metrics.json` | selected settings, test metrics (mean ± std over seeds), per-horizon metrics, Wilcoxon tests, MAE by archetype |
| `outputs/forecasts.json` | per developer: weekly history, test-period predicted vs actual, forecast for weeks 17-18 with seed spread |
| `outputs/forecast_tuning.csv` | every grid configuration and its validation score |

**Task.** From the last L weeks (default 4) of 7 inputs (`vuln_count`,
`fix_rate`, `ignore_rate`, `log1p(avg_response_time)`, `repeat_count`,
`severity_weighted_load`, `active`), predict `vuln_count` and `fix_rate` for the
next 2 weeks: 4 outputs, predicted directly. One model is pooled across all
developers.

**Split (chronological by target week).** Train uses origins 4-7 (targets in
weeks 5-9). Validation uses origins 9-10 (targets 10-12). Test uses origins
12-14 (targets 13-16). Standardisation uses training data only, tuning uses
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

**Target mode (`target_mode`: raw | residual).** In *raw* mode the network
predicts the targets directly. In *residual* mode it predicts the difference
from each target's 4-week mean, and the final prediction is 4-week mean +
predicted residual (then clipped). **The residual mode was added post-hoc,
after the first test results showed that no raw model beat the 4-week mean.**
To limit that bias, raw vs residual is still selected on validation only. All
candidates are compared on one common score: the masked Huber loss of the final
predictions, standardised with the raw train statistics. The two modes
standardise their targets differently, so their own training losses are not
comparable.

**Baselines.** Naive last value, mean of the last 4 weeks, and a per-developer
linear trend over the window, all clipped.

**Metrics.** MAE, RMSE and sMAPE (0/0 counts as 0; plain MAPE is undefined
when the actual count is 0), per target and per horizon. Significance uses a
paired Wilcoxon signed-rank test on per-developer MAE.

**Deployment forecast.** The variant with the best validation score is refit
on all windows with targets up to week 16. Training runs for a fixed number of
**gradient steps**: the median best epoch from validation × steps per
validation-run epoch. A fixed epoch count would mean many more updates,
because the refit has more windows per epoch. The refit forecasts weeks 17-18
from the last L weeks. The band is the min-max spread across 5 seeds. It is a
*seed spread, not a calibrated confidence interval*.

### Results (simulated data, seed 42)

Test set: 180 windows, 338 valid `vuln_count` targets and 298 valid `fix_rate`
targets. The variant rows give mean ± std over 5 seeds.

| Model | Validation score | vuln_count MAE | vuln_count sMAPE | fix_rate MAE | fix_rate sMAPE |
|---|---|---|---|---|---|
| GRU raw (h=32, L=4, d=0.1), **deployed** | **0.456** | 3.763 ± 0.030 | 77.1 ± 0.3 | 0.250 ± 0.001 | 51.3 ± 0.2 |
| LSTM raw (h=64, L=4, d=0.1) | 0.458 | 3.734 ± 0.020 | 76.5 ± 0.3 | 0.252 ± 0.001 | 51.6 ± 0.2 |
| GRU residual, post-hoc (h=32, L=3, d=0.3) | 0.466 | 3.779 ± 0.022 | 77.1 ± 0.5 | 0.250 ± 0.003 | 51.7 ± 0.4 |
| LSTM residual, post-hoc (h=16, L=3, d=0.3) | 0.465 | 3.749 ± 0.019 | 76.7 ± 0.3 | 0.257 ± 0.003 | 52.6 ± 0.4 |
| Naive last value | | 4.533 | 94.2 | 0.289 | 64.0 |
| 4-week mean | | 3.749 | 78.1 | 0.253 | 54.7 |
| Linear trend | | 5.336 | 111.3 | 0.323 | 72.6 |

Raw beat residual on validation, so the raw GRU stays deployed. It is refit
for 24 gradient steps.

- Every variant beats the naive and linear baselines (Wilcoxon on
  per-developer MAE: p ≤ 0.031 against naive, p ≤ 0.008 against linear). The
  one exception is the residual LSTM vs naive on `fix_rate` (p = 0.063).
- **No variant, raw or residual, beats the 4-week mean** (all Wilcoxon
  p ≥ 0.099). On this data, most of the predictable signal is the developer's
  recent level.
- The residual variants trade errors between archetypes. They improve on
  worsening developers (fix_rate MAE 0.213 vs 0.252 for the GRU) and get worse
  on improving ones (vuln_count 1.96 vs 1.74). The net effect is no gain.

`archetypeMae` in `forecast_metrics.json` is labelled *diagnostic, simulated
data only*. It needs the simulator's ground truth, which real data will not
have.

## Risk classification (Phase 3)

```bash
.venv/Scripts/python -m src.risk --fit-thresholds   # once: prints train-percentile thresholds to freeze in config.yaml
.venv/Scripts/python -m src.risk --quick            # smoke test: one grid point, 2 CV repeats, 200 resamples (~30 s)
.venv/Scripts/python -m src.risk                    # full: 24-point grid, 5 CV repeats, 2000 resamples (~1.5 min on CPU)
.venv/Scripts/python -m pytest tests/test_risk.py
```

Outputs (not committed):
- `outputs/risk.json`: per developer, the band, class probabilities, measured drivers and score history.
- `outputs/risk_metrics.json`: class balance, selection, the repeated-CV headline, significance tests, round-1 results and global importance.
- `outputs/risk_tuning.csv`: every grid configuration with its CV score.

The output is a **research risk profile based on measured behaviour**. It is
not a judgment of the person.

**Rows.** One row per developer per origin week t = 6..12. Features use weeks
≤ t only: each developer's weekly arrays are cut at week t before any feature
is computed. The label uses weeks t+1..t+4 only, which is the developer's
*future* behaviour.

**Label: future risk score** (pooled over weeks t+1..t+4):
`0.4 × severity-weighted ignore rate + 0.3 × (1 − fix rate) + 0.2 × normalised repeat rate + 0.1 × normalised log response time`.
- The severity-weighted ignore rate is ignored severity weight / total severity
  weight (LOW=1, MEDIUM=2, HIGH=3).
- The repeat rate is `repeat_count / vuln_count`.
- The label is a fixed measuring instrument. Its min-max constants and its
  band thresholds (medium ≥ 0.3215, high ≥ 0.4660, the 40th and 80th
  percentiles) were set once in round 1 from the 48 round-1 training
  developers.
- No rows were dropped. Class balance over all 420 rows: 164 LOW / 174 MEDIUM /
  82 HIGH.

**Features.**
- *Original set (30, round 1).* For fix rate, ignore rate, false-positive
  rate, repeat rate, severity-weighted load, high-severity share, log response
  time and weekly findings: the last-4-week value, the all-history value and
  the 4-week slope. Also the per-type shares, active-week ratio and weeks since
  first activity.
- *Extended set (35, round 2, **added post-hoc** after round-1 results were
  seen).* The original set plus the severity-weighted ignore rate (last 4,
  all, slope) and the past risk score. The past score uses the label's exact
  formula over weeks t-3..t and over all history. Its min-max constants come
  from the training developers of each fold only.
- No feature uses the archetype or any week after t.

**Selection.** The configuration is chosen by `GroupKFold(5)` CV on the 48
round-1 training developers only. The grid is max_depth {2, 3, 4} ×
n_estimators {100, 300} × learning_rate {0.05, 0.1} × min_child_weight {1, 5}
for XGBoost, and C {0.1, 1, 10} for logistic regression. XGBoost uses
balanced class weights, with early stopping on a 20% inner developer split.
Selected: XGBoost depth 2, lr 0.1, mcw 1 (early stopping keeps ~17 trees);
logistic regression C = 0.1.

**Headline evaluation.** Repeated `GroupKFold` over all 60 developers (5
repeats × 5 folds, developers shuffled differently each repeat). All rows of a
developer stay in one fold. For each repeat, macro F1 is computed on the
pooled out-of-fold predictions; the table shows mean ± std over repeats. The
95% CI comes from a developer-level bootstrap (2000 resamples; a resampled
developer brings all their rows). The main significance test is a **paired
developer-level bootstrap** of the macro-F1 difference. McNemar is reported
only as a secondary check, because rows from one developer are not
independent.

**Baselines.**
- majority class;
- the proposal's static fix-rate rule on all-history fix rate (< 0.5 HIGH,
  < 0.75 MEDIUM, else LOW);
- **persistence**: the label formula applied to weeks t-3..t, banded with the
  frozen thresholds;
- multinomial logistic regression on the same features.

**Per-developer reasons.** The reasons shown to users ("drivers") are the
developer's **own measured metrics** for the last 4 weeks, compared with the
study median. For example: "Fix rate 27% in weeks 13-16 (below the study
median of 57%)". For MEDIUM/HIGH, they are the metrics furthest on the worse
side of the median, scaled by the IQR. For LOW, they are the metrics furthest
on the better side. They are not model explanations. SHAP is used only for the
global importance chart. Correlated features (for example the last-4 and
all-history versions of one metric) share credit, so read it as which feature
groups matter, not as causes.

**Deployment.** The model is refit on all 60 developers with the early-stopped
tree count. Every developer is scored at week 16 for weeks 17-20.

### Results (simulated data, seed 42)

**Headline: repeated grouped CV (extended features, all 60 developers).**

| Model | Macro F1 mean ± std | 95% CI | Accuracy | HIGH recall |
|---|---|---|---|---|
| XGBoost | **0.521 ± 0.026** | [0.463, 0.567] | 0.521 | 0.661 |
| Persistence | 0.508 ± 0.000 | [0.443, 0.559] | 0.517 | 0.415 |
| Logistic regression | 0.468 ± 0.022 | [0.408, 0.526] | 0.465 | 0.563 |
| Fix-rate rule | 0.323 ± 0.000 | [0.250, 0.397] | 0.383 | 0.622 |
| Majority class | 0.215 ± 0.018 | [0.187, 0.240] | 0.355 | 0.000 |

| XGBoost vs | Paired bootstrap macro-F1 diff, 95% CI | P(XGBoost better) | McNemar p (repeat 1, secondary) |
|---|---|---|---|
| Persistence | **+0.013 [−0.052, +0.074] → tie** | 0.66 | 0.26 |
| Logistic regression | +0.052 [+0.007, +0.098] → beats | 0.99 | 0.005 |
| Fix-rate rule | +0.197 [+0.127, +0.257] → beats | 1.00 | < 0.001 |
| Majority class | +0.304 [+0.233, +0.370] → beats | 1.00 | < 0.001 |

**XGBoost still does not beat persistence.** The difference is +0.013, with a
CI that clearly includes 0, so I report it as a tie and did no further tuning.
XGBoost catches more HIGH rows (recall 0.66 vs 0.42) but makes more errors
elsewhere. The most important feature (mean |SHAP|) is `past_score_last4`,
which is the persistence score itself. Recent behaviour is the strongest
predictor.

**Round 1 (already seen): the 12 held-out developers.**

| Model | Macro F1, original features | Macro F1, extended features |
|---|---|---|
| Persistence | **0.550** | **0.550** |
| XGBoost | 0.369 | 0.414 |
| Logistic regression | 0.378 | 0.376 |
| Fix-rate rule | 0.215 | 0.215 |
| Majority class | 0.211 | 0.211 |

These developers have been looked at twice, so the numbers are a record and
not the headline. On these 12 developers, persistence won both times.

## Correlation (Phase 4)

`python -m src.correlation` writes `outputs/correlations.json`.

- **Variables:** fix rate, ignore rate, repeat rate, average response time,
  severity-weighted load, findings per week, false-positive rate.
- **Main analysis: developer level.** Each developer's mean over their active
  weeks, so n = 60. Using developer-weeks directly would count each developer
  up to 16 times (pseudo-replication) and give p-values that are far too small.
- **Secondary analysis: active developer-weeks,** with a repeated-measures
  warning.
- **Statistics:**
  - Pearson r with a Fisher z CI.
  - Spearman rho with a Fisher z CI, using se = sqrt(1.06 / (n − 3)).
  - Benjamini-Hochberg correction across the 21 pairs, within each level and
    method. Raw and adjusted p-values are both stored.
  - Heatmap-ready matrices: r, adjusted p and a significance flag.

**Developer-level results (simulated).** 10 of 21 pairs are significant after
BH, and both methods agree on all 10:

| Pair | Pearson r | Spearman rho |
|---|---|---|
| Severity-weighted load ~ findings per week | +1.00 | +1.00 |
| Fix rate ~ ignore rate | −0.80 | −0.75 |
| Fix rate ~ repeat rate | −0.49 | −0.53 |
| Ignore rate ~ repeat rate | +0.48 | +0.49 |
| Fix rate ~ findings per week | −0.47 | −0.49 |
| Fix rate ~ severity-weighted load | −0.46 | −0.48 |
| Repeat rate ~ findings per week | +0.46 | +0.39 |
| Repeat rate ~ severity-weighted load | +0.46 | +0.39 |
| Ignore rate ~ findings per week | +0.32 | +0.36 |
| Ignore rate ~ severity-weighted load | +0.31 | +0.35 |

Response time and false-positive rate are not significantly related to
anything. Some pairs are related **by construction**, not by behaviour:
- Fix and ignore rates are shares of the same findings.
- Severity-weighted load is a weighted count of findings, so it is almost a
  copy of findings per week.

At developer-week level, 15 of 21 pairs look significant. That shows how
pseudo-replication inflates significance.

## Recommendations (Phase 4)

`python -m src.recommend` writes `outputs/recommendations.json`.

**How rules work.**
- The rules live in `config.yaml` (`recommend.rules`).
- Each rule has an id, a priority (1 = most urgent), a list of conditions
  that must all hold, and a plain-language template.
- Conditions are structured `{field, op, value}` data, never evaluated as
  code. A condition on a missing value is false.

**Inputs per developer:**
- the risk band;
- the forecast direction for findings and for fix rate: up, down or flat. The
  weeks 17-18 forecast is compared with the developer's weeks 13-16 mean;
  findings count as flat within ±max(15%, 0.5), fix rate within ±5 points;
- the developer's own last-4-week ignore rate, fix rate, repeat rate and
  response time;
- the dominant vulnerability type.

**Output per developer:** a priority, up to 3 recommendations and every rule
id that fired. If no rule fires, the fallback rule R0 is used.

| Rule | Priority | Fires when |
|---|---|---|
| R1 | 1 | band HIGH and ignore rate ≥ 30% |
| R2 | 1 | band MEDIUM/HIGH and fix rate < 50% |
| R3 | 2 | repeat rate ≥ 50% |
| R4 | 2 | findings forecast to rise |
| R5 | 2 | fix rate forecast to fall and band MEDIUM/HIGH |
| R6 | 3 | average response time > 15 minutes |
| R7 | 3 | band MEDIUM/HIGH and a dominant type exists (type-specific tip) |
| R8 | 3 | band LOW and findings not forecast to rise |

## Export and the contract file (Phase 4)

`python -m src.export` writes `outputs/analytics.json`, the single file the
dashboard reads, and validates it against `analytics.schema.json`. `tests/test_export.py`
checks both the full file and the committed sample.

**Sections:**
- `meta`: `dataSource: "simulated"`, a disclaimer, the seed and when the file
  was generated.
- `overview`: KPIs.
- `trends`: team weekly trends and per-developer trends.
- `forecast`: history, test-period predicted vs actual, weeks 17-18 forecasts
  and the seed band.
- `forecastEvaluation`: all baselines, Wilcoxon tests, the residual variant
  labelled post-hoc, and archetype MAE labelled diagnostic.
- `risk`: band, probabilities, measured drivers and score history.
- `riskEvaluation`: the headline repeated CV, significance tests, round 1 and
  global importance with its caveat.
- `correlations`: both levels, with heatmap matrices.
- `recommendations`.
- `keyFindings`: plain statements generated from the significance verdicts.

`frontend/public/sample-analytics.json` has the same shape, cut to 20
developers (about 225 KB). Its team-level and evaluation sections still cover
all developers. It is committed so the frontend can run without the pipeline.

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
- **Small sample.** There are 60 developers. Every CI over developers is wide,
  and the round-1 held-out set had only 12.
- **Post-hoc changes are labelled.** Two changes were made after earlier test
  results were seen: the residual forecast mode and the extended classifier
  features. Both were selected on validation or training CV only, but they
  are still post-hoc.
- **Label constants.** The risk label's min-max constants and thresholds were
  set from the 48 round-1 training developers. In the repeated CV, some of
  those developers fall in test folds. These are 6 fixed scalars that define
  the label, not learned model parameters. Model features are always
  normalised per fold.
- **Correlation is not causation.** Several significant pairs exist by
  construction (shares of the same findings; load is a weighted count).
  Associations between developers do not show what drives an individual.
- **Recommendation thresholds are design choices** (for example ignore rate
  ≥ 30%), not fitted values. On real data, they should be reviewed with the
  team.
