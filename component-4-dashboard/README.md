# Component 4: Analytics and Dashboard

> **Simulated data.** Components 1-3 do not produce data yet, so every result
> here comes from a seeded simulator built on stated assumptions (see
> `ml/README.md`). The numbers describe those assumptions, not real developers.
> When real events arrive, they replace the simulated ones through the same
> event schema.

## What Component 4 is

Sentinel is a four-component research system. It asks whether adaptive,
behaviour-aware security feedback improves developers' secure coding over
time. Component 4 is the analytics layer: it turns security events into weekly
trends, forecasts, research risk profiles, correlations, recommendations, a
research summary report, and a dashboard that opens inside VS Code.

```
 Component 1  Sentinel VS Code extension ── detects vulnerabilities as you type
      │ security events
      ▼
 Component 2  Behaviour tracker ─────────── stores events and developer responses
      │ events (schema in ml/README.md)            ▲
      ▼                                            │ feedback
 Component 4  Analytics (this folder)       Component 3  Feedback engine
   ml/          Python pipeline ──► outputs/analytics.json (one contract file)
   frontend/    React dashboard  ◄─┘
   extension/   VS Code extension that shows the dashboard in a webview
```

Until Component 2 is ready, `ml/src/simulate.py` stands in for it.

## Run the pipeline

Setup (Windows, Python 3.12; on macOS/Linux use `python3.12` and `.venv/bin/python`):

```bash
cd component-4-dashboard/ml
py -3.12 -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
```

Run:

```bash
.venv/Scripts/python -m src.pipeline           # full run, about 5 minutes on CPU
.venv/Scripts/python -m src.pipeline --quick   # smoke test, under 1 minute
.venv/Scripts/python -m pytest                 # Python tests
```

The steps run in this order: simulate → features → trends → forecast → risk →
correlation → recommend → export → report. Each step can also be run alone with
`python -m src.<step>`.

Outputs go to `ml/outputs/`. They are generated files and are not committed.

| File | Contents |
|---|---|
| `analytics.json` | The single contract file the dashboard reads (schema: `ml/analytics.schema.json`) |
| `research_summary.md`, `research_summary.html` | Research summary report |
| `figures/*.png` | Report figures (200 dpi, readable in black and white) |
| `forecast_metrics.json`, `risk_metrics.json`, `correlations.json`, `recommendations.json`, ... | Intermediate results |

The export step also refreshes `frontend/public/sample-analytics.json`. This is
a 20-developer sample of the same file, committed so the dashboard runs without
the pipeline.

## Build and run the dashboard extension

Requires Node.js 20 or later (tested with 24) and VS Code 1.90 or later.

```bash
cd component-4-dashboard/frontend && npm install
cd ../extension && npm install
npm run build          # builds the React webview into extension/media, then bundles the extension into out/
```

1. Open the folder `component-4-dashboard/extension` in VS Code and press
   **F5**. This builds the extension and opens an Extension Development Host
   window.
2. In that window, run **Sentinel Analytics: Open Dashboard** from the Command
   Palette (Ctrl+Shift+P), or click **Sentinel Analytics** in the status bar.
3. The bundled sample loads first. To show a fresh full run, set
   **`sentinelAnalytics.dataPath`** in Settings to the path of
   `analytics.json`, then click **Reload data**. The path can be absolute or
   relative to the first workspace folder, e.g.
   `component-4-dashboard/ml/outputs/analytics.json`. If the file cannot be
   read, the sample is shown with a warning.

To package and install the extension:

```bash
cd component-4-dashboard/extension
npm run package                                   # build + vsce package; nothing is published
code --install-extension sentinel-analytics-0.1.0.vsix
```

Other useful commands:
- **Browser preview:** `npm run dev` in `frontend/` serves the sample at
  http://localhost:5173. To view the full file, copy `ml/outputs/analytics.json`
  to `frontend/public/analytics.json` (gitignored) and open `?data=analytics.json`.
- **Frontend checks:** `npm test` and `npm run typecheck`. They validate the
  sample against the schema and check the app types against types generated
  from it.

**Tabs:** Overview, Trends, Forecast, Risk, Correlations, Recommendations and
Model evaluation. Every tab shows a "Simulated data" banner.

**Security:**
- The webview uses a strict CSP: `default-src 'none'` and nonce-only scripts.
- Assets load only from the extension's `media/` folder.
- There are no network calls and no external fonts or CDNs.

## The analytics.json contract (short)

`ml/analytics.schema.json` (JSON Schema 2020-12) is the source of truth. Both
the Python tests and the frontend tests validate against it.

| Section | Contents |
|---|---|
| `meta` | `dataSource` (`"simulated"` or `"component2"`), disclaimer, seed, number of developers and weeks, generation time |
| `overview` | KPIs: findings, sessions, fix/ignore/false-positive rates, response time, risk-band and priority counts |
| `trends` | Team weekly series; per-developer weekly series with trend direction and slope |
| `forecast`, `forecastEvaluation` | Per-developer history, test predictions vs actuals, weeks 17-18 forecast with seed-spread band; metrics, Wilcoxon tests, selected variants (residual marked post-hoc) |
| `risk`, `riskEvaluation` | Band, probabilities, measured-behaviour drivers, score history; repeated-CV headline, bootstrap verdicts, round-1 record, global SHAP importance |
| `correlations` | Developer level (main) and developer-week level (secondary): pairs with r, CI, raw and BH-adjusted p, plus heatmap matrices |
| `recommendations` | Per developer: priority, up to 3 texts, rule ids that fired |
| `keyFindings` | Plain statements generated from the significance verdicts |

## Results summary (simulated data, seed 42)

| Question | Result |
|---|---|
| Forecasting (test weeks 13-16) | The deployed GRU (MAE 3.76 findings/week, 0.250 fix rate) **beats** the naive last value and the linear trend, but **ties** the 4-week mean (Wilcoxon p = 0.39 and 0.92). The residual variants (post-hoc) also tie the 4-week mean. |
| Risk classification (repeated grouped CV, 60 developers) | XGBoost macro F1 0.521 [0.463, 0.567]. It **beats** logistic regression, the static fix-rate rule and the majority class, but **ties** persistence (difference +0.013, 95% CI [−0.052, +0.074]). The extra features are post-hoc. |
| Overall | **Recent behaviour is the strongest predictor** on this data. Neither model is reliably better than repeating the last 4 weeks, and the classifier's top feature is the past-4-week risk score. |
| Correlations (developer level) | 10 of 21 pairs are significant after Benjamini-Hochberg correction. Two of them are partly true by construction (fix vs ignore rate; load vs findings). |

Full tables are in `ml/outputs/research_summary.md` and in the dashboard's
Model evaluation tab.

## Limitations

- **Simulated data:** archetypes and linear trajectories are assumptions, so
  the models partly recover the simulator's own rules.
- **Small sample:** 60 developers and 16 weeks give wide confidence intervals
  and few training windows for a neural model.
- **Post-hoc variants:** the residual forecasting mode and the extra
  classifier features were added after the first results were seen.
- **Designed label:** the risk label is a designed formula with frozen
  thresholds. Recommendation thresholds are design choices, not fitted values.
- **Band meaning:** the forecast band is a seed spread, not a calibrated
  confidence interval.
- **Correlation is not causation:** some pairs are related by construction.

## Status

The dashboard currently runs as a **separate VS Code extension**
(`component-4-dashboard/extension`). Integration into the Sentinel extension
(Component 1) is planned. Real data will come from Sentinel's stored
vulnerability records and Component 2 through an ingest adapter that maps them
onto the Component 4 event schema.
