# Component 4: Analytics and Dashboard

Component 4 of the Sentinel research system turns developer security events
into research analytics. It covers weekly trends, behaviour forecasts,
research risk profiles, correlations and rule-based recommendations. The
results are shown in a dashboard that opens inside VS Code.

> **All current results come from SIMULATED data** generated from stated
> assumptions (see `ml/README.md`). They are not findings about real developers.
> When Component 2 produces real events, they replace the simulated ones through
> the same schema.

| Folder | What it is |
|---|---|
| `ml/` | Python pipeline: simulate → features → trends → forecast → risk → correlation → recommend → export. It writes one contract file, `ml/outputs/analytics.json`, validated against `ml/analytics.schema.json`. See `ml/README.md`. |
| `frontend/` | Vite + React + TypeScript + Recharts dashboard. It builds into `extension/media/` and also runs standalone in a browser. |
| `extension/` | VS Code extension (TypeScript, esbuild). It opens the dashboard in a webview and sends it `analytics.json`. |

## Requirements

Node.js 20 or later (tested with Node 24) and VS Code 1.90 or later. For
the pipeline, you also need Python 3.12 (see `ml/README.md`).

## 1. Install

```bash
cd component-4-dashboard/frontend && npm install
cd ../extension && npm install
```

## 2. Build

```bash
cd component-4-dashboard/extension
npm run build      # frontend (typecheck + vite build into extension/media), then extension (typecheck + esbuild into out/)
npm run watch      # rebuild both on change (vite --watch and esbuild --watch side by side)
```

## 3. Run in VS Code (Extension Development Host)

1. Open the folder `component-4-dashboard/extension` in VS Code (**File → Open Folder**).
2. Press **F5**. The "Run Sentinel Analytics" launch config builds first, then
   opens a second VS Code window with the extension loaded.
3. In that window, open the Command Palette (Ctrl+Shift+P) and run
   **Sentinel Analytics: Open Dashboard**. You can also click
   **Sentinel Analytics** in the status bar.
4. The dashboard shows the bundled 20-developer sample. To show the full
   pipeline output, set **`sentinelAnalytics.dataPath`** in Settings to the
   path of `analytics.json`. Use an absolute path, or one relative to the first
   workspace folder, for example
   `component-4-dashboard/ml/outputs/analytics.json`. Then click
   **Reload data**. If the file cannot be read, the sample is shown with a
   warning.

To create the full file first:

```bash
cd component-4-dashboard/ml
.venv/Scripts/python -m src.pipeline      # about 5 minutes; --quick for a smoke test
```

## 4. Package and install the .vsix

```bash
cd component-4-dashboard/extension
npm run package        # build + vsce package (nothing is published)
code --install-extension sentinel-analytics-0.1.0.vsix
```

Or, in VS Code: Extensions view → `...` → **Install from VSIX...**. To remove
it: `code --uninstall-extension sentinel-research.sentinel-analytics`.

## 5. Run the dashboard in a browser (no VS Code)

```bash
cd component-4-dashboard/frontend
npm run dev            # http://localhost:5173 loads public/sample-analytics.json
```

To view the full file in the browser, copy `ml/outputs/analytics.json` to
`frontend/public/analytics.json` (gitignored) and open
`http://localhost:5173/?data=analytics.json`. As a fallback, open the same URL
in VS Code's **Simple Browser**.

## Tests and type checks

```bash
cd component-4-dashboard/frontend
npm test               # smoke test: sample passes analytics.schema.json and loads through the app's parser, types and selectors
npm run typecheck      # includes a compile-time check that the app types fit the schema-generated types
npm run check:types    # fails if src/types/schema.generated.ts is out of date with ml/analytics.schema.json
npm run gen:types      # regenerate it after a schema change
```

The Python tests run with `.venv/Scripts/python -m pytest` in `ml/`.

## Dashboard tabs

Every tab shows a **Simulated data** banner taken from `meta.dataSource`.

| Tab | Shows |
|---|---|
| Overview | KPI cards (developers, vulnerabilities, fix rate, ignore rate, average response time, findings per session), the key summary finding, the team weekly trend (findings, 4-week average, fix rate), risk band counts and trend directions |
| Trends | Weekly vulnerability introduction rate per session for a chosen developer against the team rate, with the trend label (improving / stable / worsening) and slope |
| Forecast | One developer's history, test-period predictions (deployed GRU and the 4-week mean, 1 or 2 weeks ahead) against actuals, and the weeks 17-18 forecast with a band labelled *seed spread, not a calibrated confidence interval*. Also a table of the GRU against the baselines (MAE and Wilcoxon p) |
| Risk | Table headed *research risk profile based on measured behaviour*: band, class probabilities and reasons from the developer's own measured metrics. It can be sorted by any column and filtered by band |
| Correlations | Heatmap of r and BH-adjusted p, with significant cells marked. Switches between developer level (main) and developer-week level (secondary), and between Pearson and Spearman |
| Recommendations | Each developer's priority, rule ids that fired and up to 3 recommendations, filterable by priority |
| Model evaluation | Key findings, forecasting metrics and Wilcoxon verdicts, the classifier headline (repeated CV) with bootstrap verdicts, round-1 results (already seen) and global SHAP importance with its caveat |

## Security notes

- The webview uses a strict CSP: `default-src 'none'`, scripts only with a
  per-load nonce, and styles and images only from the extension's `media`
  folder.
- Assets load through `asWebviewUri` and `localResourceRoots` is limited to
  `media/`.
- The extension makes no network calls, and the dashboard uses no external
  fonts or CDNs.
- In browser mode, `?data=` only accepts same-origin paths.
