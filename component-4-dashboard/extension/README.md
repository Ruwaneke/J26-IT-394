# Sentinel Analytics (Component 4)

A VS Code extension that opens the Component 4 research dashboard of the
Sentinel project in a webview. It shows trends, forecasts, research risk
profiles, correlations, recommendations and model evaluation, all read from
`analytics.json` written by the Component 4 pipeline.

> **Simulated data.** Until Component 2 produces real events, all content comes
> from simulated data generated from stated assumptions. A banner on every tab
> says so (`meta.dataSource`).

## Use

- Run **Sentinel Analytics: Open Dashboard** from the Command Palette. You can
  also click **Sentinel Analytics** in the status bar, or the graph icon in the
  editor title when an `analytics.json` file is open.
- **Reload data** in the dashboard re-reads the file.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `sentinelAnalytics.dataPath` | `""` | Path to `analytics.json`, either absolute or relative to the first workspace folder (for example `component-4-dashboard/ml/outputs/analytics.json`). If it is empty, or the file cannot be read, the bundled 20-developer sample is used and the dashboard shows a warning. |
| `sentinelAnalytics.showStatusBar` | `true` | Show the status bar entry. |

## Privacy and security

- The extension makes no network calls.
- The webview runs under a strict Content Security Policy:
  - `default-src 'none'`;
  - scripts only with a per-load nonce;
  - styles and images only from the extension's `media` folder.
- Data reaches the webview only through `postMessage`.

The risk view is a research risk profile based on measured behaviour. It is
not a judgment of the person.
