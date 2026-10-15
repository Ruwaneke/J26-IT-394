import * as vscode from "vscode";
import * as path from "node:path";
import { randomBytes } from "node:crypto";

// Opens the Component 4 dashboard (React app built into ./media) in a webview.
// Data flow: the webview posts "ready" or "reload", the extension reads
// analytics.json (setting sentinelAnalytics.dataPath, else the bundled sample)
// and posts it back. No network access is used or allowed.

const VIEW_TYPE = "sentinelAnalytics.dashboard";
const COMMAND = "sentinelAnalytics.openDashboard";
const SAMPLE = "sample-analytics.json";

type WebviewMessage = { type: "ready" } | { type: "reload" };
type HostMessage =
  | { type: "data"; payload: unknown; source: string; warning?: string }
  | { type: "error"; message: string };

let panel: vscode.WebviewPanel | undefined;

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(vscode.commands.registerCommand(COMMAND, () => openDashboard(context)));

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.text = "$(graph) Sentinel Analytics";
  status.tooltip = "Open the Sentinel Analytics dashboard";
  status.command = COMMAND;
  const updateStatus = () => {
    if (vscode.workspace.getConfiguration("sentinelAnalytics").get<boolean>("showStatusBar", true)) status.show();
    else status.hide();
  };
  updateStatus();
  context.subscriptions.push(status);

  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration("sentinelAnalytics.showStatusBar")) updateStatus();
    if (e.affectsConfiguration("sentinelAnalytics.dataPath") && panel) void sendData(context, panel);
  }));
}

export function deactivate(): void {
  panel = undefined;
}

function openDashboard(context: vscode.ExtensionContext): void {
  if (panel) {
    panel.reveal();
    return;
  }
  const media = vscode.Uri.joinPath(context.extensionUri, "media");
  panel = vscode.window.createWebviewPanel(VIEW_TYPE, "Sentinel Analytics", vscode.ViewColumn.Active, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [media],
  });
  panel.webview.html = renderHtml(panel.webview, media);
  panel.webview.onDidReceiveMessage((msg: WebviewMessage) => {
    if (msg?.type === "ready" || msg?.type === "reload") void sendData(context, panel!);
  }, undefined, context.subscriptions);
  panel.onDidDispose(() => { panel = undefined; }, undefined, context.subscriptions);
}

/** Resolve the configured path: absolute, or relative to the first workspace folder. */
function configuredUri(): vscode.Uri | undefined {
  const setting = vscode.workspace.getConfiguration("sentinelAnalytics").get<string>("dataPath", "").trim();
  if (!setting) return undefined;
  if (path.isAbsolute(setting)) return vscode.Uri.file(setting);
  const folder = vscode.workspace.workspaceFolders?.[0];
  return folder ? vscode.Uri.joinPath(folder.uri, setting) : vscode.Uri.file(path.resolve(setting));
}

async function readJson(uri: vscode.Uri): Promise<unknown> {
  const bytes = await vscode.workspace.fs.readFile(uri);
  return JSON.parse(new TextDecoder("utf-8").decode(bytes));
}

async function sendData(context: vscode.ExtensionContext, target: vscode.WebviewPanel): Promise<void> {
  const sample = vscode.Uri.joinPath(context.extensionUri, "media", SAMPLE);
  const configured = configuredUri();
  let message: HostMessage;
  try {
    if (configured) {
      try {
        message = { type: "data", payload: await readJson(configured), source: configured.fsPath };
      } catch (err) {
        message = {
          type: "data",
          payload: await readJson(sample),
          source: `${SAMPLE} (bundled sample)`,
          warning: `Could not read ${configured.fsPath} (${errorText(err)}). Showing the bundled sample instead. Check the sentinelAnalytics.dataPath setting or run the pipeline.`,
        };
      }
    } else {
      message = { type: "data", payload: await readJson(sample), source: `${SAMPLE} (bundled sample; set sentinelAnalytics.dataPath for the full file)` };
    }
  } catch (err) {
    message = { type: "error", message: `Could not read the bundled sample: ${errorText(err)}. Rebuild the extension with npm run build.` };
  }
  await target.webview.postMessage(message);
}

function errorText(err: unknown): string {
  if (err instanceof vscode.FileSystemError) return err.code === "FileNotFound" ? "file not found" : err.message;
  return err instanceof Error ? err.message : String(err);
}

/**
 * Strict CSP: no network (default-src 'none'), scripts only with this page's
 * nonce, styles and images only from the extension's media folder.
 */
function renderHtml(webview: vscode.Webview, media: vscode.Uri): string {
  const nonce = randomBytes(16).toString("base64");
  const script = webview.asWebviewUri(vscode.Uri.joinPath(media, "assets", "index.js"));
  const style = webview.asWebviewUri(vscode.Uri.joinPath(media, "assets", "style.css"));
  const csp = [
    "default-src 'none'",
    `img-src ${webview.cspSource} data:`,
    `style-src ${webview.cspSource}`,
    `font-src ${webview.cspSource}`,
    `script-src 'nonce-${nonce}'`,
  ].join("; ");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="${style}">
  <title>Sentinel Analytics</title>
</head>
<body>
  <div id="root"></div>
  <script type="module" nonce="${nonce}" src="${script}"></script>
</body>
</html>`;
}
