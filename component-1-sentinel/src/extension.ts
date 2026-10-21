/**
 * Sentinel — VS Code Extension Entry Point
 *
 * This file wires together all components:
 *   SecurityAnalyzer → DiagnosticManager → SecurityEventClient
 *
 * Lifecycle:
 *   activate() → registers all listeners and commands
 *   deactivate() → cleanup
 */

import * as path from 'path';
import * as vscode from 'vscode';
import { SecurityAnalyzer } from './analyzer/securityAnalyzer.js';
import { DiagnosticManager, SentinelHoverProvider } from './diagnostics/diagnosticManager.js';
import { SecurityEventClient } from './events/securityEventClient.js';
import { DeveloperAction, SecurityFinding } from './analyzer/types.js';
import { VULNERABILITY_METADATA } from './diagnostics/vulnerabilityMetadata.js';
import { generateContextualExplanation } from './diagnostics/contextualExplainer.js';
import { DeveloperRecordStore } from './data/developerRecordStore.js';
import { NeonDatabaseService } from './data/neonDatabaseService.js';
import { AuthManager } from './auth/authManager.js';
import { buildLoginHtml } from './webview/loginView.js';
import { buildLoadingHtml } from './webview/loadingView.js';
import { buildDeveloperDashboardHtml } from './webview/developerDashboard.js';
import { buildSupervisorDashboardHtml, setDeveloperStats } from './webview/supervisorDashboard.js';
import { buildAdminDashboardHtml } from './webview/adminDashboard.js';
import { AIEnhancedAnalyzer, AIEnhancedAnalyzerConfig } from './ai/aiEnhancedAnalyzer.js';
import { DeveloperLearningStore } from './ai/developerLearningStore.js';
import { ProjectStore, SessionFinding } from './data/projectStore.js';
import { SentinelApiServer, SentinelApiServerOptions } from './api/sentinelApiServer.js';
import { computeDeveloperInsights } from './analytics/developerInsights.js';
import { setThemePreference, setVsCodeThemeKind, ThemePreference } from './webview/theme.js';
import { DatabaseAdminService, isAdminTable, TABLES } from './data/databaseAdminService.js';
import { NotificationService, Principal, NotificationLevel } from './notifications/notificationService.js';
import { Shift } from './data/projectStore.js';

// ─── Module-level instances (kept alive for the extension lifetime) ─────────

let analyzer: SecurityAnalyzer;
let aiAnalyzer: AIEnhancedAnalyzer;
let learningStore: DeveloperLearningStore;
let projectStore: ProjectStore;

/** ID of the currently active ShiftSession (null = no shift in progress) */
let activeShiftSessionId: string | null = null;
let diagnosticManager: DiagnosticManager;
let eventClient: SecurityEventClient;
let recordStore: DeveloperRecordStore;
let authManager: AuthManager;
let outputChannel: vscode.OutputChannel;
let apiServer: SentinelApiServer | undefined;
let notifications: NotificationService | undefined;
let statusBar: vscode.StatusBarItem;
let apiServerError: string | null = null;
let debounceTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

// Per-file finding cache (used by code actions)
let findingsCache: Map<string, SecurityFinding[]> = new Map();

// Live dashboard panel — kept open and refreshed on every analysis
let dashboardPanel: vscode.WebviewPanel | undefined;

// Extension root URI — stored in activate() for resource loading
let extensionUri: vscode.Uri;

// Extension context — stored for authManager and DATA dir access
let extensionContext: vscode.ExtensionContext;

// ─── activate() ──────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  extensionUri = context.extensionUri; // store for webview resource loading
  extensionContext = context;           // store for auth + DATA dir access
  outputChannel = vscode.window.createOutputChannel('Sentinel Security');
  log('🛡 Sentinel activated.');

  analyzer = new SecurityAnalyzer();
  diagnosticManager = new DiagnosticManager();
  eventClient = new SecurityEventClient();

  // Initialise developer record store — persists findings to Neon PostgreSQL
  recordStore = new DeveloperRecordStore(context.extensionPath);

  // Initialise the Developer Learning Store — persists per-developer mistake learning data
  learningStore = new DeveloperLearningStore(context.extensionPath);
  log('🧠 Developer learning store initialised.');

  // Initialise the AI-Enhanced Analyzer — wraps base analyzer with learning filters + IFE enrichment
  aiAnalyzer = new AIEnhancedAnalyzer(analyzer, learningStore);
  log('🤖 AI-enhanced analyzer initialised.');

  // Initialise Project Store — Projects, Shifts, ShiftSessions
  projectStore = new ProjectStore(context.extensionPath);
  log('📁 Project store initialised.');

  // Initialise auth manager — role-based login system
  authManager = new AuthManager(context);
  log('🔐 Auth manager initialised.');

  // Initialise Neon PostgreSQL database service
  const neonDb = NeonDatabaseService.getInstance(context.extensionPath);
  neonDb.initialize().then(ok => {
    if (ok) {
      log('⚡ Connected to Neon PostgreSQL database.');
      // Re-analyze open documents now that DB is guaranteed online
      vscode.workspace.textDocuments.forEach(doc => {
        if (doc.uri.scheme === 'file') {
          void analyzeDocument(doc, false);
        }
      });
      void refreshDashboard();
    } else {
      log('⚠️ Neon PostgreSQL offline, using local storage mode.');
    }
  });

  // ── Light / dark theme for all webviews ──────────────────────────────────────
  syncThemeFromVsCode();
  context.subscriptions.push(
    vscode.window.onDidChangeActiveColorTheme(() => syncThemeFromVsCode()),
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('sentinel.theme')) {
        syncThemeFromVsCode();
        void refreshDashboard();
      }
    }),
  );

  // ── Component 2 data API (pull model) ────────────────────────────────────────
  startApiServer();
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('sentinel.api')) { void restartApiServer(); }
    })
  );

  // ── Silently restore GitHub session (no prompt shown) ────────────────────────
  // If the developer was previously signed in via GitHub, restore their
  // session automatically. Only runs if no session already exists in state.
  if (!authManager.isLoggedIn()) {
    authManager.refreshGitHubSession().then(session => {
      if (session) {
        log(`👋 Auto-restored GitHub session: ${session.githubUsername ?? session.username} (${session.role})`);
        refreshDashboard();
      }
    }).catch(() => {
      // Silent refresh failed — user will see login screen
    });
  }

  // ── Register commands ────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand('sentinel.showOutput', () => {
      outputChannel.show();
    }),

    vscode.commands.registerCommand('sentinel.analyzeDocument', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        analyzeDocument(editor.document, true);
      } else {
        vscode.window.showInformationMessage('Sentinel: No active document to analyze.');
      }
    }),

    vscode.commands.registerCommand('sentinel.scanWorkspace', () => {
      void scanEntireWorkspace();
    }),

    vscode.commands.registerCommand('sentinel.showDashboard', () => {
      showDashboard(context);
    }),

    vscode.commands.registerCommand('sentinel.explainFinding',
      (args: { findingId: string }) => {
        handleExplainAction(args.findingId);
      }
    ),

    vscode.commands.registerCommand('sentinel.applyFix',
      (args: { findingId: string }) => {
        handleFixAction(args.findingId);
      }
    ),

    vscode.commands.registerCommand('sentinel.ignoreFinding',
      (args: { findingId: string }) => {
        handleIgnoreAction(args.findingId);
      }
    ),
  );

  // ── Register hover provider ──────────────────────────────────────────────

  const hoverProvider = new SentinelHoverProvider(diagnosticManager, logoFileUri());
  context.subscriptions.push(
    vscode.languages.registerHoverProvider({ scheme: 'file' }, hoverProvider)
  );

  // ── Register code action provider ───────────────────────────────────────

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new SentinelCodeActionProvider(),
    )
  );

  // ── Document event listeners ─────────────────────────────────────────────

  // Analyze when a file is opened
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => {
      if (doc.uri.scheme === 'file') {
        analyzeDocument(doc, false);
      }
    })
  );

  // Analyze with debounce when code changes (Phase 9 in guide)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      if (event.document.uri.scheme !== 'file') {
        return;
      }

      const config = vscode.workspace.getConfiguration('sentinel');
      if (!config.get<boolean>('enabled', true)) {
        return;
      }

      const key = event.document.uri.toString();
      const delay = config.get<number>('debounceMs', 400);

      // Clear previous timer for this document
      const existing = debounceTimers.get(key);
      if (existing !== undefined) {
        clearTimeout(existing);
      }

      // Schedule analysis after debounce delay
      const timer = setTimeout(() => {
        debounceTimers.delete(key);
        analyzeDocument(event.document, false);
      }, delay);

      debounceTimers.set(key, timer);
    })
  );

  // Clear diagnostics when a file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {
      diagnosticManager.clearDiagnostics(doc);
      findingsCache.delete(doc.uri.toString());
    })
  );

  // On file save: immediate analysis (no debounce) + instant dashboard refresh
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (doc.uri.scheme !== 'file') {
        return;
      }
      // Cancel any pending debounce for this file — we'll run immediately
      const key = doc.uri.toString();
      const existing = debounceTimers.get(key);
      if (existing !== undefined) {
        clearTimeout(existing);
        debounceTimers.delete(key);
      }
      analyzeDocument(doc, false);
    })
  );

  // Analyze files already open when extension activates
  vscode.workspace.textDocuments.forEach(doc => {
    if (doc.uri.scheme === 'file') {
      analyzeDocument(doc, false);
    }
  });

  // Status bar item
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.text = '$(shield) Sentinel';
  statusBar.tooltip = 'Sentinel Security — Click to show dashboard';
  statusBar.command = 'sentinel.showDashboard';
  statusBar.show();
  context.subscriptions.push(statusBar);

  // ── System-wide notifications, background refresh & scheduled shift checks ──
  notifications = new NotificationService(context, currentPrincipal, section => {
    showDashboard(context);
    if (section) { setTimeout(() => void dashboardPanel?.webview.postMessage({ command: 'NAVIGATE', section }), 600); }
  }, log);
  notifications.onChange((_items, fresh) => {
    pushNotifications(fresh);
    updateStatusBar();
    // Shift / project changes made by someone else: reload the shared data and re-render.
    if (fresh.some(n => n.category === 'shift' || n.category === 'project')) {
      void projectStore.hydrate().then(() => refreshDashboard());
    }
  });
  notifications.start(30000);
  context.subscriptions.push(notifications);
  const backgroundTimer = setInterval(() => void backgroundTick(), 60000);
  context.subscriptions.push({ dispose: () => clearInterval(backgroundTimer) });
  setTimeout(() => void backgroundTick(), 8000);

  log(`Session: ${eventClient.getSessionId()}`);
  log(`Rules loaded: ${analyzer.getRules().map(r => r.ruleName).join(', ')}`);
  log('Developer records → Neon PostgreSQL');
}

// ─── deactivate() ─────────────────────────────────────────────────────────────

export function deactivate(): void {
  diagnosticManager.dispose();
  eventClient.dispose();
  void apiServer?.stop();
  notifications?.dispose();
  recordStore.dispose();
  outputChannel.dispose();
  void NeonDatabaseService.getInstance().close();
  // Clear all pending debounce timers
  debounceTimers.forEach(t => clearTimeout(t));
  debounceTimers.clear();
}

// ─── Core Analysis Flow ───────────────────────────────────────────────────────

async function analyzeDocument(
  document: vscode.TextDocument,
  forceNotify: boolean,
): Promise<void> {
  const config = vscode.workspace.getConfiguration('sentinel');
  if (!config.get<boolean>('enabled', true)) {
    return;
  }

  const text       = document.getText();
  const fileName   = document.uri.fsPath;
  const languageId = document.languageId;

  // Resolve developer ID (GitHub username → config → fallback)
  const developerId = await resolveDeveloperId();
  const sessionId   = eventClient.getSessionId();
  const ifeEnabled  = config.get<boolean>('enableAI', false);
  const ifeUrl      = config.get<string>('ifeUrl', 'http://localhost:4000');
  const minConfidence = config.get<number>('minConfidence', 0.70);

  const aiConfig: AIEnhancedAnalyzerConfig = {
    developerId,
    sessionId,
    ifeUrl,
    ifeEnabled,
    minConfidence,
  };

  // ── Step 1: Analyze + apply learning filters (synchronous) ──────────────
  const previousFindings = findingsCache.get(document.uri.toString()) ?? [];
  const findings = aiAnalyzer.analyze(text, fileName, languageId, aiConfig);
  const summary  = analyzer.summarize(findings);

  // ── Step 2: Show diagnostics immediately (don't wait for AI) ────────────
  diagnosticManager.updateDiagnostics(document, findings);
  findingsCache.set(document.uri.toString(), findings);

  // ── Step 2b: Real-time fix detection in memory (developer typed/fixed code) ──
  const resolvedInMemory = previousFindings.filter(
    prev => !findings.some(curr => curr.id === prev.id)
  );

  for (const resolved of resolvedInMemory) {
    log(`🛡️ [Real-Time Fix Detected] Developer resolved ${resolved.type} at line ${resolved.lineNumber} in ${path.basename(fileName)}`);
    aiAnalyzer.recordAction(resolved, 'FIXED', developerId);
    void eventClient.reportAction(resolved, DeveloperAction.FIXED);
    recordStore.unmarkSaved(resolved.id);
    vscode.window.setStatusBarMessage(
      `✅ Sentinel: Fixed ${resolved.type.replace(/_/g, ' ')} at line ${resolved.lineNumber}`,
      4000
    );
  }

  if (findings.length > 0 || forceNotify) {
    logFindings(document, findings);
  }

  // ── Step 3: Record DETECTED events in learning store + active shift session
  for (const finding of findings) {
    aiAnalyzer.recordDetection(finding, developerId);

    // Forward finding to the active shift session (if one is running)
    if (activeShiftSessionId) {
      const sf: SessionFinding = {
        id:          finding.id,
        type:        finding.type,
        severity:    finding.severity,
        confidence:  finding.confidence,
        fileName:    finding.fileName,
        lineNumber:  finding.lineNumber,
        codeSnippet: finding.codeSnippet,
        detectedAt:  finding.detectedAt,
        ruleId:      finding.detectedByRule ?? 'unknown',
      };
      projectStore.addFindingToSession(activeShiftSessionId, sf);
      if (finding.severity === 'CRITICAL') {
        const sess = projectStore.getAllSessions().find(x => x.id === activeShiftSessionId);
        if (sess) {
          void notifications?.criticalFinding(finding.id, finding.type, path.basename(finding.fileName), finding.lineNumber,
            sess.developerDisplayName, sess, projectStore.getProject(sess.projectId));
        }
      }
    }
  }

  // ── Step 4: Report to backend (behaviour tracker) ───────────────────────
  for (const finding of findings) {
    void eventClient.reportDetection(finding);
  }

  // ── Step 5: Persist developer vulnerability record to DATA/ and Neon DB ──
  const githubUser = authManager?.getSession()?.githubUsername ?? null;
  for (const finding of findings) {
    await recordStore.save(finding, sessionId, developerId, githubUser);
  }

  // ── Step 5b: Auto-detect fixed findings in this file via Neon DB ────────
  const activeFindingIds = findings.map(f => f.id);
  void NeonDatabaseService.getInstance().autoDetectFixedFindingsInFile(
    fileName,
    developerId,
    activeFindingIds
  ).then(fixedItems => {
    if (fixedItems && fixedItems.length > 0) {
      for (const item of fixedItems) {
        log(`[NeonDb] Real-time fix recorded for ${item.vulnerabilityType} (${item.findingId}) in ${path.basename(fileName)}`);
        recordStore.unmarkSaved(item.findingId);
        aiAnalyzer.recordAction({ id: item.findingId, type: item.vulnerabilityType as any } as any, 'FIXED', developerId);
      }
      void refreshDashboard();
    }
  });

  // ── Step 6: Show terminal alert for HIGH/CRITICAL findings ──────────────
  if (findings.some(f => f.severity === 'HIGH' || f.severity === 'CRITICAL')) {
    logSecurityAlert(findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL'));
  }

  refreshDashboard();

  // ── Step 7: Async AI enrichment via IFE (non-blocking) ──────────────────
  if (ifeEnabled && findings.length > 0) {
    aiAnalyzer.enrich(findings, aiConfig).then(enriched => {
      // Show escalation notification for the most severe AI-enriched finding
      const topEnriched = enriched.find(f => (f as any).escalationMessage);
      if (topEnriched && (topEnriched as any).escalationMessage) {
        const ef = topEnriched as any;
        const msgPrefix = ef.feedbackLevel === 'CRITICAL_PATTERN' ? '🚨' :
                          ef.feedbackLevel === 'PERSISTENT'       ? '⚠️' :
                          ef.feedbackLevel === 'REPEATED'         ? '🔁' : '💡';
        vscode.window.showWarningMessage(
          `${msgPrefix} Sentinel AI: ${ef.escalationMessage}`,
          'View Explanation'
        ).then(selection => {
          if (selection === 'View Explanation') {
            handleExplainAction(topEnriched.id);
          }
        });
      }

      // Update cache with enriched findings so hover provider can use AI text
      findingsCache.set(document.uri.toString(), enriched);
      log(`[AI] Enriched ${enriched.filter((f: any) => f.aiGenerated).length} findings with AI explanations.`);
    }).catch(err => {
      log(`[AI] Enrichment failed: ${err}`);
    });
  }
}

/**
 * Scans all supported source code files in the entire workspace using Sentinel's OWASP Top 10 rules,
 * generates AI explanations, records all findings into the Neon PostgreSQL database,
 * updates the Problems panel with diagnostic markers, and refreshes the dashboard.
 */
async function scanEntireWorkspace(): Promise<void> {
  const wsFolders = vscode.workspace.workspaceFolders;
  if (!wsFolders || wsFolders.length === 0) {
    vscode.window.showInformationMessage('Sentinel: No workspace folder open to scan.');
    return;
  }

  const developerId = await resolveDeveloperId();
  const githubUser = authManager?.getSession()?.githubUsername ?? null;
  const sessionId = eventClient.getSessionId();

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Sentinel: Scanning workspace & syncing vulnerabilities to Database...',
      cancellable: false,
    },
    async (progress) => {
      // Find all supported code and manifest files in workspace
      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,jsx,tsx,py,java,cs,php,rb,go,json}',
        '**/{node_modules,.git,out,dist,build,.vscode}/**'
      );

      let scannedCount = 0;
      let totalFindings = 0;

      for (const fileUri of files) {
        try {
          const doc = await vscode.workspace.openTextDocument(fileUri);
          const text = doc.getText();
          const fileName = doc.uri.fsPath;
          const languageId = doc.languageId;

          const findings = analyzer.analyze(text, fileName, languageId);
          if (findings.length > 0) {
            diagnosticManager.updateDiagnostics(doc, findings);
            findingsCache.set(doc.uri.toString(), findings);

            for (const finding of findings) {
              await recordStore.save(finding, sessionId, developerId, githubUser);
              totalFindings++;
            }
          }
          scannedCount++;
          progress.report({
            message: `Scanned ${scannedCount}/${files.length} files (${totalFindings} vulnerabilities found)`,
          });
        } catch (err: any) {
          console.error('[Sentinel] Error scanning file:', fileUri.fsPath, err.message);
        }
      }

      vscode.window.showInformationMessage(
        `✅ Sentinel: Scanned ${scannedCount} files. Identified ${totalFindings} vulnerabilities and saved them to Neon PostgreSQL database!`
      );
      void refreshDashboard();
    }
  );
}

// ─── Developer Action Handlers ────────────────────────────────────────────────

function handleExplainAction(findingId: string): void {
  const finding = findFindingById(findingId);
  if (!finding) {
    return;
  }

  const meta = VULNERABILITY_METADATA[finding.type];
  const panel = vscode.window.createWebviewPanel(
    'sentinel.explain',
    `Sentinel: ${finding.type}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false, localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'resources')] },
  );
  panel.iconPath = logoFileUri();

  panel.webview.html = buildExplainHtml(finding, meta, panel.webview.asWebviewUri(logoFileUri()).toString(), panel.webview.cspSource);
  void eventClient.reportAction(finding, DeveloperAction.EXPLANATION_VIEWED);
  log(`[Action] EXPLANATION_VIEWED — ${finding.type} at line ${finding.lineNumber}`);
}

function handleFixAction(findingId: string): void {
  const finding = findFindingById(findingId);
  if (!finding) {
    return;
  }

  const meta = VULNERABILITY_METADATA[finding.type];
  if (meta?.secureExample) {
    const panel = vscode.window.createWebviewPanel(
      'sentinel.fix',
      `Sentinel Fix: ${finding.type}`,
      vscode.ViewColumn.Beside,
      { enableScripts: false, localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'resources')] },
    );
    panel.iconPath = logoFileUri();
    panel.webview.html = buildFixHtml(finding, meta, panel.webview.asWebviewUri(logoFileUri()).toString(), panel.webview.cspSource);
  }

  void eventClient.reportAction(finding, DeveloperAction.SECURE_EXAMPLE_VIEWED);
  log(`[Action] SECURE_EXAMPLE_VIEWED — ${finding.type} at line ${finding.lineNumber}`);
}

function handleIgnoreAction(findingId: string): void {
  const finding = findFindingById(findingId);
  if (!finding) {
    return;
  }

  vscode.window.showInformationMessage(
    `Sentinel: Ignored ${finding.type} at line ${finding.lineNumber}. ` +
    `This finding will reappear if the code is not fixed.`
  );

  void eventClient.reportAction(finding, DeveloperAction.IGNORED);
  log(`[Action] IGNORED — ${finding.type} at line ${finding.lineNumber}`);

  // ── Learning feedback: developer dismissed this finding ─────────────────
  resolveDeveloperId().then(developerId => {
    aiAnalyzer.recordAction(finding, 'IGNORED', developerId);
    log(`[AI Learning] Recorded IGNORED for ${finding.type} (dev: ${developerId})`);
  });
}

function findFindingById(findingId: string): SecurityFinding | undefined {
  for (const findings of findingsCache.values()) {
    const found = findings.find(f => f.id === findingId);
    if (found) {
      return found;
    }
  }
  return undefined;
}

// ─── Administrator & database management messages ────────────────────────────

const dbAdmin = new DatabaseAdminService();

/** Native modal confirmation — cannot be spoofed or skipped by the webview. */
async function confirmDestructive(message: string, detail: string, action: string): Promise<boolean> {
  const choice = await vscode.window.showWarningMessage(message, { modal: true, detail }, action);
  return choice === action;
}

async function auditAdmin(actionType: string, details: Record<string, unknown>): Promise<void> {
  const s = authManager.getSession();
  await NeonDatabaseService.getInstance().logActivity({
    userId: s?.userId, username: s?.username, githubUsername: s?.githubUsername,
    actionType, details,
  });
  log(`[Admin] ${actionType} ${JSON.stringify(details)}`);
}

function postToDashboard(msg: Record<string, unknown>): void {
  void dashboardPanel?.webview.postMessage(msg);
}

async function handleAdminMessage(message: { command: string; [key: string]: any }): Promise<void> {
  // Server-side authorisation: the webview UI is not a security boundary.
  const session = authManager.getSession();
  if (session?.role !== 'administrator') {
    log(`[Admin] Rejected ${message.command}: caller is not an administrator.`);
    postToDashboard({ command: 'DB_RESULT', op: message.command, success: false, message: 'Administrator access required.' });
    return;
  }

  const op = message.command;
  const reply = (success: boolean, msg: string, data?: unknown) =>
    postToDashboard({ command: 'DB_RESULT', op, success, message: msg, data });

  try {
    switch (op) {
      // ── Users ──
      case 'ADMIN_ADD_USER': {
        const result = await authManager.addUser(
          String(message.username), String(message.password),
          message.role as 'developer' | 'supervisor' | 'administrator',
          String(message.displayName), String(message.email),
        );
        if (result.success) { await auditAdmin('ADMIN_USER_ADDED', { username: message.username, role: message.role }); }
        postToDashboard({ command: 'ADMIN_ADD_RESULT', ...result });
        return;
      }
      case 'ADMIN_REMOVE_USER': {
        if (message.userId === session.userId) {
          postToDashboard({ command: 'ADMIN_USER_RESULT', success: false, message: 'You cannot remove your own account.' });
          return;
        }
        if (!await confirmDestructive(`Remove user "${message.username}"?`,
          'The account is deleted. Their vulnerability records and activity history are kept.', 'Remove user')) { return; }
        const result = await authManager.removeUser(String(message.userId));
        if (result.success) { await auditAdmin('ADMIN_USER_REMOVED', { userId: message.userId, username: message.username }); }
        postToDashboard({ command: 'ADMIN_USER_RESULT', ...result });
        return;
      }
      case 'ADMIN_UPDATE_USER': {
        const role = ['developer', 'supervisor', 'administrator'].includes(message.role) ? message.role : undefined;
        if (message.userId === session.userId && role && role !== 'administrator') {
          postToDashboard({ command: 'ADMIN_USER_RESULT', success: false, message: 'You cannot remove your own administrator role.' });
          return;
        }
        const result = await NeonDatabaseService.getInstance().updateUser(String(message.userId), {
          role, displayName: String(message.displayName ?? ''), email: typeof message.email === 'string' ? message.email : undefined,
        });
        if (result.success) {
          await auditAdmin('ADMIN_USER_UPDATED', { userId: message.userId, role });
          if (role) {
            void notifications?.notify({
              level: 'info', category: 'system', title: 'Your Sentinel role changed',
              message: `An administrator set your role to ${role}. Sign out and back in to see the new dashboard.`,
              recipientIds: [String(message.userId)], recipientRoles: [], createdBy: session.displayName,
            });
          }
        }
        postToDashboard({ command: 'ADMIN_USER_RESULT', ...result });
        return;
      }
      case 'ADMIN_OPEN_SETTINGS':
        await vscode.commands.executeCommand('workbench.action.openSettings', '@ext:sentinel-research.sentinel');
        return;
      case 'ADMIN_SHOW_OUTPUT':
        outputChannel.show();
        return;
      // ── Database: read ──
      case 'DB_OVERVIEW':
        return reply(true, '', await dbAdmin.getOverview());
      case 'DB_PING': {
        const p = await NeonDatabaseService.getInstance().ping();
        return reply(p.ok, p.ok ? `Connection OK — ${p.ms} ms round-trip.` : `Connection failed: ${p.error}`);
      }
      case 'DB_BROWSE': {
        if (!isAdminTable(message.table)) { return reply(false, 'Unknown table.'); }
        const status = typeof message.status === 'string' && message.status ? message.status : undefined;
        return reply(true, '', await dbAdmin.browse(message.table, {
          page: Number(message.page) || 1,
          search: typeof message.search === 'string' ? message.search : '',
          filterColumn: status ? 'status' : undefined,
          filterValue: status,
        }));
      }

      // ── Database: row edits ──
      case 'DB_SET_STATUS': {
        const n = await dbAdmin.setRecordStatus(String(message.recordId), String(message.status));
        await auditAdmin('ADMIN_DB_STATUS_CHANGED', { recordId: message.recordId, status: message.status });
        return reply(n > 0, n > 0 ? `Record marked ${message.status}.` : 'Record not found.');
      }
      case 'DB_DELETE_ROW': {
        if (!isAdminTable(message.table)) { return reply(false, 'Unknown table.'); }
        if (!await confirmDestructive(`Delete this row from ${TABLES[message.table].label}?`,
          JSON.stringify(message.key), 'Delete row')) { return; }
        const n = await dbAdmin.deleteRow(message.table, message.key ?? {});
        await auditAdmin('ADMIN_DB_ROW_DELETED', { table: message.table, key: message.key });
        return reply(n > 0, n > 0 ? 'Row deleted.' : 'Row not found.');
      }

      // ── Database: maintenance ──
      case 'DB_PURGE_LOGS': {
        const days = Number(message.days);
        if (!await confirmDestructive(`Purge activity logs older than ${days} days?`, 'This permanently deletes audit history.', 'Purge')) { return; }
        const n = await dbAdmin.purgeActivityOlderThan(days);
        await auditAdmin('ADMIN_DB_PURGE_LOGS', { days, deleted: n });
        return reply(true, `Deleted ${n} activity log entr${n === 1 ? 'y' : 'ies'}.`);
      }
      case 'DB_PURGE_RESOLVED': {
        const days = Number(message.days);
        if (!await confirmDestructive(`Purge resolved findings not updated for ${days} days?`,
          'FIXED, IGNORED and FALSE_POSITIVE records are deleted. Developer fix-rate history will change.', 'Purge')) { return; }
        const n = await dbAdmin.purgeResolvedRecordsOlderThan(days);
        await auditAdmin('ADMIN_DB_PURGE_RESOLVED', { days, deleted: n });
        return reply(true, `Deleted ${n} resolved record${n === 1 ? '' : 's'}.`);
      }
      case 'DB_DELETE_DEVELOPER': {
        const dev = String(message.developerId ?? '');
        if (!dev) { return reply(false, 'Choose a developer.'); }
        if (!await confirmDestructive(`Delete all data for "${dev}"?`,
          'All of their vulnerability records and activity logs are permanently deleted. The user account is kept.', 'Delete data')) { return; }
        const n = await dbAdmin.deleteDeveloperData(dev);
        recordStore.dispose();
        await auditAdmin('ADMIN_DB_DEVELOPER_DELETED', { developerId: dev, deleted: n });
        return reply(true, `Deleted ${n} record${n === 1 ? '' : 's'} for ${dev}.`);
      }
      case 'CLEAR_DB':
      case 'DB_CLEAR': {
        const table = op === 'CLEAR_DB' ? 'vulnerability_records' : message.table;
        if (!isAdminTable(table)) { return reply(false, 'Unknown table.'); }
        const what = message.collection ? `the "${message.collection}" document collection` : `every row in ${TABLES[table].label}`;
        if (!await confirmDestructive(`Permanently delete ${what}?`, 'This cannot be undone. Export a backup first if you may need this data.', 'Delete everything')) { return; }
        const n = await dbAdmin.truncate(table, typeof message.collection === 'string' ? message.collection : undefined);
        if (table === 'vulnerability_records') { recordStore.dispose(); }
        await auditAdmin('ADMIN_DB_CLEARED', { table, collection: message.collection ?? null, deleted: n });
        return reply(true, `Deleted ${n} row${n === 1 ? '' : 's'}.`);
      }
      case 'DB_VACUUM': {
        const tables = await dbAdmin.vacuumAnalyze();
        await auditAdmin('ADMIN_DB_VACUUM', { tables });
        return reply(true, `VACUUM ANALYZE completed on ${tables.length} tables.`);
      }
      case 'DB_MIGRATE': {
        const ok = await dbAdmin.rerunMigrations();
        await auditAdmin('ADMIN_DB_MIGRATE', { ok });
        return reply(ok, ok ? 'Schema verified — all tables and indexes are present.' : 'Migration failed — see the output log.');
      }

      // ── Database: backup ──
      case 'DB_EXPORT': {
        const target = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(path.join(
            vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? require('os').homedir(),
            `sentinel-backup-${new Date().toISOString().slice(0, 10)}.json`)),
          filters: { JSON: ['json'] },
          saveLabel: 'Export backup',
        });
        if (!target) { return; }
        const dump = await dbAdmin.exportAll();
        await vscode.workspace.fs.writeFile(target, Buffer.from(JSON.stringify(dump, null, 2), 'utf8'));
        const counts = Object.fromEntries(Object.entries(dump.tables).map(([k, v]) => [k, v.length]));
        await auditAdmin('ADMIN_DB_EXPORT', { file: path.basename(target.fsPath), counts });
        return reply(true, `Backup saved to ${path.basename(target.fsPath)}.`);
      }

      default:
        log(`[Admin] Unknown admin command ${op}`);
    }
  } catch (err: any) {
    log(`[Admin] ${op} failed: ${err?.message ?? err}`);
    reply(false, `${op.replace(/_/g, ' ').toLowerCase()} failed: ${err?.message ?? err}`);
  }
}

// ─── Notifications plumbing ───────────────────────────────────────────────────

function currentPrincipal(): Principal | null {
  const s = authManager?.getSession();
  if (!s) { return null; }
  return { userId: s.userId, username: s.username, githubUsername: s.githubUsername, role: s.role, displayName: s.displayName };
}

function pushNotifications(fresh: Array<{ id: string }> = []): void {
  if (!dashboardPanel || !notifications) { return; }
  const p = currentPrincipal();
  const items = notifications.list().slice(0, 100).map(n => ({
    id: n.id, level: n.level, category: n.category, title: n.title, message: n.message,
    createdAt: n.createdAt, section: n.section, unread: !!p && !n.readBy.includes(p.userId),
  }));
  const freshIds = new Set(fresh.map(f => f.id));
  void dashboardPanel.webview.postMessage({
    command: 'NOTIFICATIONS', items, unread: notifications.unreadCount(),
    fresh: items.filter(i => freshIds.has(i.id)),
  });
}

function updateStatusBar(): void {
  if (!statusBar) { return; }
  const n = notifications?.unreadCount() ?? 0;
  statusBar.text = n > 0 ? `$(shield) Sentinel  $(bell-dot) ${n}` : '$(shield) Sentinel';
  statusBar.tooltip = n > 0 ? `Sentinel — ${n} unread notification${n === 1 ? '' : 's'}` : 'Sentinel Security — Click to show dashboard';
}

async function handleNotificationMessage(message: { command: string; [key: string]: any }): Promise<void> {
  if (!notifications) { return; }
  switch (message.command) {
    case 'NOTIFICATIONS_READY':
      pushNotifications();
      break;
    case 'NOTIFICATIONS_MARK_READ':
      await notifications.markRead(message.ids === 'all' ? 'all' : (Array.isArray(message.ids) ? message.ids.map(String) : []));
      updateStatusBar();
      break;
    case 'NOTIFICATION_OPEN':
      await notifications.markRead([String(message.id)]);
      updateStatusBar();
      break;
  }
}

/** Every minute: reload shared project data, restore an in-progress shift, run reminders. */
async function backgroundTick(): Promise<void> {
  try {
    await projectStore.hydrate();
    const s = authManager?.getSession();
    if (s && !activeShiftSessionId && s.role === 'developer') {
      const active = projectStore.getActiveSession(s.githubUsername ?? s.username) ?? projectStore.getActiveSession(s.username);
      if (active) {
        activeShiftSessionId = active.id;
        log(`[Shift] Resumed tracking for active shift session ${active.id}`);
      }
    }
    const minutes = vscode.workspace.getConfiguration('sentinel').get<number>('notifications.shiftReminderMinutes', 15);
    await notifications?.runScheduledChecks(projectStore.getShifts(), projectStore.getAllSessions(), projectStore.getProjects(), minutes);
  } catch (err) {
    log(`[Background] ${err}`);
  }
}

// ─── Supervisor actions ───────────────────────────────────────────────────────

const SUPERVISOR_COMMANDS = new Set([
  'CREATE_PROJECT', 'UPDATE_PROJECT', 'DELETE_PROJECT', 'CREATE_SHIFT', 'UPDATE_SHIFT', 'DELETE_SHIFT',
  'UPDATE_SHIFT_ASSIGNMENT', 'ANNOUNCE', 'SET_NOTIFICATION_PREFS', 'REPORT_EXPORT', 'REFRESH_SUPERVISOR',
]);

/** Projects the signed-in supervisor owns (administrators see all). */
function supervisedProjects(session: { role: string; userId: string; username: string; githubUsername?: string }) {
  if (session.role === 'administrator') { return projectStore.getProjects(); }
  const ids = [session.githubUsername, session.username, session.userId].filter(Boolean);
  return projectStore.getProjects().filter(p => ids.includes(p.supervisorId));
}

async function handleSupervisorMessage(message: { command: string; [key: string]: any }): Promise<void> {
  const session = authManager.getSession();
  const reply = (success: boolean, msg: string) =>
    void dashboardPanel?.webview.postMessage({ command: 'SUP_RESULT', op: message.command, success, message: msg });
  if (!session || (session.role !== 'supervisor' && session.role !== 'administrator')) {
    log(`[Supervisor] Rejected ${message.command}: caller is not a supervisor.`);
    return reply(false, 'Supervisor access required.');
  }
  const by = session.displayName;
  const owned = (projectId: string) => supervisedProjects(session).find(p => p.id === projectId);
  const shiftOwned = (shiftId: string): Shift | undefined => {
    const sh = projectStore.getShift(shiftId);
    return sh && owned(sh.projectId) ? sh : undefined;
  };
  const cleanIds = (v: unknown) => Array.isArray(v) ? [...new Set(v.map(String).filter(Boolean))] : [];
  const nameOf = async (ids: string[]) => {
    const users = await NeonDatabaseService.getInstance().getAllUsers();
    return ids.map(id => users.find(u => u.githubUsername === id || u.username === id)?.displayName ?? id);
  };
  const done = async (msg: string) => { reply(true, msg); await refreshDashboard(); };

  try {
    switch (message.command) {
      case 'REFRESH_SUPERVISOR':
        await projectStore.hydrate();
        return void refreshDashboard();

      case 'CREATE_PROJECT': {
        const name = String(message.name ?? '').trim();
        if (!name) { return reply(false, 'Project name is required.'); }
        const project = projectStore.createProject(name, String(message.description ?? ''),
          session.githubUsername ?? session.username, session.displayName, message.color);
        log(`[Supervisor] Project created: "${project.name}" (${project.id})`);
        return done(`Project "${project.name}" created.`);
      }
      case 'UPDATE_PROJECT': {
        const p = owned(String(message.projectId));
        if (!p) { return reply(false, 'Project not found.'); }
        projectStore.updateProject(p.id, { name: message.name, description: message.description, color: message.color, status: message.status });
        return done(message.status && message.status !== p.status && !message.name ? `Project ${message.status === 'archived' ? 'archived' : 'restored'}.` : 'Project updated.');
      }
      case 'DELETE_PROJECT': {
        const p = owned(String(message.projectId));
        if (!p) { return reply(false, 'Project not found.'); }
        const shifts = projectStore.getShifts(p.id);
        if (projectStore.getSessionsForProject(p.id).some(s => !s.endedAt)) {
          return reply(false, 'This project has a shift in progress. End it before deleting the project.');
        }
        const choice = await vscode.window.showWarningMessage(`Delete project "${p.name}"?`,
          { modal: true, detail: `${shifts.length} shift(s) will be removed and assigned developers notified. Completed shift reports are kept.` }, 'Delete project');
        if (choice !== 'Delete project') { return; }
        for (const sh of shifts.filter(x => x.status === 'scheduled' && Date.parse(x.scheduledStart) > Date.now())) {
          void notifications?.shiftCancelled(sh, by);
        }
        projectStore.deleteProject(p.id);
        return done(`Project "${p.name}" deleted.`);
      }

      case 'CREATE_SHIFT': {
        const p = owned(String(message.projectId));
        if (!p || p.status !== 'active') { return reply(false, 'Choose an active project you supervise.'); }
        const name = String(message.name ?? '').trim();
        const occ: Array<{ start: string; end: string }> = Array.isArray(message.occurrences) ? message.occurrences.slice(0, 60) : [];
        const valid = occ.filter(o => !isNaN(Date.parse(o.start)) && !isNaN(Date.parse(o.end)) && Date.parse(o.end) > Date.parse(o.start));
        if (!name || valid.length === 0) { return reply(false, 'A shift needs a name, a date and a valid time range.'); }
        const devIds = cleanIds(message.developerIds);
        const devNames = await nameOf(devIds);
        const seriesId = valid.length > 1 ? `series-${Date.now().toString(36)}` : undefined;
        const created = valid.map(o => projectStore.createShift(p.id, name, String(message.description ?? ''), o.start, o.end,
          devIds, devNames, session.githubUsername ?? session.username, seriesId)).filter((x): x is Shift => !!x);
        if (devIds.length && created.length) {
          if (created.length === 1) { void notifications?.shiftAssigned(created[0], devIds, by); }
          else {
            void notifications?.notify({
              level: 'info', category: 'shift', section: 'shift', createdBy: by,
              title: `New recurring shift: ${name}`,
              message: `${by} assigned you to ${created.length} "${name}" shifts (${p.name}), first on ${new Date(created[0].scheduledStart).toLocaleString('en-GB', { weekday: 'short', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}.`,
              recipientIds: devIds, recipientRoles: [],
            });
          }
        }
        log(`[Supervisor] ${created.length} shift(s) "${name}" created in ${p.name}`);
        return done(created.length === 1 ? `Shift "${name}" scheduled${devIds.length ? ` — ${devIds.length} developer(s) notified` : ''}.` : `${created.length} shifts scheduled.`);
      }
      case 'UPDATE_SHIFT':
      case 'UPDATE_SHIFT_ASSIGNMENT': {
        const sh = shiftOwned(String(message.shiftId));
        if (!sh) { return reply(false, 'Shift not found.'); }
        if (sh.status === 'completed') { return reply(false, 'Completed shifts cannot be changed.'); }
        const before = { start: sh.scheduledStart, end: sh.scheduledEnd, devs: [...sh.assignedDeveloperIds] };
        if (message.command === 'UPDATE_SHIFT') {
          if (message.scheduledStart && message.scheduledEnd && Date.parse(message.scheduledEnd) <= Date.parse(message.scheduledStart)) {
            return reply(false, 'The end time must be after the start time.');
          }
          projectStore.updateShift(sh.id, { name: message.name, description: message.description, scheduledStart: message.scheduledStart, scheduledEnd: message.scheduledEnd });
        }
        if (Array.isArray(message.developerIds)) {
          const ids = cleanIds(message.developerIds);
          projectStore.updateShiftAssignments(sh.id, ids, await nameOf(ids));
        }
        const after = projectStore.getShift(sh.id)!;
        const added = after.assignedDeveloperIds.filter(d => !before.devs.includes(d));
        const removed = before.devs.filter(d => !after.assignedDeveloperIds.includes(d));
        if (added.length) { void notifications?.shiftAssigned(after, added, by); }
        if (removed.length) { void notifications?.shiftUnassigned(after, removed, by); }
        if (before.start !== after.scheduledStart || before.end !== after.scheduledEnd) {
          const stay = after.assignedDeveloperIds.filter(d => before.devs.includes(d));
          if (stay.length) { void notifications?.notify({ level: 'warning', category: 'shift', section: 'shift', createdBy: by,
            title: `Shift rescheduled: ${after.name}`,
            message: `"${after.name}" (${after.projectName}) moved to ${new Date(after.scheduledStart).toLocaleString('en-GB', { weekday: 'short', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}.`,
            recipientIds: stay, recipientRoles: [] }); }
        }
        return done('Shift updated.');
      }
      case 'DELETE_SHIFT': {
        const sh = shiftOwned(String(message.shiftId));
        if (!sh) { return reply(false, 'Shift not found.'); }
        if (projectStore.getSessionsForShift(sh.id).some(s => !s.endedAt)) { return reply(false, 'This shift is in progress and cannot be cancelled.'); }
        const choice = await vscode.window.showWarningMessage(`Cancel shift "${sh.name}"?`,
          { modal: true, detail: `${new Date(sh.scheduledStart).toLocaleString()} · ${sh.assignedDeveloperIds.length} developer(s) will be notified.` }, 'Cancel shift');
        if (choice !== 'Cancel shift') { return; }
        if (Date.parse(sh.scheduledEnd) > Date.now()) { void notifications?.shiftCancelled(sh, by); }
        projectStore.deleteShift(sh.id);
        return done(`Shift "${sh.name}" cancelled.`);
      }

      case 'ANNOUNCE': {
        const title = String(message.title ?? '').trim().slice(0, 120);
        const text = String(message.message ?? '').trim().slice(0, 600);
        if (!title || !text) { return reply(false, 'Add a title and a message.'); }
        const level: NotificationLevel = ['info', 'warning', 'critical'].includes(message.level) ? message.level : 'info';
        let recipientIds: string[] = [];
        if (message.audience === 'dev') { recipientIds = [String(message.target)]; }
        else if (message.audience === 'project') {
          const p = owned(String(message.target));
          if (!p) { return reply(false, 'Choose one of your projects.'); }
          recipientIds = [...new Set(projectStore.getShifts(p.id).flatMap(sh => sh.assignedDeveloperIds))];
          if (!recipientIds.length) { return reply(false, `No developers are assigned to shifts in "${p.name}" yet.`); }
        } else {
          const users = await NeonDatabaseService.getInstance().getAllUsers();
          recipientIds = users.filter(u => u.role === 'developer').map(u => u.githubUsername || u.username);
        }
        await notifications?.notify({ level, category: 'announcement', title, message: `${text} — ${by}`, recipientIds, recipientRoles: [], createdBy: by });
        return reply(true, `Announcement sent to ${recipientIds.length} developer${recipientIds.length === 1 ? '' : 's'}.`);
      }
      case 'SET_NOTIFICATION_PREFS': {
        const cfg = vscode.workspace.getConfiguration('sentinel');
        const mins = Number(message.reminderMinutes);
        if ([0, 5, 10, 15, 30, 60].includes(mins)) { await cfg.update('notifications.shiftReminderMinutes', mins, vscode.ConfigurationTarget.Global); }
        if (['all', 'important', 'off'].includes(message.popups)) { await cfg.update('notifications.popups', message.popups, vscode.ConfigurationTarget.Global); }
        return reply(true, 'Alert preferences saved.');
      }
      case 'REPORT_EXPORT': {
        const fmt = ['csv', 'json', 'html'].includes(message.format) ? message.format as string : 'json';
        const name = String(message.filename ?? `sentinel-report.${fmt}`).replace(/[^\w.-]+/g, '-');
        const target = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? require('os').homedir(), name)),
          filters: fmt === 'csv' ? { CSV: ['csv'] } : fmt === 'html' ? { HTML: ['html'] } : { JSON: ['json'] },
          saveLabel: 'Export report',
        });
        if (!target) { return; }
        await vscode.workspace.fs.writeFile(target, Buffer.from(String(message.content ?? ''), 'utf8'));
        reply(true, `Report saved to ${path.basename(target.fsPath)}.`);
        if (fmt === 'html') {
          const open = await vscode.window.showInformationMessage(`Report saved to ${path.basename(target.fsPath)}.`, 'Open in browser');
          if (open) { void vscode.env.openExternal(target); }
        }
        return;
      }
    }
  } catch (err: any) {
    log(`[Supervisor] ${message.command} failed: ${err?.message ?? err}`);
    reply(false, `Something went wrong: ${err?.message ?? err}`);
  }
}

// ─── Theme ────────────────────────────────────────────────────────────────────

/** Feed the `sentinel.theme` setting and the active VS Code theme kind into the webview theme module. */
function syncThemeFromVsCode(): void {
  const kind = vscode.window.activeColorTheme.kind;
  setVsCodeThemeKind(
    kind === vscode.ColorThemeKind.Light || kind === vscode.ColorThemeKind.HighContrastLight ? 'light' : 'dark'
  );
  setThemePreference(vscode.workspace.getConfiguration('sentinel').get<ThemePreference>('theme', 'auto'));
}

// ─── Component 2 API server ───────────────────────────────────────────────────

function apiServerOptions(): SentinelApiServerOptions & { enabled: boolean } {
  const config = vscode.workspace.getConfiguration('sentinel');
  return {
    enabled: config.get<boolean>('api.enabled', true),
    port: config.get<number>('api.port', 7420),
    apiKey: config.get<string>('api.key', '') || undefined,
    log,
  };
}

function startApiServer(): void {
  const opts = apiServerOptions();
  if (!opts.enabled) {
    apiServerError = 'Disabled in settings (sentinel.api.enabled)';
    return;
  }
  apiServer = new SentinelApiServer({
    getLiveFindings: () => [...findingsCache.values()].flat(),
    getRecentEvents: (since, limit) => eventClient.getRecentEvents(since, limit),
    getCurrentDeveloperId: resolveDeveloperId,
    getLearningProfile: devId => learningStore.getProfile(devId),
    getShifts: devId => ({
      assigned: projectStore.getShiftsForDeveloper(devId),
      active: projectStore.getActiveSession(devId),
      sessions: projectStore.getSessionsForDeveloper(devId),
    }),
    getSessionId: () => eventClient.getSessionId(),
    getExtensionVersion: () => String(extensionContext.extension.packageJSON?.version ?? '0.0.0'),
  }, opts);
  apiServer.start().then(() => {
    apiServerError = null;
  }).catch((err: any) => {
    apiServerError = err?.code === 'EADDRINUSE'
      ? `Port ${opts.port} is already in use — change sentinel.api.port`
      : String(err?.message ?? err);
    log(`⚠️ Sentinel API failed to start: ${apiServerError}`);
  }).finally(() => { void refreshDashboard(); });
}

async function restartApiServer(): Promise<void> {
  await apiServer?.stop();
  apiServer = undefined;
  startApiServer();
}

/**
 * Resolve the current developer ID.
 * Priority: GitHub username → sentinel.developerId config → 'DEV_UNKNOWN'
 */
async function resolveDeveloperId(): Promise<string> {
  if (authManager?.isLoggedIn()) {
    const s = authManager.getSession();
    if (s?.githubUsername) return s.githubUsername;
    if (s?.username) return s.username;
  }
  try {
    const session = await vscode.authentication.getSession('github', ['user:email'], { silent: true });
    if (session?.account?.label) {
      return session.account.label;
    }
  } catch {
    // GitHub auth not available — fall through
  }
  const config = vscode.workspace.getConfiguration('sentinel');
  return config.get<string>('developerId', 'DEV_UNKNOWN');
}

// ─── Code Actions Provider ────────────────────────────────────────────────────

class SentinelCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
  ): vscode.CodeAction[] {
    const findings = findingsCache.get(document.uri.toString()) ?? [];
    const actions: vscode.CodeAction[] = [];

    for (const finding of findings) {
      const findingLine = finding.lineNumber - 1;
      if (!range.contains(new vscode.Position(findingLine, 0))) { continue; }

      const aiSuggestAction = new vscode.CodeAction(
        `🤖 Sentinel AI: View Fix Suggestion & Secure Example (${finding.type})`, vscode.CodeActionKind.QuickFix);
      aiSuggestAction.command = { command: 'sentinel.explainFinding', title: 'View AI Fix Suggestion', arguments: [{ findingId: finding.id }] };

      const ignoreAction = new vscode.CodeAction(
        `$(eye-closed) Sentinel: Ignore warning for this line`, vscode.CodeActionKind.QuickFix);
      ignoreAction.command = { command: 'sentinel.ignoreFinding', title: 'Ignore', arguments: [{ findingId: finding.id }] };

      actions.push(aiSuggestAction, ignoreAction);
    }
    return actions;
  }
}

// ─── Dashboard Webview ──────────────────────────────────────────────────────────────

/**
 * Refresh the live dashboard panel.
 * - If no session → show login screen.
 * - If session → route to the correct role dashboard.
 */
let lastRenderedUser: string | null = null;

function showLoadingScreen(title: string, subtitle: string): void {
  if (!dashboardPanel) { return; }
  const logoUri = dashboardPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'resources', 'sentinel-logo.png')
  ).toString();
  dashboardPanel.title = 'Sentinel — Loading';
  dashboardPanel.webview.html = buildLoadingHtml(dashboardPanel.webview.cspSource, logoUri, title, subtitle);
}

async function refreshDashboard(): Promise<void> {
  if (!dashboardPanel) { return; }

  const logoUri = dashboardPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'resources', 'sentinel-logo.png')
  ).toString() + '?t=' + Date.now();

  const cspSource = dashboardPanel.webview.cspSource;
  const session   = authManager?.getSession();

  if (!session) {
    lastRenderedUser = null;
    dashboardPanel.title = 'Sentinel — Login';
    dashboardPanel.webview.html = buildLoginHtml(cspSource, logoUri);
    return;
  }

  // First render after sign-in: show a proper loading screen while data loads from the DB
  const userKey = `${session.userId}:${session.role}`;
  if (lastRenderedUser !== userKey) {
    showLoadingScreen('Loading your dashboard', 'Fetching your data from the database…');
    lastRenderedUser = userKey;
  }

  const allFindings: SecurityFinding[] = [];
  for (const findings of findingsCache.values()) { allFindings.push(...findings); }
  const summary = analyzer.summarize(allFindings);
  const dataDir = path.join(extensionContext.extensionPath, 'src', 'data');
  const db = NeonDatabaseService.getInstance();

  if (session.role === 'developer') {
    dashboardPanel.title = `Sentinel — ${session.displayName}`;
    const devId          = session.githubUsername ?? session.username;
    const assignedShifts = projectStore.getShiftsForDeveloper([devId, session.username]);
    const activeSession  = projectStore.getActiveSession(devId) ?? projectStore.getActiveSession(session.username);
    const recentSessions = projectStore.getSessionsForDeveloper(devId);

    // Fetch live statistics and vulnerability tracking records from Neon PostgreSQL
    let stats: any;
    let dbRecords: any[] = [];
    let activities: any[] = [];
    const dbStatus = db.getStatus();

    try {
      [stats, dbRecords, activities] = await Promise.all([
        db.getVulnerabilityStats(devId),
        db.getVulnerabilityRecords(devId, 'ALL', 500),
        db.getRecentActivities(devId, 200),
      ]);
    } catch (e) {
      console.warn('[Sentinel] Error querying Neon DB for dashboard:', e);
    }

    const insights = computeDeveloperInsights({
      developerId: devId,
      liveFindings: allFindings,
      records: dbRecords,
      learningProfile: learningStore.getProfile(devId),
      activities,
      shiftSessions: recentSessions,
    });

    dashboardPanel.webview.html = buildDeveloperDashboardHtml(
      summary,
      allFindings,
      session,
      logoUri,
      cspSource,
      analyzer.getRules().length,
      eventClient?.getSessionId() ?? 'N/A',
      assignedShifts,
      activeSession,
      recentSessions,
      stats,
      dbRecords,
      dbStatus,
      activities.slice(0, 25),
      insights,
      {
        running: apiServer?.isRunning ?? false,
        url: apiServer?.isRunning ? apiServer.url : '',
        error: apiServerError,
      },
    );
  } else if (session.role === 'supervisor') {
    dashboardPanel.title = 'Sentinel — Supervisor Dashboard';
    const [devStats, users, records] = await Promise.all([
      db.getDeveloperStatsSummary(),
      db.getAllUsers(),
      db.getVulnerabilityRecords(undefined, 'ALL', 5000),
    ]).catch(err => {
      log(`[Supervisor] Failed to load dashboard data: ${err}`);
      return [[], [], []] as [any[], any[], any[]];
    });
    setDeveloperStats(devStats);
    const projects  = supervisedProjects(session);
    const projIds   = new Set(projects.map(p => p.id));
    const shifts    = projectStore.getShifts().filter(s => projIds.has(s.projectId));
    const shiftIds  = new Set(shifts.map(s => s.id));
    const sessions  = projectStore.getAllSessions().filter(s => shiftIds.has(s.shiftId));
    const cfg = vscode.workspace.getConfiguration('sentinel');
    dashboardPanel.webview.html = buildSupervisorDashboardHtml({
      session, cspSource, logoUri, projects, shifts, sessions, devStats,
      developers: users.filter(u => u.role === 'developer').map(u => ({
        key: u.githubUsername || u.username, userId: u.id, username: u.username,
        githubUsername: u.githubUsername ?? undefined, displayName: u.displayName,
        githubAvatarUrl: u.githubAvatarUrl ?? undefined, lastLoginAt: u.lastLoginAt,
      })),
      records: records.map(r => ({
        d: r.githubUsername || r.developerId, t: r.vulnerabilityType, s: r.severity,
        st: r.status, at: r.detectedAt, fx: r.fixedAt,
      })),
      prefs: {
        reminderMinutes: cfg.get<number>('notifications.shiftReminderMinutes', 15),
        popups: cfg.get<string>('notifications.popups', 'all'),
      },
    });
  } else if (session.role === 'administrator') {
    dashboardPanel.title = 'Sentinel — Admin Dashboard';
    const config = vscode.workspace.getConfiguration('sentinel');
    const [devStats, dbUsers, records, activities] = await Promise.all([
      db.getDeveloperStatsSummary(),
      db.getAllUsers(),
      db.getVulnerabilityRecords(undefined, 'ALL', 5000),
      db.getRecentActivities(undefined, 300),
    ]).catch(err => {
      log(`[Admin] Failed to load dashboard data: ${err}`);
      return [[], [], [], []] as [any[], any[], any[], any[]];
    });
    setDeveloperStats(devStats);
    const insights = computeDeveloperInsights({
      developerId: 'ALL', liveFindings: [], records, learningProfile: null, activities, shiftSessions: [],
    });
    dashboardPanel.webview.html = buildAdminDashboardHtml({
      session, cspSource, logoUri,
      users: dbUsers.map(u => ({
        id: u.id, username: u.username, githubUsername: u.githubUsername, role: u.role,
        displayName: u.displayName, email: u.email, githubAvatarUrl: u.githubAvatarUrl,
        createdAt: u.createdAt, lastLoginAt: u.lastLoginAt,
      })),
      devStats, records, activities, insights,
      dbStatus: db.getStatus(),
      system: {
        extensionVersion: String(extensionContext.extension.packageJSON?.version ?? '0.0.0'),
        backendUrl: config.get<string>('backendUrl', 'http://localhost:3000'),
        ifeUrl: config.get<string>('ifeUrl', 'http://localhost:4000'),
        apiUrl: apiServer?.isRunning ? apiServer.url : '',
        apiRunning: apiServer?.isRunning ?? false,
        apiError: apiServerError,
        theme: config.get<string>('theme', 'auto'),
        minConfidence: config.get<number>('minConfidence', 0.7),
        analysisEnabled: config.get<boolean>('enabled', true),
        aiEnabled: config.get<boolean>('enableAI', false),
        rulesCount: analyzer.getRules().length,
        debounceMs: config.get<number>('debounceMs', 400),
      },
    });
  }
}

function showDashboard(context: vscode.ExtensionContext): void {
  // If already open, just bring it to front and refresh
  if (dashboardPanel) {
    dashboardPanel.reveal(vscode.ViewColumn.Beside);
    refreshDashboard();
    return;
  }

  dashboardPanel = vscode.window.createWebviewPanel(
    'sentinel.dashboard',
    'Sentinel Security Dashboard',
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'resources')],
    },
  );
  dashboardPanel.iconPath = logoFileUri();

  // Clear the reference when the user closes the panel
  dashboardPanel.onDidDispose(() => {
    dashboardPanel = undefined;
  }, null, context.subscriptions);

  // Handle messages from the webview (login, logout, admin actions)
  dashboardPanel.webview.onDidReceiveMessage(
    (message: { command: string; [key: string]: any }) => {
      handleWebviewMessage(message);
    },
    undefined,
    context.subscriptions,
  );

  refreshDashboard();
}

// ─── Webview Message Handler ──────────────────────────────────────────────────

function handleWebviewMessage(message: { command: string; [key: string]: any }): void {
  if (/^(ADMIN_|DB_)/.test(message.command) || message.command === 'CLEAR_DB') {
    void handleAdminMessage(message);
    return;
  }
  if (SUPERVISOR_COMMANDS.has(message.command)) {
    void handleSupervisorMessage(message);
    return;
  }
  if (message.command.startsWith('NOTIFICATION')) {
    void handleNotificationMessage(message);
    return;
  }
  switch (message.command) {
    case 'START_SHIFT': {
      const authSession = authManager.getSession();
      if (!authSession) { break; }
      const shift = projectStore.getShift(message.shiftId as string);
      if (!shift) { break; }
      const myIds = [authSession.githubUsername, authSession.username].filter(Boolean) as string[];
      if (!shift.assignedDeveloperIds.some(id => myIds.includes(id))) {
        vscode.window.showWarningMessage(`Sentinel: You are not assigned to "${shift.name}".`);
        break;
      }

      const developerId = authSession.githubUsername ?? authSession.username;
      const shiftSession = projectStore.startSession(
        shift,
        developerId,
        authSession.username,
        authSession.displayName,
        authSession.githubAvatarUrl,
      );

      activeShiftSessionId = shiftSession.id;
      void notifications?.shiftStarted(shift, projectStore.getProject(shift.projectId), authSession.displayName);
      log(`▶ Shift started: "${shift.name}" by ${authSession.displayName} (session: ${shiftSession.id})`);
      vscode.window.showInformationMessage(
        `🟢 Shift "${shift.name}" started! Sentinel is now tracking your vulnerabilities.`
      );
      refreshDashboard();
      break;
    }

    case 'END_SHIFT': {
      const sessionId = message.sessionId as string;
      const owned = projectStore.getAllSessions().find(x => x.id === sessionId);
      const me = authManager.getSession();
      if (!owned || !me || ![me.githubUsername, me.username].includes(owned.developerId)) { break; }
      const endedSession = projectStore.endSession(sessionId);

      activeShiftSessionId = null;
      if (endedSession) {
        const sh = projectStore.getShift(endedSession.shiftId);
        void notifications?.shiftEnded(endedSession, sh ? projectStore.getProject(sh.projectId) : undefined, sh);
      }

      if (endedSession?.summary) {
        const sum = endedSession.summary;
        const sc = sum.securityScore;
        const icon = sc >= 80 ? '🌟' : sc >= 50 ? '⚠️' : '🚨';
        vscode.window.showInformationMessage(
          `${icon} Shift ended! Security Score: ${sc}/100 — ${sum.totalFindings} vulnerabilities detected. Check your Reports tab.`,
          'View Report'
        ).then(sel => {
          if (sel === 'View Report') { showDashboard(extensionContext); }
        });
        log(`⏹ Shift ended: session ${sessionId} — score: ${sc}, findings: ${sum.totalFindings}`);
      }
      refreshDashboard();
      break;
    }

    case 'GITHUB_LOGIN': {
      // Triggered when the user clicks "Continue with GitHub" in the webview.
      // This calls VS Code's OAuth flow — shows the system browser auth prompt.
      showLoadingScreen('Signing in with GitHub', 'Complete the sign-in in your browser…');
      authManager.loginWithGitHub(false).then(session => {
        if (session) {
          log(`👋 GitHub login: @${session.githubUsername ?? session.username} (${session.role})`);
          refreshDashboard();
        } else {
          // User cancelled or GitHub auth failed — re-show login with error
          if (dashboardPanel) {
            const logoUri = dashboardPanel.webview.asWebviewUri(
              vscode.Uri.joinPath(extensionUri, 'resources', 'sentinel-logo.png')
            ).toString();
            dashboardPanel.webview.html = buildLoginHtml(
              dashboardPanel.webview.cspSource,
              logoUri,
              '',
              'GitHub sign-in was cancelled or failed. Please try again.',
            );
          }
        }
      }).catch(err => {
        log(`[Auth] GitHub login error: ${err}`);
        if (dashboardPanel) {
          const logoUri = dashboardPanel.webview.asWebviewUri(
            vscode.Uri.joinPath(extensionUri, 'resources', 'sentinel-logo.png')
          ).toString();
          dashboardPanel.webview.html = buildLoginHtml(
            dashboardPanel.webview.cspSource,
            logoUri,
            '',
            'GitHub authentication failed. Check your internet connection.',
          );
        }
      });
      break;
    }

    case 'LOGIN': {
      showLoadingScreen('Signing in', 'Verifying your credentials…');
      void (async () => {
        const session = await authManager.login(message.username as string, message.password as string);
        if (session) {
          log(`🔐 Login: ${session.username} (${session.role})`);
          refreshDashboard();
        } else {
          // Show login screen again with error
          if (dashboardPanel) {
            const logoUri = dashboardPanel.webview.asWebviewUri(
              vscode.Uri.joinPath(extensionUri, 'resources', 'sentinel-logo.png')
            ).toString();
            dashboardPanel.webview.html = buildLoginHtml(
              dashboardPanel.webview.cspSource,
              logoUri,
              'Invalid username or password. Please try again.',
            );
          }
        }
      })();
      break;
    }

    case 'LOGOUT': {
      const wasUser = authManager.getSession()?.username ?? 'unknown';
      authManager.logout();
      log(`🔐 Logout: ${wasUser}`);
      refreshDashboard();
      break;
    }

    case 'REFRESH_ADMIN': {
      void refreshDashboard();
      break;
    }

    case 'APPLY_FIX': {
      const fileName = message.fileName as string;
      const line = (message.line as number) || 1;
      vscode.window.showInformationMessage(
        'Sentinel: Auto-fix buttons are disabled. Please edit the code directly in your editor using the AI suggestion. Sentinel tracks changes in real time and automatically records the fix once resolved!'
      );
      const lineIndex = Math.max(0, line - 1);
      vscode.workspace.openTextDocument(fileName).then(doc => {
        vscode.window.showTextDocument(doc, {
          selection: new vscode.Range(lineIndex, 0, lineIndex, 100),
          preview: false,
        });
      });
      break;
    }

    case 'MARK_FIXED': {
      vscode.window.showInformationMessage(
        'Sentinel: Vulnerabilities are automatically marked as FIXED only when the problem is corrected in your code and the red squiggly line disappears.'
      );
      break;
    }

    case 'MARK_IGNORED': {
      const findingId = message.findingId as string;
      const sess = authManager.getSession();
      const devId = sess?.githubUsername ?? sess?.username ?? 'DEV_UNKNOWN';
      NeonDatabaseService.getInstance().updateVulnerabilityStatus(findingId, devId, 'IGNORED', sess?.username).then(() => {
        vscode.window.showInformationMessage(`Vulnerability marked as IGNORED.`);
        void refreshDashboard();
      });
      break;
    }

    case 'JUMP_TO_CODE': {
      const fileName = message.fileName as string;
      const line = Math.max(0, (message.line as number) - 1);
      vscode.workspace.openTextDocument(fileName).then(doc => {
        vscode.window.showTextDocument(doc, {
          selection: new vscode.Range(line, 0, line, 100),
          preview: false,
        });
      });
      break;
    }

    case 'RATE_FEEDBACK': {
      const sess = authManager.getSession();
      const devId = sess?.githubUsername ?? sess?.username ?? 'DEV_UNKNOWN';
      const findingId = typeof message.findingId === 'string' && !message.findingId.startsWith('fb-')
        ? message.findingId : undefined;
      void NeonDatabaseService.getInstance().logActivity({
        userId: sess?.userId,
        username: sess?.username,
        developerId: devId,
        githubUsername: sess?.githubUsername,
        actionType: 'FEEDBACK_RATED',
        findingId,
        vulnerabilityType: message.vulnerabilityType ?? undefined,
        details: {
          helpful: !!message.helpful,
          comment: message.comment ?? null,
          source: findingId ? 'warning' : message.findingId ? 'recommendation' : 'general',
        },
      }).then(() => {
        if (message.comment) {
          vscode.window.showInformationMessage('Sentinel: Thanks — your feedback was recorded.');
          void refreshDashboard();
        }
      });
      break;
    }

    case 'SET_THEME': {
      // The webview has already applied it; persist so every Sentinel view opens in this mode.
      const pref = ['auto', 'light', 'dark'].includes(message.pref) ? message.pref as ThemePreference : 'auto';
      setThemePreference(pref);
      void vscode.workspace.getConfiguration('sentinel').update('theme', pref, vscode.ConfigurationTarget.Global);
      break;
    }

    case 'OPEN_URL': {
      const url = String(message.url ?? '');
      if (/^https:\/\//.test(url)) {
        void vscode.env.openExternal(vscode.Uri.parse(url));
      }
      break;
    }

    case 'SCAN_WORKSPACE': {
      void scanEntireWorkspace();
      break;
    }

    default:
      break;
  }
}

async function applyCodeFixDirectly(
  fileName: string,
  lineNumber: number,
  fixedCode: string
): Promise<boolean> {
  try {
    const doc = await vscode.workspace.openTextDocument(fileName);
    const lineIndex = Math.max(0, lineNumber - 1);
    if (lineIndex >= doc.lineCount) {
      return false;
    }
    const line = doc.lineAt(lineIndex);
    const edit = new vscode.WorkspaceEdit();
    edit.replace(doc.uri, line.range, fixedCode);
    const success = await vscode.workspace.applyEdit(edit);
    if (success) {
      await doc.save();
    }
    return success;
  } catch (err) {
    console.error('[Sentinel] Error applying code fix:', err);
    return false;
  }
}

// ─── Logging ──────────────────────────────────────────────────────────────────

function log(message: string): void {
  const timestamp = new Date().toLocaleTimeString();
  outputChannel.appendLine(`[${timestamp}] ${message}`);
}

function logFindings(document: vscode.TextDocument, findings: SecurityFinding[]): void {
  const name = document.fileName.split('/').pop() ?? document.fileName;
  if (findings.length === 0) {
    log(`✅ ${name} — No issues found`);
    return;
  }

  log(`\n${'─'.repeat(50)}`);
  log(`📄 ${name} — ${findings.length} issue(s) found`);
  for (const f of findings) {
    const conf = Math.round(f.confidence * 100);
    log(`  ${severityIcon(f.severity)} [${f.severity}] ${f.type} — Line ${f.lineNumber} (${conf}% confidence)`);
    log(`     ${f.codeSnippet.substring(0, 80)}${f.codeSnippet.length > 80 ? '...' : ''}`);
  }
  log('─'.repeat(50));
}

function logSecurityAlert(findings: SecurityFinding[]): void {
  outputChannel.appendLine('');
  outputChannel.appendLine('━'.repeat(44));
  outputChannel.appendLine('  🛡 SENTINEL SECURITY ALERT');
  outputChannel.appendLine('━'.repeat(44));
  for (const f of findings) {
    outputChannel.appendLine('');
    outputChannel.appendLine(`  ${f.type}`);
    outputChannel.appendLine(`  File:     ${f.fileName.split('/').pop()}`);
    outputChannel.appendLine(`  Line:     ${f.lineNumber}`);
    outputChannel.appendLine(`  Severity: ${f.severity}`);
    outputChannel.appendLine(`  Confidence: ${Math.round(f.confidence * 100)}%`);
    outputChannel.appendLine('');
    outputChannel.appendLine('  Actions: [Explain] [Fix] [Ignore]');
    outputChannel.appendLine('  (Use the lightbulb 💡 or hover over the red underline)');
    outputChannel.appendLine('');
    outputChannel.appendLine('─'.repeat(44));
  }
  outputChannel.appendLine('');
}

function severityIcon(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return '🚨';
    case 'HIGH':     return '🔴';
    case 'MEDIUM':   return '🟠';
    case 'LOW':      return '🟡';
    default:         return 'ℹ️';
  }
}

// ─── HTML Builders ────────────────────────────────────────────────────────────

/** File URI of the Sentinel brand logo (used for panel tab icons, hovers and webview headers). */
function logoFileUri(): vscode.Uri {
  return vscode.Uri.joinPath(extensionUri, 'resources', 'sentinel-logo.png');
}

/** Small "logo + Sentinel" brand strip shown at the top of the explain / fix panels. */
function brandStripHtml(logoUri: string): string {
  return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:18px;font-weight:700;font-size:0.95em;letter-spacing:-0.2px">
    <img src="${logoUri}" alt="" width="24" height="24" style="object-fit:contain">Sentinel
  </div>`;
}


function buildExplainHtml(finding: SecurityFinding, _meta: any, logoUri: string, cspSource: string): string {
  const ctx = generateContextualExplanation(finding);
  const conf = Math.round(finding.confidence * 100);
  const sevColor = finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? '#f14c4c' :
                   finding.severity === 'MEDIUM' ? '#e9a825' : '#73c991';
  const meta = VULNERABILITY_METADATA[finding.type];
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource};">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', var(--vscode-font-family), sans-serif; padding: 24px; color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); line-height: 1.6; }
    .header { display: flex; align-items: flex-start; gap: 16px; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--vscode-panel-border); }
    .severity-dot { width: 14px; height: 14px; border-radius: 50%; background: ${sevColor}; margin-top: 6px; flex-shrink: 0; box-shadow: 0 0 8px ${sevColor}; }
    .title { font-size: 1.3em; font-weight: 700; color: var(--vscode-editor-foreground); }
    .subtitle { font-size: 0.9em; color: var(--vscode-descriptionForeground); margin-top: 4px; }
    .badges { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
    .badge { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 100px; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; }
    .badge-sev { background: ${sevColor}22; color: ${sevColor}; border: 1px solid ${sevColor}44; }
    .badge-conf { background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); }
    .badge-rule { background: var(--vscode-editor-inactiveSelectionBackground); color: var(--vscode-descriptionForeground); }
    .section { margin: 20px 0; }
    .section-label { font-size: 11px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--vscode-descriptionForeground); margin-bottom: 10px; }
    .section-body { font-size: 0.93em; color: var(--vscode-editor-foreground); }
    .code-block { position: relative; border-radius: 8px; overflow: hidden; margin: 10px 0; }
    .code-label { font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding: 6px 14px; }
    .code-label.danger { background: #f14c4c22; color: #f14c4c; border-bottom: 1px solid #f14c4c33; }
    .code-label.safe { background: #73c99122; color: #73c991; border-bottom: 1px solid #73c99133; }
    pre { font-family: 'Fira Code', 'Courier New', monospace; font-size: 13px; padding: 14px 16px; background: var(--vscode-textCodeBlock-background); overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-word; }
    .pre-danger { border: 1px solid #f14c4c33; border-radius: 8px; overflow: hidden; }
    .pre-safe   { border: 1px solid #73c99133; border-radius: 8px; overflow: hidden; }
    .attack-box { background: #e9a82511; border: 1px solid #e9a82533; border-radius: 8px; padding: 14px 16px; font-size: 0.9em; white-space: pre-wrap; font-family: 'Fira Code', monospace; }
    .fix-note { background: #73c99111; border: 1px solid #73c99133; border-radius: 8px; padding: 12px 16px; font-size: 0.9em; margin-top: 10px; }
    .divider { border: none; border-top: 1px solid var(--vscode-panel-border); margin: 24px 0; }
    code { font-family: 'Fira Code', monospace; background: var(--vscode-textCodeBlock-background); padding: 1px 6px; border-radius: 3px; font-size: 0.92em; }
    a { color: var(--vscode-textLink-foreground); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .ref-list { list-style: none; margin-top: 8px; display: flex; flex-direction: column; gap: 4px; }
    .ref-list a { font-size: 0.85em; }
  </style>
</head>
<body>
  ${brandStripHtml(logoUri)}
  <div class="header">
    <div class="severity-dot"></div>
    <div>
      <div class="title">${finding.type.replace(/_/g, ' ')}</div>
      <div class="subtitle">${ctx.headline}</div>
      <div class="badges">
        <span class="badge badge-sev">${finding.severity}</span>
        <span class="badge badge-conf">${conf}% confidence</span>
        <span class="badge badge-rule">${finding.detectedByRule} &mdash; Line ${finding.lineNumber}</span>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-label">Why is your code vulnerable?</div>
    <div class="section-body">${ctx.whyDangerous}</div>
  </div>

  <div class="section">
    <div class="section-label">Your vulnerable code</div>
    <div class="pre-danger">
      <div class="code-label danger">❌ Detected in your file &mdash; Line ${finding.lineNumber}</div>
      <pre>${escHtml(ctx.vulnerableCode)}</pre>
    </div>
  </div>

  <div class="section">
    <div class="section-label">Attack scenario</div>
    <div class="attack-box">${escHtml(ctx.attackScenario)}</div>
  </div>

  <hr class="divider">

  <div class="section">
    <div class="section-label">Fixed version of your code</div>
    <div class="pre-safe">
      <div class="code-label safe">Secure replacement</div>
      <pre>${escHtml(ctx.fixedCode)}</pre>
    </div>
    <div class="fix-note">💡 ${escHtml(ctx.fixExplanation)}</div>
  </div>

  ${meta?.references?.length ? `
  <div class="section">
    <div class="section-label">References</div>
    <ul class="ref-list">
      ${meta.references.map((r: string) => `<li><a href="${r}" target="_blank">${r}</a></li>`).join('')}
    </ul>
  </div>` : ''}
</body>
</html>`;
}

function buildFixHtml(finding: SecurityFinding, _meta: any, logoUri: string, cspSource: string): string {
  const ctx = generateContextualExplanation(finding);
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource};">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Fira+Code&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', sans-serif; padding: 24px; color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); line-height: 1.6; }
    h1 { font-size: 1.2em; color: #3fb950; margin-bottom: 6px; }
    .subtitle { color: var(--vscode-descriptionForeground); font-size: 0.9em; margin-bottom: 24px; }
    .code-label { font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding: 6px 14px; }
    .code-label.danger { background: #f47067222; color: #f47067; }
    .code-label.safe   { background: #3fb9501a; color: #3fb950; }
    pre { font-family: 'Fira Code', monospace; font-size: 13px; padding: 14px 16px; background: var(--vscode-textCodeBlock-background); overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-word; }
    .pre-danger { border: 1px solid rgba(244,112,103,0.25); border-radius: 8px; overflow: hidden; }
    .pre-safe   { border: 1px solid rgba(63,185,80,0.2);   border-radius: 8px; overflow: hidden; }
    .note { background: rgba(63,185,80,0.07); border: 1px solid rgba(63,185,80,0.18); border-radius: 8px; padding: 12px 16px; font-size: 0.9em; margin-top: 12px; color: #3fb950; }
  </style>
</head>
<body>
  ${brandStripHtml(logoUri)}
  <h1>Secure Fix &mdash; ${finding.type.replace(/_/g, ' ')}</h1>
  <div class="subtitle">Line ${finding.lineNumber} in ${finding.fileName.split('/').pop()}</div>
  <div class="pre-danger">
    <div class="code-label danger">Your vulnerable code</div>
    <pre>${escHtml(ctx.vulnerableCode)}</pre>
  </div>
  <div class="pre-safe" style="margin-top:16px">
    <div class="code-label safe">Fixed version</div>
    <pre>${escHtml(ctx.fixedCode)}</pre>
  </div>
  <div class="note">💡 <strong>Remediation:</strong> ${escHtml(ctx.fixExplanation)}<br><br>✍️ <em>Edit your code in the editor to apply this fix. Sentinel monitors keystrokes in real time and automatically records this vulnerability as FIXED once cleared!</em></div>
</body>
</html>`;
}

function buildDashboardHtml(summary: any, findings: SecurityFinding[], logoUri: string = '', cspSource: string = 'vscode-webview:'): string {
  const scoreRaw = findings.length === 0 ? 100 :
    Math.max(0, 100 - (summary.criticalCount * 25 + summary.highCount * 10 + summary.mediumCount * 5 + summary.lowCount * 2));
  const scoreColor  = scoreRaw >= 80 ? '#3fb950' : scoreRaw >= 50 ? '#d29922' : '#f47067';
  const circumference = 283;
  const dashOffset    = circumference - (scoreRaw / 100) * circumference;

  const findingCards = findings.map(f => {
    const ctx      = generateContextualExplanation(f);
    const conf     = Math.round(f.confidence * 100);
    const sevColor = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '#f47067'
                   : f.severity === 'MEDIUM' ? '#d29922' : '#3fb950';
    const sevIcon  = f.severity === 'CRITICAL' ? '&#x1F6A8;'
                   : f.severity === 'HIGH'     ? '&#x1F534;'
                   : f.severity === 'MEDIUM'   ? '&#x1F7E0;' : '&#x1F7E1;';
    return `
<div class="card" id="card-${f.id}">
  <div class="card-hdr" onclick="tog('${f.id}')">
    <div class="lft">
      <span class="pill" style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}44">${sevIcon} ${f.severity}</span>
      <div>
        <div class="ctitle">${f.type.replace(/_/g, ' ')}</div>
        <div class="cfile">&#x1F4C4; ${escHtml(f.fileName.split('/').pop() ?? '')} &middot; Line ${f.lineNumber}</div>
      </div>
    </div>
    <div class="rgt">
      <span class="conf">${conf}%</span>
      <span class="chev" id="chev-${f.id}">&#9660;</span>
    </div>
  </div>
  <div class="chl">${escHtml(ctx.headline)}</div>
  <div class="cbody" id="body-${f.id}">
    <div class="dlbl">Why is this vulnerable?</div>
    <div class="dtxt">${escHtml(ctx.whyDangerous)}</div>
    <div class="cmp">
      <div>
        <div class="clbl dlbl-d">Vulnerable code</div>
        <pre class="pre-d">${escHtml(ctx.vulnerableCode)}</pre>
      </div>
      <div>
        <div class="clbl dlbl-s">Fixed version</div>
        <pre class="pre-s">${escHtml(ctx.fixedCode)}</pre>
      </div>
    </div>
    <div class="dlbl">Attack scenario</div>
    <div class="atk">${escHtml(ctx.attackScenario)}</div>
    <div class="fix">&#x1F4A1; ${escHtml(ctx.fixExplanation)}</div>
  </div>
</div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src ${cspSource} data:; script-src 'unsafe-inline';">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0d1117;color:#e6edf3;line-height:1.6;min-height:100vh}
.hero{background:linear-gradient(135deg,#0d1117 0%,#161b22 55%,#1a1f2e 100%);border-bottom:1px solid rgba(255,255,255,.08);padding:22px 28px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.logo-box{width:38px;height:38px;background:linear-gradient(135deg,#1f6feb,#388bfd);border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:19px;box-shadow:0 0 14px rgba(88,166,255,.3);flex-shrink:0}
.logo-img{width:38px;height:38px;object-fit:contain;border-radius:8px}
.bname{font-size:1.35em;font-weight:800;letter-spacing:-.4px;color:#e6edf3}
.bsub{font-size:.67em;font-weight:500;color:#8b949e;text-transform:uppercase;letter-spacing:1.3px;margin-top:1px}
.sess{display:flex;align-items:center;gap:6px;background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.22);border-radius:100px;padding:5px 12px;font-size:.69em;color:#58a6ff;white-space:nowrap;font-family:'Courier New',monospace}
.dot{width:6px;height:6px;border-radius:50%;background:#3fb950;box-shadow:0 0 6px #3fb950;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.wrap{padding:22px 28px}
.mrow{display:grid;grid-template-columns:auto 1fr;gap:14px;margin-bottom:26px;align-items:stretch}
.scard{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:13px;padding:20px 22px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:7px;min-width:155px}
.rw{position:relative;width:106px;height:106px}
.rw svg{transform:rotate(-90deg);width:106px;height:106px}
.rbg{fill:none;stroke:rgba(255,255,255,.06);stroke-width:9}
.rfg{fill:none;stroke:${scoreColor};stroke-width:9;stroke-linecap:round;stroke-dasharray:${circumference};stroke-dashoffset:${circumference};animation:rng 1.2s cubic-bezier(.4,0,.2,1) forwards .15s}
@keyframes rng{to{stroke-dashoffset:${dashOffset}}}
.rlbl{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column}
.rnum{font-size:1.6em;font-weight:800;color:${scoreColor};line-height:1}
.rsub{font-size:.58em;color:#8b949e;font-weight:500}
.sttl{font-size:.67em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#8b949e}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:9px}
.stat{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:15px 13px;display:flex;flex-direction:column;gap:4px;transition:border-color .2s,transform .15s;cursor:default}
.stat:hover{border-color:rgba(255,255,255,.16);transform:translateY(-2px)}
.sico{font-size:.95em}
.snum{font-size:1.85em;font-weight:800;line-height:1;letter-spacing:-1px}
.slbl{font-size:.63em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.7px}
.shdr{display:flex;align-items:center;gap:8px;margin-bottom:13px}
.stxt{font-size:.7em;font-weight:700;text-transform:uppercase;letter-spacing:1.1px;color:#8b949e}
.shdr::after{content:'';flex:1;height:1px;background:rgba(255,255,255,.08)}
.cbadge{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:100px;font-size:.67em;font-weight:600;padding:2px 8px;color:#8b949e}
.cards{display:flex;flex-direction:column;gap:9px}
.card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:11px;overflow:hidden;transition:border-color .2s,box-shadow .2s,transform .15s}
.card:hover{border-color:rgba(255,255,255,.15);box-shadow:0 4px 18px rgba(0,0,0,.35);transform:translateY(-1px)}
.card-hdr{display:flex;align-items:center;justify-content:space-between;padding:12px 15px;cursor:pointer;user-select:none;background:#1c2128;transition:background .15s}
.card-hdr:hover{background:rgba(255,255,255,.04)}
.lft{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.rgt{display:flex;align-items:center;gap:7px;flex-shrink:0}
.pill{padding:3px 9px;border-radius:100px;font-size:9.5px;font-weight:700;letter-spacing:.5px;white-space:nowrap}
.ctitle{font-weight:700;font-size:.87em;color:#e6edf3}
.cfile{font-size:.7em;color:#8b949e;margin-top:1px}
.conf{font-size:.69em;font-weight:600;color:#8b949e;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);border-radius:100px;padding:2px 7px}
.chev{font-size:10px;color:#484f58;transition:transform .22s ease;display:inline-block}
.chev.open{transform:rotate(180deg)}
.chl{padding:8px 15px 10px;font-size:.8em;color:#8b949e;border-top:1px solid rgba(255,255,255,.08)}
.cbody{display:none;padding:16px 15px;border-top:1px solid rgba(255,255,255,.08);background:#0d1117}
.cbody.open{display:block;animation:sl .18s ease}
@keyframes sl{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:translateY(0)}}
.dlbl{font-size:.66em;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#8b949e;margin-bottom:6px;margin-top:13px}
.dlbl:first-child{margin-top:0}
.dtxt{font-size:.84em;color:#e6edf3}
.cmp{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin:9px 0 3px}
.clbl{font-size:.63em;font-weight:700;letter-spacing:.7px;text-transform:uppercase;padding:4px 9px;border-radius:5px 5px 0 0}
.dlbl-d{background:rgba(244,112,103,.12);color:#f47067}
.dlbl-s{background:rgba(63,185,80,.1);color:#3fb950}
pre{font-family:'Cascadia Code','Fira Code','Courier New',monospace;font-size:11px;padding:10px 11px;background:rgba(0,0,0,.35);border-radius:0 0 5px 5px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;color:#e6edf3}
.pre-d{border:1px solid rgba(244,112,103,.22);border-top:none}
.pre-s{border:1px solid rgba(63,185,80,.17);border-top:none}
.atk{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.2);border-radius:7px;padding:9px 11px;font-size:.79em;white-space:pre-wrap;font-family:'Cascadia Code','Fira Code','Courier New',monospace;color:#d29922;margin-bottom:3px}
.fix{background:rgba(63,185,80,.07);border:1px solid rgba(63,185,80,.16);border-radius:7px;padding:9px 11px;font-size:.82em;color:#3fb950;margin-top:9px}
.empty{text-align:center;padding:56px 20px;color:#8b949e}
.eico{font-size:3em;margin-bottom:11px;filter:drop-shadow(0 0 16px rgba(63,185,80,.5))}
.ettl{font-size:1.02em;font-weight:700;color:#3fb950;margin-bottom:4px}
.esub{font-size:.82em}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.18)}
@media(max-width:580px){.mrow{grid-template-columns:1fr}.cmp{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="hero">
  <div class="brand">
    ${logoUri ? `<img src="${logoUri}" alt="Sentinel" class="logo-img">` : `<div class="logo-box">&#x1F6E1;</div>`}
    <div>
      <div class="bname">Sentinel</div>
      <div class="bsub">Security Dashboard</div>
    </div>
  </div>
  <div class="sess"><span class="dot"></span>${escHtml(eventClient?.getSessionId() ?? 'N/A')}</div>
</div>
<div class="wrap">
  <div class="mrow">
    <div class="scard">
      <div class="rw">
        <svg viewBox="0 0 106 106">
          <circle class="rbg" cx="53" cy="53" r="44"/>
          <circle class="rfg" cx="53" cy="53" r="44"/>
        </svg>
        <div class="rlbl">
          <span class="rnum">${scoreRaw}</span>
          <span class="rsub">/ 100</span>
        </div>
      </div>
      <div class="sttl">Security Score</div>
    </div>
    <div class="sgrid">
      <div class="stat"><div class="sico">&#x1F6A8;</div><div class="snum" style="color:#f47067">${summary.criticalCount}</div><div class="slbl">Critical</div></div>
      <div class="stat"><div class="sico">&#x1F534;</div><div class="snum" style="color:#f0883e">${summary.highCount}</div><div class="slbl">High</div></div>
      <div class="stat"><div class="sico">&#x1F7E0;</div><div class="snum" style="color:#d29922">${summary.mediumCount}</div><div class="slbl">Medium</div></div>
      <div class="stat"><div class="sico">&#x1F4CB;</div><div class="snum">${summary.totalFindings}</div><div class="slbl">Total</div></div>
      <div class="stat"><div class="sico">&#x2699;&#xFE0F;</div><div class="snum" style="color:#58a6ff">${analyzer?.getRules().length ?? 0}</div><div class="slbl">Rules</div></div>
    </div>
  </div>
  <div class="shdr">
    <span class="stxt">Detected Vulnerabilities</span>
    <span class="cbadge">${findings.length}</span>
  </div>
  ${findings.length === 0
    ? `<div class="empty"><div class="eico">&#x2705;</div><div class="ettl">All Clear</div><div class="esub">No vulnerabilities detected in open files.</div></div>`
    : `<div class="cards">${findingCards}</div>`}
</div>
<script>
function tog(id){
  var b=document.getElementById('body-'+id),c=document.getElementById('chev-'+id);
  if(!b||!c)return;
  var o=b.classList.contains('open');
  b.classList.toggle('open',!o);
  c.classList.toggle('open',!o);
}
var h=document.querySelector('.card-hdr');
if(h){var el=h.parentElement;if(el&&el.id)tog(el.id.replace('card-',''));}
</script>
</body>
</html>`;
}
function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
