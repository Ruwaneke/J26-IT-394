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
import { AuthManager } from './auth/authManager.js';
import { buildLoginHtml } from './webview/loginView.js';
import { buildDeveloperDashboardHtml } from './webview/developerDashboard.js';
import { buildSupervisorDashboardHtml } from './webview/supervisorDashboard.js';
import { buildAdminDashboardHtml } from './webview/adminDashboard.js';
import { AIEnhancedAnalyzer, AIEnhancedAnalyzerConfig } from './ai/aiEnhancedAnalyzer.js';
import { DeveloperLearningStore } from './ai/developerLearningStore.js';
import { ProjectStore, SessionFinding } from './data/projectStore.js';

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

  // Initialise developer record store — persists findings to src/DATA/<developerId>_vulnerability_records.json
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

  const hoverProvider = new SentinelHoverProvider(diagnosticManager);
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
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.text = '$(shield) Sentinel';
  statusBar.tooltip = 'Sentinel Security — Click to show dashboard';
  statusBar.command = 'sentinel.showDashboard';
  statusBar.show();
  context.subscriptions.push(statusBar);

  log(`Session: ${eventClient.getSessionId()}`);
  log(`Rules loaded: ${analyzer.getRules().map(r => r.ruleName).join(', ')}`);
  log(`Developer records → ${recordStore.getRecordFilePath()}`);
}

// ─── deactivate() ─────────────────────────────────────────────────────────────

export function deactivate(): void {
  diagnosticManager.dispose();
  eventClient.dispose();
  recordStore.dispose();
  outputChannel.dispose();
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
  const findings = aiAnalyzer.analyze(text, fileName, languageId, aiConfig);
  const summary  = analyzer.summarize(findings);

  // ── Step 2: Show diagnostics immediately (don't wait for AI) ────────────
  diagnosticManager.updateDiagnostics(document, findings);
  findingsCache.set(document.uri.toString(), findings);

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
    }
  }

  // ── Step 4: Report to backend (behaviour tracker) ───────────────────────
  for (const finding of findings) {
    void eventClient.reportDetection(finding);
  }

  // ── Step 5: Persist developer vulnerability record to DATA/ ─────────────
  for (const finding of findings) {
    void recordStore.save(finding, sessionId);
  }

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
    { enableScripts: false },
  );

  panel.webview.html = buildExplainHtml(finding, meta);
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
      { enableScripts: false },
    );
    panel.webview.html = buildFixHtml(finding, meta);
  }

  void eventClient.reportAction(finding, DeveloperAction.SECURE_EXAMPLE_VIEWED);
  log(`[Action] SECURE_EXAMPLE_VIEWED — ${finding.type} at line ${finding.lineNumber}`);

  // ── Learning feedback: developer viewed the fix (treat as intent to fix) ──
  resolveDeveloperId().then(developerId => {
    aiAnalyzer.recordAction(finding, 'FIXED', developerId);
    log(`[AI Learning] Recorded FIXED for ${finding.type} (dev: ${developerId})`);
  });
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

/**
 * Resolve the current developer ID.
 * Priority: GitHub username → sentinel.developerId config → 'DEV_UNKNOWN'
 */
async function resolveDeveloperId(): Promise<string> {
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

      const explainAction = new vscode.CodeAction(
        `$(book) Sentinel: Explain ${finding.type}`, vscode.CodeActionKind.QuickFix);
      explainAction.command = { command: 'sentinel.explainFinding', title: 'Explain', arguments: [{ findingId: finding.id }] };

      const fixAction = new vscode.CodeAction(
        `$(wrench) Sentinel: Show Secure Fix for ${finding.type}`, vscode.CodeActionKind.QuickFix);
      fixAction.command = { command: 'sentinel.applyFix', title: 'Show Fix', arguments: [{ findingId: finding.id }] };

      const ignoreAction = new vscode.CodeAction(
        `$(eye-closed) Sentinel: Ignore this ${finding.type} warning`, vscode.CodeActionKind.QuickFix);
      ignoreAction.command = { command: 'sentinel.ignoreFinding', title: 'Ignore', arguments: [{ findingId: finding.id }] };

      actions.push(explainAction, fixAction, ignoreAction);
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
function refreshDashboard(): void {
  if (!dashboardPanel) { return; }

  const logoUri = dashboardPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'resources', 'sentinel-logo.png')
  ).toString() + '?t=' + Date.now();

  const cspSource = dashboardPanel.webview.cspSource;
  const session   = authManager?.getSession();

  if (!session) {
    dashboardPanel.title = 'Sentinel — Login';
    dashboardPanel.webview.html = buildLoginHtml(cspSource, logoUri);
    return;
  }

  const allFindings: SecurityFinding[] = [];
  for (const findings of findingsCache.values()) { allFindings.push(...findings); }
  const summary = analyzer.summarize(allFindings);
  const dataDir = path.join(extensionContext.extensionPath, 'src', 'data');

  if (session.role === 'developer') {
    dashboardPanel.title = `Sentinel — ${session.displayName}`;
    const devId          = session.githubUsername ?? session.username;
    const assignedShifts = projectStore.getShiftsForDeveloper(devId);
    const activeSession  = projectStore.getActiveSession(devId);
    const recentSessions = projectStore.getSessionsForDeveloper(devId);
    dashboardPanel.webview.html = buildDeveloperDashboardHtml(
      summary, allFindings, session, logoUri, cspSource,
      analyzer.getRules().length,
      eventClient?.getSessionId() ?? 'N/A',
      assignedShifts,
      activeSession,
      recentSessions,
    );
  } else if (session.role === 'supervisor') {
    dashboardPanel.title = 'Sentinel — Supervisor Dashboard';
    const supId      = session.githubUsername ?? session.username;
    const projects   = projectStore.getProjects(supId);
    const shifts     = projectStore.getShifts();
    const allUsers   = authManager.getAllUsers()
      .filter(u => u.role === 'developer')
      .map(u => ({
        id: u.id, username: u.username, displayName: u.displayName,
        githubUsername: (u as any).githubUsername,
        githubAvatarUrl: (u as any).githubAvatarUrl,
      }));
    const allSessions = projectStore.getAllSessions();
    dashboardPanel.webview.html = buildSupervisorDashboardHtml(
      session, dataDir, cspSource, logoUri,
      projects, shifts, allUsers, allSessions,
    );
  } else if (session.role === 'administrator') {
    dashboardPanel.title = 'Sentinel — Admin Dashboard';
    const config = vscode.workspace.getConfiguration('sentinel');
    const packageJson = require(path.join(extensionContext.extensionPath, 'package.json'));
    dashboardPanel.webview.html = buildAdminDashboardHtml(
      session,
      authManager.getAllUsers(),
      dataDir,
      cspSource,
      logoUri,
      packageJson.version ?? '0.1.0',
      config.get<string>('backendUrl', 'http://localhost:3000'),
    );
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
  switch (message.command) {
    case 'CREATE_PROJECT': {
      const session = authManager.getSession();
      if (!session) { break; }
      const project = projectStore.createProject(
        message.name as string,
        message.description as string,
        session.githubUsername ?? session.username,
        session.displayName,
      );
      log(`📁 Project created: "${project.name}" (${project.id})`);
      refreshDashboard();
      break;
    }

    case 'CREATE_SHIFT': {
      const shift = projectStore.createShift(
        message.projectId as string,
        message.name as string,
        message.description as string,
        message.scheduledStart as string,
        message.scheduledEnd as string,
        (message.developerIds as string[]) ?? [],
        (message.developerNames as string[]) ?? [],
        authManager.getSession()?.username ?? 'unknown',
      );
      if (shift) {
        log(`📅 Shift created: "${shift.name}" in project ${shift.projectId}`);
        refreshDashboard();
      }
      break;
    }

    case 'UPDATE_SHIFT_ASSIGNMENT': {
      projectStore.updateShiftAssignments(
        message.shiftId as string,
        (message.developerIds as string[]) ?? [],
        (message.developerNames as string[]) ?? [],
      );
      log(`👥 Updated assignments for shift ${message.shiftId as string}`);
      refreshDashboard();
      break;
    }

    case 'START_SHIFT': {
      const authSession = authManager.getSession();
      if (!authSession) { break; }
      const shift = projectStore.getShift(message.shiftId as string);
      if (!shift) { break; }

      const developerId = authSession.githubUsername ?? authSession.username;
      const shiftSession = projectStore.startSession(
        shift,
        developerId,
        authSession.username,
        authSession.displayName,
        authSession.githubAvatarUrl,
      );

      activeShiftSessionId = shiftSession.id;
      log(`▶ Shift started: "${shift.name}" by ${authSession.displayName} (session: ${shiftSession.id})`);
      vscode.window.showInformationMessage(
        `🟢 Shift "${shift.name}" started! Sentinel is now tracking your vulnerabilities.`
      );
      refreshDashboard();
      break;
    }

    case 'END_SHIFT': {
      const sessionId = message.sessionId as string;
      const endedSession = projectStore.endSession(sessionId);

      activeShiftSessionId = null;

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
      const session = authManager.login(message.username as string, message.password as string);
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
      break;
    }

    case 'LOGOUT': {
      const wasUser = authManager.getSession()?.username ?? 'unknown';
      authManager.logout();
      log(`🔐 Logout: ${wasUser}`);
      refreshDashboard();
      break;
    }

    case 'ADMIN_ADD_USER': {
      const result = authManager.addUser(
        message.username as string,
        message.password as string,
        message.role as 'developer' | 'supervisor' | 'administrator',
        message.displayName as string,
        message.email as string,
      );
      log(`[Admin] Add user "${message.username as string}": ${result.message}`);
      dashboardPanel?.webview.postMessage({ command: 'ADMIN_ADD_RESULT', ...result });
      break;
    }

    case 'ADMIN_REMOVE_USER': {
      const result = authManager.removeUser(message.userId as string);
      log(`[Admin] Remove user "${message.username as string}": ${result.message}`);
      dashboardPanel?.webview.postMessage({ command: 'ADMIN_USER_RESULT', ...result });
      break;
    }

    case 'REFRESH_ADMIN': {
      refreshDashboard();
      break;
    }

    default:
      break;
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

function buildExplainHtml(finding: SecurityFinding, _meta: any): string {
  const ctx = generateContextualExplanation(finding);
  const conf = Math.round(finding.confidence * 100);
  const sevColor = finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? '#f14c4c' :
                   finding.severity === 'MEDIUM' ? '#e9a825' : '#73c991';
  const meta = VULNERABILITY_METADATA[finding.type];
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
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
      <div class="code-label safe">✅ Secure replacement</div>
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

function buildFixHtml(finding: SecurityFinding, _meta: any): string {
  const ctx = generateContextualExplanation(finding);
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
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
  <h1>✅ Secure Fix &mdash; ${finding.type.replace(/_/g, ' ')}</h1>
  <div class="subtitle">Line ${finding.lineNumber} in ${finding.fileName.split('/').pop()}</div>
  <div class="pre-danger">
    <div class="code-label danger">❌ Your vulnerable code</div>
    <pre>${escHtml(ctx.vulnerableCode)}</pre>
  </div>
  <div class="pre-safe" style="margin-top:16px">
    <div class="code-label safe">✅ Fixed version</div>
    <pre>${escHtml(ctx.fixedCode)}</pre>
  </div>
  <div class="note">💡 ${escHtml(ctx.fixExplanation)}</div>
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
