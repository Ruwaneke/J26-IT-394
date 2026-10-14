/**
 * Sentinel — Auth Manager  (v2 — GitHub OAuth + Password fallback)
 *
 * Authentication flow:
 *   PRIMARY  → GitHub OAuth via VS Code's built-in authentication provider.
 *              On success, fetches the GitHub user profile, auto-provisions
 *              a local user record (role = 'developer' for new accounts),
 *              and creates an AuthSession enriched with GitHub metadata.
 *
 *   FALLBACK → Username + SHA-256 password hash against users.json.
 *              Used by supervisors and administrators who may not have GitHub.
 *
 * Sessions are persisted to workspaceState so they survive panel close/reopen.
 * GitHub sessions are refreshed silently on every activation.
 *
 * BACKEND  → After a GitHub sign-in the access token is sent to the behaviour
 *            tracker backend (POST /api/auth/github), which verifies it with
 *            GitHub and returns the matching Developer. Its id is kept in
 *            globalState (getDeveloperId) and attached to security events.
 *            The token itself is never stored by Sentinel.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

// ─── Types ────────────────────────────────────────────────────────────────────

export type UserRole = 'developer' | 'supervisor' | 'administrator';
export type AuthMethod = 'github' | 'password';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: UserRole;
  displayName: string;
  email: string;
  createdAt: string;
  /** GitHub username — set when user first logs in via GitHub */
  githubUsername?: string;
  /** GitHub avatar URL — cached for display */
  githubAvatarUrl?: string;
}

export interface AuthSession {
  userId: string;
  username: string;
  displayName: string;
  role: UserRole;
  email: string;
  loggedInAt: string;
  /** How the user authenticated */
  authMethod: AuthMethod;
  /** GitHub-specific fields (populated when authMethod = 'github') */
  githubUsername?: string;
  githubAvatarUrl?: string;
  githubName?: string;
  /** GitHub numeric user ID (as a string) */
  githubId?: string;
}

/** Minimal shape returned by the GitHub REST API /user endpoint */
export interface GitHubUserProfile {
  login: string;           // GitHub username
  name: string | null;     // display name
  email: string | null;
  avatar_url: string;
  id: number;
  bio: string | null;
  public_repos: number;
  followers: number;
}

/** Developer returned by the backend's POST /api/auth/github (DeveloperResponse) */
export interface BackendDeveloper {
  id: number;
  developerIdentifier: string;
  githubUsername: string | null;
  email: string | null;
}

type SignInFailureKind =
  | 'invalid-token'        // GitHub rejected the access token (401)
  | 'signed-out'           // no GitHub session for this account in VS Code any more
  | 'account-conflict'     // the GitHub login is linked to another account (409)
  | 'backend-unavailable'  // backend not running, timed out or failing (5xx)
  | 'github-unavailable'   // GitHub (or the backend's call to GitHub) failed
  | 'network'              // DNS failure, connection reset, ...
  | 'unexpected';          // bad backendUrl setting, malformed response, other 4xx

/** A failed GitHub or backend sign-in, with a message that can be shown to the user. */
class SignInError extends Error {
  constructor(readonly kind: SignInFailureKind, message: string) {
    super(message);
    this.name = 'SignInError';
  }

  /** Whether trying again later with the same token can succeed */
  get retryable(): boolean {
    return this.kind !== 'invalid-token' && this.kind !== 'signed-out' && this.kind !== 'account-conflict';
  }
}

const SESSION_KEY      = 'sentinel.authSession';
const DEVELOPER_ID_KEY = 'sentinel.backendDeveloperId';
const USERS_FILE       = 'users.json';
const SIGN_IN_AGAIN    = 'Sign in again';

// The backend verifies the token with GitHub before it answers
const BACKEND_TIMEOUT_MS = 10000;
const GITHUB_TIMEOUT_MS  = 5000;

// GitHub OAuth scopes we need:
//   read:user  → access profile (login, name, avatar)
//   user:email → access primary email
const GITHUB_SCOPES = ['read:user', 'user:email'];

// ─── AuthManager ──────────────────────────────────────────────────────────────

export class AuthManager {
  private users: User[] = [];
  private readonly dataDir: string;
  /** Set when the backend rejected the token or account; background retries wait for a new sign-in */
  private backendSignInBlocked = false;
  /** Background retries report a failure once, not on every attempt, until a sign-in succeeds */
  private backgroundErrorShown = false;

  constructor(private readonly context: vscode.ExtensionContext) {
    this.dataDir = path.join(context.extensionPath, 'src', 'data');
    this.loadUsers();
  }

  // ── GitHub OAuth Authentication ──────────────────────────────────────────────

  /**
   * Attempt to authenticate via GitHub OAuth.
   *
   * Behaviour:
   *   - If `silent = true`, tries to reuse an existing GitHub session without
   *     showing a UI prompt. Used during activate() to restore login state.
   *   - If `silent = false`, shows the VS Code "Sign in with GitHub" prompt.
   *   - If `forceNewSession = true`, asks VS Code for a new GitHub token
   *     (offered after GitHub or the backend rejected the current one).
   *
   * On success:
   *   1. Fetches the GitHub user profile via the REST API.
   *   2. Auto-provisions a local user record if none exists for this GitHub login.
   *   3. Updates the cached avatar URL and display name.
   *   4. Persists the AuthSession.
   *   5. Signs in to the behaviour tracker backend with the access token and
   *      stores the returned developer id in globalState.
   *
   * Never throws. Failures are shown as VS Code error messages for an
   * interactive sign-in; a silent refresh only logs them.
   *
   * @returns The new AuthSession on success, or null on failure/cancellation.
   */
  async loginWithGitHub(silent: boolean = false, forceNewSession: boolean = false): Promise<AuthSession | null> {
    try {
      const vsSession = forceNewSession
        ? await vscode.authentication.getSession('github', GITHUB_SCOPES, {
            forceNewSession: { detail: 'Sentinel needs a new GitHub sign-in to link you to the behaviour tracker.' },
          })
        : await vscode.authentication.getSession('github', GITHUB_SCOPES, { silent, createIfNone: !silent });

      if (!vsSession) {
        return null; // User cancelled or silent refresh found nothing
      }

      const profile = await this.fetchGitHubProfile(vsSession.accessToken);

      // Find or auto-provision a local user for this GitHub account
      const user = this.findOrProvisionGitHubUser(profile);

      const session: AuthSession = {
        userId:          user.id,
        username:        user.username,
        displayName:     profile.name ?? profile.login,
        role:            user.role,
        email:           profile.email ?? user.email,
        loggedInAt:      new Date().toISOString(),
        authMethod:      'github',
        githubUsername:  profile.login,
        githubAvatarUrl: profile.avatar_url,
        githubName:      profile.name ?? profile.login,
        githubId:        String(profile.id),
      };

      await this.context.workspaceState.update(SESSION_KEY, session);

      console.log(
        `[AuthManager] GitHub login: ${profile.login} → role: ${user.role}`
      );

      // Link the GitHub identity to a backend developer. The previous id is cleared
      // first so events are never sent under another account's id. Not fatal for
      // the local session: ensureBackendDeveloperId() retries when events are sent.
      this.backendSignInBlocked = false;
      await this.clearDeveloperId();
      await this.signInToBackend(vsSession.accessToken, silent ? 'background' : 'interactive');

      return session;

    } catch (err) {
      // User dismissed the sign-in dialog
      if (isUserCancellation(err)) {
        return null;
      }
      console.error('[AuthManager] GitHub login error:', err);
      if (!silent) {
        this.showSignInError(toSignInError(err));
      }
      return null;
    }
  }

  /**
   * Silently refresh GitHub session on extension activate.
   * Restores the active session without prompting if one already exists.
   */
  async refreshGitHubSession(): Promise<AuthSession | null> {
    return this.loginWithGitHub(true);
  }

  // ── Password Authentication (fallback) ──────────────────────────────────────

  /**
   * Authenticate with username + password (SHA-256).
   * Used for supervisor and administrator accounts.
   */
  login(username: string, password: string): AuthSession | null {
    this.loadUsers();
    const hash = AuthManager.hashPassword(password);
    const user = this.users.find(
      u => u.username === username && u.passwordHash === hash
    );

    if (!user) { return null; }

    const session: AuthSession = {
      userId:      user.id,
      username:    user.username,
      displayName: user.displayName,
      role:        user.role,
      email:       user.email,
      loggedInAt:  new Date().toISOString(),
      authMethod:  'password',
    };

    void this.context.workspaceState.update(SESSION_KEY, session);
    return session;
  }

  // ── Session Management ───────────────────────────────────────────────────────

  logout(): void {
    void this.context.workspaceState.update(SESSION_KEY, undefined);
    void this.clearDeveloperId();
    this.backendSignInBlocked = false;
  }

  getSession(): AuthSession | undefined {
    return this.context.workspaceState.get<AuthSession>(SESSION_KEY);
  }

  isLoggedIn(): boolean {
    return !!this.getSession();
  }

  // ── Backend Developer ID (globalState) ──────────────────────────────────────

  /** Backend Developer.id of the signed-in GitHub user, or undefined if not obtained yet. */
  getDeveloperId(): number | undefined {
    const id = this.context.globalState.get<unknown>(DEVELOPER_ID_KEY);
    return typeof id === 'number' && Number.isSafeInteger(id) && id > 0 ? id : undefined;
  }

  async setDeveloperId(developerId: number): Promise<void> {
    await this.context.globalState.update(DEVELOPER_ID_KEY, developerId);
  }

  async clearDeveloperId(): Promise<void> {
    await this.context.globalState.update(DEVELOPER_ID_KEY, undefined);
  }

  /**
   * Return the backend developer id for the current GitHub session, signing in to
   * the backend first if it has not been obtained yet. Called before security
   * events are sent. Returns undefined for password sessions, while the backend is
   * unreachable, or after it rejected the token (until the next GitHub sign-in).
   */
  async ensureBackendDeveloperId(): Promise<number | undefined> {
    const session = this.getSession();
    if (!session || session.authMethod !== 'github' || !session.githubId) {
      return undefined;
    }
    const storedId = this.getDeveloperId();
    if (storedId !== undefined) {
      return storedId;
    }
    if (this.backendSignInBlocked) {
      return undefined;
    }

    // Sentinel does not store the token: take the current one from VS Code
    let vsSession: vscode.AuthenticationSession | undefined;
    try {
      vsSession = await vscode.authentication.getSession('github', GITHUB_SCOPES, { silent: true });
    } catch (err) {
      console.error('[AuthManager] Could not read the GitHub session:', err);
      return undefined;
    }
    if (!vsSession || vsSession.account.label !== session.githubUsername) {
      this.reportBackendFailure(new SignInError('signed-out',
        `You are no longer signed in to GitHub as @${session.githubUsername} in VS Code. ` +
        'Sign in again so your security events can be sent.'), 'background');
      return undefined;
    }
    return this.signInToBackend(vsSession.accessToken, 'background');
  }

  // ── Private: Backend Sign-in ─────────────────────────────────────────────────

  /**
   * Exchange the GitHub access token for the backend developer and store its id.
   * Never throws: a failure is logged and reported (see reportBackendFailure).
   */
  private async signInToBackend(accessToken: string, mode: 'interactive' | 'background'): Promise<number | undefined> {
    try {
      const developer = await this.postGitHubToken(accessToken);
      await this.setDeveloperId(developer.id);
      this.backgroundErrorShown = false;
      console.log(
        `[AuthManager] Backend developer id for @${developer.githubUsername ?? developer.developerIdentifier}: ${developer.id}`
      );
      return developer.id;
    } catch (err) {
      this.reportBackendFailure(toSignInError(err), mode);
      return undefined;
    }
  }

  /**
   * POST /api/auth/github with the access token only. The backend verifies it
   * with GitHub, then finds or creates the matching Developer record.
   */
  private async postGitHubToken(accessToken: string): Promise<BackendDeveloper> {
    const backendUrl = vscode.workspace.getConfiguration('sentinel')
      .get<string>('backendUrl') ?? 'http://localhost:8080';

    const response = await fetch(`${backendUrl}/api/auth/github`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body:    JSON.stringify({ githubAccessToken: accessToken }),
      signal:  AbortSignal.timeout(BACKEND_TIMEOUT_MS),
    }).catch((err: unknown) => {
      throw backendConnectionError(err, backendUrl);
    });

    if (!response.ok) {
      const detail = await readErrorMessage(response);
      if (response.status === 401) {
        throw new SignInError('invalid-token', 'GitHub rejected your sign-in token. Sign in to GitHub again.');
      }
      if (response.status === 409) {
        throw new SignInError('account-conflict',
          detail ?? 'This GitHub login is already linked to a different account in the behaviour tracker.');
      }
      if (response.status === 502 && detail) {
        // GitHubApiException: the backend is up but could not reach GitHub
        throw new SignInError('github-unavailable', 'The Sentinel backend could not reach GitHub to verify your sign-in.');
      }
      if (response.status >= 500) {
        throw new SignInError('backend-unavailable',
          `The Sentinel backend at ${backendUrl} returned an error (HTTP ${response.status}).`);
      }
      throw new SignInError('unexpected',
        `The Sentinel backend refused the sign-in (HTTP ${response.status})${detail ? `: ${detail}` : '.'}`);
    }

    const developer: unknown = await response.json().catch(() => undefined);
    if (!isBackendDeveloper(developer)) {
      throw new SignInError('unexpected', 'The Sentinel backend returned an unexpected sign-in response.');
    }
    return developer;
  }

  /**
   * Log a sign-in failure and show it as a VS Code error message: always for an
   * interactive sign-in, once per run of failures for background retries.
   */
  private reportBackendFailure(failure: SignInError, mode: 'interactive' | 'background'): void {
    console.error(`[AuthManager] Backend sign-in failed (${failure.kind}): ${failure.message}`);
    if (!failure.retryable) {
      // The same token or account would be rejected again
      this.backendSignInBlocked = true;
    }
    if (mode === 'interactive' || !this.backgroundErrorShown) {
      this.backgroundErrorShown = true;
      this.showSignInError(failure);
    }
  }

  private showSignInError(failure: SignInError): void {
    const consequence = failure.retryable
      ? ' Security events are kept and sent once sign-in succeeds.'
      : '';
    const message = `Sentinel: ${failure.message}${consequence}`;

    if (failure.kind === 'invalid-token' || failure.kind === 'signed-out') {
      void vscode.window.showErrorMessage(message, SIGN_IN_AGAIN).then(choice => {
        if (choice === SIGN_IN_AGAIN) {
          void this.loginWithGitHub(false, true);
        }
      });
      return;
    }
    void vscode.window.showErrorMessage(message);
  }

  // ── User Store ──────────────────────────────────────────────────────────────

  private loadUsers(): void {
    try {
      const filePath = path.join(this.dataDir, USERS_FILE);
      const raw = fs.readFileSync(filePath, 'utf8');
      this.users = JSON.parse(raw) as User[];
    } catch {
      this.users = [];
    }
  }

  private saveUsers(): void {
    try {
      const filePath = path.join(this.dataDir, USERS_FILE);
      fs.writeFileSync(filePath, JSON.stringify(this.users, null, 2), 'utf8');
    } catch {
      // Ignore write errors in read-only environments
    }
  }

  getAllUsers(): Omit<User, 'passwordHash'>[] {
    this.loadUsers();
    return this.users.map(({ passwordHash: _ph, ...u }) => u);
  }

  // ── Crypto ──────────────────────────────────────────────────────────────────

  static hashPassword(password: string): string {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  // ── Admin: User Management ──────────────────────────────────────────────────

  addUser(
    username: string,
    password: string,
    role: UserRole,
    displayName: string,
    email: string
  ): { success: boolean; message: string } {
    this.loadUsers();

    if (this.users.find(u => u.username === username)) {
      return { success: false, message: `Username "${username}" already exists.` };
    }

    const newUser: User = {
      id: `user-${role.substring(0, 3)}-${Date.now()}`,
      username,
      passwordHash: AuthManager.hashPassword(password),
      role,
      displayName,
      email,
      createdAt: new Date().toISOString(),
    };

    this.users.push(newUser);
    this.saveUsers();
    return { success: true, message: `User "${username}" created successfully.` };
  }

  removeUser(userId: string): { success: boolean; message: string } {
    this.loadUsers();
    const idx = this.users.findIndex(u => u.id === userId);
    if (idx === -1) {
      return { success: false, message: 'User not found.' };
    }
    const removed = this.users[idx];
    if (
      removed.role === 'administrator' &&
      this.users.filter(u => u.role === 'administrator').length <= 1
    ) {
      return { success: false, message: 'Cannot remove the last administrator.' };
    }
    this.users.splice(idx, 1);
    this.saveUsers();
    return { success: true, message: `User "${removed.username}" removed.` };
  }

  // ── Private: GitHub Helpers ──────────────────────────────────────────────────

  /**
   * Call the GitHub REST API to fetch the authenticated user's profile.
   * Throws a SignInError if GitHub rejects the token or cannot be reached.
   */
  private async fetchGitHubProfile(accessToken: string): Promise<GitHubUserProfile> {
    const response = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept:        'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent':  'Sentinel-VSCode-Extension',
      },
      signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
    }).catch((err: unknown) => {
      throw githubConnectionError(err);
    });

    if (response.status === 401) {
      throw new SignInError('invalid-token', 'GitHub rejected your sign-in token. Sign in to GitHub again.');
    }
    if (!response.ok) {
      throw new SignInError('github-unavailable',
        `GitHub returned HTTP ${response.status} while loading your profile. Try again later.`);
    }
    return await response.json() as GitHubUserProfile;
  }

  /**
   * Find an existing local user whose githubUsername matches the profile login,
   * or provision a new developer account automatically.
   *
   * Provisioning rules:
   *   - New GitHub users → role: 'developer'
   *   - Existing password users linked by githubUsername → keep their role
   */
  private findOrProvisionGitHubUser(profile: GitHubUserProfile): User {
    this.loadUsers();

    // 1. Look for an existing user already linked to this GitHub account
    let user = this.users.find(u => u.githubUsername === profile.login);

    // 2. Look for a user whose username matches the GitHub login
    if (!user) {
      user = this.users.find(u => u.username === profile.login);
    }

    // 3. Auto-provision a new developer account
    if (!user) {
      user = {
        id:              `user-dev-gh-${Date.now()}`,
        username:        profile.login,
        passwordHash:    '', // GitHub-only accounts have no password
        role:            'developer',
        displayName:     profile.name ?? profile.login,
        email:           profile.email ?? `${profile.login}@github.com`,
        createdAt:       new Date().toISOString(),
        githubUsername:  profile.login,
        githubAvatarUrl: profile.avatar_url,
      };
      this.users.push(user);
      console.log(`[AuthManager] Auto-provisioned new developer: ${profile.login}`);
    }

    // 4. Update GitHub metadata on existing user if changed
    if (user.githubUsername !== profile.login || user.githubAvatarUrl !== profile.avatar_url) {
      user.githubUsername  = profile.login;
      user.githubAvatarUrl = profile.avatar_url;
      if (!user.displayName || user.displayName === user.username) {
        user.displayName = profile.name ?? profile.login;
      }
    }

    this.saveUsers();
    return user;
  }
}

// ─── Sign-in Error Helpers ────────────────────────────────────────────────────

function errorName(err: unknown): string | undefined {
  return (err as { name?: string } | undefined)?.name;
}

/** Node's fetch reports connection problems as TypeError('fetch failed') with the reason in `cause.code` */
function errorCode(err: unknown): string | undefined {
  const e = err as { code?: string; cause?: { code?: string } } | undefined;
  return e?.cause?.code ?? e?.code;
}

function backendConnectionError(err: unknown, backendUrl: string): SignInError {
  const code = errorCode(err);
  if (code === 'ERR_INVALID_URL') {
    return new SignInError('unexpected', `The sentinel.backendUrl setting is not a valid URL: "${backendUrl}".`);
  }
  if (errorName(err) === 'TimeoutError') {
    return new SignInError('backend-unavailable',
      `The Sentinel backend at ${backendUrl} did not respond within ${BACKEND_TIMEOUT_MS / 1000} seconds.`);
  }
  if (code === 'ECONNREFUSED') {
    return new SignInError('backend-unavailable',
      `Cannot reach the Sentinel backend at ${backendUrl}. Make sure it is running.`);
  }
  return new SignInError('network',
    `Network error while contacting the Sentinel backend at ${backendUrl}${code ? ` (${code})` : ''}.`);
}

function githubConnectionError(err: unknown): SignInError {
  if (errorName(err) === 'TimeoutError') {
    return new SignInError('network', `GitHub did not respond within ${GITHUB_TIMEOUT_MS / 1000} seconds.`);
  }
  const code = errorCode(err);
  return new SignInError('network', `Cannot reach GitHub${code ? ` (${code})` : ''}. Check your internet connection.`);
}

function toSignInError(err: unknown): SignInError {
  if (err instanceof SignInError) {
    return err;
  }
  return new SignInError('unexpected', `Sign-in failed: ${err instanceof Error ? err.message : String(err)}`);
}

/** The `message` of the backend's ApiErrorResponse body, if there is one */
async function readErrorMessage(response: { json(): Promise<unknown> }): Promise<string | undefined> {
  try {
    const body = await response.json() as { message?: unknown } | null;
    return typeof body?.message === 'string' && body.message.trim() ? body.message : undefined;
  } catch {
    return undefined;
  }
}

function isBackendDeveloper(value: unknown): value is BackendDeveloper {
  const id = (value as { id?: unknown } | null)?.id;
  return typeof id === 'number' && Number.isSafeInteger(id) && id > 0;
}

/** VS Code rejects getSession when the user dismisses the GitHub sign-in prompt */
function isUserCancellation(err: unknown): boolean {
  const message = err instanceof Error ? err.message : '';
  return message.includes('User did not consent') || message === 'Cancelled';
}
