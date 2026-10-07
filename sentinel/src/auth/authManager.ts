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
  /** Raw VS Code GitHub access token (used for API calls) */
  githubAccessToken?: string;
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

const SESSION_KEY = 'sentinel.authSession';
const USERS_FILE  = 'users.json';

// GitHub OAuth scopes we need:
//   read:user  → access profile (login, name, avatar)
//   user:email → access primary email
const GITHUB_SCOPES = ['read:user', 'user:email'];

// ─── AuthManager ──────────────────────────────────────────────────────────────

export class AuthManager {
  private users: User[] = [];
  private readonly dataDir: string;

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
   *
   * On success:
   *   1. Fetches the GitHub user profile via the REST API.
   *   2. Auto-provisions a local user record if none exists for this GitHub login.
   *   3. Updates the cached avatar URL and display name.
   *   4. Persists the AuthSession.
   *
   * @returns The new AuthSession on success, or null on failure/cancellation.
   */
  async loginWithGitHub(silent: boolean = false): Promise<AuthSession | null> {
    try {
      const vsSession = await vscode.authentication.getSession(
        'github',
        GITHUB_SCOPES,
        { silent, createIfNone: !silent },
      );

      if (!vsSession) {
        return null; // User cancelled or silent refresh found nothing
      }

      const profile = await this.fetchGitHubProfile(vsSession.accessToken);
      if (!profile) {
        return null;
      }

      // Find or auto-provision a local user for this GitHub account
      const user = this.findOrProvisionGitHubUser(profile);

      const session: AuthSession = {
        userId:            user.id,
        username:          user.username,
        displayName:       profile.name ?? profile.login,
        role:              user.role,
        email:             profile.email ?? user.email,
        loggedInAt:        new Date().toISOString(),
        authMethod:        'github',
        githubUsername:    profile.login,
        githubAvatarUrl:   profile.avatar_url,
        githubName:        profile.name ?? profile.login,
        githubAccessToken: vsSession.accessToken,
      };

      await this.context.workspaceState.update(SESSION_KEY, session);

      console.log(
        `[AuthManager] GitHub login: ${profile.login} → role: ${user.role}`
      );

      return session;

    } catch (err: any) {
      // User dismissed the sign-in dialog
      if (err?.message?.includes('User did not consent')) {
        return null;
      }
      console.error('[AuthManager] GitHub login error:', err);
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
  }

  getSession(): AuthSession | undefined {
    return this.context.workspaceState.get<AuthSession>(SESSION_KEY);
  }

  isLoggedIn(): boolean {
    return !!this.getSession();
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
   */
  private async fetchGitHubProfile(
    accessToken: string
  ): Promise<GitHubUserProfile | null> {
    try {
      const response = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept:        'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent':  'Sentinel-VSCode-Extension',
        },
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        console.error(`[AuthManager] GitHub API error: ${response.status}`);
        return null;
      }

      return await response.json() as GitHubUserProfile;

    } catch (err) {
      console.error('[AuthManager] Failed to fetch GitHub profile:', err);
      return null;
    }
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
