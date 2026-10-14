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
import * as vscode from 'vscode';
import { NeonDatabaseService, DbUser } from '../data/neonDatabaseService.js';

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
const SIGNED_OUT_KEY = 'sentinel.signedOut';

// GitHub OAuth scopes we need:
//   read:user  → access profile (login, name, avatar)
//   user:email → access primary email
const GITHUB_SCOPES = ['read:user', 'user:email'];

// ─── AuthManager ──────────────────────────────────────────────────────────────

export class AuthManager {
  constructor(private readonly context: vscode.ExtensionContext) {}

  /** Returns the DB service after making sure the connection is initialised. */
  private static async db(): Promise<NeonDatabaseService> {
    const db = NeonDatabaseService.getInstance();
    await db.initialize();
    return db;
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
      // After an explicit sign-out, force a brand-new GitHub sign-in (browser prompt)
      // instead of silently reusing the account VS Code remembers.
      const signedOut = this.context.globalState.get<boolean>(SIGNED_OUT_KEY, false);
      const options: vscode.AuthenticationGetSessionOptions = silent
        ? { silent: true }
        : signedOut
          ? { forceNewSession: { detail: 'Sign in to Sentinel with your GitHub account.' } }
          : { createIfNone: true };
      const vsSession = await vscode.authentication.getSession('github', GITHUB_SCOPES, options);

      if (!vsSession) {
        return null; // User cancelled or silent refresh found nothing
      }

      const profile = await this.fetchGitHubProfile(vsSession.accessToken);
      if (!profile) {
        return null;
      }

      // Find or auto-provision a local user for this GitHub account
      const user = await this.findOrProvisionGitHubUser(profile);

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
      await this.context.globalState.update(SIGNED_OUT_KEY, false);

      // Sync to Neon PostgreSQL
      void NeonDatabaseService.getInstance().upsertGitHubUser({
        login: profile.login,
        name: profile.name ?? profile.login,
        email: profile.email ?? `${profile.login}@github.com`,
        avatar_url: profile.avatar_url,
        role: user.role,
      }).then(() => {
        void NeonDatabaseService.getInstance().logActivity({
          developerId: profile.login,
          username: profile.login,
          actionType: 'GITHUB_LOGIN',
          details: { role: user.role, name: profile.name },
        });
      });

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
   * Switch or pick the active developer by their GitHub username.
   * Enables selecting a developer from the team roster or entering a GitHub username.
   */
  async pickDeveloperByGitHub(githubUsername: string): Promise<AuthSession | null> {
    const cleanGh = githubUsername.trim().replace(/^@/, '');
    if (!cleanGh) { return null; }

    const db = await AuthManager.db();
    // 1. Check Neon PostgreSQL
    try {
      const dbUser = await db.getUserByUsernameOrGitHub(cleanGh);
      if (dbUser) {
        const session: AuthSession = {
          userId:          dbUser.id,
          username:        dbUser.username,
          displayName:     dbUser.displayName,
          role:            dbUser.role,
          email:           dbUser.email,
          loggedInAt:      new Date().toISOString(),
          authMethod:      'github',
          githubUsername:  dbUser.githubUsername || dbUser.username,
          githubAvatarUrl: dbUser.githubAvatarUrl || `https://avatars.githubusercontent.com/${cleanGh}`,
          githubName:      dbUser.displayName,
        };
        await this.context.workspaceState.update(SESSION_KEY, session);
        await db.updateLastLogin(dbUser.id);
        await db.logActivity({
          developerId: session.githubUsername || session.username,
          username: session.username,
          actionType: 'DEVELOPER_SELECTED',
          details: { githubUsername: cleanGh },
        });
        console.log(`[AuthManager] Picked developer from Neon DB: @${cleanGh}`);
        return session;
      }
    } catch (err) {
      console.warn('[AuthManager] Could not lookup developer in DB, checking local store:', err);
    }

    // 2. Not found in DB — provision as a new developer directly in the DB
    const user = AuthManager.toUser(await db.upsertGitHubUser({
      login: cleanGh,
      name: cleanGh,
      avatar_url: `https://avatars.githubusercontent.com/${cleanGh}`,
      role: 'developer',
    }));

    const session: AuthSession = {
      userId:          user.id,
      username:        user.username,
      displayName:     user.displayName,
      role:            user.role,
      email:           user.email,
      loggedInAt:      new Date().toISOString(),
      authMethod:      'github',
      githubUsername:  user.githubUsername || user.username,
      githubAvatarUrl: user.githubAvatarUrl,
      githubName:      user.displayName,
    };

    await this.context.workspaceState.update(SESSION_KEY, session);
    console.log(`[AuthManager] Picked & provisioned developer: @${cleanGh}`);
    return session;
  }

  /**
   * Silently refresh GitHub session on extension activate.
   * Restores the active session without prompting if one already exists.
   */
  async refreshGitHubSession(): Promise<AuthSession | null> {
    // Respect an explicit sign-out: never auto-restore until the user signs in again.
    if (this.context.globalState.get<boolean>(SIGNED_OUT_KEY, false)) {
      return null;
    }
    return this.loginWithGitHub(true);
  }

  // ── Password Authentication (fallback) ──────────────────────────────────────

  /**
   * Authenticate with username + password (SHA-256).
   * Used for supervisor and administrator accounts.
   */
  async login(username: string, password: string): Promise<AuthSession | null> {
    const hash = AuthManager.hashPassword(password);
    const dbUser = await (await AuthManager.db()).getUserByUsernameOrGitHub(username);
    if (!dbUser || dbUser.username !== username || !dbUser.passwordHash || dbUser.passwordHash !== hash) {
      return null;
    }
    const user = AuthManager.toUser(dbUser);

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
    void this.context.globalState.update(SIGNED_OUT_KEY, true);
  }

  getSession(): AuthSession | undefined {
    return this.context.workspaceState.get<AuthSession>(SESSION_KEY);
  }

  isLoggedIn(): boolean {
    return !!this.getSession();
  }

  // ── User Store (Neon PostgreSQL only) ───────────────────────────────────────

  async getAllUsers(): Promise<Omit<User, 'passwordHash'>[]> {
    const rows = await (await AuthManager.db()).getAllUsers();
    return rows.map(r => {
      const { passwordHash: _ph, ...u } = AuthManager.toUser(r);
      return u;
    });
  }

  // ── Crypto ──────────────────────────────────────────────────────────────────

  static hashPassword(password: string): string {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  // ── Admin: User Management ──────────────────────────────────────────────────

  async addUser(
    username: string,
    password: string,
    role: UserRole,
    displayName: string,
    email: string
  ): Promise<{ success: boolean; message: string }> {
    const { success, message } = await (await AuthManager.db()).addUser(
      username, AuthManager.hashPassword(password), role, displayName, email,
    );
    return { success, message };
  }

  async removeUser(userId: string): Promise<{ success: boolean; message: string }> {
    const db = await AuthManager.db();
    const users = await db.getAllUsers();
    const target = users.find(u => u.id === userId);
    if (!target) {
      return { success: false, message: 'User not found.' };
    }
    if (
      target.role === 'administrator' &&
      users.filter(u => u.role === 'administrator').length <= 1
    ) {
      return { success: false, message: 'Cannot remove the last administrator.' };
    }
    return db.removeUser(userId);
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
  private async findOrProvisionGitHubUser(profile: GitHubUserProfile): Promise<User> {
    const db = await AuthManager.db();
    // Existing role is preserved by the DB upsert; new accounts become 'developer'.
    const dbUser = await db.upsertGitHubUser({
      login:      profile.login,
      name:       profile.name ?? profile.login,
      email:      profile.email ?? `${profile.login}@github.com`,
      avatar_url: profile.avatar_url,
    });
    return AuthManager.toUser(dbUser);
  }

  private static toUser(u: DbUser): User {
    return {
      id:              u.id,
      username:        u.username,
      passwordHash:    u.passwordHash,
      role:            u.role as UserRole,
      displayName:     u.displayName,
      email:           u.email,
      createdAt:       u.createdAt,
      githubUsername:  u.githubUsername ?? undefined,
      githubAvatarUrl: u.githubAvatarUrl ?? undefined,
    };
  }
}
