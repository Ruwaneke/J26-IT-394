/**
 * Sentinel — Neon PostgreSQL Database Service
 *
 * Provides persistent database storage for:
 *   1. System Users by role (developer, supervisor, administrator)
 *      with GitHub username mapping & avatar caching.
 *   2. Vulnerability Records per developer/user with lifecycle status
 *      ('OPEN', 'FIXED', 'IGNORED', 'FALSE_POSITIVE'),
 *      root-cause explanation (Why it is vulnerable),
 *      and remediation guidance (How to fix + secure replacement code).
 *   3. User Activity & Audit Logs tracking all user actions in the system.
 *   4. Projects & Shifts management metadata.
 *
 * Connected to Neon Serverless PostgreSQL with SSL.
 * Automatically provisions tables and seeds initial users if empty.
 * Provides offline fallback if database is momentarily unreachable.
 */

import { Pool, PoolConfig, QueryResult } from 'pg';
import * as fs from 'fs';
import * as path from 'path';
import { SecurityFinding, VulnerabilityType } from '../analyzer/types.js';
import { ContextualExplanation } from '../diagnostics/contextualExplainer.js';

// ─── Interfaces ───────────────────────────────────────────────────────────────

export type UserRole = 'developer' | 'supervisor' | 'administrator';
export type VulnerabilityStatus = 'OPEN' | 'FIXED' | 'IGNORED' | 'FALSE_POSITIVE';

export interface DbUser {
  id: string;
  username: string;
  githubUsername: string | null;
  passwordHash: string;
  role: UserRole;
  displayName: string;
  email: string;
  githubAvatarUrl: string | null;
  createdAt: string;
  lastLoginAt: string;
}

export interface DbVulnerabilityRecord {
  recordId: string;
  findingId: string;
  developerId: string;
  githubUsername: string | null;
  sessionId: string;
  shiftId: string | null;
  vulnerabilityType: string;
  severity: string;
  confidence: number;
  fileName: string;
  lineNumber: number;
  columnNumber: number;
  codeSnippet: string;
  whyVulnerable: string;
  howToFix: string;
  fixedCode: string;
  attackScenario: string;
  status: VulnerabilityStatus;
  detectedByRule: string;
  detectedAt: string;
  fixedAt: string | null;
  updatedAt: string;
}

export interface VulnerabilityStats {
  totalIdentified: number;
  fixedCount: number;
  openCount: number;
  ignoredCount: number;
  fixPercentage: number;
  openPercentage: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  byType: Record<string, number>;
  byStatus: Record<string, number>;
}

export interface UserActivityLog {
  id: string;
  userId?: string;
  username?: string;
  developerId?: string;
  githubUsername?: string;
  actionType: string;
  findingId?: string;
  vulnerabilityType?: string;
  details?: any;
  createdAt: string;
}

// ─── Default Connection Config (Neon DB) ──────────────────────────────────────

export const DEFAULT_POSTGRES_CONFIG = {
  host: process.env.PGHOST || 'ep-silent-art-b48vcnb1-pooler.c-6.us-east-2.aws.neon.tech',
  database: process.env.PGDATABASE || 'neondb',
  user: process.env.PGUSER || 'neondb_owner',
  password: process.env.PGPASSWORD || 'npg_xHO4F1ATCpZQ',
  port: parseInt(process.env.PGPORT || '5432', 10),
  ssl: {
    rejectUnauthorized: false,
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
};

// ─── Service Class ────────────────────────────────────────────────────────────

export class NeonDatabaseService {
  private static instance: NeonDatabaseService | null = null;
  private pool: Pool | null = null;
  private isInitialized = false;
  private isOnline = false;
  private lastPingMs = -1;
  private lastError: string | null = null;
  private dataDir: string;

  constructor(extensionPath?: string) {
    this.dataDir = extensionPath
      ? path.join(extensionPath, 'src', 'data')
      : path.join(__dirname, '..', 'data');
    this.initPool();
  }

  public static getInstance(extensionPath?: string): NeonDatabaseService {
    if (!NeonDatabaseService.instance) {
      NeonDatabaseService.instance = new NeonDatabaseService(extensionPath);
    }
    return NeonDatabaseService.instance;
  }

  private initPool(): void {
    try {
      this.pool = new Pool(DEFAULT_POSTGRES_CONFIG);
      this.pool.on('error', (err) => {
        console.error('[NeonDb] Unexpected pool client error:', err.message);
        this.isOnline = false;
        this.lastError = err.message;
      });
    } catch (err: any) {
      console.error('[NeonDb] Failed to instantiate pg.Pool:', err.message);
      this.pool = null;
      this.isOnline = false;
      this.lastError = err.message;
    }
  }

  // ── Database Initialization & DDL Migration ──────────────────────────────────

  private initPromise: Promise<boolean> | null = null;

  public async initialize(): Promise<boolean> {
    if (this.isInitialized && this.isOnline) {
      return true;
    }
    if (!this.initPromise) {
      this.initPromise = this.doInitialize().finally(() => { this.initPromise = null; });
    }
    return this.initPromise;
  }

  /**
   * Helper that guarantees the database is initialized and connection is verified
   * before any read or write operation executes.
   */
  public async ensureInitialized(): Promise<boolean> {
    if (this.isInitialized && this.isOnline && this.pool) {
      return true;
    }
    return this.initialize();
  }

  private async doInitialize(): Promise<boolean> {
    if (this.isInitialized && this.isOnline) {
      return true;
    }
    if (!this.pool) {
      this.initPool();
    }
    if (!this.pool) {
      return false;
    }

    const startTime = Date.now();
    try {
      // 1. Verify connection
      const pingResult = await this.pool.query('SELECT NOW() as now, current_database() as db;');
      this.lastPingMs = Date.now() - startTime;
      this.isOnline = true;
      this.lastError = null;
      console.log(`[NeonDb] Connected to Neon PostgreSQL in ${this.lastPingMs}ms (${pingResult.rows[0].db})`);

      // 2. Create Schema / Tables
      await this.pool.query(`
        -- Users table
        CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(64) PRIMARY KEY,
          username VARCHAR(100) UNIQUE NOT NULL,
          github_username VARCHAR(100) UNIQUE,
          password_hash VARCHAR(128) DEFAULT '',
          role VARCHAR(32) NOT NULL DEFAULT 'developer',
          display_name VARCHAR(200) NOT NULL,
          email VARCHAR(200) DEFAULT '',
          github_avatar_url TEXT DEFAULT '',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          last_login_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        -- Vulnerability Records table
        CREATE TABLE IF NOT EXISTS vulnerability_records (
          record_id VARCHAR(64) PRIMARY KEY,
          finding_id VARCHAR(64) NOT NULL,
          developer_id VARCHAR(100) NOT NULL,
          github_username VARCHAR(100),
          session_id VARCHAR(100),
          shift_id VARCHAR(100),
          vulnerability_type VARCHAR(100) NOT NULL,
          severity VARCHAR(20) NOT NULL,
          confidence NUMERIC(5, 4) NOT NULL,
          file_name TEXT NOT NULL,
          line_number INTEGER NOT NULL,
          column_number INTEGER NOT NULL DEFAULT 0,
          code_snippet TEXT NOT NULL,
          why_vulnerable TEXT,
          how_to_fix TEXT,
          fixed_code TEXT,
          attack_scenario TEXT,
          status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
          detected_by_rule VARCHAR(100),
          detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          fixed_at TIMESTAMP WITH TIME ZONE,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_vuln_dev ON vulnerability_records(developer_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerability_records(status);
        CREATE INDEX IF NOT EXISTS idx_vuln_finding ON vulnerability_records(finding_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_file_line ON vulnerability_records(file_name, line_number);

        -- User activity / audit logs
        CREATE TABLE IF NOT EXISTS user_activity_logs (
          id VARCHAR(64) PRIMARY KEY,
          user_id VARCHAR(64),
          username VARCHAR(100),
          developer_id VARCHAR(100),
          github_username VARCHAR(100),
          action_type VARCHAR(64) NOT NULL,
          finding_id VARCHAR(64),
          vulnerability_type VARCHAR(100),
          details JSONB,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_act_dev ON user_activity_logs(developer_id);
        CREATE INDEX IF NOT EXISTS idx_act_time ON user_activity_logs(created_at DESC);

        -- Generic JSON documents (projects, shifts, sessions, learning profiles)
        CREATE TABLE IF NOT EXISTS sentinel_documents (
          collection VARCHAR(64) NOT NULL,
          doc_key VARCHAR(200) NOT NULL,
          data JSONB NOT NULL,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          PRIMARY KEY (collection, doc_key)
        );
      `);

      // 3. Seed initial users if table is empty
      await this.seedUsersIfEmpty();

      // 4. Migrate any local vulnerability records to DB
      await this.syncLocalRecordsIfEmpty();

      this.isInitialized = true;
      return true;
    } catch (err: any) {
      this.isOnline = false;
      this.lastError = err.message;
      console.error('[NeonDb] Database initialization error:', err.message);
      return false;
    }
  }

  public getStatus(): { isOnline: boolean; pingMs: number; error: string | null } {
    return {
      isOnline: this.isOnline,
      pingMs: this.lastPingMs,
      error: this.lastError,
    };
  }

  // ─── Seed & Local Sync ───────────────────────────────────────────────────────

  private async seedUsersIfEmpty(): Promise<void> {
    if (!this.pool) { return; }
    try {
      const res = await this.pool.query('SELECT COUNT(*) as count FROM users;');
      const count = parseInt(res.rows[0].count, 10);
      if (count > 0) { return; }

      let usersToSeed: any[] = [];

      if (usersToSeed.length === 0) {
        usersToSeed = [
          {
            id: 'user-adm-001',
            username: 'admin',
            passwordHash: '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
            role: 'administrator',
            displayName: 'System Admin',
            email: 'admin@sentinel-research.dev',
          },
          {
            id: 'user-sup-001',
            username: 'supervisor01',
            passwordHash: '1c8b3a939e438b44507d10fe725bc34c206a0a9d0189be00e47300b4e8e6d6d9',
            role: 'supervisor',
            displayName: 'Carol (Supervisor)',
            email: 'carol@sentinel-research.dev',
          },
          {
            id: 'user-dev-gh-hishen',
            username: 'HishenPerera',
            githubUsername: 'HishenPerera',
            passwordHash: '',
            role: 'developer',
            displayName: 'Hishen Sandaru Perera',
            email: 'hishenperera@gmail.com',
            githubAvatarUrl: 'https://avatars.githubusercontent.com/u/165247062?v=4',
          },
          {
            id: 'user-dev-001',
            username: 'dev01',
            passwordHash: '87274af01876341455b32d805946f272871bb42effa6604dccf28bb027afa82b',
            role: 'developer',
            displayName: 'Alice (Developer)',
            email: 'alice@sentinel-research.dev',
          },
        ];
      }

      for (const u of usersToSeed) {
        await this.pool.query(
          `INSERT INTO users (id, username, github_username, password_hash, role, display_name, email, github_avatar_url, created_at, last_login_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
           ON CONFLICT (username) DO NOTHING;`,
          [
            u.id || `user-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            u.username,
            u.githubUsername || null,
            u.passwordHash || '',
            u.role || 'developer',
            u.displayName || u.username,
            u.email || '',
            u.githubAvatarUrl || null,
          ]
        );
      }
      console.log(`[NeonDb] Seeded ${usersToSeed.length} initial users into users table.`);
    } catch (err: any) {
      console.error('[NeonDb] Failed to seed initial users:', err.message);
    }
  }

  /** JSON import removed — the database is the sole source of truth. */
  private async syncLocalRecordsIfEmpty(): Promise<void> {
    return;
  }

  // ─── User Management API ────────────────────────────────────────────────────

  public async getAllUsers(): Promise<DbUser[]> {
    if (!this.pool || !this.isOnline) {
      return this.getLocalUsers();
    }
    try {
      const res = await this.pool.query(
        `SELECT id, username, github_username, password_hash, role, display_name, email,
                github_avatar_url, created_at, last_login_at
         FROM users
         ORDER BY role ASC, display_name ASC;`
      );
      return res.rows.map(this.mapDbUser);
    } catch (err: any) {
      console.error('[NeonDb] getAllUsers error:', err.message);
      return this.getLocalUsers();
    }
  }

  public async getDevelopers(): Promise<DbUser[]> {
    const all = await this.getAllUsers();
    return all.filter(u => u.role === 'developer');
  }

  public async getUserByUsernameOrGitHub(usernameOrGh: string): Promise<DbUser | null> {
    if (!this.pool || !this.isOnline) {
      const local = this.getLocalUsers();
      return local.find(u => u.username === usernameOrGh || u.githubUsername === usernameOrGh) || null;
    }
    try {
      const res = await this.pool.query(
        `SELECT id, username, github_username, password_hash, role, display_name, email,
                github_avatar_url, created_at, last_login_at
         FROM users
         WHERE username = $1 OR github_username = $1
         LIMIT 1;`,
        [usernameOrGh]
      );
      if (res.rows.length === 0) { return null; }
      return this.mapDbUser(res.rows[0]);
    } catch (err: any) {
      console.error('[NeonDb] getUserByUsernameOrGitHub error:', err.message);
      return null;
    }
  }

  public async upsertGitHubUser(profile: {
    login: string;
    name?: string | null;
    email?: string | null;
    avatar_url?: string;
    role?: UserRole;
  }): Promise<DbUser> {
    const role = profile.role || 'developer';
    const displayName = profile.name || profile.login;
    const email = profile.email || `${profile.login}@github.com`;
    const avatarUrl = profile.avatar_url || '';
    const userId = `user-gh-${profile.login}`;

    if (this.pool && this.isOnline) {
      try {
        const res = await this.pool.query(
          `INSERT INTO users (id, username, github_username, password_hash, role, display_name, email, github_avatar_url, created_at, last_login_at)
           VALUES ($1, $2, $3, '', $4, $5, $6, $7, NOW(), NOW())
           ON CONFLICT (username) DO UPDATE SET
             github_username = EXCLUDED.github_username,
             display_name = EXCLUDED.display_name,
             email = EXCLUDED.email,
             github_avatar_url = EXCLUDED.github_avatar_url,
             last_login_at = NOW()
           RETURNING *;`,
          [userId, profile.login, profile.login, role, displayName, email, avatarUrl]
        );
        return this.mapDbUser(res.rows[0]);
      } catch (err: any) {
        console.error('[NeonDb] upsertGitHubUser error, falling back to local:', err.message);
      }
    }

    // Local fallback
    const user: DbUser = {
      id: userId,
      username: profile.login,
      githubUsername: profile.login,
      passwordHash: '',
      role,
      displayName,
      email,
      githubAvatarUrl: avatarUrl,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };
    this.saveLocalUser(user);
    return user;
  }

  public async addUser(
    username: string,
    passwordHash: string,
    role: UserRole,
    displayName: string,
    email: string
  ): Promise<{ success: boolean; message: string; user?: DbUser }> {
    const userId = `user-${role.slice(0, 3)}-${Date.now()}`;
    if (this.pool && this.isOnline) {
      try {
        const res = await this.pool.query(
          `INSERT INTO users (id, username, password_hash, role, display_name, email, created_at, last_login_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
           RETURNING *;`,
          [userId, username, passwordHash, role, displayName, email]
        );
        const user = this.mapDbUser(res.rows[0]);
        this.saveLocalUser(user);
        return { success: true, message: `User "${username}" created successfully.`, user };
      } catch (err: any) {
        if (err.code === '23505') {
          return { success: false, message: `Username "${username}" already exists in PostgreSQL.` };
        }
        return { success: false, message: `Failed to create user: ${err.message}` };
      }
    }

    // Local fallback
    const user: DbUser = {
      id: userId,
      username,
      githubUsername: null,
      passwordHash,
      role,
      displayName,
      email,
      githubAvatarUrl: null,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };
    this.saveLocalUser(user);
    return { success: true, message: `User "${username}" created in local store (offline mode).`, user };
  }

  public async removeUser(userId: string): Promise<{ success: boolean; message: string }> {
    if (this.pool && this.isOnline) {
      try {
        const res = await this.pool.query('DELETE FROM users WHERE id = $1 RETURNING username;', [userId]);
        if (res.rowCount && res.rowCount > 0) {
          this.removeLocalUser(userId);
          return { success: true, message: `User "${res.rows[0].username}" deleted successfully.` };
        }
        return { success: false, message: 'User not found in PostgreSQL.' };
      } catch (err: any) {
        return { success: false, message: `Failed to delete user: ${err.message}` };
      }
    }
    this.removeLocalUser(userId);
    return { success: true, message: 'User deleted from local store.' };
  }

  public async updateLastLogin(usernameOrId: string): Promise<void> {
    if (this.pool && this.isOnline) {
      try {
        await this.pool.query(
          `UPDATE users SET last_login_at = NOW() WHERE id = $1 OR username = $1 OR github_username = $1;`,
          [usernameOrId]
        );
      } catch { /* ignore */ }
    }
  }

  /** Per-developer severity counts + score, computed from the DB. */
  public async getDeveloperStatsSummary(): Promise<Array<{
    developerId: string; total: number; critical: number; high: number;
    medium: number; low: number; score: number;
  }>> {
    const map = new Map<string, { developerId: string; total: number; critical: number; high: number; medium: number; low: number; score: number }>();
    const rows: Array<{ developer_id: string; severity: string; cnt: number }> = [];
    if (this.pool && this.isOnline) {
      try {
        const res = await this.pool.query(
          `SELECT developer_id, severity, COUNT(*)::int AS cnt
           FROM vulnerability_records GROUP BY developer_id, severity;`
        );
        rows.push(...res.rows);
      } catch (err: any) {
        console.error('[NeonDb] getDeveloperStatsSummary error:', err.message);
      }
    } else {
      for (const r of this.memRecords) {
        rows.push({ developer_id: r.developerId, severity: r.severity, cnt: 1 });
      }
    }
    for (const r of rows) {
      const s = map.get(r.developer_id) ??
        { developerId: r.developer_id, total: 0, critical: 0, high: 0, medium: 0, low: 0, score: 100 };
      s.total += r.cnt;
      if (r.severity === 'CRITICAL') { s.critical += r.cnt; }
      else if (r.severity === 'HIGH') { s.high += r.cnt; }
      else if (r.severity === 'MEDIUM') { s.medium += r.cnt; }
      else { s.low += r.cnt; }
      map.set(r.developer_id, s);
    }
    for (const s of map.values()) {
      s.score = Math.max(0, 100 - s.critical * 25 - s.high * 10 - s.medium * 5 - s.low * 2);
    }
    return [...map.values()];
  }

  // ─── Administration helpers (used by DatabaseAdminService) ─────────────────

  /**
   * Run a parameterised query for the admin console. Throws when the database is offline.
   * Never pass user-supplied SQL here — callers build SQL from whitelisted identifiers only.
   */
  public async adminQuery<T = any>(sql: string, params: unknown[] = []): Promise<QueryResult<T & Record<string, any>>> {
    await this.ensureInitialized();
    if (!this.pool || !this.isOnline) {
      throw new Error(this.lastError ? `Database offline: ${this.lastError}` : 'Database offline');
    }
    return this.pool.query(sql, params as any[]);
  }

  /** Round-trip latency check; refreshes the status shown in the dashboards. */
  public async ping(): Promise<{ ok: boolean; ms: number; error: string | null }> {
    if (!this.pool) { this.initPool(); }
    const start = Date.now();
    try {
      await this.pool!.query('SELECT 1;');
      this.lastPingMs = Date.now() - start;
      this.isOnline = true;
      this.lastError = null;
      return { ok: true, ms: this.lastPingMs, error: null };
    } catch (err: any) {
      this.isOnline = false;
      this.lastError = err.message;
      return { ok: false, ms: Date.now() - start, error: err.message };
    }
  }

  /** Re-run connection check + idempotent schema migration (CREATE TABLE IF NOT EXISTS …). */
  public async reinitialize(): Promise<boolean> {
    this.isInitialized = false;
    return this.initialize();
  }

  /** Update role / display name / email. Refuses to demote the last administrator. */
  public async updateUser(
    userId: string,
    changes: { role?: UserRole; displayName?: string; email?: string },
  ): Promise<{ success: boolean; message: string }> {
    const res = await this.adminQuery('SELECT id, username, role FROM users WHERE id = $1;', [userId]);
    const target = res.rows[0];
    if (!target) { return { success: false, message: 'User not found.' }; }
    if (changes.role && changes.role !== 'administrator' && target.role === 'administrator') {
      const admins = await this.adminQuery(`SELECT COUNT(*)::int AS n FROM users WHERE role = 'administrator';`);
      if (admins.rows[0].n <= 1) {
        return { success: false, message: 'Cannot change the role of the last administrator.' };
      }
    }
    await this.adminQuery(
      `UPDATE users SET
         role = COALESCE($2::varchar, role),
         display_name = COALESCE(NULLIF($3::varchar, ''), display_name),
         email = COALESCE($4::varchar, email)
       WHERE id = $1;`,
      [userId, changes.role ?? null, changes.displayName ?? null, changes.email ?? null],
    );
    return { success: true, message: `User "${target.username}" updated.` };
  }

  // ─── Generic Document Store (JSONB) ─────────────────────────────────────────

  public async saveDocument(collection: string, key: string, data: unknown): Promise<void> {
    if (!this.pool) { return; }
    try {
      await this.initialize();
      if (!this.isOnline) { return; }
      await this.pool.query(
        `INSERT INTO sentinel_documents (collection, doc_key, data, updated_at)
         VALUES ($1, $2, $3::jsonb, NOW())
         ON CONFLICT (collection, doc_key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW();`,
        [collection, key, JSON.stringify(data)]
      );
    } catch (err: any) {
      console.error(`[NeonDb] saveDocument ${collection}/${key} error:`, err.message);
    }
  }

  public async loadCollection<T = any>(collection: string): Promise<Array<{ key: string; data: T }>> {
    if (!this.pool) { return []; }
    try {
      await this.initialize();
      if (!this.isOnline) { return []; }
      const res = await this.pool.query(
        'SELECT doc_key, data FROM sentinel_documents WHERE collection = $1;',
        [collection]
      );
      return res.rows.map(r => ({ key: r.doc_key as string, data: r.data as T }));
    } catch (err: any) {
      console.error(`[NeonDb] loadCollection ${collection} error:`, err.message);
      return [];
    }
  }

  /**
   * Insert a document only if (collection, key) does not exist yet.
   * Returns true when inserted. Used for idempotent notifications generated by several instances.
   */
  public async insertDocumentIfAbsent(collection: string, key: string, data: unknown): Promise<boolean> {
    if (!this.pool) { return false; }
    try {
      await this.initialize();
      if (!this.isOnline) { return false; }
      const res = await this.pool.query(
        `INSERT INTO sentinel_documents (collection, doc_key, data, updated_at)
         VALUES ($1, $2, $3::jsonb, NOW()) ON CONFLICT (collection, doc_key) DO NOTHING;`,
        [collection, key, JSON.stringify(data)]
      );
      return (res.rowCount ?? 0) > 0;
    } catch (err: any) {
      console.error(`[NeonDb] insertDocumentIfAbsent ${collection}/${key} error:`, err.message);
      return false;
    }
  }

  /** Load documents of a collection updated within the last `days` days. */
  public async loadRecentDocuments<T = any>(collection: string, days: number): Promise<Array<{ key: string; data: T }>> {
    if (!this.pool) { return []; }
    try {
      await this.initialize();
      if (!this.isOnline) { return []; }
      const res = await this.pool.query(
        `SELECT doc_key, data FROM sentinel_documents
         WHERE collection = $1 AND updated_at > NOW() - make_interval(days => $2)
         ORDER BY updated_at DESC LIMIT 500;`,
        [collection, days]
      );
      return res.rows.map(r => ({ key: r.doc_key as string, data: r.data as T }));
    } catch (err: any) {
      console.error(`[NeonDb] loadRecentDocuments ${collection} error:`, err.message);
      return [];
    }
  }

  /** Atomically add a value to a JSON string-array field of a document (e.g. readBy). */
  public async addToDocumentArray(collection: string, key: string, field: string, value: string): Promise<void> {
    if (!this.pool || !this.isOnline) { return; }
    try {
      await this.pool.query(
        `UPDATE sentinel_documents
           SET data = jsonb_set(data, ARRAY[$3::text],
                 COALESCE(data->$3, '[]'::jsonb) || to_jsonb($4::text), true)
         WHERE collection = $1 AND doc_key = $2
           AND NOT COALESCE(data->$3, '[]'::jsonb) ? $4::text;`,
        [collection, key, field, value]
      );
    } catch (err: any) {
      console.error(`[NeonDb] addToDocumentArray ${collection}/${key} error:`, err.message);
    }
  }

  /** Delete documents of a collection older than `days` days. */
  public async pruneDocuments(collection: string, days: number): Promise<number> {
    if (!this.pool || !this.isOnline) { return 0; }
    try {
      const res = await this.pool.query(
        `DELETE FROM sentinel_documents WHERE collection = $1 AND updated_at < NOW() - make_interval(days => $2);`,
        [collection, days]
      );
      return res.rowCount ?? 0;
    } catch { return 0; }
  }

  // ─── Vulnerability Records API ──────────────────────────────────────────────

  /**
   * Save a newly identified vulnerability record into PostgreSQL.
   * Status defaults to 'OPEN'.
   */
  public async saveVulnerabilityRecord(
    finding: SecurityFinding,
    developerId: string,
    githubUsername: string | null,
    sessionId: string,
    explanation: ContextualExplanation,
    shiftId: string | null = null
  ): Promise<DbVulnerabilityRecord> {
    const recordId = `REC-${Date.now()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;

    const record: DbVulnerabilityRecord = {
      recordId,
      findingId: finding.id,
      developerId,
      githubUsername,
      sessionId,
      shiftId,
      vulnerabilityType: finding.type,
      severity: finding.severity,
      confidence: finding.confidence,
      fileName: finding.fileName,
      lineNumber: finding.lineNumber,
      columnNumber: finding.columnNumber,
      codeSnippet: finding.codeSnippet,
      whyVulnerable: explanation.whyDangerous,
      howToFix: explanation.fixExplanation,
      fixedCode: explanation.fixedCode,
      attackScenario: explanation.attackScenario,
      status: 'OPEN',
      detectedByRule: finding.detectedByRule,
      detectedAt: finding.detectedAt || new Date().toISOString(),
      fixedAt: null,
      updatedAt: new Date().toISOString(),
    };

    // Ensure database connection is ready
    await this.ensureInitialized();

    if (this.pool && this.isOnline) {
      try {
        // Check if this finding already exists for this developer
        const existing = await this.pool.query(
          `SELECT record_id, status FROM vulnerability_records
           WHERE finding_id = $1 AND (developer_id = $2 OR github_username = $2)
           LIMIT 1;`,
          [finding.id, developerId]
        );

        if (existing.rows.length > 0) {
          const row = existing.rows[0];
          // Keep or reopen as OPEN, update line number and snippet
          await this.pool.query(
            `UPDATE vulnerability_records SET
              line_number = $1,
              column_number = $2,
              code_snippet = $3,
              why_vulnerable = $4,
              how_to_fix = $5,
              fixed_code = $6,
              attack_scenario = $7,
              status = 'OPEN',
              updated_at = NOW()
             WHERE record_id = $8;`,
            [
              finding.lineNumber,
              finding.columnNumber,
              finding.codeSnippet,
              explanation.whyDangerous,
              explanation.fixExplanation,
              explanation.fixedCode,
              explanation.attackScenario,
              row.record_id,
            ]
          );

          // Log update activity
          await this.logActivity({
            developerId,
            username: githubUsername || developerId,
            actionType: 'VULNERABILITY_UPDATED',
            findingId: finding.id,
            vulnerabilityType: finding.type,
            details: { file: finding.fileName, line: finding.lineNumber, severity: finding.severity },
          });

          return {
            ...record,
            recordId: row.record_id,
            status: 'OPEN',
          };
        }

        // Insert new record
        await this.pool.query(
          `INSERT INTO vulnerability_records (
            record_id, finding_id, developer_id, github_username, session_id, shift_id,
            vulnerability_type, severity, confidence, file_name, line_number, column_number,
            code_snippet, why_vulnerable, how_to_fix, fixed_code, attack_scenario,
            status, detected_by_rule, detected_at, fixed_at, updated_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,NULL,NOW());`,
          [
            record.recordId,
            record.findingId,
            record.developerId,
            record.githubUsername,
            record.sessionId,
            record.shiftId,
            record.vulnerabilityType,
            record.severity,
            record.confidence,
            record.fileName,
            record.lineNumber,
            record.columnNumber,
            record.codeSnippet,
            record.whyVulnerable,
            record.howToFix,
            record.fixedCode,
            record.attackScenario,
            'OPEN',
            record.detectedByRule,
            record.detectedAt,
          ]
        );

        // Log detection activity
        await this.logActivity({
          developerId,
          username: githubUsername || developerId,
          actionType: 'VULNERABILITY_DETECTED',
          findingId: finding.id,
          vulnerabilityType: finding.type,
          details: { file: finding.fileName, line: finding.lineNumber, severity: finding.severity },
        });

        console.log(`[NeonDb] Successfully saved ${record.vulnerabilityType} (${record.findingId}) for ${developerId} in ${path.basename(record.fileName)}`);
      } catch (err: any) {
        console.error('[NeonDb] saveVulnerabilityRecord error:', err.message);
      }
    }

    // Also persist to local file for safety
    this.appendLocalRecord(developerId, record);
    return record;
  }

  /**
   * Update the status of a vulnerability (e.g. to 'FIXED' or 'IGNORED').
   */
  public async updateVulnerabilityStatus(
    findingIdOrRecordId: string,
    developerId: string,
    status: VulnerabilityStatus,
    actionByUsername?: string
  ): Promise<boolean> {
    const isFixed = status === 'FIXED';
    const nowIso = new Date().toISOString();

    await this.ensureInitialized();

    if (this.pool && this.isOnline) {
      try {
        const res = await this.pool.query(
          `UPDATE vulnerability_records
           SET status = $1,
               fixed_at = ${isFixed ? 'NOW()' : 'fixed_at'},
               updated_at = NOW()
           WHERE (finding_id = $2 OR record_id = $2)
             AND ($3 = '' OR developer_id = $3 OR github_username = $3);`,
          [status, findingIdOrRecordId, developerId || '']
        );

        if (res.rowCount && res.rowCount > 0) {
          // Log user action in activity logs
          await this.logActivity({
            developerId,
            username: actionByUsername || developerId,
            actionType: isFixed ? 'VULNERABILITY_FIXED' : `VULNERABILITY_${status}`,
            findingId: findingIdOrRecordId,
            details: { newStatus: status, timestamp: nowIso },
          });
          return true;
        }
      } catch (err: any) {
        console.error('[NeonDb] updateVulnerabilityStatus error:', err.message);
      }
    }

    // Local fallback update
    this.updateLocalRecordStatus(developerId, findingIdOrRecordId, status);
    return true;
  }

  /**
   * Automatically detect when previously 'OPEN' vulnerabilities in a file
   * have been resolved (are no longer returned in currentActiveFindingIds).
   * Marks them as 'FIXED' in PostgreSQL and local memory!
   *
   * Triggers in real time as the developer edits/fixes code in the editor.
   */
  public async autoDetectFixedFindingsInFile(
    fileName: string,
    developerId: string,
    currentActiveFindingIds: string[]
  ): Promise<Array<{ findingId: string; recordId: string; vulnerabilityType: string; fileName: string; lineNumber: number }>> {
    const normFile = (fileName || '').replace(/\\/g, '/').toLowerCase();

    await this.ensureInitialized();

    if (!this.pool || !this.isOnline) {
      // Offline fallback: update in-memory records
      const toFixMem = this.memRecords.filter(r =>
        (r.developerId === developerId || r.githubUsername === developerId) &&
        (r.fileName === fileName || (r.fileName || '').replace(/\\/g, '/').toLowerCase() === normFile) &&
        r.status === 'OPEN' &&
        !currentActiveFindingIds.includes(r.findingId)
      );

      for (const fixed of toFixMem) {
        fixed.status = 'FIXED';
        fixed.fixedAt = new Date().toISOString();
        fixed.updatedAt = new Date().toISOString();
      }

      if (toFixMem.length > 0) {
        console.log(`[NeonDb-Offline] Auto-marked ${toFixMem.length} vulnerabilities as FIXED for ${developerId} in ${path.basename(fileName)}`);
      }

      return toFixMem.map(r => ({
        findingId: r.findingId,
        recordId: r.recordId,
        vulnerabilityType: r.vulnerabilityType,
        fileName: r.fileName,
        lineNumber: r.lineNumber,
      }));
    }

    try {
      // Find open records for this developer and file (path insensitive)
      const res = await this.pool.query(
        `SELECT finding_id, record_id, vulnerability_type, file_name, line_number
         FROM vulnerability_records
         WHERE (file_name = $1 OR LOWER(REPLACE(file_name, '\\', '/')) = LOWER(REPLACE($1, '\\', '/')))
           AND (developer_id = $2 OR github_username = $2)
           AND status = 'OPEN';`,
        [fileName, developerId]
      );

      const toFix = res.rows.filter(
        row => !currentActiveFindingIds.includes(row.finding_id)
      );

      if (toFix.length === 0) {
        return [];
      }

      const findingIdsToFix = toFix.map(r => r.finding_id);
      await this.pool.query(
        `UPDATE vulnerability_records
         SET status = 'FIXED',
             fixed_at = NOW(),
             updated_at = NOW()
         WHERE finding_id = ANY($1::text[])
           AND (developer_id = $2 OR github_username = $2);`,
        [findingIdsToFix, developerId]
      );

      // Log automated real-time fix event and sync local records
      for (const fixed of toFix) {
        this.updateLocalRecordStatus(developerId, fixed.finding_id, 'FIXED');
        await this.logActivity({
          developerId,
          username: developerId,
          actionType: 'CODE_FIX_DETECTED',
          findingId: fixed.finding_id,
          vulnerabilityType: fixed.vulnerability_type,
          details: { file: fileName, line: fixed.line_number, method: 'REALTIME_TYPING', timestamp: new Date().toISOString() },
        });
      }

      console.log(`[NeonDb] Real-time auto-marked ${toFix.length} vulnerabilities as FIXED for ${developerId} in ${path.basename(fileName)}`);
      return toFix.map(r => ({
        findingId: r.finding_id,
        recordId: r.record_id,
        vulnerabilityType: r.vulnerability_type,
        fileName: r.file_name,
        lineNumber: r.line_number,
      }));
    } catch (err: any) {
      console.error('[NeonDb] autoDetectFixedFindingsInFile error:', err.message);
      return [];
    }
  }

  /**
   * Clear all vulnerability records and activity logs from the database,
   * optionally filtered by developer ID.
   */
  public async clearAllVulnerabilityRecords(developerId?: string): Promise<{ success: boolean; deletedCount: number }> {
    await this.ensureInitialized();

    if (developerId) {
      this.memRecords = this.memRecords.filter(r => r.developerId !== developerId);
    } else {
      this.memRecords = [];
    }

    if (!this.pool || !this.isOnline) {
      return { success: true, deletedCount: 0 };
    }

    try {
      let query = 'DELETE FROM vulnerability_records';
      const params: any[] = [];
      if (developerId) {
        query += ' WHERE developer_id = $1 OR github_username = $1';
        params.push(developerId);
      }
      query += ';';
      const res = await this.pool.query(query, params);

      if (developerId) {
        await this.pool.query('DELETE FROM user_activity_logs WHERE developer_id = $1 OR github_username = $1;', [developerId]);
      } else {
        await this.pool.query('DELETE FROM user_activity_logs;');
      }

      console.log(`[NeonDb] Cleared vulnerability records and activity logs (${res.rowCount || 0} rows deleted).`);
      return { success: true, deletedCount: res.rowCount || 0 };
    } catch (err: any) {
      console.error('[NeonDb] clearAllVulnerabilityRecords error:', err.message);
      return { success: false, deletedCount: 0 };
    }
  }

  /**
   * Calculate precise vulnerability progress and counts for a developer or all users,
   * optionally filtered by a specific file.
   *
   * Formats precise percentage based on identified vs fixed findings count.
   */
  public async getVulnerabilityStats(developerId?: string, fileName?: string): Promise<VulnerabilityStats> {
    await this.ensureInitialized();

    const stats: VulnerabilityStats = {
      totalIdentified: 0,
      fixedCount: 0,
      openCount: 0,
      ignoredCount: 0,
      fixPercentage: 0,
      openPercentage: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      byType: {},
      byStatus: { OPEN: 0, FIXED: 0, IGNORED: 0, FALSE_POSITIVE: 0 },
    };

    if (this.pool && this.isOnline) {
      try {
        let query = `SELECT vulnerability_type, severity, status, COUNT(*) as count FROM vulnerability_records`;
        const params: any[] = [];
        const whereClauses: string[] = [];

        if (developerId) {
          params.push(developerId);
          whereClauses.push(`(developer_id = $${params.length} OR github_username = $${params.length})`);
        }

        if (fileName) {
          params.push(fileName);
          whereClauses.push(`(file_name = $${params.length} OR LOWER(REPLACE(file_name, '\\', '/')) = LOWER(REPLACE($${params.length}, '\\', '/')))`);
        }

        if (whereClauses.length > 0) {
          query += ` WHERE ` + whereClauses.join(' AND ');
        }

        query += ` GROUP BY vulnerability_type, severity, status;`;

        const res = await this.pool.query(query, params);

        for (const row of res.rows) {
          const c = parseInt(row.count, 10);
          stats.totalIdentified += c;

          if (row.status === 'FIXED') { stats.fixedCount += c; }
          else if (row.status === 'OPEN') { stats.openCount += c; }
          else if (row.status === 'IGNORED') { stats.ignoredCount += c; }

          if (row.status === 'OPEN') {
            if (row.severity === 'CRITICAL') stats.criticalCount += c;
            else if (row.severity === 'HIGH') stats.highCount += c;
            else if (row.severity === 'MEDIUM') stats.mediumCount += c;
            else if (row.severity === 'LOW') stats.lowCount += c;
          }

          stats.byStatus[row.status] = (stats.byStatus[row.status] || 0) + c;
          stats.byType[row.vulnerability_type] = (stats.byType[row.vulnerability_type] || 0) + c;
        }

        // Calculate mathematically precise percentages:
        // fixPercentage is strictly the ratio of fixed findings to total identified findings.
        // When 6 vulnerabilities exist and 0 are fixed, fixPercentage is 0.0%.
        if (stats.totalIdentified > 0) {
          stats.fixPercentage = Math.round((stats.fixedCount / stats.totalIdentified) * 1000) / 10;
          stats.openPercentage = Math.round((stats.openCount / stats.totalIdentified) * 1000) / 10;
        } else {
          stats.fixPercentage = 0.0;
          stats.openPercentage = 0.0;
        }

        return stats;
      } catch (err: any) {
        console.error('[NeonDb] getVulnerabilityStats error, using local:', err.message);
      }
    }

    // Fallback to local records calculation
    return this.calculateLocalStats(developerId, fileName);
  }

  /**
   * Fetch records for display in the modern UI.
   */
  public async getVulnerabilityRecords(
    developerId?: string,
    statusFilter?: string,
    limit = 100
  ): Promise<DbVulnerabilityRecord[]> {
    await this.ensureInitialized();
    if (this.pool && this.isOnline) {
      try {
        let sql = `SELECT record_id, finding_id, developer_id, github_username, session_id,
                          shift_id, vulnerability_type, severity, confidence, file_name,
                          line_number, column_number, code_snippet, why_vulnerable, how_to_fix,
                          fixed_code, attack_scenario, status, detected_by_rule, detected_at,
                          fixed_at, updated_at
                   FROM vulnerability_records WHERE 1=1`;
        const params: any[] = [];

        if (developerId) {
          params.push(developerId);
          sql += ` AND (developer_id = $${params.length} OR github_username = $${params.length})`;
        }
        if (statusFilter && statusFilter !== 'ALL') {
          params.push(statusFilter);
          sql += ` AND status = $${params.length}`;
        }

        sql += ` ORDER BY detected_at DESC LIMIT $${params.length + 1};`;
        params.push(limit);

        const res = await this.pool.query(sql, params);
        return res.rows.map(this.mapDbRecord);
      } catch (err: any) {
        console.error('[NeonDb] getVulnerabilityRecords error:', err.message);
      }
    }

    // Fallback
    return this.getLocalRecords(developerId, statusFilter, limit);
  }

  // ─── Activity & Audit Logs API ──────────────────────────────────────────────

  public async logActivity(activity: {
    userId?: string;
    username?: string;
    developerId?: string;
    githubUsername?: string;
    actionType: string;
    findingId?: string;
    vulnerabilityType?: string;
    details?: any;
  }): Promise<void> {
    const id = `ACT-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    await this.ensureInitialized();
    if (this.pool && this.isOnline) {
      try {
        await this.pool.query(
          `INSERT INTO user_activity_logs (id, user_id, username, developer_id, github_username, action_type, finding_id, vulnerability_type, details, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW());`,
          [
            id,
            activity.userId || null,
            activity.username || activity.developerId || 'system',
            activity.developerId || null,
            activity.githubUsername || null,
            activity.actionType,
            activity.findingId || null,
            activity.vulnerabilityType || null,
            JSON.stringify(activity.details || {}),
          ]
        );
      } catch (err: any) {
        console.error('[NeonDb] logActivity error:', err.message);
      }
    }
  }

  public async getRecentActivities(developerId?: string, limit = 20): Promise<UserActivityLog[]> {
    if (!this.pool || !this.isOnline) { return []; }
    try {
      const sql = developerId
        ? `SELECT * FROM user_activity_logs WHERE developer_id = $1 OR github_username = $1 ORDER BY created_at DESC LIMIT $2;`
        : `SELECT * FROM user_activity_logs ORDER BY created_at DESC LIMIT $1;`;
      const params = developerId ? [developerId, limit] : [limit];
      const res = await this.pool.query(sql, params);
      return res.rows.map(r => ({
        id: r.id,
        userId: r.user_id,
        username: r.username,
        developerId: r.developer_id,
        githubUsername: r.github_username,
        actionType: r.action_type,
        findingId: r.finding_id,
        vulnerabilityType: r.vulnerability_type,
        details: r.details,
        createdAt: r.created_at,
      }));
    } catch {
      return [];
    }
  }

  // ─── In-memory Offline Fallback (no JSON files are read or written) ─────────

  private memUsers: DbUser[] = [];
  private memRecords: DbVulnerabilityRecord[] = [];

  private getLocalUsers(): DbUser[] {
    return [...this.memUsers];
  }

  private saveLocalUser(user: DbUser): void {
    const idx = this.memUsers.findIndex(u => u.username === user.username);
    if (idx >= 0) { this.memUsers[idx] = user; }
    else { this.memUsers.push(user); }
  }

  private removeLocalUser(userId: string): void {
    this.memUsers = this.memUsers.filter(u => u.id !== userId);
  }

  private appendLocalRecord(_developerId: string, record: DbVulnerabilityRecord): void {
    this.memRecords.push(record);
  }

  private updateLocalRecordStatus(developerId: string, findingId: string, status: VulnerabilityStatus): void {
    for (const r of this.memRecords) {
      if (r.developerId === developerId && (r.findingId === findingId || r.recordId === findingId)) {
        r.status = status;
        if (status === 'FIXED') { (r as any).fixedAt = new Date().toISOString(); }
      }
    }
  }

  private getLocalRecords(developerId?: string, statusFilter?: string, limit = 100, fileName?: string): DbVulnerabilityRecord[] {
    const normFile = fileName ? fileName.replace(/\\/g, '/').toLowerCase() : null;
    return this.memRecords
      .filter(r => (!developerId || r.developerId === developerId || r.githubUsername === developerId)
        && (!statusFilter || statusFilter === 'ALL' || r.status === statusFilter)
        && (!normFile || r.fileName.replace(/\\/g, '/').toLowerCase() === normFile))
      .slice(0, limit);
  }

  private calculateLocalStats(developerId?: string, fileName?: string): VulnerabilityStats {
    const list = this.getLocalRecords(developerId, 'ALL', 1000, fileName);
    const stats: VulnerabilityStats = {
      totalIdentified: list.length,
      fixedCount: 0,
      openCount: 0,
      ignoredCount: 0,
      fixPercentage: 0,
      openPercentage: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      byType: {},
      byStatus: { OPEN: 0, FIXED: 0, IGNORED: 0, FALSE_POSITIVE: 0 },
    };

    for (const r of list) {
      if (r.status === 'FIXED') stats.fixedCount++;
      else if (r.status === 'IGNORED') stats.ignoredCount++;
      else {
        stats.openCount++;
        if (r.severity === 'CRITICAL') stats.criticalCount++;
        else if (r.severity === 'HIGH') stats.highCount++;
        else if (r.severity === 'MEDIUM') stats.mediumCount++;
        else stats.lowCount++;
      }
      stats.byStatus[r.status] = (stats.byStatus[r.status] || 0) + 1;
      stats.byType[r.vulnerabilityType] = (stats.byType[r.vulnerabilityType] || 0) + 1;
    }

    if (stats.totalIdentified > 0) {
      stats.fixPercentage = Math.round((stats.fixedCount / stats.totalIdentified) * 1000) / 10;
      stats.openPercentage = Math.round((stats.openCount / stats.totalIdentified) * 1000) / 10;
    } else {
      stats.fixPercentage = 0.0;
      stats.openPercentage = 0.0;
    }
    return stats;
  }

  // ─── Row Mappers ────────────────────────────────────────────────────────────

  private mapDbUser(row: any): DbUser {
    return {
      id: row.id,
      username: row.username,
      githubUsername: row.github_username || null,
      passwordHash: row.password_hash || '',
      role: row.role as UserRole,
      displayName: row.display_name,
      email: row.email || '',
      githubAvatarUrl: row.github_avatar_url || null,
      createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
      lastLoginAt: row.last_login_at ? new Date(row.last_login_at).toISOString() : new Date().toISOString(),
    };
  }

  private mapDbRecord(row: any): DbVulnerabilityRecord {
    return {
      recordId: row.record_id || row.recordId,
      findingId: row.finding_id || row.findingId,
      developerId: row.developer_id || row.developerId,
      githubUsername: row.github_username || row.githubUsername || null,
      sessionId: row.session_id || row.sessionId,
      shiftId: row.shift_id || row.shiftId || null,
      vulnerabilityType: row.vulnerability_type || row.vulnerabilityType,
      severity: row.severity,
      confidence: parseFloat(row.confidence || '0.9'),
      fileName: row.file_name || row.fileName,
      lineNumber: parseInt(row.line_number || row.lineNumber || '1', 10),
      columnNumber: parseInt(row.column_number || row.columnNumber || '0', 10),
      codeSnippet: row.code_snippet || row.codeSnippet || '',
      whyVulnerable: row.why_vulnerable || row.whyVulnerable || 'Vulnerable code detected.',
      howToFix: row.how_to_fix || row.howToFix || 'Apply recommended secure coding fix.',
      fixedCode: row.fixed_code || row.fixedCode || '// Secure replacement',
      attackScenario: row.attack_scenario || row.attackScenario || 'Potential security exploit.',
      status: (row.status as VulnerabilityStatus) || 'OPEN',
      detectedByRule: row.detected_by_rule || row.detectedByRule || 'SENTINEL-RULE',
      detectedAt: row.detected_at ? new Date(row.detected_at).toISOString() : (row.detectedAt || new Date().toISOString()),
      fixedAt: row.fixed_at ? new Date(row.fixed_at).toISOString() : (row.fixedAt || null),
      updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : new Date().toISOString(),
    };
  }

  public async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
      this.isOnline = false;
    }
  }
}
