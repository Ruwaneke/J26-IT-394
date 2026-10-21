/**
 * Sentinel — Database Administration Service
 *
 * Backs the "Database" section of the administrator dashboard: connection health,
 * table statistics, a paginated data browser, row edits/deletes, maintenance jobs
 * and JSON backup export.
 *
 * Safety rules
 *   • Only tables and columns listed in TABLES can be touched. Identifiers are never
 *     taken from the webview; values are always bound as query parameters.
 *   • `users.password_hash` is never returned to the UI or included in exports.
 *   • The `users` table is browse-only here; user changes go through the Users section
 *     (which enforces the "last administrator" guard).
 *   • Role checks, confirmation dialogs and audit logging are done by the caller
 *     (extension.ts) before any method here is invoked.
 */

import { NeonDatabaseService } from './neonDatabaseService.js';

export type AdminTable = 'users' | 'vulnerability_records' | 'user_activity_logs' | 'sentinel_documents';

interface TableDef {
  label: string;
  description: string;
  pk: string[];
  /** Columns returned to the browser (password_hash intentionally absent from users) */
  columns: string[];
  searchable: string[];
  orderBy: string;
  timestampColumn: string;
  deletable: boolean;
  truncatable: boolean;
}

export const TABLES: Record<AdminTable, TableDef> = {
  users: {
    label: 'Users',
    description: 'Accounts and roles (developers, supervisors, administrators)',
    pk: ['id'],
    columns: ['id', 'username', 'github_username', 'role', 'display_name', 'email', 'created_at', 'last_login_at'],
    searchable: ['username', 'github_username', 'display_name', 'email', 'role'],
    orderBy: 'created_at DESC',
    timestampColumn: 'last_login_at',
    deletable: false,
    truncatable: false,
  },
  vulnerability_records: {
    label: 'Vulnerability Records',
    description: 'Every finding detected by Sentinel with its lifecycle status',
    pk: ['record_id'],
    columns: ['record_id', 'finding_id', 'developer_id', 'github_username', 'vulnerability_type', 'severity', 'status',
      'confidence', 'file_name', 'line_number', 'detected_by_rule', 'detected_at', 'fixed_at', 'updated_at',
      'code_snippet', 'why_vulnerable', 'how_to_fix', 'fixed_code', 'attack_scenario', 'session_id', 'shift_id'],
    searchable: ['developer_id', 'github_username', 'vulnerability_type', 'severity', 'status', 'file_name', 'detected_by_rule'],
    orderBy: 'detected_at DESC',
    timestampColumn: 'updated_at',
    deletable: true,
    truncatable: true,
  },
  user_activity_logs: {
    label: 'Activity Logs',
    description: 'Audit trail of user and system actions',
    pk: ['id'],
    columns: ['id', 'username', 'developer_id', 'github_username', 'action_type', 'vulnerability_type', 'finding_id', 'details', 'created_at'],
    searchable: ['username', 'developer_id', 'github_username', 'action_type', 'vulnerability_type'],
    orderBy: 'created_at DESC',
    timestampColumn: 'created_at',
    deletable: true,
    truncatable: true,
  },
  sentinel_documents: {
    label: 'Documents',
    description: 'JSON documents: projects, shifts, shift sessions, learning profiles',
    pk: ['collection', 'doc_key'],
    columns: ['collection', 'doc_key', 'data', 'updated_at'],
    searchable: ['collection', 'doc_key'],
    orderBy: 'updated_at DESC',
    timestampColumn: 'updated_at',
    deletable: true,
    truncatable: true,
  },
};

const VALID_STATUSES = ['OPEN', 'FIXED', 'IGNORED', 'FALSE_POSITIVE'];

export interface TableStat {
  table: AdminTable;
  label: string;
  description: string;
  rows: number;
  sizeBytes: number;
  lastActivity: string | null;
  deletable: boolean;
  truncatable: boolean;
}

export interface DatabaseOverview {
  online: boolean;
  pingMs: number;
  error: string | null;
  database: string | null;
  serverVersion: string | null;
  host: string | null;
  sizeBytes: number | null;
  serverTime: string | null;
  tables: TableStat[];
  collections: Array<{ collection: string; count: number }>;
  statusBreakdown: Record<string, number>;
}

export interface BrowseResult {
  table: AdminTable;
  columns: string[];
  pk: string[];
  rows: Record<string, unknown>[];
  total: number;
  page: number;
  pageSize: number;
  deletable: boolean;
}

export function isAdminTable(t: unknown): t is AdminTable {
  return typeof t === 'string' && Object.prototype.hasOwnProperty.call(TABLES, t);
}

export class DatabaseAdminService {
  constructor(private readonly db: NeonDatabaseService = NeonDatabaseService.getInstance()) {}

  // ─── Overview ───────────────────────────────────────────────────────────────

  async getOverview(): Promise<DatabaseOverview> {
    const ping = await this.db.ping();
    const host = (process.env.PGHOST || 'ep-silent-art-b48vcnb1-pooler.c-6.us-east-2.aws.neon.tech')
      .replace(/^([^.]{0,6})[^.]*/, '$1••••'); // mask the endpoint id
    const overview: DatabaseOverview = {
      online: ping.ok, pingMs: ping.ms, error: ping.error,
      database: null, serverVersion: null, host, sizeBytes: null, serverTime: null,
      tables: [], collections: [], statusBreakdown: {},
    };
    if (!ping.ok) { return overview; }

    const info = await this.db.adminQuery(
      `SELECT current_database() AS db, version() AS version,
              pg_database_size(current_database())::bigint AS size, NOW() AS now;`);
    const r = info.rows[0];
    overview.database = r.db;
    overview.serverVersion = String(r.version).split(' on ')[0];
    overview.sizeBytes = Number(r.size);
    overview.serverTime = new Date(r.now).toISOString();

    for (const [table, def] of Object.entries(TABLES) as Array<[AdminTable, TableDef]>) {
      const res = await this.db.adminQuery(
        `SELECT COUNT(*)::int AS n,
                pg_total_relation_size('${table}')::bigint AS size,
                MAX(${def.timestampColumn}) AS last
         FROM ${table};`);
      overview.tables.push({
        table, label: def.label, description: def.description,
        rows: res.rows[0].n,
        sizeBytes: Number(res.rows[0].size),
        lastActivity: res.rows[0].last ? new Date(res.rows[0].last).toISOString() : null,
        deletable: def.deletable, truncatable: def.truncatable,
      });
    }

    const cols = await this.db.adminQuery(
      `SELECT collection, COUNT(*)::int AS n FROM sentinel_documents GROUP BY collection ORDER BY collection;`);
    overview.collections = cols.rows.map(c => ({ collection: c.collection, count: c.n }));

    const st = await this.db.adminQuery(
      `SELECT status, COUNT(*)::int AS n FROM vulnerability_records GROUP BY status;`);
    for (const row of st.rows) { overview.statusBreakdown[row.status] = row.n; }
    return overview;
  }

  // ─── Browser ────────────────────────────────────────────────────────────────

  async browse(table: AdminTable, opts: { page?: number; pageSize?: number; search?: string; filterColumn?: string; filterValue?: string }): Promise<BrowseResult> {
    const def = TABLES[table];
    const pageSize = Math.min(Math.max(opts.pageSize ?? 25, 5), 100);
    const page = Math.max(opts.page ?? 1, 1);
    const where: string[] = [];
    const params: unknown[] = [];

    const search = (opts.search ?? '').trim();
    if (search) {
      params.push(`%${search}%`);
      where.push('(' + def.searchable.map(c => `${c}::text ILIKE $${params.length}`).join(' OR ') + ')');
    }
    if (opts.filterColumn && def.searchable.includes(opts.filterColumn) && opts.filterValue) {
      params.push(opts.filterValue);
      where.push(`${opts.filterColumn} = $${params.length}`);
    }
    const whereSql = where.length ? ` WHERE ${where.join(' AND ')}` : '';

    const count = await this.db.adminQuery(`SELECT COUNT(*)::int AS n FROM ${table}${whereSql};`, params);
    params.push(pageSize, (page - 1) * pageSize);
    const rows = await this.db.adminQuery(
      `SELECT ${def.columns.join(', ')} FROM ${table}${whereSql}
       ORDER BY ${def.orderBy} LIMIT $${params.length - 1} OFFSET $${params.length};`, params);

    return {
      table, columns: def.columns, pk: def.pk,
      rows: rows.rows.map(r => normaliseRow(r)),
      total: count.rows[0].n, page, pageSize, deletable: def.deletable,
    };
  }

  // ─── Row operations ─────────────────────────────────────────────────────────

  async deleteRow(table: AdminTable, key: Record<string, string>): Promise<number> {
    const def = TABLES[table];
    if (!def.deletable) { throw new Error(`${def.label} rows cannot be deleted here.`); }
    const values = def.pk.map(c => {
      if (typeof key[c] !== 'string' || !key[c]) { throw new Error(`Missing key column ${c}`); }
      return key[c];
    });
    const res = await this.db.adminQuery(
      `DELETE FROM ${table} WHERE ${def.pk.map((c, i) => `${c} = $${i + 1}`).join(' AND ')};`, values);
    return res.rowCount ?? 0;
  }

  async setRecordStatus(recordId: string, status: string): Promise<number> {
    if (!VALID_STATUSES.includes(status)) { throw new Error(`Invalid status "${status}"`); }
    const res = await this.db.adminQuery(
      `UPDATE vulnerability_records
         SET status = $2::varchar, updated_at = NOW(),
             fixed_at = CASE WHEN $2::varchar = 'FIXED' THEN COALESCE(fixed_at, NOW()) ELSE NULL END
       WHERE record_id = $1;`, [recordId, status]);
    return res.rowCount ?? 0;
  }

  // ─── Maintenance ────────────────────────────────────────────────────────────

  async truncate(table: AdminTable, collection?: string): Promise<number> {
    const def = TABLES[table];
    if (!def.truncatable) { throw new Error(`${def.label} cannot be cleared.`); }
    if (table === 'sentinel_documents' && collection) {
      const res = await this.db.adminQuery('DELETE FROM sentinel_documents WHERE collection = $1;', [collection]);
      return res.rowCount ?? 0;
    }
    const res = await this.db.adminQuery(`DELETE FROM ${table};`);
    return res.rowCount ?? 0;
  }

  async purgeActivityOlderThan(days: number): Promise<number> {
    const res = await this.db.adminQuery(
      `DELETE FROM user_activity_logs WHERE created_at < NOW() - make_interval(days => $1);`, [clampDays(days)]);
    return res.rowCount ?? 0;
  }

  async purgeResolvedRecordsOlderThan(days: number): Promise<number> {
    const res = await this.db.adminQuery(
      `DELETE FROM vulnerability_records
       WHERE status IN ('FIXED', 'IGNORED', 'FALSE_POSITIVE')
         AND updated_at < NOW() - make_interval(days => $1);`, [clampDays(days)]);
    return res.rowCount ?? 0;
  }

  async deleteDeveloperData(developerId: string): Promise<number> {
    const res = await this.db.clearAllVulnerabilityRecords(developerId);
    if (!res.success) { throw new Error('Delete failed'); }
    return res.deletedCount;
  }

  async vacuumAnalyze(): Promise<string[]> {
    const done: string[] = [];
    for (const table of Object.keys(TABLES)) {
      await this.db.adminQuery(`VACUUM (ANALYZE) ${table};`);
      done.push(table);
    }
    return done;
  }

  async rerunMigrations(): Promise<boolean> {
    return this.db.reinitialize();
  }

  // ─── Backup ─────────────────────────────────────────────────────────────────

  /** Full JSON snapshot of every table (password hashes excluded). */
  async exportAll(): Promise<{ exportedAt: string; database: string | null; tables: Record<string, unknown[]> }> {
    const info = await this.db.adminQuery('SELECT current_database() AS db;');
    const tables: Record<string, unknown[]> = {};
    for (const [table, def] of Object.entries(TABLES) as Array<[AdminTable, TableDef]>) {
      const res = await this.db.adminQuery(`SELECT ${def.columns.join(', ')} FROM ${table} ORDER BY ${def.orderBy};`);
      tables[table] = res.rows.map(r => normaliseRow(r));
    }
    return { exportedAt: new Date().toISOString(), database: info.rows[0].db, tables };
  }
}

function clampDays(d: number): number {
  const n = Math.floor(Number(d));
  if (!Number.isFinite(n) || n < 1) { throw new Error('Days must be a positive number'); }
  return Math.min(n, 3650);
}

function normaliseRow(r: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(r)) {
    out[k] = v instanceof Date ? v.toISOString() : v;
  }
  return out;
}
