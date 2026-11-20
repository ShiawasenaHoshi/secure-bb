// secure-bb's own SQLite. Policy lives here (never in plugin settings: anyone
// can change settings through the API without authentication).
import type BetterSqlite3 from "better-sqlite3";

export type Db = BetterSqlite3.Database;

/** Append-only: never edit or reorder shipped statements, only push new ones. */
export const MIGRATIONS: string[] = [
  `CREATE TABLE IF NOT EXISTS policy (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS totp (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     secret TEXT NOT NULL,
     state TEXT NOT NULL,
     last_step INTEGER NOT NULL DEFAULT 0,
     created_at INTEGER NOT NULL,
     locked_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS attempts (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     ts INTEGER NOT NULL,
     ok INTEGER NOT NULL,
     purpose TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS approvals (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     content_hash TEXT NOT NULL,
     plugin_id TEXT NOT NULL,
     version TEXT NOT NULL,
     source TEXT NOT NULL,
     source_kind TEXT NOT NULL,
     git_commit TEXT,
     npm_integrity TEXT,
     via TEXT NOT NULL,
     window_id INTEGER,
     thread_id TEXT,
     approved_at INTEGER NOT NULL,
     revoked_at INTEGER,
     last_seen INTEGER,
     local_hash TEXT)`,
  `CREATE INDEX IF NOT EXISTS approvals_hash ON approvals (content_hash)`,
  `CREATE TABLE IF NOT EXISTS queue (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     kind TEXT NOT NULL,
     content_hash TEXT,
     plugin_id TEXT NOT NULL,
     version TEXT NOT NULL,
     source TEXT NOT NULL,
     source_kind TEXT NOT NULL,
     root_dir TEXT,
     git_commit TEXT,
     npm_integrity TEXT,
     trigger TEXT,
     thread_id TEXT,
     proposal_id INTEGER,
     status TEXT NOT NULL,
     reason TEXT,
     first_seen INTEGER NOT NULL,
     last_seen INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS queue_hash ON queue (content_hash)`,
  `CREATE TABLE IF NOT EXISTS windows (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     plugin_id TEXT NOT NULL,
     thread_id TEXT NOT NULL,
     scope TEXT NOT NULL,
     mode TEXT NOT NULL,
     size_sec INTEGER NOT NULL,
     cap_sec INTEGER NOT NULL,
     opened_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     hard_expires_at INTEGER NOT NULL,
     closed_at INTEGER,
     closed_reason TEXT)`,
  `CREATE TABLE IF NOT EXISTS proposals (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     plugin_id TEXT NOT NULL,
     local_hash TEXT NOT NULL,
     snapshot_dir TEXT NOT NULL,
     thread_id TEXT,
     window_id INTEGER,
     touch_approved_at INTEGER,
     built_hash TEXT,
     loaded_at INTEGER,
     created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS log (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     ts INTEGER NOT NULL,
     kind TEXT NOT NULL,
     plugin_id TEXT,
     content_hash TEXT,
     detail TEXT)`,
  `CREATE TABLE IF NOT EXISTS seen_plugins (
     plugin_id TEXT PRIMARY KEY,
     first_seen INTEGER NOT NULL,
     baseline INTEGER NOT NULL DEFAULT 0,
     local_hash TEXT)`,
];

export interface Policy {
  /** Trust-window size in minutes. */
  windowMin: number;
  /** Hard ceiling of one window, minutes. */
  capMin: number;
  mode: "sliding" | "fixed";
  scope: "tree" | "thread";
}
export const DEFAULT_POLICY: Policy = { windowMin: 30, capMin: 240, mode: "sliding", scope: "tree" };

export interface TotpRow {
  secret: string;
  state: "pending" | "locked";
  lastStep: number;
  createdAt: number;
  lockedAt: number | null;
}
export interface ApprovalRow {
  id: number;
  contentHash: string;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  gitCommit: string | null;
  npmIntegrity: string | null;
  via: "touch" | "window" | "pin";
  windowId: number | null;
  threadId: string | null;
  approvedAt: number;
  revokedAt: number | null;
  lastSeen: number | null;
  /** Secure-bb's own hash of the reviewed source (snapshots only). */
  localHash: string | null;
}
export interface QueueRow {
  id: number;
  kind: "hook" | "proposal" | "afterfact";
  contentHash: string | null;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  rootDir: string | null;
  gitCommit: string | null;
  npmIntegrity: string | null;
  trigger: string | null;
  threadId: string | null;
  proposalId: number | null;
  status: "held" | "approved" | "dismissed";
  reason: string | null;
  firstSeen: number;
  lastSeen: number;
}
export interface WindowRow {
  id: number;
  pluginId: string;
  threadId: string;
  scope: "tree" | "thread";
  mode: "sliding" | "fixed";
  sizeSec: number;
  capSec: number;
  openedAt: number;
  expiresAt: number;
  hardExpiresAt: number;
  closedAt: number | null;
  closedReason: string | null;
}
export interface ProposalRow {
  id: number;
  pluginId: string;
  localHash: string;
  snapshotDir: string;
  threadId: string | null;
  windowId: number | null;
  /** Set when a human approved this proposal with a touch before it was installed. */
  touchApprovedAt: number | null;
  /** Hash of the tree INCLUDING dist/ right after bb built it (null until installed). */
  builtHash: string | null;
  /** Set when the hook first let this snapshot load: it is pinned from then on. */
  loadedAt: number | null;
  createdAt: number;
}
export interface LogRow {
  id: number;
  ts: number;
  kind: string;
  pluginId: string | null;
  contentHash: string | null;
  detail: unknown;
}

type Raw = Record<string, unknown>;

const approval = (r: Raw): ApprovalRow => ({
  id: r.id as number,
  contentHash: r.content_hash as string,
  pluginId: r.plugin_id as string,
  version: r.version as string,
  source: r.source as string,
  sourceKind: r.source_kind as string,
  gitCommit: (r.git_commit as string | null) ?? null,
  npmIntegrity: (r.npm_integrity as string | null) ?? null,
  via: r.via as "touch" | "window" | "pin",
  windowId: (r.window_id as number | null) ?? null,
  threadId: (r.thread_id as string | null) ?? null,
  approvedAt: r.approved_at as number,
  revokedAt: (r.revoked_at as number | null) ?? null,
  lastSeen: (r.last_seen as number | null) ?? null,
  localHash: (r.local_hash as string | null) ?? null,
});
const queueRow = (r: Raw): QueueRow => ({
  id: r.id as number,
  kind: r.kind as QueueRow["kind"],
  contentHash: (r.content_hash as string | null) ?? null,
  pluginId: r.plugin_id as string,
  version: r.version as string,
  source: r.source as string,
  sourceKind: r.source_kind as string,
  rootDir: (r.root_dir as string | null) ?? null,
  gitCommit: (r.git_commit as string | null) ?? null,
  npmIntegrity: (r.npm_integrity as string | null) ?? null,
  trigger: (r.trigger as string | null) ?? null,
  threadId: (r.thread_id as string | null) ?? null,
  proposalId: (r.proposal_id as number | null) ?? null,
  status: r.status as QueueRow["status"],
  reason: (r.reason as string | null) ?? null,
  firstSeen: r.first_seen as number,
  lastSeen: r.last_seen as number,
});
const windowRow = (r: Raw): WindowRow => ({
  id: r.id as number,
  pluginId: r.plugin_id as string,
  threadId: r.thread_id as string,
  scope: r.scope as "tree" | "thread",
  mode: r.mode as "sliding" | "fixed",
  sizeSec: r.size_sec as number,
  capSec: r.cap_sec as number,
  openedAt: r.opened_at as number,
  expiresAt: r.expires_at as number,
  hardExpiresAt: r.hard_expires_at as number,
  closedAt: (r.closed_at as number | null) ?? null,
  closedReason: (r.closed_reason as string | null) ?? null,
});
const proposalRow = (r: Raw): ProposalRow => ({
  id: r.id as number,
  pluginId: r.plugin_id as string,
  localHash: r.local_hash as string,
  snapshotDir: r.snapshot_dir as string,
  threadId: (r.thread_id as string | null) ?? null,
  windowId: (r.window_id as number | null) ?? null,
  touchApprovedAt: (r.touch_approved_at as number | null) ?? null,
  builtHash: (r.built_hash as string | null) ?? null,
  loadedAt: (r.loaded_at as number | null) ?? null,
  createdAt: r.created_at as number,
});

export interface NewQueue {
  kind: QueueRow["kind"];
  contentHash: string | null;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  rootDir: string | null;
  gitCommit: string | null;
  npmIntegrity: string | null;
  trigger: string | null;
  threadId: string | null;
  proposalId: number | null;
  reason: string | null;
}
export interface NewApproval {
  contentHash: string;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  gitCommit: string | null;
  npmIntegrity: string | null;
  via: "touch" | "window" | "pin";
  windowId: number | null;
  threadId: string | null;
  localHash?: string | null;
}

export class Store {
  constructor(
    readonly db: Db,
    private readonly now: () => number,
  ) {}

  // ---- policy -----------------------------------------------------------
  policy(): Policy {
    const rows = this.db.prepare(`SELECT key, value FROM policy`).all() as Array<{ key: string; value: string }>;
    const map = new Map(rows.map((r) => [r.key, r.value]));
    const num = (k: string, d: number) => {
      const n = Number(map.get(k));
      return Number.isFinite(n) && n > 0 ? n : d;
    };
    return {
      windowMin: num("window_min", DEFAULT_POLICY.windowMin),
      capMin: num("cap_min", DEFAULT_POLICY.capMin),
      mode: map.get("mode") === "fixed" ? "fixed" : "sliding",
      scope: map.get("scope") === "thread" ? "thread" : "tree",
    };
  }
  setPolicy(patch: Partial<Policy>): void {
    const put = this.db.prepare(`INSERT INTO policy (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`);
    if (patch.windowMin !== undefined) put.run("window_min", String(patch.windowMin));
    if (patch.capMin !== undefined) put.run("cap_min", String(patch.capMin));
    if (patch.mode !== undefined) put.run("mode", patch.mode);
    if (patch.scope !== undefined) put.run("scope", patch.scope);
  }
  getMeta(key: string): string | null {
    const r = this.db.prepare(`SELECT value FROM policy WHERE key = ?`).get(`meta.${key}`) as { value: string } | undefined;
    return r?.value ?? null;
  }
  setMeta(key: string, value: string): void {
    this.db
      .prepare(`INSERT INTO policy (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
      .run(`meta.${key}`, value);
  }

  // ---- totp -------------------------------------------------------------
  totp(): TotpRow | null {
    const r = this.db.prepare(`SELECT * FROM totp WHERE id = 1`).get() as Raw | undefined;
    if (!r) return null;
    return {
      secret: r.secret as string,
      state: r.state as "pending" | "locked",
      lastStep: r.last_step as number,
      createdAt: r.created_at as number,
      lockedAt: (r.locked_at as number | null) ?? null,
    };
  }
  putPendingTotp(secret: string): void {
    this.db
      .prepare(
        `INSERT INTO totp (id, secret, state, last_step, created_at) VALUES (1, ?, 'pending', 0, ?)
         ON CONFLICT(id) DO UPDATE SET secret = excluded.secret, state = 'pending', last_step = 0, created_at = excluded.created_at
         WHERE totp.state = 'pending'`,
      )
      .run(secret, this.now());
  }
  lockTotp(step: number): void {
    this.db.prepare(`UPDATE totp SET state = 'locked', locked_at = ?, last_step = ? WHERE id = 1 AND state = 'pending'`).run(this.now(), step);
  }
  setLastStep(step: number): void {
    this.db.prepare(`UPDATE totp SET last_step = ? WHERE id = 1 AND last_step < ?`).run(step, step);
  }
  /** Last used step for externally-held secrets (the file has no state of its own). */
  externalLastStep(): number {
    return Number(this.getMeta("external_last_step") ?? 0);
  }
  setExternalLastStep(step: number): void {
    if (step > this.externalLastStep()) this.setMeta("external_last_step", String(step));
  }

  // ---- attempts ---------------------------------------------------------
  recordAttempt(ok: boolean, purpose: string): void {
    this.db.prepare(`INSERT INTO attempts (ts, ok, purpose) VALUES (?, ?, ?)`).run(this.now(), ok ? 1 : 0, purpose);
  }
  failuresSince(sinceMs: number): number {
    const r = this.db.prepare(`SELECT COUNT(*) AS n FROM attempts WHERE ok = 0 AND ts > ?`).get(sinceMs) as { n: number };
    return r.n;
  }

  // ---- approvals --------------------------------------------------------
  activeApproval(contentHash: string): ApprovalRow | null {
    const r = this.db
      .prepare(`SELECT * FROM approvals WHERE content_hash = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1`)
      .get(contentHash) as Raw | undefined;
    return r ? approval(r) : null;
  }
  addApproval(a: NewApproval): ApprovalRow {
    const existing = this.activeApproval(a.contentHash);
    if (existing) return existing;
    const info = this.db
      .prepare(
        `INSERT INTO approvals (content_hash, plugin_id, version, source, source_kind, git_commit, npm_integrity, via, window_id, thread_id, approved_at, last_seen, local_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(a.contentHash, a.pluginId, a.version, a.source, a.sourceKind, a.gitCommit, a.npmIntegrity, a.via, a.windowId, a.threadId, this.now(), this.now(), a.localHash ?? null);
    return approval(this.db.prepare(`SELECT * FROM approvals WHERE id = ?`).get(info.lastInsertRowid) as Raw);
  }
  /** The newest active approval of a plugin: the version that stays pinned. */
  latestApproval(pluginId: string): ApprovalRow | null {
    const r = this.db.prepare(`SELECT * FROM approvals WHERE plugin_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1`).get(pluginId) as Raw | undefined;
    return r ? approval(r) : null;
  }
  touchApproval(id: number): void {
    this.db.prepare(`UPDATE approvals SET last_seen = ? WHERE id = ?`).run(this.now(), id);
  }
  listApprovals(limit = 200): ApprovalRow[] {
    return (this.db.prepare(`SELECT * FROM approvals ORDER BY id DESC LIMIT ?`).all(limit) as Raw[]).map(approval);
  }
  getApproval(id: number): ApprovalRow | null {
    const r = this.db.prepare(`SELECT * FROM approvals WHERE id = ?`).get(id) as Raw | undefined;
    return r ? approval(r) : null;
  }
  revokeApproval(id: number): void {
    this.db.prepare(`UPDATE approvals SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`).run(this.now(), id);
  }

  // ---- queue ------------------------------------------------------------
  /** One held entry per content hash; repeated asks only refresh `last_seen`. */
  upsertQueue(q: NewQueue): QueueRow {
    const now = this.now();
    let existing: Raw | undefined;
    if (q.contentHash) {
      existing = this.db
        .prepare(`SELECT * FROM queue WHERE content_hash = ? AND status = 'held' ORDER BY id DESC LIMIT 1`)
        .get(q.contentHash) as Raw | undefined;
    }
    if (!existing && q.proposalId !== null) {
      existing = this.db
        .prepare(`SELECT * FROM queue WHERE proposal_id = ? AND status = 'held' ORDER BY id DESC LIMIT 1`)
        .get(q.proposalId) as Raw | undefined;
    }
    if (existing) {
      this.db
        .prepare(
          `UPDATE queue SET last_seen = ?, content_hash = COALESCE(?, content_hash), root_dir = COALESCE(?, root_dir),
             version = ?, source = ?, source_kind = ?, git_commit = ?, npm_integrity = ?, trigger = COALESCE(?, trigger),
             reason = COALESCE(?, reason) WHERE id = ?`,
        )
        .run(now, q.contentHash, q.rootDir, q.version, q.source, q.sourceKind, q.gitCommit, q.npmIntegrity, q.trigger, q.reason, existing.id);
      return this.getQueue(existing.id as number)!;
    }
    const info = this.db
      .prepare(
        `INSERT INTO queue (kind, content_hash, plugin_id, version, source, source_kind, root_dir, git_commit, npm_integrity, trigger, thread_id, proposal_id, status, reason, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'held', ?, ?, ?)`,
      )
      .run(q.kind, q.contentHash, q.pluginId, q.version, q.source, q.sourceKind, q.rootDir, q.gitCommit, q.npmIntegrity, q.trigger, q.threadId, q.proposalId, q.reason, now, now);
    return this.getQueue(Number(info.lastInsertRowid))!;
  }
  getQueue(id: number): QueueRow | null {
    const r = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(id) as Raw | undefined;
    return r ? queueRow(r) : null;
  }
  listQueue(limit = 100): QueueRow[] {
    return (this.db.prepare(`SELECT * FROM queue ORDER BY (status = 'held') DESC, id DESC LIMIT ?`).all(limit) as Raw[]).map(queueRow);
  }
  setQueueStatus(id: number, status: QueueRow["status"]): void {
    this.db.prepare(`UPDATE queue SET status = ? WHERE id = ?`).run(status, id);
  }
  /** Marks every held entry for a hash as approved (after any approval path). */
  resolveQueueByHash(contentHash: string): void {
    this.db.prepare(`UPDATE queue SET status = 'approved' WHERE content_hash = ? AND status = 'held'`).run(contentHash);
  }

  // ---- windows ----------------------------------------------------------
  insertWindow(w: Omit<WindowRow, "id" | "closedAt" | "closedReason">): WindowRow {
    const info = this.db
      .prepare(
        `INSERT INTO windows (plugin_id, thread_id, scope, mode, size_sec, cap_sec, opened_at, expires_at, hard_expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(w.pluginId, w.threadId, w.scope, w.mode, w.sizeSec, w.capSec, w.openedAt, w.expiresAt, w.hardExpiresAt);
    return this.getWindow(Number(info.lastInsertRowid))!;
  }
  getWindow(id: number): WindowRow | null {
    const r = this.db.prepare(`SELECT * FROM windows WHERE id = ?`).get(id) as Raw | undefined;
    return r ? windowRow(r) : null;
  }
  /** Windows that are not yet closed (they may already be past `expires_at`). */
  unclosedWindows(): WindowRow[] {
    return (this.db.prepare(`SELECT * FROM windows WHERE closed_at IS NULL ORDER BY id`).all() as Raw[]).map(windowRow);
  }
  recentWindows(limit = 50): WindowRow[] {
    return (this.db.prepare(`SELECT * FROM windows ORDER BY id DESC LIMIT ?`).all(limit) as Raw[]).map(windowRow);
  }
  closeWindow(id: number, reason: string, at = this.now()): void {
    this.db.prepare(`UPDATE windows SET closed_at = ?, closed_reason = ? WHERE id = ? AND closed_at IS NULL`).run(at, reason, id);
  }
  setWindowExpiry(id: number, expiresAt: number): void {
    this.db.prepare(`UPDATE windows SET expires_at = ? WHERE id = ? AND closed_at IS NULL`).run(expiresAt, id);
  }

  // ---- proposals --------------------------------------------------------
  addProposal(p: Omit<ProposalRow, "id" | "createdAt" | "touchApprovedAt" | "builtHash" | "loadedAt">): ProposalRow {
    const info = this.db
      .prepare(`INSERT INTO proposals (plugin_id, local_hash, snapshot_dir, thread_id, window_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(p.pluginId, p.localHash, p.snapshotDir, p.threadId, p.windowId, this.now());
    return this.getProposal(Number(info.lastInsertRowid))!;
  }
  getProposal(id: number): ProposalRow | null {
    const r = this.db.prepare(`SELECT * FROM proposals WHERE id = ?`).get(id) as Raw | undefined;
    return r ? proposalRow(r) : null;
  }
  /** The newest proposal whose snapshot lives exactly at `dir`. */
  proposalByDir(dir: string): ProposalRow | null {
    const r = this.db.prepare(`SELECT * FROM proposals WHERE snapshot_dir = ? ORDER BY id DESC LIMIT 1`).get(dir) as Raw | undefined;
    return r ? proposalRow(r) : null;
  }
  /** Re-proposing the same snapshot reuses its row (and keeps its approval and build state). */
  retargetProposal(id: number, threadId: string | null, windowId: number | null): void {
    this.db.prepare(`UPDATE proposals SET thread_id = ?, window_id = ? WHERE id = ?`).run(threadId, windowId, id);
  }
  /** Revocation must also end the pin of every snapshot with this reviewed source. */
  unpinProposals(pluginId: string, localHash: string): void {
    this.db.prepare(`UPDATE proposals SET loaded_at = NULL, touch_approved_at = NULL, window_id = NULL WHERE plugin_id = ? AND local_hash = ?`).run(pluginId, localHash);
  }
  setProposalBuilt(id: number, builtHash: string): void {
    this.db.prepare(`UPDATE proposals SET built_hash = ? WHERE id = ?`).run(builtHash, id);
  }
  markProposalLoaded(id: number): void {
    this.db.prepare(`UPDATE proposals SET loaded_at = COALESCE(loaded_at, ?) WHERE id = ?`).run(this.now(), id);
  }
  approveProposal(id: number): void {
    this.db.prepare(`UPDATE proposals SET touch_approved_at = ? WHERE id = ?`).run(this.now(), id);
  }
  setProposalWindow(id: number, windowId: number | null): void {
    this.db.prepare(`UPDATE proposals SET window_id = ? WHERE id = ?`).run(windowId, id);
  }

  // ---- log --------------------------------------------------------------
  log(kind: string, pluginId: string | null, contentHash: string | null, detail: unknown = null): void {
    this.db
      .prepare(`INSERT INTO log (ts, kind, plugin_id, content_hash, detail) VALUES (?, ?, ?, ?, ?)`)
      .run(this.now(), kind, pluginId, contentHash, detail === null ? null : JSON.stringify(detail));
  }
  listLog(limit = 100): LogRow[] {
    return (this.db.prepare(`SELECT * FROM log ORDER BY id DESC LIMIT ?`).all(limit) as Raw[]).map((r) => ({
      id: r.id as number,
      ts: r.ts as number,
      kind: r.kind as string,
      pluginId: (r.plugin_id as string | null) ?? null,
      contentHash: (r.content_hash as string | null) ?? null,
      detail: r.detail ? JSON.parse(r.detail as string) : null,
    }));
  }

  // ---- seen plugins (after-the-fact baseline) ---------------------------
  /** Records a plugin that was already installed before secure-bb ran. */
  markBaseline(pluginId: string, localHash: string): void {
    this.db
      .prepare(
        `INSERT INTO seen_plugins (plugin_id, first_seen, baseline, local_hash) VALUES (?, ?, 1, ?)
         ON CONFLICT(plugin_id) DO UPDATE SET local_hash = excluded.local_hash WHERE seen_plugins.baseline = 1`,
      )
      .run(pluginId, this.now(), localHash);
  }
  baselineHash(pluginId: string): string | null {
    const r = this.db.prepare(`SELECT local_hash FROM seen_plugins WHERE plugin_id = ? AND baseline = 1`).get(pluginId) as { local_hash: string | null } | undefined;
    return r?.local_hash ?? null;
  }
  listBaseline(): Array<{ pluginId: string; localHash: string | null }> {
    return (this.db.prepare(`SELECT plugin_id, local_hash FROM seen_plugins WHERE baseline = 1`).all() as Array<{ plugin_id: string; local_hash: string | null }>).map((r) => ({ pluginId: r.plugin_id, localHash: r.local_hash }));
  }
}
