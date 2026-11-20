// secure-bb's own SQLite. Policy lives here (never in plugin settings: anyone
// can change settings through the API without authentication).
import type BetterSqlite3 from "better-sqlite3";
import type { CheckResult } from "./checks/types.js";
import { appendRecord, lastHead, sealLegacy, verifyChain, type JournalAnchor, type JournalReport } from "./journal.js";
import { PRUNE_MS, type RegistryCache, type RegistryEntry } from "./deps/registry.js";
import { SKILL_MIGRATIONS } from "./skills/store.js";
import { DEFAULT_AI, type AiSettings, type ScanResult, type ScanRow, type ScanStatus, type ScanTrigger } from "./scan/types.js";
import type { Category, ConfigWindowRow, Drift, DriftKind, DriftStatus, SnapshotRow, WindowScope } from "./watch/model.js";

export type Db = BetterSqlite3.Database;

export interface StoredCheck {
  ts: number;
  result: CheckResult;
}

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
  `CREATE TABLE IF NOT EXISTS check_results (
     content_hash TEXT PRIMARY KEY,
     plugin_id TEXT NOT NULL,
     ts INTEGER NOT NULL,
     result TEXT NOT NULL)`,
  // Stage 2.2: the capabilities a trust window was opened with (JSON array of tokens); NULL = none known.
  `ALTER TABLE windows ADD COLUMN caps TEXT`,
  // Stage 2a: config watchdog. The approved snapshot (names, states, hashes: no secrets), the only
  // blob kept for rollback (instruction text), the drift feed and configuration trust windows.
  `CREATE TABLE IF NOT EXISTS watch_snapshot (
     key TEXT PRIMARY KEY,
     category TEXT NOT NULL,
     source TEXT NOT NULL,
     label TEXT NOT NULL,
     value TEXT NOT NULL,
     approved_at INTEGER NOT NULL,
     via TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS watch_blobs (key TEXT PRIMARY KEY, text TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS watch_drifts (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     key TEXT NOT NULL,
     category TEXT NOT NULL,
     source TEXT NOT NULL,
     kind TEXT NOT NULL,
     label TEXT NOT NULL,
     before_value TEXT,
     after_value TEXT,
     first_seen INTEGER NOT NULL,
     last_seen INTEGER NOT NULL,
     status TEXT NOT NULL,
     resolved_at INTEGER,
     note TEXT,
     rollbackable INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS watch_drifts_key ON watch_drifts (key, status)`,
  `CREATE TABLE IF NOT EXISTS cfg_windows (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     scopes TEXT NOT NULL,
     mode TEXT NOT NULL,
     size_sec INTEGER NOT NULL,
     cap_sec INTEGER NOT NULL,
     opened_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     hard_expires_at INTEGER NOT NULL,
     closed_at INTEGER,
     closed_reason TEXT)`,
  // Stage 2.3: what the npm registry said about a package (publish time of every version, tags).
  // Filled by the server process; read without network. `state` is ok or missing (the registry answered 404).
  `CREATE TABLE IF NOT EXISTS registry_cache (
     name TEXT PRIMARY KEY,
     state TEXT NOT NULL,
     fetched_at INTEGER NOT NULL,
     dist_tags TEXT NOT NULL,
     times TEXT NOT NULL)`,
  // Stage 3: optional AI scan results (spec §8). Keyed by the scanned source tree; the core's hash is kept when known.
  `CREATE TABLE IF NOT EXISTS scans (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     plugin_id TEXT NOT NULL,
     version TEXT NOT NULL,
     local_hash TEXT NOT NULL,
     content_hash TEXT,
     trigger TEXT NOT NULL,
     status TEXT NOT NULL,
     started_at INTEGER NOT NULL,
     finished_at INTEGER,
     result TEXT)`,
  `CREATE INDEX IF NOT EXISTS scans_local ON scans (local_hash)`,
  `CREATE INDEX IF NOT EXISTS scans_content ON scans (content_hash)`,
  // Stage 5: the journal is a hash chain (every record holds the hash of the one before it).
  `ALTER TABLE log ADD COLUMN prev_hash TEXT`,
  `ALTER TABLE log ADD COLUMN hash TEXT`,
  // Stage 5: threads that read untrusted content. One row per event that did (thread, event seq);
  // `note` says what kind of thing, never what was read. The cursor is the last event seq looked at.
  `CREATE TABLE IF NOT EXISTS taint_hits (
     thread_id TEXT NOT NULL,
     seq INTEGER NOT NULL,
     kind TEXT NOT NULL,
     at INTEGER NOT NULL,
     note TEXT NOT NULL,
     PRIMARY KEY (thread_id, seq))`,
  `CREATE TABLE IF NOT EXISTS taint_cursor (
     thread_id TEXT PRIMARY KEY,
     last_seq INTEGER NOT NULL,
     scanned_at INTEGER NOT NULL)`,
  // Stage 5: repositories whose use does not taint a thread (`owner/name`, `owner/*`, github.com). Empty by default; changed only with a code.
  `CREATE TABLE IF NOT EXISTS trusted_repos (pattern TEXT PRIMARY KEY, added_at INTEGER NOT NULL)`,
  // Stage 6: skills module (pins, queue, trusted registry sources).
  ...SKILL_MIGRATIONS,
];

export interface Policy {
  /** Trust-window size in minutes. */
  windowMin: number;
  /** Hard ceiling of one window, minutes. */
  capMin: number;
  mode: "sliding" | "fixed";
  scope: "tree" | "thread";
  /** Configuration trust window (spec §6): size in minutes, default 10. */
  cfgWindowMin: number;
  /** Hard ceiling of one configuration window, minutes. */
  cfgCapMin: number;
  cfgMode: "sliding" | "fixed";
}
export const DEFAULT_POLICY: Policy = { windowMin: 30, capMin: 240, mode: "sliding", scope: "tree", cfgWindowMin: 10, cfgCapMin: 240, cfgMode: "sliding" };

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
  via: "touch" | "window" | "pin" | "auto";
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
  status: "held" | "approved" | "dismissed" | "stale";
  reason: string | null;
  firstSeen: number;
  lastSeen: number;
}
export interface TaintHitRow {
  threadId: string;
  seq: number;
  kind: string;
  at: number;
  note: string;
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
  /** Capability tokens present when the window was opened (plus those a human accepted since). */
  caps: string[];
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
  via: r.via as ApprovalRow["via"],
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
  caps: r.caps ? (JSON.parse(r.caps as string) as string[]) : [],
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

const scanRow = (r: Raw): ScanRow => ({
  id: r.id as number,
  pluginId: r.plugin_id as string,
  version: r.version as string,
  localHash: r.local_hash as string,
  contentHash: (r.content_hash as string | null) ?? null,
  trigger: r.trigger as ScanTrigger,
  status: r.status as ScanStatus,
  startedAt: r.started_at as number,
  finishedAt: (r.finished_at as number | null) ?? null,
  result: r.result ? (JSON.parse(r.result as string) as ScanResult) : null,
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
  via: ApprovalRow["via"];
  windowId: number | null;
  threadId: string | null;
  localHash?: string | null;
}

export class Store implements RegistryCache {
  constructor(
    readonly db: Db,
    private readonly now: () => number,
    /** Where the journal head is also kept (a file next to the database); absent in tests. */
    private readonly anchor: JournalAnchor | null = null,
  ) {
    if (this.getMeta("journal_sealed") === null) {
      const sealed = sealLegacy(db);
      this.setMeta("journal_sealed", String(this.now()));
      this.setMeta("journal_sealed_count", String(sealed));
      this.pinHead();
    }
  }

  private pinHead(): void {
    const head = lastHead(this.db);
    if (!head || !this.anchor) return;
    try {
      this.anchor.write(head);
    } catch {
      /* the head file is a second witness; failing to write it must not stop the journal (verify shows a stale file as "behind", which is harmless) */
    }
  }

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
      cfgWindowMin: num("cfg_window_min", DEFAULT_POLICY.cfgWindowMin),
      cfgCapMin: num("cfg_cap_min", DEFAULT_POLICY.cfgCapMin),
      cfgMode: map.get("cfg_mode") === "fixed" ? "fixed" : "sliding",
    };
  }
  setPolicy(patch: Partial<Policy>): void {
    const put = this.db.prepare(`INSERT INTO policy (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`);
    if (patch.windowMin !== undefined) put.run("window_min", String(patch.windowMin));
    if (patch.capMin !== undefined) put.run("cap_min", String(patch.capMin));
    if (patch.mode !== undefined) put.run("mode", patch.mode);
    if (patch.scope !== undefined) put.run("scope", patch.scope);
    if (patch.cfgWindowMin !== undefined) put.run("cfg_window_min", String(patch.cfgWindowMin));
    if (patch.cfgCapMin !== undefined) put.run("cfg_cap_min", String(patch.cfgCapMin));
    if (patch.cfgMode !== undefined) put.run("cfg_mode", patch.cfgMode);
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

  // ---- check results (key: the core's content hash, or `local:<localHash>` for a snapshot checked at propose time) ----
  putCheck(contentHash: string, pluginId: string, result: CheckResult): void {
    this.db
      .prepare(`INSERT INTO check_results (content_hash, plugin_id, ts, result) VALUES (?, ?, ?, ?)
                ON CONFLICT(content_hash) DO UPDATE SET plugin_id = excluded.plugin_id, ts = excluded.ts, result = excluded.result`)
      .run(contentHash, pluginId, this.now(), JSON.stringify(result));
  }
  getCheck(contentHash: string): StoredCheck | null {
    const r = this.db.prepare(`SELECT * FROM check_results WHERE content_hash = ?`).get(contentHash) as Raw | undefined;
    return r ? { ts: r.ts as number, result: JSON.parse(r.result as string) as CheckResult } : null;
  }

  // ---- npm registry cache (stage 2.3) -------------------------------------
  getRegistry(name: string): RegistryEntry | null {
    const r = this.db.prepare(`SELECT * FROM registry_cache WHERE name = ?`).get(name) as Raw | undefined;
    if (!r) return null;
    return { name, state: r.state === "missing" ? "missing" : "ok", fetchedAt: r.fetched_at as number, distTags: JSON.parse(r.dist_tags as string), times: JSON.parse(r.times as string) };
  }
  putRegistry(e: RegistryEntry): void {
    this.db
      .prepare(`INSERT INTO registry_cache (name, state, fetched_at, dist_tags, times) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET state = excluded.state, fetched_at = excluded.fetched_at, dist_tags = excluded.dist_tags, times = excluded.times`)
      .run(e.name, e.state, e.fetchedAt, JSON.stringify(e.distTags), JSON.stringify(e.times));
    this.db.prepare(`DELETE FROM registry_cache WHERE fetched_at < ?`).run(this.now() - PRUNE_MS);
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
  /** A held entry's reason that starts with `prefix` no longer applies (e.g. the directory was fixed). */
  clearQueueReason(contentHash: string, prefix: string): void {
    this.db.prepare(`UPDATE queue SET reason = NULL WHERE content_hash = ? AND status = 'held' AND reason LIKE ? ESCAPE '\\'`).run(contentHash, `${prefix.replace(/[\\%_]/g, "\\$&")}%`);
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
  /**
   * Marks the held entries of a proposal as approved. An entry made by `propose` has no
   * content hash (the core has not hashed the plugin yet), so the hash alone never finds it.
   */
  resolveQueueByProposal(proposalId: number): void {
    this.db.prepare(`UPDATE queue SET status = 'approved' WHERE proposal_id = ? AND status = 'held'`).run(proposalId);
  }
  /** Marks every held entry for a hash as approved (after any approval path). */
  resolveQueueByHash(contentHash: string): void {
    this.db.prepare(`UPDATE queue SET status = 'approved' WHERE content_hash = ? AND status = 'held'`).run(contentHash);
  }

  /**
   * The plugin loaded under an approved hash: entries still held for it because
   * its snapshot was tampered with are obsolete (the original is back).
   */
  supersedeTampered(pluginId: string, loadedHash: string): void {
    this.db
      .prepare(`UPDATE queue SET status = 'stale' WHERE plugin_id = ? AND status = 'held' AND reason LIKE 'снимок изменён%' AND (content_hash IS NULL OR content_hash <> ?)`)
      .run(pluginId, loadedHash);
  }

  // ---- windows ----------------------------------------------------------
  insertWindow(w: Omit<WindowRow, "id" | "closedAt" | "closedReason">): WindowRow {
    const info = this.db
      .prepare(
        `INSERT INTO windows (plugin_id, thread_id, scope, mode, size_sec, cap_sec, opened_at, expires_at, hard_expires_at, caps)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(w.pluginId, w.threadId, w.scope, w.mode, w.sizeSec, w.capSec, w.openedAt, w.expiresAt, w.hardExpiresAt, JSON.stringify(w.caps));
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
  /** A human accepted a new capability inside the window: it is part of the window's set from now on. */
  setWindowCaps(id: number, caps: string[]): void {
    this.db.prepare(`UPDATE windows SET caps = ? WHERE id = ? AND closed_at IS NULL`).run(JSON.stringify(caps), id);
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

  // ---- config watchdog (stage 2a) ----------------------------------------
  listSnapshot(): SnapshotRow[] {
    return (this.db.prepare(`SELECT * FROM watch_snapshot ORDER BY key`).all() as Raw[]).map((r) => ({
      key: r.key as string,
      category: r.category as Category,
      source: r.source as string,
      label: r.label as string,
      value: r.value as string,
      approvedAt: r.approved_at as number,
      via: r.via as string,
    }));
  }
  putSnapshot(row: Omit<SnapshotRow, "approvedAt">): void {
    this.db
      .prepare(
        `INSERT INTO watch_snapshot (key, category, source, label, value, approved_at, via) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET category = excluded.category, source = excluded.source, label = excluded.label,
           value = excluded.value, approved_at = excluded.approved_at, via = excluded.via`,
      )
      .run(row.key, row.category, row.source, row.label, row.value, this.now(), row.via);
  }
  deleteSnapshot(key: string): void {
    this.db.prepare(`DELETE FROM watch_snapshot WHERE key = ?`).run(key);
  }
  getBlob(key: string): string | null {
    const r = this.db.prepare(`SELECT text FROM watch_blobs WHERE key = ?`).get(key) as { text: string } | undefined;
    return r?.text ?? null;
  }
  putBlob(key: string, text: string): void {
    this.db.prepare(`INSERT INTO watch_blobs (key, text) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET text = excluded.text`).run(key, text);
  }

  private drift = (r: Raw): Drift => ({
    id: r.id as number,
    key: r.key as string,
    category: r.category as Category,
    source: r.source as string,
    kind: r.kind as DriftKind,
    label: r.label as string,
    before: (r.before_value as string | null) ?? null,
    after: (r.after_value as string | null) ?? null,
    firstSeen: r.first_seen as number,
    lastSeen: r.last_seen as number,
    status: r.status as DriftStatus,
    resolvedAt: (r.resolved_at as number | null) ?? null,
    note: (r.note as string | null) ?? null,
    rollbackable: r.rollbackable === 1,
  });
  /** The open drift of a key, if any. */
  openDrift(key: string): Drift | null {
    const r = this.db.prepare(`SELECT * FROM watch_drifts WHERE key = ? AND status IN ('open', 'rollback-failed') ORDER BY id DESC LIMIT 1`).get(key) as Raw | undefined;
    return r ? this.drift(r) : null;
  }
  getDrift(id: number): Drift | null {
    const r = this.db.prepare(`SELECT * FROM watch_drifts WHERE id = ?`).get(id) as Raw | undefined;
    return r ? this.drift(r) : null;
  }
  listDrifts(limit = 100): Drift[] {
    return (this.db.prepare(`SELECT * FROM watch_drifts ORDER BY (status IN ('open', 'rollback-failed')) DESC, id DESC LIMIT ?`).all(limit) as Raw[]).map(this.drift);
  }
  unresolvedDrifts(): Drift[] {
    return (this.db.prepare(`SELECT * FROM watch_drifts WHERE status IN ('open', 'rollback-failed') ORDER BY id`).all() as Raw[]).map(this.drift);
  }
  insertDrift(d: Pick<Drift, "key" | "category" | "source" | "kind" | "label" | "before" | "after" | "rollbackable">): Drift {
    const now = this.now();
    const info = this.db
      .prepare(
        `INSERT INTO watch_drifts (key, category, source, kind, label, before_value, after_value, first_seen, last_seen, status, rollbackable)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)`,
      )
      .run(d.key, d.category, d.source, d.kind, d.label, d.before, d.after, now, now, d.rollbackable ? 1 : 0);
    return this.getDrift(Number(info.lastInsertRowid))!;
  }
  /** The same key drifted again (a different value): the open entry follows it. */
  updateDrift(id: number, d: Pick<Drift, "kind" | "label" | "after" | "rollbackable">): void {
    this.db
      .prepare(`UPDATE watch_drifts SET kind = ?, label = ?, after_value = ?, rollbackable = ?, last_seen = ?, status = 'open' WHERE id = ?`)
      .run(d.kind, d.label, d.after, d.rollbackable ? 1 : 0, this.now(), id);
  }
  touchDrift(id: number): void {
    this.db.prepare(`UPDATE watch_drifts SET last_seen = ? WHERE id = ?`).run(this.now(), id);
  }
  resolveDrift(id: number, status: DriftStatus, note: string | null = null): void {
    this.db.prepare(`UPDATE watch_drifts SET status = ?, resolved_at = ?, note = COALESCE(?, note) WHERE id = ?`).run(status, this.now(), note, id);
  }
  /** Marks a drift as failed-to-roll-back but still open (it keeps being shown, and is retried next scan). */
  failRollback(id: number, note: string): void {
    this.db.prepare(`UPDATE watch_drifts SET status = 'rollback-failed', note = ? WHERE id = ?`).run(note, id);
  }

  private cfgWindow = (r: Raw): ConfigWindowRow => ({
    id: r.id as number,
    scopes: JSON.parse(r.scopes as string) as WindowScope[],
    mode: r.mode as "sliding" | "fixed",
    sizeSec: r.size_sec as number,
    capSec: r.cap_sec as number,
    openedAt: r.opened_at as number,
    expiresAt: r.expires_at as number,
    hardExpiresAt: r.hard_expires_at as number,
    closedAt: (r.closed_at as number | null) ?? null,
    closedReason: (r.closed_reason as string | null) ?? null,
  });
  insertCfgWindow(w: Omit<ConfigWindowRow, "id" | "closedAt" | "closedReason">): ConfigWindowRow {
    const info = this.db
      .prepare(`INSERT INTO cfg_windows (scopes, mode, size_sec, cap_sec, opened_at, expires_at, hard_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(JSON.stringify(w.scopes), w.mode, w.sizeSec, w.capSec, w.openedAt, w.expiresAt, w.hardExpiresAt);
    return this.getCfgWindow(Number(info.lastInsertRowid))!;
  }
  getCfgWindow(id: number): ConfigWindowRow | null {
    const r = this.db.prepare(`SELECT * FROM cfg_windows WHERE id = ?`).get(id) as Raw | undefined;
    return r ? this.cfgWindow(r) : null;
  }
  unclosedCfgWindows(): ConfigWindowRow[] {
    return (this.db.prepare(`SELECT * FROM cfg_windows WHERE closed_at IS NULL ORDER BY id`).all() as Raw[]).map(this.cfgWindow);
  }
  closeCfgWindow(id: number, reason: string, at = this.now()): void {
    this.db.prepare(`UPDATE cfg_windows SET closed_at = ?, closed_reason = ? WHERE id = ? AND closed_at IS NULL`).run(at, reason, id);
  }
  setCfgWindowExpiry(id: number, expiresAt: number): void {
    this.db.prepare(`UPDATE cfg_windows SET expires_at = ? WHERE id = ? AND closed_at IS NULL`).run(expiresAt, id);
  }

  // ---- AI scan (stage 3) ---------------------------------------------------
  /** Settings live in our database next to the policy; no token or secret is ever kept here. */
  aiSettings(): AiSettings {
    const rows = this.db.prepare(`SELECT key, value FROM policy WHERE key LIKE 'ai.%'`).all() as Array<{ key: string; value: string }>;
    const map = new Map(rows.map((r) => [r.key, r.value]));
    return {
      enabled: map.get("ai.enabled") === "1",
      autoFreeze: map.get("ai.auto_freeze") === "1",
      autoExternal: map.get("ai.auto_external") === "1",
      second: map.get("ai.second") === "1",
      secondModel: map.get("ai.second_model") ?? DEFAULT_AI.secondModel,
      freezePlugins: rows.filter((r) => r.key.startsWith("ai.freeze:") && r.value === "1").map((r) => r.key.slice("ai.freeze:".length)).sort(),
    };
  }
  setAiSettings(next: AiSettings): void {
    const put = this.db.prepare(`INSERT INTO policy (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`);
    const flag = (b: boolean) => (b ? "1" : "0");
    put.run("ai.enabled", flag(next.enabled));
    put.run("ai.auto_freeze", flag(next.autoFreeze));
    put.run("ai.auto_external", flag(next.autoExternal));
    put.run("ai.second", flag(next.second));
    put.run("ai.second_model", next.secondModel);
    this.db.prepare(`DELETE FROM policy WHERE key LIKE 'ai.freeze:%'`).run();
    for (const id of next.freezePlugins) put.run(`ai.freeze:${id}`, "1");
  }
  insertScan(s: { pluginId: string; version: string; localHash: string; contentHash: string | null; trigger: ScanTrigger }): ScanRow {
    const info = this.db
      .prepare(`INSERT INTO scans (plugin_id, version, local_hash, content_hash, trigger, status, started_at) VALUES (?, ?, ?, ?, ?, 'running', ?)`)
      .run(s.pluginId, s.version, s.localHash, s.contentHash, s.trigger, this.now());
    return this.getScan(Number(info.lastInsertRowid))!;
  }
  finishScan(id: number, result: ScanResult): void {
    this.db.prepare(`UPDATE scans SET status = ?, finished_at = ?, result = ? WHERE id = ?`).run(result.status, this.now(), JSON.stringify(result), id);
  }
  /** Scans that were really run (a model was asked, or is being asked) since `ts`; `unavailable` ones cost nothing. */
  countScansSince(ts: number): number {
    return (this.db.prepare(`SELECT COUNT(*) AS n FROM scans WHERE started_at > ? AND status != 'unavailable'`).get(ts) as { n: number }).n;
  }
  /** The last such scan of exactly this tree since `ts`. */
  recentScanOfTree(localHash: string, ts: number): ScanRow | null {
    const r = this.db.prepare(`SELECT * FROM scans WHERE local_hash = ? AND started_at > ? AND status != 'unavailable' ORDER BY id DESC LIMIT 1`).get(localHash, ts) as Raw | undefined;
    return r ? scanRow(r) : null;
  }
  /** An earlier scan of the same tree also answers for this core hash. */
  linkScan(id: number, contentHash: string): void {
    this.db.prepare(`UPDATE scans SET content_hash = ? WHERE id = ? AND content_hash IS NULL`).run(contentHash, id);
  }
  /** A scan the process never finished (restart, crash) is not a result: say so instead of showing it as running forever. */
  interruptRunningScans(): number {
    const result: ScanResult = { status: "unavailable", models: [], files: 0, chars: 0, incomplete: [], skipped: [], note: "прервано перезапуском сервера" };
    return this.db.prepare(`UPDATE scans SET status = 'unavailable', finished_at = ?, result = ? WHERE status = 'running'`).run(this.now(), JSON.stringify(result)).changes;
  }
  getScan(id: number): ScanRow | null {
    const r = this.db.prepare(`SELECT * FROM scans WHERE id = ?`).get(id) as Raw | undefined;
    return r ? scanRow(r) : null;
  }
  listScans(limit = 40): ScanRow[] {
    return (this.db.prepare(`SELECT * FROM scans ORDER BY id DESC LIMIT ?`).all(limit) as Raw[]).map(scanRow);
  }
  /** The newest scan (finished or running) of exactly this tree or this core hash. */
  latestScanFor(k: { localHash?: string | null; contentHash?: string | null }): ScanRow | null {
    const r = this.db
      .prepare(`SELECT * FROM scans WHERE (local_hash = ? AND ? IS NOT NULL) OR (content_hash = ? AND ? IS NOT NULL) ORDER BY id DESC LIMIT 1`)
      .get(k.localHash ?? null, k.localHash ?? null, k.contentHash ?? null, k.contentHash ?? null) as Raw | undefined;
    return r ? scanRow(r) : null;
  }
  latestScanOfPlugin(pluginId: string): ScanRow | null {
    const r = this.db.prepare(`SELECT * FROM scans WHERE plugin_id = ? ORDER BY id DESC LIMIT 1`).get(pluginId) as Raw | undefined;
    return r ? scanRow(r) : null;
  }
  /** The proposal whose reviewed source has this hash. */
  proposalByLocalHash(pluginId: string, localHash: string): ProposalRow | null {
    const r = this.db.prepare(`SELECT * FROM proposals WHERE plugin_id = ? AND local_hash = ? ORDER BY id DESC LIMIT 1`).get(pluginId, localHash) as Raw | undefined;
    return r ? proposalRow(r) : null;
  }

  // ---- log --------------------------------------------------------------
  log(kind: string, pluginId: string | null, contentHash: string | null, detail: unknown = null): void {
    const head = appendRecord(this.db, this.now(), kind, pluginId, contentHash, detail === null ? null : JSON.stringify(detail));
    if (this.anchor) {
      try {
        this.anchor.write(head);
      } catch {
        /* see pinHead */
      }
    }
  }
  /** Checks the hash chain, the head file and that every approval has a journal record. */
  verifyJournal(): JournalReport {
    return verifyChain(this.db, this.now(), this.anchor);
  }
  /** How many records existed before the chain began (their history before that cannot be proven). */
  journalSealedLegacy(): number {
    return Number(this.getMeta("journal_sealed_count") ?? 0);
  }
  /**
   * Logs a decision unless the latest decision about this version says exactly the same
   * (a held or rejected plugin that is rechecked again and again is one fact, not many).
   * Returns whether a row was written.
   */
  logDecision(kind: string, pluginId: string | null, contentHash: string | null, detail: unknown): boolean {
    if (contentHash) {
      const last = this.db
        .prepare(`SELECT kind, detail FROM log WHERE content_hash = ? AND (kind IN ('hold', 'reject', 'revoked', 'dismissed', 'block.lifted') OR kind LIKE 'approved.%') ORDER BY id DESC LIMIT 1`)
        .get(contentHash) as { kind: string; detail: string | null } | undefined;
      if (last && last.kind === kind && last.detail === JSON.stringify(detail)) return false;
    }
    this.log(kind, pluginId, contentHash, detail);
    return true;
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

  // ---- trusted repositories (stage 5) -------------------------------------------
  trustedRepos(): string[] {
    return (this.db.prepare(`SELECT pattern FROM trusted_repos ORDER BY pattern`).all() as Array<{ pattern: string }>).map((r) => r.pattern);
  }
  addTrustedRepo(pattern: string): boolean {
    return this.db.prepare(`INSERT OR IGNORE INTO trusted_repos (pattern, added_at) VALUES (?, ?)`).run(pattern, this.now()).changes > 0;
  }
  removeTrustedRepo(pattern: string): boolean {
    return this.db.prepare(`DELETE FROM trusted_repos WHERE pattern = ?`).run(pattern).changes > 0;
  }

  // ---- taint (stage 5): threads that read untrusted content ---------------------
  taintCursor(threadId: string): number | null {
    const r = this.db.prepare(`SELECT last_seq FROM taint_cursor WHERE thread_id = ?`).get(threadId) as { last_seq: number } | undefined;
    return r ? r.last_seq : null;
  }
  setTaintCursor(threadId: string, seq: number): void {
    this.db
      .prepare(`INSERT INTO taint_cursor (thread_id, last_seq, scanned_at) VALUES (?, ?, ?) ON CONFLICT(thread_id) DO UPDATE SET last_seq = excluded.last_seq, scanned_at = excluded.scanned_at`)
      .run(threadId, seq, this.now());
  }
  /** Returns true when the hit is new. */
  addTaintHit(h: TaintHitRow): boolean {
    const info = this.db.prepare(`INSERT OR IGNORE INTO taint_hits (thread_id, seq, kind, at, note) VALUES (?, ?, ?, ?, ?)`).run(h.threadId, h.seq, h.kind, h.at, h.note);
    return info.changes > 0;
  }
  clearTaintHit(threadId: string, seq: number): void {
    this.db.prepare(`DELETE FROM taint_hits WHERE thread_id = ? AND seq = ?`).run(threadId, seq);
  }
  /** Hits in the given threads (all threads when `threadIds` is null) at or after `since`; a project's `.bb-env-setup.sh` counts whenever it was first seen. */
  taintHits(threadIds: readonly string[] | null, since: number): TaintHitRow[] {
    const rows =
      threadIds === null
        ? (this.db.prepare(`SELECT * FROM taint_hits WHERE (at >= ? OR kind = 'env-setup') ORDER BY at, thread_id, seq`).all(since) as Raw[])
        : threadIds.length === 0
          ? []
          : (this.db
              .prepare(`SELECT * FROM taint_hits WHERE (at >= ? OR kind = 'env-setup') AND thread_id IN (${threadIds.map(() => "?").join(",")}) ORDER BY at, thread_id, seq`)
              .all(since, ...threadIds) as Raw[]);
    return rows.map((r) => ({ threadId: r.thread_id as string, seq: r.seq as number, kind: r.kind as string, at: r.at as number, note: r.note as string }));
  }
  /** A hit that exists in the thread regardless of when (the "this thread is tainted" fact, for the page). */
  taintedThreads(limit = 50): Array<{ threadId: string; kinds: string[]; first: number; last: number }> {
    const rows = this.db.prepare(`SELECT thread_id, GROUP_CONCAT(DISTINCT kind) AS kinds, MIN(at) AS first, MAX(at) AS last FROM taint_hits GROUP BY thread_id ORDER BY last DESC LIMIT ?`).all(limit) as Raw[];
    return rows.map((r) => ({ threadId: r.thread_id as string, kinds: String(r.kinds).split(","), first: r.first as number, last: r.last as number }));
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
