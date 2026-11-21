// The skills module's tables (stage 6) in secure-bb's own database.
import type { Db } from "../store.js";
import { SKILL_RULES_VERSION } from "./inspect.js";
import type { SkillCheck, SkillPinRow, SkillQueueRow, SkillState } from "./types.js";

/** Appended to the plugin's MIGRATIONS (append-only). */
export const SKILL_MIGRATIONS: string[] = [
  // Approved content hash of every skill (names and hashes only: no skill text).
  `CREATE TABLE IF NOT EXISTS skill_pins (
     key TEXT PRIMARY KEY,
     skill_id TEXT NOT NULL,
     name TEXT NOT NULL,
     scope TEXT NOT NULL,
     project_id TEXT NOT NULL,
     hash TEXT NOT NULL,
     kind TEXT NOT NULL,
     via TEXT NOT NULL,
     approved_at INTEGER NOT NULL,
     files INTEGER NOT NULL DEFAULT 0)`,
  // Skills that were held, removed or raised an alarm. A removed skill keeps what it contained (page only).
  `CREATE TABLE IF NOT EXISTS skill_queue (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     key TEXT NOT NULL,
     skill_id TEXT NOT NULL,
     name TEXT NOT NULL,
     scope TEXT NOT NULL,
     project_id TEXT NOT NULL,
     hash TEXT NOT NULL,
     decision TEXT NOT NULL,
     state TEXT NOT NULL,
     reason TEXT NOT NULL,
     check_json TEXT,
     source TEXT,
     preexisting INTEGER NOT NULL DEFAULT 0,
     first_seen INTEGER NOT NULL,
     last_seen INTEGER NOT NULL,
     resolved_at INTEGER,
     via TEXT,
     removed_json TEXT,
     note TEXT)`,
  `CREATE INDEX IF NOT EXISTS skill_queue_key ON skill_queue (key, state)`,
  // Registry sources (`owner/repo`, `owner/*`) whose clean skills are accepted without a touch. Empty by default; changed only with a code.
  `CREATE TABLE IF NOT EXISTS trusted_skill_sources (pattern TEXT PRIMARY KEY, added_at INTEGER NOT NULL)`,
];

type Raw = Record<string, unknown>;

const pinRow = (r: Raw): SkillPinRow => ({
  key: String(r.key),
  skillId: String(r.skill_id),
  name: String(r.name),
  scope: String(r.scope),
  projectId: String(r.project_id),
  hash: String(r.hash),
  kind: r.kind as SkillPinRow["kind"],
  via: String(r.via),
  approvedAt: Number(r.approved_at),
  files: Number(r.files),
});

const queueRow = (r: Raw): SkillQueueRow => ({
  id: Number(r.id),
  key: String(r.key),
  skillId: String(r.skill_id),
  name: String(r.name),
  scope: String(r.scope),
  projectId: String(r.project_id),
  hash: String(r.hash),
  decision: r.decision as SkillQueueRow["decision"],
  state: r.state as SkillState,
  reason: String(r.reason),
  check: r.check_json ? (JSON.parse(String(r.check_json)) as SkillCheck) : null,
  source: r.source === null ? null : String(r.source),
  preexisting: Number(r.preexisting) === 1,
  firstSeen: Number(r.first_seen),
  lastSeen: Number(r.last_seen),
  resolvedAt: r.resolved_at === null ? null : Number(r.resolved_at),
  via: r.via === null ? null : String(r.via),
  removedFiles: r.removed_json ? (JSON.parse(String(r.removed_json)) as SkillQueueRow["removedFiles"]) : null,
  note: r.note === null ? null : String(r.note),
  rulesVersion: Number(r.rules_version ?? 0),
});

export interface NewQueueRow {
  key: string;
  skillId: string;
  name: string;
  scope: string;
  projectId: string;
  hash: string;
  decision: "review" | "block";
  state: SkillState;
  reason: string;
  check: SkillCheck | null;
  source: string | null;
  preexisting: boolean;
}

/** `held` and `alarm` rows are open: they wait for a person. */
export const OPEN_STATES: readonly SkillState[] = ["held", "alarm"];

export class SkillStore {
  constructor(
    private readonly db: Db,
    private readonly now: () => number,
  ) {}

  // ---- pins ----
  pins(): SkillPinRow[] {
    return (this.db.prepare(`SELECT * FROM skill_pins ORDER BY key`).all() as Raw[]).map(pinRow);
  }
  pin(key: string): SkillPinRow | null {
    const r = this.db.prepare(`SELECT * FROM skill_pins WHERE key = ?`).get(key) as Raw | undefined;
    return r ? pinRow(r) : null;
  }
  putPin(p: Omit<SkillPinRow, "approvedAt">): void {
    this.db
      .prepare(
        `INSERT INTO skill_pins (key, skill_id, name, scope, project_id, hash, kind, via, approved_at, files)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET skill_id = excluded.skill_id, name = excluded.name, scope = excluded.scope, project_id = excluded.project_id,
           hash = excluded.hash, kind = excluded.kind, via = excluded.via, approved_at = excluded.approved_at, files = excluded.files`,
      )
      .run(p.key, p.skillId, p.name, p.scope, p.projectId, p.hash, p.kind, p.via, this.now(), p.files);
  }
  deletePin(key: string): void {
    this.db.prepare(`DELETE FROM skill_pins WHERE key = ?`).run(key);
  }

  // ---- queue ----
  insertRow(r: NewQueueRow, rulesVersion = SKILL_RULES_VERSION): SkillQueueRow {
    const t = this.now();
    const res = this.db
      .prepare(
        `INSERT INTO skill_queue (key, skill_id, name, scope, project_id, hash, decision, state, reason, check_json, source, preexisting, first_seen, last_seen, rules_version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(r.key, r.skillId, r.name, r.scope, r.projectId, r.hash, r.decision, r.state, r.reason, r.check ? JSON.stringify(r.check) : null, r.source, r.preexisting ? 1 : 0, t, t, rulesVersion);
    return this.getRow(Number(res.lastInsertRowid))!;
  }
  getRow(id: number): SkillQueueRow | null {
    const r = this.db.prepare(`SELECT * FROM skill_queue WHERE id = ?`).get(id) as Raw | undefined;
    return r ? queueRow(r) : null;
  }
  /** The row of this skill that waits for a person, if any. */
  openRow(key: string): SkillQueueRow | null {
    const r = this.db.prepare(`SELECT * FROM skill_queue WHERE key = ? AND state IN ('held','alarm') ORDER BY id DESC LIMIT 1`).get(key) as Raw | undefined;
    return r ? queueRow(r) : null;
  }
  /** The latest row of this skill with this content hash (any state). */
  rowByHash(key: string, hash: string): SkillQueueRow | null {
    const r = this.db.prepare(`SELECT * FROM skill_queue WHERE key = ? AND hash = ? ORDER BY id DESC LIMIT 1`).get(key, hash) as Raw | undefined;
    return r ? queueRow(r) : null;
  }
  openRows(): SkillQueueRow[] {
    return (this.db.prepare(`SELECT * FROM skill_queue WHERE state IN ('held','alarm') ORDER BY id`).all() as Raw[]).map(queueRow);
  }
  recentRows(limit: number): SkillQueueRow[] {
    return (this.db.prepare(`SELECT * FROM skill_queue WHERE state NOT IN ('held','alarm') ORDER BY id DESC LIMIT ?`).all(limit) as Raw[]).map(queueRow);
  }
  /** The same skill changed again while it waited: the row follows the new content. */
  retarget(id: number, r: Pick<NewQueueRow, "skillId" | "hash" | "decision" | "state" | "reason" | "check" | "source">): void {
    this.db
      .prepare(`UPDATE skill_queue SET skill_id = ?, hash = ?, decision = ?, state = ?, reason = ?, check_json = ?, source = ?, last_seen = ?, rules_version = ? WHERE id = ?`)
      .run(r.skillId, r.hash, r.decision, r.state, r.reason, r.check ? JSON.stringify(r.check) : null, r.source, this.now(), SKILL_RULES_VERSION, id);
  }
  touchRow(id: number): void {
    this.db.prepare(`UPDATE skill_queue SET last_seen = ? WHERE id = ?`).run(this.now(), id);
  }
  resolve(id: number, state: SkillState, via: string | null, note: string | null): void {
    this.db.prepare(`UPDATE skill_queue SET state = ?, via = ?, note = ?, resolved_at = ?, last_seen = ? WHERE id = ?`).run(state, via, note, this.now(), this.now(), id);
  }
  setRemoved(id: number, files: Array<{ path: string; content: string | null }>): void {
    this.db.prepare(`UPDATE skill_queue SET removed_json = ? WHERE id = ?`).run(JSON.stringify(files), id);
  }
  setNote(id: number, note: string): void {
    this.db.prepare(`UPDATE skill_queue SET note = ? WHERE id = ?`).run(note, id);
  }

  // ---- trusted sources ----
  trustedSources(): string[] {
    return (this.db.prepare(`SELECT pattern FROM trusted_skill_sources ORDER BY pattern`).all() as Array<{ pattern: string }>).map((r) => r.pattern);
  }
  addTrustedSource(pattern: string): boolean {
    return this.db.prepare(`INSERT OR IGNORE INTO trusted_skill_sources (pattern, added_at) VALUES (?, ?)`).run(pattern, this.now()).changes > 0;
  }
  removeTrustedSource(pattern: string): boolean {
    return this.db.prepare(`DELETE FROM trusted_skill_sources WHERE pattern = ?`).run(pattern).changes > 0;
  }
}
