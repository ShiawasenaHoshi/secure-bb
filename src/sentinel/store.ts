// The sentinel's tables in secure-bb's own database. Settings are here, not in plugin settings (anyone can change those).
// Nothing secret is stored: the feed holds masked, shortened text and numbers.
import type { Db } from "../store.js";
import { CATEGORY_IDS, DEFAULT_SETTINGS } from "./questions.js";
import type { CategoryScore, FeedRow, NotScoredReason, Outcome, SentinelSettings } from "./types.js";

/** Appended to the plugin's MIGRATIONS (append-only). */
export const SENTINEL_MIGRATIONS: string[] = [
  `CREATE TABLE IF NOT EXISTS sentinel_config (id INTEGER PRIMARY KEY CHECK (id = 1), json TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sentinel_feed (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     ts INTEGER NOT NULL,
     thread_id TEXT NOT NULL,
     interaction_id TEXT NOT NULL UNIQUE,
     provider_id TEXT NOT NULL,
     window_plugin TEXT,
     tool TEXT NOT NULL,
     args TEXT NOT NULL,
     task TEXT,
     status TEXT NOT NULL,
     reason TEXT,
     reason_kind TEXT,
     categories_json TEXT NOT NULL DEFAULT '[]',
     risk_json TEXT,
     solver TEXT NOT NULL,
     outcome TEXT NOT NULL DEFAULT 'pending',
     outcome_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS sentinel_feed_outcome ON sentinel_feed (outcome, thread_id)`,
];

type Raw = Record<string, unknown>;

const clamp = (v: unknown, lo: number, hi: number, dflt: number): number => (typeof v === "number" && Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : dflt);

/** Reads a stored settings object defensively: anything odd falls back to the default. */
export function normalizeSettings(raw: unknown): SentinelSettings {
  const r = (raw !== null && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const thresholds: Record<string, number> = { ...DEFAULT_SETTINGS.thresholds };
  const t = (r.thresholds !== null && typeof r.thresholds === "object" ? r.thresholds : {}) as Record<string, unknown>;
  for (const id of CATEGORY_IDS) thresholds[id] = clamp(t[id], 0, 1, DEFAULT_SETTINGS.thresholds[id]!);
  const instructions: Record<string, string> = {};
  const ins = (r.instructions !== null && typeof r.instructions === "object" ? r.instructions : {}) as Record<string, unknown>;
  for (const [k, v] of Object.entries(ins)) if (typeof v === "string" && v.trim() !== "") instructions[k] = v;
  return {
    provider: r.provider === "openrouter" ? "openrouter" : "typesafe",
    enabled: r.enabled === true,
    allThreads: r.allThreads === true,
    timeoutMs: Math.round(clamp(r.timeoutMs, 1000, 60_000, DEFAULT_SETTINGS.timeoutMs)),
    maxPerMinute: Math.round(clamp(r.maxPerMinute, 1, 600, DEFAULT_SETTINGS.maxPerMinute)),
    thresholds,
    riskThreshold: clamp(r.riskThreshold, 0, 2, DEFAULT_SETTINGS.riskThreshold),
    instructions,
  };
}

const feedRow = (r: Raw): FeedRow => ({
  id: Number(r.id),
  ts: Number(r.ts),
  threadId: String(r.thread_id),
  interactionId: String(r.interaction_id),
  providerId: String(r.provider_id),
  windowPlugin: (r.window_plugin as string | null) ?? null,
  tool: String(r.tool),
  args: String(r.args),
  task: (r.task as string | null) ?? null,
  status: r.status as FeedRow["status"],
  reason: (r.reason as string | null) ?? null,
  reasonKind: (r.reason_kind as NotScoredReason | null) ?? null,
  categories: JSON.parse(String(r.categories_json)) as CategoryScore[],
  risk: r.risk_json ? (JSON.parse(String(r.risk_json)) as FeedRow["risk"]) : null,
  solver: String(r.solver),
  outcome: r.outcome as Outcome,
  outcomeAt: r.outcome_at === null ? null : Number(r.outcome_at),
});

export class SentinelStore {
  constructor(
    private readonly db: Db,
    private readonly now: () => number,
  ) {}

  settings(): SentinelSettings {
    const row = this.db.prepare(`SELECT json FROM sentinel_config WHERE id = 1`).get() as { json: string } | undefined;
    if (!row) return normalizeSettings({});
    try {
      return normalizeSettings(JSON.parse(row.json));
    } catch {
      return normalizeSettings({});
    }
  }
  setSettings(next: SentinelSettings): void {
    this.db.prepare(`INSERT INTO sentinel_config (id, json) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET json = excluded.json`).run(JSON.stringify(next));
  }

  /** Inserts the record for a card; false when the card was already recorded (the event came twice). */
  insert(r: { threadId: string; interactionId: string; providerId: string; windowPlugin: string | null; tool: string; args: string; task: string | null; solver: string }): FeedRow | null {
    const info = this.db
      .prepare(
        `INSERT OR IGNORE INTO sentinel_feed (ts, thread_id, interaction_id, provider_id, window_plugin, tool, args, task, status, solver)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'evaluating', ?)`,
      )
      .run(this.now(), r.threadId, r.interactionId, r.providerId, r.windowPlugin, r.tool, r.args, r.task, r.solver);
    return info.changes === 0 ? null : this.get(Number(info.lastInsertRowid));
  }
  setTask(id: number, task: string | null): void {
    this.db.prepare(`UPDATE sentinel_feed SET task = ? WHERE id = ?`).run(task, id);
  }
  setScored(id: number, categories: CategoryScore[], risk: FeedRow["risk"]): void {
    this.db.prepare(`UPDATE sentinel_feed SET status = 'scored', categories_json = ?, risk_json = ? WHERE id = ?`).run(JSON.stringify(categories), risk ? JSON.stringify(risk) : null, id);
  }
  setNotScored(id: number, kind: NotScoredReason, reason: string): void {
    this.db.prepare(`UPDATE sentinel_feed SET status = 'not_scored', reason_kind = ?, reason = ? WHERE id = ?`).run(kind, reason, id);
  }
  setOutcome(id: number, outcome: Outcome): void {
    this.db.prepare(`UPDATE sentinel_feed SET outcome = ?, outcome_at = ? WHERE id = ?`).run(outcome, outcome === "pending" ? null : this.now(), id);
  }
  /** A start after a crash: records that were mid-evaluation will never finish. */
  failEvaluating(): number {
    return this.db.prepare(`UPDATE sentinel_feed SET status = 'not_scored', reason_kind = 'error', reason = 'сервер перезапущен до оценки' WHERE status = 'evaluating'`).run().changes;
  }
  get(id: number): FeedRow | null {
    const r = this.db.prepare(`SELECT * FROM sentinel_feed WHERE id = ?`).get(id) as Raw | undefined;
    return r ? feedRow(r) : null;
  }
  byInteraction(interactionId: string): FeedRow | null {
    const r = this.db.prepare(`SELECT * FROM sentinel_feed WHERE interaction_id = ?`).get(interactionId) as Raw | undefined;
    return r ? feedRow(r) : null;
  }
  list(limit: number): FeedRow[] {
    return (this.db.prepare(`SELECT * FROM sentinel_feed ORDER BY id DESC LIMIT ?`).all(limit) as Raw[]).map(feedRow);
  }
  /** Cards whose outcome is not known yet; of a thread when given. */
  openOutcomes(threadId?: string, limit = 50): FeedRow[] {
    const rows = threadId
      ? (this.db.prepare(`SELECT * FROM sentinel_feed WHERE outcome = 'pending' AND thread_id = ? ORDER BY id LIMIT ?`).all(threadId, limit) as Raw[])
      : (this.db.prepare(`SELECT * FROM sentinel_feed WHERE outcome = 'pending' ORDER BY id LIMIT ?`).all(limit) as Raw[]);
    return rows.map(feedRow);
  }
}
