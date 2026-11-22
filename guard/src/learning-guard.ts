// The guard's layer for the journal that teaches: what the page says it showed (`view`), the snapshot and the timing that go into a decision's record,
// the owner's mark afterwards (`mark`) and the console's export. It decides nothing: no record written here changes what is approved or held.
// The page's report is advisory (a plugin's page can lie in it); the guard's own facts (rights, rules, reason, block, the clock) are not.
import { GuardError, HOUR_MS, intOf, queueOf, type ApprovalRow, type QueueRow, type Raw } from "./guard-types.ts";
import type { Rights } from "./trust.ts";
import { cleanHow, cleanReason, cleanViewReport, exportRecord, isDecisionKind, MARKS, rightKeys, type ExportRecord, type How, type Mark, type MarkRow, type Seen, type ViewReport } from "./learning.ts";
import { FactorGuard } from "./factor.ts";

/** At most this many marks an hour: a mark costs a journal record, and marks are not authenticated. */
export const MAX_MARKS_PER_HOUR = 200;
/** Views of cards kept: the newest queue ids. */
export const MAX_CARD_VIEWS = 1000;

const EVENTS = ["shown", "details", "later"] as const;
type ViewEvent = (typeof EVENTS)[number];

export class LearningGuard extends FactorGuard {
  /** `view {requestId, event, level?, findings?, ai?, textsVersion?, detailsOpen?}`: the page tells that it showed a card, that «Подробнее» was opened, that «Решить позже» was pressed. */
  view(raw: Record<string, unknown>): { ok: true } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    const event = raw.event as ViewEvent;
    if (!EVENTS.includes(event)) throw new GuardError("invalid", "event is shown, details or later");
    if (!this.db.prepare(`SELECT 1 FROM queue WHERE id = ?`).get(id)) throw new GuardError("not_found", "no such request");
    const now = this.now();
    this.tx(() => {
      this.db.prepare(`INSERT OR IGNORE INTO card_views (queue_id, shown_at) VALUES (?, ?)`).run(id, now);
      if (event === "shown") {
        // The newest report counts: the card may change while it is open (a verdict of the AI arrives).
        this.db.prepare(`UPDATE card_views SET report = ?, details_open = ? WHERE queue_id = ?`).run(JSON.stringify(cleanViewReport(raw)), raw.detailsOpen === true ? 1 : 0, id);
      } else if (event === "details") this.db.prepare(`UPDATE card_views SET details_at = COALESCE(details_at, ?) WHERE queue_id = ?`).run(now, id);
      else this.db.prepare(`UPDATE card_views SET later_n = later_n + 1 WHERE queue_id = ?`).run(id);
      this.db.prepare(`DELETE FROM card_views WHERE queue_id NOT IN (SELECT queue_id FROM card_views ORDER BY queue_id DESC LIMIT ?)`).run(MAX_CARD_VIEWS);
    });
    return { ok: true };
  }

  /** What goes into a decision's record. `queue` is the held version the person decided on (null: a decision with no card, a revoke or a rule). */
  protected learning(o: { queue?: QueueRow | null; rights?: Rights | null; contentHash?: string | null }): { seen: Seen; how?: How } {
    const q = o.queue ?? null;
    const rights = q?.rights ?? o.rights ?? null;
    const v = q ? (this.db.prepare(`SELECT * FROM card_views WHERE queue_id = ?`).get(q.id) as Raw | undefined) : undefined;
    let report: ViewReport = { level: null, findings: [], ai: [], textsVersion: null };
    if (v && typeof v.report === "string") {
      try {
        report = cleanViewReport(JSON.parse(v.report));
      } catch {
        /* a report that does not parse is the same as none */
      }
    }
    const seen: Seen = {
      ...report,
      rights: rightKeys(rights?.tokens ?? []),
      reviewRules: rights?.review.slice(0, 40) ?? [],
      reasonKind: q?.reasonKind ?? null,
      blocked: q ? (q.blocks === null ? null : q.blocks.length > 0) : null,
    };
    if (!v) return { seen };
    const now = this.now();
    const how = cleanHow({ decideMs: now - Number(v.shown_at), detailsOpened: v.details_open === 1 || (v.details_at !== null && Number(v.details_at) <= now), snoozedBefore: Number(v.later_n) > 0 });
    return how ? { seen, how } : { seen };
  }

  /** What was seen for a revoke: the held version of the same code, if the page showed one, else the rights it was approved with. */
  protected seenForApproval(a: ApprovalRow): { seen: Seen } {
    const row = this.db.prepare(`SELECT * FROM queue WHERE content_hash = ? AND plugin_id = ? ORDER BY id DESC LIMIT 1`).get(a.contentHash, a.pluginId) as Raw | undefined;
    // The time since the card was shown means nothing for a revoke made later: only what was seen.
    return { seen: this.learning({ ...(row ? { queue: queueOf(row) } : {}), rights: a.rights }).seen };
  }

  /**
   * `mark {record, mark, reason?}`: the owner's note on a decision, after the fact: «ложная тревога» / «правда было опасно» / «не знаю». A record of its own in the journal
   * (the chain keeps it; the latest mark of a record counts). No proof: it changes nothing a decision depends on. It is not authenticated, and the export says so.
   */
  mark(raw: Record<string, unknown>): { ok: true } {
    const record = intOf(raw.record, "record", 1, Number.MAX_SAFE_INTEGER);
    if (typeof raw.mark !== "string" || !(MARKS as readonly string[]).includes(raw.mark)) throw new GuardError("invalid", `mark is one of ${MARKS.join(", ")}`);
    const reason = cleanReason(raw.reason);
    const row = this.db.prepare(`SELECT kind, plugin_id, content_hash FROM journal WHERE id = ?`).get(record) as { kind: string; plugin_id: string | null; content_hash: string | null } | undefined;
    if (!row) throw new GuardError("not_found", "no such record");
    if (!isDecisionKind(row.kind)) throw new GuardError("invalid", "only a decision can be marked");
    this.tx(() => {
      const recent = (this.db.prepare(`SELECT COUNT(*) AS n FROM journal WHERE kind = 'decision.mark' AND ts > ?`).get(this.now() - HOUR_MS) as { n: number }).n;
      if (recent >= MAX_MARKS_PER_HOUR) throw new GuardError("conflict", "too many marks this hour");
      this.log("decision.mark", row.plugin_id, row.content_hash, { record, mark: raw.mark, ...(reason ? { reason } : {}) });
    });
    return { ok: true };
  }

  /** Console only (there is no socket op for it): the decisions since `since` as export records, the latest mark of each beside it. */
  exportDecisions(since: number): ExportRecord[] {
    const marks = new Map<number, MarkRow>();
    for (const r of this.db.prepare(`SELECT ts, detail FROM journal WHERE kind = 'decision.mark' ORDER BY id`).all() as Array<{ ts: number; detail: string | null }>) {
      try {
        const d = JSON.parse(r.detail ?? "null") as { record?: unknown; mark?: unknown; reason?: unknown } | null;
        if (d && typeof d.record === "number" && typeof d.mark === "string" && (MARKS as readonly string[]).includes(d.mark)) marks.set(d.record, { record: d.record, mark: d.mark as Mark, reason: typeof d.reason === "string" ? cleanReason(d.reason) : null, ts: Number(r.ts) });
      } catch {
        /* a record that does not parse is skipped */
      }
    }
    const out: ExportRecord[] = [];
    for (const r of this.db.prepare(`SELECT id, ts, kind, plugin_id, detail FROM journal WHERE ts >= ? ORDER BY id`).all(since) as Array<{ id: number; ts: number; kind: string; plugin_id: string | null; detail: string | null }>) {
      let detail: Record<string, unknown> | null = null;
      try {
        detail = r.detail === null ? null : (JSON.parse(r.detail) as Record<string, unknown>);
      } catch {
        detail = null;
      }
      const rec = exportRecord({ id: Number(r.id), ts: Number(r.ts), kind: r.kind, pluginId: r.plugin_id, detail }, marks.get(Number(r.id)) ?? null);
      if (rec) out.push(rec);
    }
    return out;
  }
}
