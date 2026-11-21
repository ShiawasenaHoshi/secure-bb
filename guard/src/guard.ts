// The guard's decisions. Pure logic over the database and an injected clock: no sockets here (server.ts),
// no terminal here (cli.ts). Everything that changes state happens in one transaction together with its
// journal record, and the journal head file is rewritten right after the commit.
//
// Two kinds of requests (design doc, "Сокет и протокол"):
//  - without a secret (any process of the bb user can send them, including a harmful plugin, so they may
//    decide nothing a human has not already decided): decide, state, lookup, annotate, close-window, revoke, dismiss (held entries only);
//  - with a touch (a TOTP code): approve, open-window, policy, touch.
// The TOTP secret is only ever written by `sbb-guard totp-register` on the console, and is never returned
// by anything in this file.
import { readFileSync, renameSync, writeFileSync, openSync, closeSync, writeSync, constants } from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import { append, HeadFile, readHead, verify, type JournalHead, type JournalReport } from "./journal.ts";
import { verifyTotp } from "./totp.ts";

export type GuardErrorCode = "invalid" | "not_found" | "conflict" | "not_registered" | "invalid_code" | "blocked" | "unknown_op";

export class GuardError extends Error {
  readonly code: GuardErrorCode;
  constructor(code: GuardErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export const HOUR_MS = 3_600_000;
export const MAX_FAILURES = 5;
const MAX_HOLDS_PER_HOUR = 200;
const MAX_QUEUE_ROWS = 1000;
const MAX_ANNOTATIONS = 500;
const MAX_FINDINGS_BYTES = 64 * 1024;

export interface Policy {
  /** Default size of a window, minutes. */
  windowMin: number;
  /** Hard ceiling of a window from its opening, minutes. */
  capMin: number;
  mode: "sliding" | "fixed";
}
export const DEFAULT_POLICY: Policy = { windowMin: 30, capMin: 240, mode: "sliding" };

export interface DecideInput {
  pluginId: string;
  version: string;
  contentHash: string;
  rootDir: string;
  source: string;
  sourceKind: string;
  trigger: string;
}
export type Decision = { action: "proceed"; via: "approval" | "window" } | { action: "wait"; reason: string; requestId: number | null };

export interface ApprovalRow {
  id: number;
  contentHash: string;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  gitCommit: string | null;
  npmIntegrity: string | null;
  via: string;
  windowId: number | null;
  approvedAt: number;
  revokedAt: number | null;
}
export interface QueueRow {
  id: number;
  contentHash: string;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  rootDir: string;
  trigger: string;
  status: "held" | "approved" | "dismissed";
  firstSeen: number;
  lastSeen: number;
  seenCount: number;
}
export interface WindowRow {
  id: number;
  pluginId: string;
  sizeSec: number;
  capSec: number;
  mode: "sliding" | "fixed";
  openedAt: number;
  expiresAt: number;
  hardExpiresAt: number;
  closedAt: number | null;
  closedReason: string | null;
  uses: number;
}

type Raw = Record<string, unknown>;
const approvalOf = (r: Raw): ApprovalRow => ({
  id: Number(r.id),
  contentHash: String(r.content_hash),
  pluginId: String(r.plugin_id),
  version: String(r.version),
  source: String(r.source),
  sourceKind: String(r.source_kind),
  gitCommit: (r.git_commit as string | null) ?? null,
  npmIntegrity: (r.npm_integrity as string | null) ?? null,
  via: String(r.via),
  windowId: r.window_id === null ? null : Number(r.window_id),
  approvedAt: Number(r.approved_at),
  revokedAt: r.revoked_at === null ? null : Number(r.revoked_at),
});
const queueOf = (r: Raw): QueueRow => ({
  id: Number(r.id),
  contentHash: String(r.content_hash),
  pluginId: String(r.plugin_id),
  version: String(r.version),
  source: String(r.source),
  sourceKind: String(r.source_kind),
  rootDir: String(r.root_dir),
  trigger: String(r.trigger),
  status: r.status as QueueRow["status"],
  firstSeen: Number(r.first_seen),
  lastSeen: Number(r.last_seen),
  seenCount: Number(r.seen_count),
});
const windowOf = (r: Raw): WindowRow => ({
  id: Number(r.id),
  pluginId: String(r.plugin_id),
  sizeSec: Number(r.size_sec),
  capSec: Number(r.cap_sec),
  mode: r.mode as WindowRow["mode"],
  openedAt: Number(r.opened_at),
  expiresAt: Number(r.expires_at),
  hardExpiresAt: Number(r.hard_expires_at),
  closedAt: r.closed_at === null ? null : Number(r.closed_at),
  closedReason: (r.closed_reason as string | null) ?? null,
  uses: Number(r.uses),
});

// ---- input validation: every string that reaches the database or the journal is checked here ---------
const PLUGIN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function str(v: unknown, name: string, max = 1024, min = 0): string {
  if (typeof v !== "string" || v.length < min || v.length > max) throw new GuardError("invalid", `${name} must be a string of ${min}..${max} characters`);
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v)) throw new GuardError("invalid", `${name} contains control characters`);
  return v;
}
export function pluginIdOf(v: unknown): string {
  const s = str(v, "pluginId", 128, 1);
  if (!PLUGIN_ID.test(s)) throw new GuardError("invalid", "pluginId is not a plugin id");
  return s;
}
export function hashOf(v: unknown): string {
  const s = str(v, "contentHash", 256, 8);
  if (!/^[A-Za-z0-9+/=_:.-]+$/.test(s)) throw new GuardError("invalid", "contentHash has characters a hash does not have");
  return s;
}
export function intOf(v: unknown, name: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw new GuardError("invalid", `${name} must be an integer ${min}..${max}`);
  return v;
}

export interface GuardOptions {
  db: DatabaseSync;
  now: () => number;
  /** The file that holds the TOTP secret (written only by the console command). */
  secretPath: string;
  /** The journal head, kept apart from the database. */
  headPath: string;
}

export interface ImportItem {
  contentHash: string;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  gitCommit: string | null;
  npmIntegrity: string | null;
  approvedAt: number;
}

export class Guard {
  private readonly db: DatabaseSync;
  private readonly now: () => number;
  private readonly secretPath: string;
  private readonly head: HeadFile;

  constructor(o: GuardOptions) {
    this.db = o.db;
    this.now = o.now;
    this.secretPath = o.secretPath;
    this.head = new HeadFile(o.headPath);
  }

  // ---- plumbing -----------------------------------------------------------
  /** One transaction; the journal head file follows the commit. A throw rolls everything back. */
  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    let out: T;
    try {
      out = fn();
      this.db.exec("COMMIT");
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* nothing open */
      }
      throw err;
    }
    this.flushHead();
    return out;
  }
  private flushHead(): void {
    const h = readHead(this.db);
    const on = this.head.read();
    if (h && (!on || on.id !== h.id || on.hash !== h.hash)) this.head.write(h);
  }
  private log(kind: string, pluginId: string | null, contentHash: string | null, detail: Record<string, unknown> | null): JournalHead {
    return append(this.db, this.now(), kind, pluginId, contentHash, detail);
  }
  private meta(key: string): string | null {
    const r = this.db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as { value: string } | undefined;
    return r ? r.value : null;
  }
  private setMeta(key: string, value: string): void {
    this.db.prepare(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(key, value);
  }

  /** Writes a record outside any request (start, stop, console commands). */
  record(kind: string, pluginId: string | null, contentHash: string | null, detail: Record<string, unknown> | null): void {
    this.tx(() => this.log(kind, pluginId, contentHash, detail));
  }

  // ---- TOTP ---------------------------------------------------------------
  /** The secret, or null. Only this file and the console command ever touch it. */
  private secret(): string | null {
    try {
      const t = readFileSync(this.secretPath, "utf8").trim();
      return /^[A-Z2-7]{16,}$/.test(t) ? t : null;
    } catch {
      return null;
    }
  }
  totpRegistered(): boolean {
    return this.secret() !== null;
  }
  blockedUntil(): number {
    const until = Number(this.meta("blocked_until") ?? 0);
    return until > this.now() ? until : 0;
  }

  /**
   * A touch: checks one TOTP code for `purpose`. A step (or any older one) is never accepted twice; five wrong
   * codes within an hour block every touch for an hour. Throws, so nothing after it runs on a bad code.
   */
  private verifyCode(purpose: string, code: unknown): void {
    const secret = this.secret();
    if (secret === null) throw new GuardError("not_registered", "no second factor is registered; run `sbb-guard totp-register` on the console");
    const until = this.blockedUntil();
    if (until > 0) throw new GuardError("blocked", `too many wrong codes; approvals are blocked until ${new Date(until).toISOString()}`);
    const given = typeof code === "string" ? code : "";
    const res = verifyTotp(secret, given, this.now(), Number(this.meta("last_step") ?? 0));
    if (!res.ok) {
      this.tx(() => {
        this.db.prepare(`INSERT INTO attempts (ts, ok, purpose) VALUES (?, 0, ?)`).run(this.now(), purpose);
        const since = Math.max(this.now() - HOUR_MS, Number(this.meta("fail_epoch") ?? 0));
        const n = (this.db.prepare(`SELECT COUNT(*) AS n FROM attempts WHERE ok = 0 AND ts > ?`).get(since) as { n: number }).n;
        this.log("totp.fail", null, null, { purpose });
        if (n >= MAX_FAILURES) {
          this.setMeta("blocked_until", String(this.now() + HOUR_MS));
          this.setMeta("fail_epoch", String(this.now()));
          this.log("totp.blocked", null, null, { purpose, until: this.now() + HOUR_MS });
        }
      });
      throw new GuardError("invalid_code", "invalid or already used code");
    }
    // The step is spent before the action runs, in a transaction of its own (a failure above also commits its record).
    // Callers check everything that can be checked without a code first, so a spent code is not wasted on a refusal.
    this.tx(() => {
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose) VALUES (?, 1, ?)`).run(this.now(), purpose);
      this.setMeta("last_step", String(res.step));
    });
  }

  /** Console only: verifies a first code of a new secret, then stores it. `replacing` needs a valid code of the old one first. */
  registerSecret(secretB32: string, code: string, opts: { replacingCode?: string } = {}): void {
    const existing = this.secret();
    if (existing !== null) {
      if (opts.replacingCode === undefined) throw new GuardError("conflict", "a second factor is already registered; replacing it needs a code of the current one");
      this.verifyCode("totp.replace", opts.replacingCode);
    }
    this.tx(() => {
      const res = verifyTotp(secretB32, code, this.now(), Number(this.meta("last_step") ?? 0));
      if (!res.ok) throw new GuardError("invalid_code", "the code does not match the new secret (or its time step was already used)");
      // Create the file exclusively with 0600 from the start (never briefly readable), then move it into place.
      const tmp = `${this.secretPath}.new`;
      const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC, 0o600);
      try {
        writeSync(fd, `${secretB32}\n`);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, this.secretPath);
      this.setMeta("last_step", String(res.step));
      this.log(existing === null ? "totp.registered" : "totp.replaced", null, null, { via: "console" });
    });
  }

  // ---- policy -------------------------------------------------------------
  policy(): Policy {
    const raw = this.meta("policy");
    if (raw === null) return { ...DEFAULT_POLICY };
    try {
      const p = JSON.parse(raw) as Partial<Policy>;
      return { windowMin: p.windowMin ?? DEFAULT_POLICY.windowMin, capMin: p.capMin ?? DEFAULT_POLICY.capMin, mode: p.mode === "fixed" ? "fixed" : "sliding" };
    } catch {
      return { ...DEFAULT_POLICY };
    }
  }

  /** Widening (a longer window, a higher ceiling, sliding instead of fixed) needs a code; narrowing does not. */
  setPolicy(patch: Partial<Policy>, code: unknown): Policy {
    const cur = this.policy();
    const next: Policy = { ...cur };
    if (patch.windowMin !== undefined) next.windowMin = intOf(patch.windowMin, "windowMin", 1, 1440);
    if (patch.capMin !== undefined) next.capMin = intOf(patch.capMin, "capMin", 1, 1440);
    if (patch.mode !== undefined) {
      if (patch.mode !== "sliding" && patch.mode !== "fixed") throw new GuardError("invalid", "mode is sliding or fixed");
      next.mode = patch.mode;
    }
    if (next.windowMin > next.capMin) throw new GuardError("invalid", "the window size cannot exceed the ceiling");
    const widens = next.windowMin > cur.windowMin || next.capMin > cur.capMin || (next.mode === "sliding" && cur.mode === "fixed");
    if (widens) this.verifyCode("policy", code);
    return this.tx(() => {
      this.setMeta("policy", JSON.stringify(next));
      this.log("policy", null, null, { from: cur, to: next, touched: widens });
      return next;
    });
  }

  // ---- approvals ----------------------------------------------------------
  private activeApproval(pluginId: string, contentHash: string): ApprovalRow | null {
    const r = this.db.prepare(`SELECT * FROM approvals WHERE content_hash = ? AND plugin_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1`).get(contentHash, pluginId) as Raw | undefined;
    return r ? approvalOf(r) : null;
  }
  private addApproval(i: Omit<ApprovalRow, "id" | "approvedAt" | "revokedAt">): ApprovalRow {
    const info = this.db
      .prepare(`INSERT INTO approvals (content_hash, plugin_id, version, source, source_kind, git_commit, npm_integrity, via, window_id, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(i.contentHash, i.pluginId, i.version, i.source, i.sourceKind, i.gitCommit, i.npmIntegrity, i.via, i.windowId, this.now());
    return { ...i, id: Number(info.lastInsertRowid), approvedAt: this.now(), revokedAt: null };
  }
  private resolveQueue(pluginId: string, contentHash: string, status: "approved" | "dismissed"): void {
    this.db.prepare(`UPDATE queue SET status = ? WHERE content_hash = ? AND plugin_id = ? AND status = 'held'`).run(status, contentHash, pluginId);
  }

  private parseDecide(raw: Record<string, unknown>): DecideInput {
    return {
      pluginId: pluginIdOf(raw.pluginId),
      version: str(raw.version, "version", 128),
      contentHash: hashOf(raw.contentHash),
      rootDir: str(raw.rootDir, "rootDir", 4096),
      source: str(raw.source, "source", 2048),
      sourceKind: str(raw.sourceKind, "sourceKind", 64),
      trigger: str(raw.trigger, "trigger", 64),
    };
  }

  /** The held entry of a version (made if there was none, unless too many were made this hour). `stop`: a window does not lift this hold. */
  private upsertHeld(req: DecideInput, stop: boolean): { id: number | null; created: boolean } {
    const held = this.db.prepare(`SELECT * FROM queue WHERE content_hash = ? AND plugin_id = ? AND status = 'held' ORDER BY id DESC LIMIT 1`).get(req.contentHash, req.pluginId) as Raw | undefined;
    if (held) {
      this.db.prepare(`UPDATE queue SET last_seen = ?, seen_count = seen_count + 1, version = ?, source = ?, source_kind = ?, root_dir = ?, trigger = ?, stop = MAX(stop, ?) WHERE id = ?`).run(this.now(), req.version, req.source, req.sourceKind, req.rootDir, req.trigger, stop ? 1 : 0, Number(held.id));
      return { id: Number(held.id), created: false };
    }
    // A process that can talk to the guard must not be able to fill it: a flood of new holds is not recorded (one record says so).
    const recent = (this.db.prepare(`SELECT COUNT(*) AS n FROM queue WHERE first_seen > ?`).get(this.now() - HOUR_MS) as { n: number }).n;
    if (recent >= MAX_HOLDS_PER_HOUR) {
      if (Number(this.meta("flood_logged") ?? 0) < this.now() - HOUR_MS) {
        this.setMeta("flood_logged", String(this.now()));
        this.log("queue.flood", null, null, { limit: MAX_HOLDS_PER_HOUR });
      }
      return { id: null, created: false };
    }
    const info = this.db
      .prepare(`INSERT INTO queue (content_hash, plugin_id, version, source, source_kind, root_dir, trigger, status, first_seen, last_seen, stop) VALUES (?, ?, ?, ?, ?, ?, ?, 'held', ?, ?, ?)`)
      .run(req.contentHash, req.pluginId, req.version, req.source, req.sourceKind, req.rootDir, req.trigger, this.now(), this.now(), stop ? 1 : 0);
    const id = Number(info.lastInsertRowid);
    this.db.prepare(`DELETE FROM queue WHERE status != 'held' AND id NOT IN (SELECT id FROM queue ORDER BY id DESC LIMIT ?)`).run(MAX_QUEUE_ROWS);
    this.log("hold", req.pluginId, req.contentHash, { review: id, version: req.version, trigger: req.trigger, source: req.source, sourceKind: req.sourceKind, ...(stop ? { stop: true } : {}) });
    return { id, created: true };
  }

  /**
   * Holds a version for a human, by request of the plugin's hook (tightening: no code). Unlike a hold made by `decide`, a window does not lift it:
   * only a human's approval does. Needed because the hook knows things the guard cannot (a new capability inside a window), and the core may not
   * ask the guard at all once a hook has held the version.
   */
  hold(raw: Record<string, unknown>): { requestId: number | null } {
    const req = this.parseDecide(raw);
    return this.tx(() => {
      this.sweepInner();
      // Already approved by a human or imported: nothing to hold (a window's approval is withdrawn by `revoke` first).
      if (this.activeApproval(req.pluginId, req.contentHash)) return { requestId: null };
      return { requestId: this.upsertHeld(req, raw.stop === true).id };
    });
  }

  /** What the core asks before it loads a plugin. Holds when nothing a human decided covers it. */
  decide(raw: Record<string, unknown>): Decision {
    const req = this.parseDecide(raw);
    return this.tx(() => {
      this.sweepInner();
      if (this.activeApproval(req.pluginId, req.contentHash)) return { action: "proceed", via: "approval" } as const;

      const stopped = this.db.prepare(`SELECT 1 FROM queue WHERE content_hash = ? AND plugin_id = ? AND status = 'held' AND stop = 1`).get(req.contentHash, req.pluginId) !== undefined;
      const w = stopped ? null : this.openWindowOf(req.pluginId);
      if (w) {
        const a = this.addApproval({ contentHash: req.contentHash, pluginId: req.pluginId, version: req.version, source: req.source, sourceKind: req.sourceKind, gitCommit: null, npmIntegrity: null, via: "window", windowId: w.id });
        this.db.prepare(`UPDATE windows SET uses = uses + 1 WHERE id = ?`).run(w.id);
        if (w.mode === "sliding") {
          const next = Math.min(this.now() + w.sizeSec * 1000, w.hardExpiresAt);
          if (next > w.expiresAt) this.db.prepare(`UPDATE windows SET expires_at = ? WHERE id = ?`).run(next, w.id);
        }
        this.resolveQueue(req.pluginId, req.contentHash, "approved");
        this.log("approved.window", req.pluginId, req.contentHash, { approval: a.id, windowId: w.id, version: req.version, source: req.source, sourceKind: req.sourceKind });
        return { action: "proceed", via: "window" } as const;
      }

      const h = this.upsertHeld(req, false);
      return h.id === null ? ({ action: "wait", reason: "held by secure-bb guard: too many new holds", requestId: null } as const) : ({ action: "wait", reason: `held by secure-bb guard: review #${h.id}`, requestId: h.id } as const);
    });
  }

  /** Read-only: is this version approved, is a window open, what is its queue entry. For the plugin's own hook. */
  lookup(raw: Record<string, unknown>): {
    approved: boolean;
    /** Who approved it: a window approval is the one a hook that holds the version for its own reasons withdraws (revoke, no code). */
    approval: { id: number; via: string; windowId: number | null } | null;
    window: { id: number; expiresAt: number; hardExpiresAt: number; mode: string; sizeSec: number } | null;
    requestId: number | null;
  } {
    const pluginId = pluginIdOf(raw.pluginId);
    const contentHash = hashOf(raw.contentHash);
    const w = this.openWindowOf(pluginId);
    const a = this.activeApproval(pluginId, contentHash);
    const q = this.db.prepare(`SELECT id FROM queue WHERE content_hash = ? AND plugin_id = ? AND status = 'held' ORDER BY id DESC LIMIT 1`).get(contentHash, pluginId) as { id: number } | undefined;
    return {
      approved: a !== null,
      approval: a ? { id: a.id, via: a.via, windowId: a.windowId } : null,
      window: w ? { id: w.id, expiresAt: w.expiresAt, hardExpiresAt: w.hardExpiresAt, mode: w.mode, sizeSec: w.sizeSec } : null,
      requestId: q ? Number(q.id) : null,
    };
  }

  /** Check results of the plugin are attached to a queue entry. For display only: nothing here changes a decision. */
  annotate(raw: Record<string, unknown>): { ok: true } {
    let hash: string;
    if (raw.requestId !== undefined) {
      const q = this.db.prepare(`SELECT content_hash FROM queue WHERE id = ?`).get(intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER)) as { content_hash: string } | undefined;
      if (!q) throw new GuardError("not_found", "no such request");
      hash = q.content_hash;
    } else hash = hashOf(raw.contentHash);
    const text = JSON.stringify(raw.findings ?? null);
    if (text === undefined || Buffer.byteLength(text) > MAX_FINDINGS_BYTES) throw new GuardError("invalid", `findings must be JSON of at most ${MAX_FINDINGS_BYTES} bytes`);
    this.tx(() => {
      this.db.prepare(`INSERT INTO annotations (content_hash, ts, findings) VALUES (?, ?, ?) ON CONFLICT(content_hash) DO UPDATE SET ts = excluded.ts, findings = excluded.findings`).run(hash, this.now(), text);
      this.db.prepare(`DELETE FROM annotations WHERE content_hash NOT IN (SELECT content_hash FROM annotations ORDER BY ts DESC LIMIT ?)`).run(MAX_ANNOTATIONS);
    });
    return { ok: true };
  }

  private heldRequest(id: number): QueueRow {
    const row = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(id) as Raw | undefined;
    if (!row) throw new GuardError("not_found", `no request #${id}`);
    const q = queueOf(row);
    if (q.status !== "held") throw new GuardError("conflict", `request #${id} is already ${q.status}`);
    return q;
  }

  /** Approves a held version with a touch. The code is checked first, in the same transaction as the approval. */
  approve(raw: Record<string, unknown>): { approval: ApprovalRow } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    const q = this.heldRequest(id);
    this.verifyCode(`approve:${q.pluginId}`, raw.code);
    return this.tx(() => {
      const a = this.addApproval({ contentHash: q.contentHash, pluginId: q.pluginId, version: q.version, source: q.source, sourceKind: q.sourceKind, gitCommit: null, npmIntegrity: null, via: "touch", windowId: null });
      this.resolveQueue(q.pluginId, q.contentHash, "approved");
      // The record says what exactly was approved: after the fact, this is what the owner reads.
      this.log("approved.touch", q.pluginId, q.contentHash, { approval: a.id, review: q.id, version: q.version, source: q.source, sourceKind: q.sourceKind, rootDir: q.rootDir });
      return { approval: a };
    });
  }

  /** Drops a held entry: tightening (the version stays unapproved), so no code and no block after wrong codes, like revoke. Held entries only; the journal gets a record. */
  dismiss(raw: Record<string, unknown>): { ok: true } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    const q = this.heldRequest(id);
    return this.tx(() => {
      this.resolveQueue(q.pluginId, q.contentHash, "dismissed");
      this.log("dismissed", q.pluginId, q.contentHash, { review: q.id, version: q.version });
      return { ok: true } as const;
    });
  }

  /**
   * Withdraws approvals: tightening, so no code and no block after wrong codes (whoever can call the guard must not
   * be able to keep the owner from revoking). By approval id: every approval of that version goes. By plugin id: all of them, and its windows.
   */
  revoke(raw: Record<string, unknown>): { revoked: number } {
    return this.tx(() => {
      let rows: ApprovalRow[];
      if (raw.approvalId !== undefined) {
        const a = this.db.prepare(`SELECT * FROM approvals WHERE id = ? AND revoked_at IS NULL`).get(intOf(raw.approvalId, "approvalId", 1, Number.MAX_SAFE_INTEGER)) as Raw | undefined;
        if (!a) throw new GuardError("not_found", "no such active approval");
        rows = (this.db.prepare(`SELECT * FROM approvals WHERE content_hash = ? AND plugin_id = ? AND revoked_at IS NULL`).all(String(a.content_hash), String(a.plugin_id)) as Raw[]).map(approvalOf);
      } else {
        const pluginId = pluginIdOf(raw.pluginId);
        rows = (this.db.prepare(`SELECT * FROM approvals WHERE plugin_id = ? AND revoked_at IS NULL`).all(pluginId) as Raw[]).map(approvalOf);
        for (const w of this.unclosedWindows()) if (w.pluginId === pluginId) this.closeWindowInner(w, "revoked");
        if (rows.length === 0) throw new GuardError("not_found", "no active approvals of this plugin");
      }
      for (const a of rows) {
        this.db.prepare(`UPDATE approvals SET revoked_at = ? WHERE id = ?`).run(this.now(), a.id);
        this.log("revoked", a.pluginId, a.contentHash, { approval: a.id, version: a.version });
      }
      return { revoked: rows.length };
    });
  }

  // ---- windows ------------------------------------------------------------
  private unclosedWindows(): WindowRow[] {
    return (this.db.prepare(`SELECT * FROM windows WHERE closed_at IS NULL`).all() as Raw[]).map(windowOf);
  }
  private openWindowOf(pluginId: string): WindowRow | null {
    const now = this.now();
    return this.unclosedWindows().find((w) => w.pluginId === pluginId && now < w.expiresAt && now < w.hardExpiresAt) ?? null;
  }
  private closeWindowInner(w: WindowRow, reason: string, at = this.now()): void {
    this.db.prepare(`UPDATE windows SET closed_at = ?, closed_reason = ? WHERE id = ? AND closed_at IS NULL`).run(at, reason, w.id);
    const pin = this.db.prepare(`SELECT version, content_hash FROM approvals WHERE plugin_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1`).get(w.pluginId) as { version: string; content_hash: string } | undefined;
    // The last approved version stays pinned: the next one needs a new window.
    this.log(reason === "expired" || reason === "ceiling" ? "window.freeze" : "window.close", w.pluginId, pin?.content_hash ?? null, { windowId: w.id, reason, pinnedVersion: pin?.version ?? null });
  }
  private sweepInner(): number {
    let n = 0;
    const now = this.now();
    for (const w of this.unclosedWindows()) {
      if (now < w.expiresAt && now < w.hardExpiresAt) continue;
      this.closeWindowInner(w, w.expiresAt >= w.hardExpiresAt ? "ceiling" : "expired", Math.min(w.expiresAt, w.hardExpiresAt));
      n++;
    }
    return n;
  }
  /** Background pass: closes windows whose time is up and journals the freeze. */
  sweep(): number {
    return this.tx(() => this.sweepInner());
  }

  /** Opens a window on a plugin id with a touch. Inside it, any version of that plugin is approved without a touch. */
  openWindow(raw: Record<string, unknown>): WindowRow {
    const pluginId = pluginIdOf(raw.pluginId);
    const policy = this.policy();
    const minutes = raw.minutes === undefined ? policy.windowMin : intOf(raw.minutes, "minutes", 1, 1440);
    if (minutes > policy.capMin) throw new GuardError("invalid", `a window is at most ${policy.capMin} minutes (the ceiling)`);
    this.verifyCode(`window.open:${pluginId}`, raw.code);
    return this.tx(() => {
      this.sweepInner();
      for (const old of this.unclosedWindows()) if (old.pluginId === pluginId) this.closeWindowInner(old, "reopened");
      const now = this.now();
      const hard = now + policy.capMin * 60_000;
      const info = this.db
        .prepare(`INSERT INTO windows (plugin_id, size_sec, cap_sec, mode, opened_at, expires_at, hard_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(pluginId, minutes * 60, policy.capMin * 60, policy.mode, now, Math.min(now + minutes * 60_000, hard), hard);
      const w = windowOf(this.db.prepare(`SELECT * FROM windows WHERE id = ?`).get(Number(info.lastInsertRowid)) as Raw);
      this.log("window.open", pluginId, null, { windowId: w.id, minutes, mode: w.mode, ceilingMin: policy.capMin });
      return w;
    });
  }

  /** Closing only tightens: no code. */
  closeWindow(raw: Record<string, unknown>): { closed: number } {
    return this.tx(() => {
      const open = this.unclosedWindows();
      let targets: WindowRow[];
      if (raw.windowId !== undefined) {
        const id = intOf(raw.windowId, "windowId", 1, Number.MAX_SAFE_INTEGER);
        targets = open.filter((w) => w.id === id);
      } else {
        const pluginId = pluginIdOf(raw.pluginId);
        targets = open.filter((w) => w.pluginId === pluginId);
      }
      if (targets.length === 0) throw new GuardError("not_found", "no such open window");
      for (const w of targets) this.closeWindowInner(w, "closed");
      return { closed: targets.length };
    });
  }

  // ---- touches for the plugin's own, local features ---------------------------------------------------
  /** Checks one code for an action the plugin itself performs (its config watchdog, skills, settings). Decides nothing in the guard. */
  touch(raw: Record<string, unknown>): { ok: true } {
    const purpose = str(raw.purpose, "purpose", 80, 1);
    this.verifyCode(`touch:${purpose}`, raw.code);
    this.record("touch", null, null, { purpose });
    return { ok: true };
  }

  // ---- migration ------------------------------------------------------------------------------------------
  /** Console only. Adds approvals exported by the plugin; skips what is already approved. Returns what was added. */
  importApprovals(items: ImportItem[], fileDigest: string): { added: number; skipped: number } {
    return this.tx(() => {
      let added = 0;
      let skipped = 0;
      for (const i of items) {
        if (this.activeApproval(i.pluginId, i.contentHash)) {
          skipped++;
          continue;
        }
        const a = this.addApproval({ ...i, via: "import", windowId: null });
        this.resolveQueue(i.pluginId, i.contentHash, "approved");
        this.log("approved.import", i.pluginId, i.contentHash, { approval: a.id, version: i.version, source: i.source, sourceKind: i.sourceKind, originalApprovedAt: i.approvedAt, file: fileDigest });
        added++;
      }
      this.log("import", null, null, { file: fileDigest, added, skipped });
      return { added, skipped };
    });
  }

  // ---- views ----------------------------------------------------------------------------------------------
  verifyJournal(): JournalReport {
    return verify(this.db, this.head);
  }

  /** Everything the page shows. No secret, no code, no hash of one. */
  state(): Record<string, unknown> {
    const now = this.now();
    const rows = <T>(sql: string, map: (r: Raw) => T, ...args: Array<string | number>): T[] => (this.db.prepare(sql).all(...args) as Raw[]).map(map);
    const notes = new Map((this.db.prepare(`SELECT content_hash, ts, findings FROM annotations`).all() as Array<{ content_hash: string; ts: number; findings: string }>).map((a) => [a.content_hash, a]));
    const withNotes = (q: QueueRow) => {
      const a = notes.get(q.contentHash);
      // Supplied by the plugin, which a harmful plugin can lie through: shown as "unverified", never used to decide.
      return { ...q, annotation: a ? { ts: a.ts, findings: JSON.parse(a.findings) as unknown, verified: false } : null };
    };
    const head = readHead(this.db);
    const blockedUntil = this.blockedUntil();
    return {
      now,
      totp: { registered: this.totpRegistered(), blockedUntil },
      policy: this.policy(),
      queue: rows(`SELECT * FROM queue ORDER BY (status = 'held') DESC, id DESC LIMIT 100`, queueOf).map(withNotes),
      approvals: rows(`SELECT * FROM approvals WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 500`, approvalOf),
      revoked: rows(`SELECT * FROM approvals WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC LIMIT 20`, approvalOf),
      windows: this.unclosedWindows()
        .filter((w) => now < w.expiresAt && now < w.hardExpiresAt)
        .map((w) => ({ ...w, remainingSec: Math.max(0, Math.floor((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000)) })),
      closedWindows: rows(`SELECT * FROM windows WHERE closed_at IS NOT NULL ORDER BY id DESC LIMIT 10`, windowOf),
      journal: {
        head: head ? { id: head.id, hash: head.hash } : null,
        recent: (this.db.prepare(`SELECT id, ts, kind, plugin_id, content_hash, detail FROM journal ORDER BY id DESC LIMIT 30`).all() as Raw[]).map((r) => ({
          id: Number(r.id),
          ts: Number(r.ts),
          kind: String(r.kind),
          pluginId: (r.plugin_id as string | null) ?? null,
          contentHash: (r.content_hash as string | null) ?? null,
          detail: r.detail === null ? null : (JSON.parse(String(r.detail)) as unknown),
        })),
      },
    };
  }
}
