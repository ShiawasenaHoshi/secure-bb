// The guard's decisions. Pure logic over the database and an injected clock: no sockets here (server.ts),
// no terminal here (cli.ts). Everything that changes state happens in one transaction together with its
// journal record, and the journal head file is rewritten right after the commit.
//
// Two kinds of requests (design doc, "Сокет и протокол"):
//  - without a secret (any process of the bb user can send them, including a harmful plugin, so they may
//    decide nothing a human has not already decided): decide, state, lookup, annotate, close-window, revoke, dismiss (held entries only);
//  - with a touch (a TOTP code): approve, open-window, policy, touch.
// The TOTP secret is only ever written by `sbb-guard totp-register` on the console, and is never returned
// by anything in this file. A touch is either a TOTP code or a passkey signature over a challenge the guard issued for exactly
// that action (see "Passkeys" below); passkeys are registered only through the console (`sbb-guard passkey-enroll`).
import { readFileSync, renameSync, unlinkSync, writeFileSync, openSync, closeSync, writeSync, constants, lstatSync } from "node:fs";
import { basename, dirname } from "node:path";
import { timingSafeEqual } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { DEFAULT_ORIGIN, DEFAULT_RP_ID, type RelyingParty } from "./config.ts";
import { append, HeadFile, readHead, verify, type JournalHead, type JournalReport } from "./journal.ts";
import {
  b64u,
  fromB64u,
  newNonce,
  newToken,
  parseAttestationObject,
  parseAuthData,
  parseClientData,
  PasskeyError,
  sha256,
  tokenDigest,
  verifyEs256,
  FLAG_UP,
  FLAG_UV,
} from "./passkey.ts";
import { verifyTotp } from "./totp.ts";
import { analyze as analyzeAgents, maskSecrets, unifiedDiff, type Change } from "./agents-rules.ts";
import { scan as scanAgents, type FileKind, type Limits, type ScanResult } from "./agents-scan.ts";

export type GuardErrorCode = "invalid" | "not_found" | "conflict" | "not_registered" | "invalid_code" | "invalid_passkey" | "expired" | "blocked" | "unknown_op";

export class GuardError extends Error {
  readonly code: GuardErrorCode;
  constructor(code: GuardErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export const HOUR_MS = 3_600_000;
export const MAX_FAILURES = 5;
/** The window the console opens for registering a passkey, and how long a challenge lives. */
export const ENROLL_WINDOW_MS = 5 * 60_000;
export const CHALLENGE_TTL_MS = 2 * 60_000;
const MAX_OPEN_CHALLENGES = 200;
const MAX_HOLDS_PER_HOUR = 200;
const MAX_QUEUE_ROWS = 1000;
const MAX_ANNOTATIONS = 500;
const MAX_FINDINGS_BYTES = 64 * 1024;
/** Agent watch: a scan asked for over the socket runs at most once in this time; the differences kept open; ids in one touch. */
export const AGENTS_SCAN_GAP_MS = 10_000;
const MAX_OPEN_DRIFTS = 1000;
const MAX_ACCEPT_IDS = 2000;

/** Is a file that the walk did not see really gone (ENOENT), or can it not be looked at (no access)? Anything else: leave it alone. */
function fileGone(path: string): "gone" | "denied" | "present" {
  try {
    lstatSync(path);
    return "present";
  } catch (e) {
    const code = (e as { code?: string }).code;
    return code === "ENOENT" || code === "ENOTDIR" ? "gone" : code === "EACCES" || code === "EPERM" ? "denied" : "present";
  }
}
const rootKindOf = (cfg: AgentsConfig, root: string): string => (root === cfg.home ? "global" : cfg.extraRoots.includes(root) ? "extra" : "workspace");

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
  /** The relying party passkeys are bound to (default localhost). */
  rp?: RelyingParty;
  /** Agent watch: the agents' home (default /var/bbagent in `serve`) and the extra roots the console named. Absent: the watch is off. */
  agents?: AgentsConfig;
}
export interface AgentsConfig {
  home: string;
  extraRoots: string[];
  /** Tests lower the limits of a scan. */
  limits?: Partial<Limits>;
  /** More directories that are never read (the guard's data and its socket; its state directory is always one). */
  deny?: string[];
  /** Tests: a function called between looking at a file and opening it. */
  hooks?: { beforeOpen?: (path: string) => void };
}

/** What a touch is made of: a TOTP code, or (instead of it) a passkey assertion. */
export interface Proof {
  code?: unknown;
  passkey?: unknown;
}
/** Who touched: how, with which key, and for what exactly (written into the journal). */
export interface Factor {
  via: "totp" | "passkey";
  key?: string;
  action?: Record<string, unknown>;
}
const factorDetail = (f: Factor): Record<string, unknown> => ({ via: f.via, ...(f.key !== undefined ? { key: f.key } : {}), ...(f.action !== undefined ? { action: f.action } : {}) });

export interface PasskeyRow {
  id: number;
  label: string;
  aaguid: string;
  fingerprint: string;
  state: "pending" | "active" | "removed";
  createdAt: number;
  confirmedAt: number | null;
  lastUsedAt: number | null;
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
  private readonly rp: RelyingParty;
  private readonly agents: AgentsConfig | null;
  private lastAgentsScan = 0;
  private readonly secretDir: string;
  private readonly headDir: string;

  constructor(o: GuardOptions) {
    this.agents = o.agents ?? null;
    this.secretDir = dirname(o.secretPath);
    this.headDir = dirname(o.headPath);
    this.rp = o.rp ?? { rpId: DEFAULT_RP_ID, origin: DEFAULT_ORIGIN };
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

  /** Blocked after too many wrong codes or signatures (one counter for both: a guess is a guess). */
  private assertNotBlocked(): void {
    const until = this.blockedUntil();
    if (until > 0) throw new GuardError("blocked", `too many wrong codes or signatures; approvals are blocked until ${new Date(until).toISOString()}`);
  }

  /** A wrong code or signature: recorded, counted, and the fifth within an hour blocks every touch for an hour. Always commits before the caller throws. */
  private recordFailure(kind: "totp.fail" | "passkey.fail", purpose: string, extra: Record<string, unknown> = {}): void {
    this.tx(() => {
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose) VALUES (?, 0, ?)`).run(this.now(), purpose);
      const since = Math.max(this.now() - HOUR_MS, Number(this.meta("fail_epoch") ?? 0));
      const n = (this.db.prepare(`SELECT COUNT(*) AS n FROM attempts WHERE ok = 0 AND ts > ?`).get(since) as { n: number }).n;
      this.log(kind, null, null, { purpose, ...extra });
      if (n >= MAX_FAILURES) {
        this.setMeta("blocked_until", String(this.now() + HOUR_MS));
        this.setMeta("fail_epoch", String(this.now()));
        this.log("totp.blocked", null, null, { purpose, until: this.now() + HOUR_MS });
      }
    });
  }

  /**
   * A touch: checks one TOTP code for `purpose`. A step (or any older one) is never accepted twice; five wrong
   * codes within an hour block every touch for an hour. Throws, so nothing after it runs on a bad code.
   */
  private verifyCode(purpose: string, code: unknown): void {
    const secret = this.secret();
    if (secret === null) {
      if (this.totpDisabled()) throw new GuardError("not_registered", "codes are switched off at this guard: touch with a passkey (`sbb-guard totp-register` on the console switches them on again)");
      throw new GuardError("not_registered", "no second factor is registered; run `sbb-guard totp-register` on the console");
    }
    this.assertNotBlocked();
    const given = typeof code === "string" ? code : "";
    const res = verifyTotp(secret, given, this.now(), Number(this.meta("last_step") ?? 0));
    if (!res.ok) {
      this.recordFailure("totp.fail", purpose);
      throw new GuardError("invalid_code", "invalid or already used code");
    }
    // The step is spent before the action runs, in a transaction of its own (a failure above also commits its record).
    // Callers check everything that can be checked without a code first, so a spent code is not wasted on a refusal.
    this.tx(() => {
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose) VALUES (?, 1, ?)`).run(this.now(), purpose);
      this.setMeta("last_step", String(res.step));
    });
  }

  /** One touch for one action: a passkey assertion when one is given (and then only that), else a TOTP code. */
  private verifyFactor(purpose: string, action: Record<string, unknown>, proof: Proof): Factor {
    if (proof.passkey !== undefined) return this.verifyPasskey(purpose, action, proof.passkey);
    this.verifyCode(purpose, proof.code);
    return { via: "totp" };
  }

  totpDisabled(): boolean {
    return this.meta("totp_disabled") === "1";
  }

  /** Console only: codes off. Needs a working passkey (else nobody could touch anything) and removes the secret for good; `totp-register` makes a new one. */
  totpDisable(): void {
    if (this.activePasskeys().length === 0) throw new GuardError("conflict", "no active passkey: switching codes off would leave no way to touch (`sbb-guard passkey-enroll` first)");
    if (this.secret() === null) throw new GuardError("conflict", "no TOTP secret is registered; nothing to switch off");
    this.tx(() => {
      unlinkSync(this.secretPath);
      this.setMeta("totp_disabled", "1");
      this.log("totp.disabled", null, null, { via: "console" });
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
      this.setMeta("totp_disabled", "0");
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
  setPolicy(patch: Partial<Policy>, proof: Proof): Policy {
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
    const factor = widens ? this.verifyFactor("policy", this.normalizeAction({ op: "policy", patch }), proof) : null;
    return this.tx(() => {
      this.setMeta("policy", JSON.stringify(next));
      this.log("policy", null, null, { from: cur, to: next, touched: widens, ...(factor ? factorDetail(factor) : {}) });
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

  /** A version a window does not lift: some entry of it was kept with stop=1 and is held or was dismissed. Only a code (approve) lifts it. */
  private isStopped(pluginId: string, contentHash: string): boolean {
    return this.db.prepare(`SELECT 1 FROM queue WHERE content_hash = ? AND plugin_id = ? AND status IN ('held', 'dismissed') AND stop = 1`).get(contentHash, pluginId) !== undefined;
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
    this.db.prepare(`DELETE FROM queue WHERE status != 'held' AND NOT (status = 'dismissed' AND stop = 1) AND id NOT IN (SELECT id FROM queue ORDER BY id DESC LIMIT ?)`).run(MAX_QUEUE_ROWS);
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

      // A stop survives a rejection: dismiss needs no code, so a process that can reach the guard could otherwise clear the stop and let the window in.
      const stopped = this.isStopped(req.pluginId, req.contentHash);
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

      const h = this.upsertHeld(req, stopped);
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
    const factor = this.verifyFactor(`approve:${q.pluginId}`, this.normalizeAction({ op: "approve", requestId: id }), raw);
    return this.tx(() => {
      const a = this.addApproval({ contentHash: q.contentHash, pluginId: q.pluginId, version: q.version, source: q.source, sourceKind: q.sourceKind, gitCommit: null, npmIntegrity: null, via: "touch", windowId: null });
      this.resolveQueue(q.pluginId, q.contentHash, "approved");
      // The record says what exactly was approved: after the fact, this is what the owner reads.
      this.log("approved.touch", q.pluginId, q.contentHash, { approval: a.id, review: q.id, version: q.version, source: q.source, sourceKind: q.sourceKind, rootDir: q.rootDir, ...factorDetail(factor) });
      return { approval: a };
    });
  }

  /** Drops a held entry: tightening (the version stays unapproved), so no code and no block after wrong codes, like revoke. Held entries only; the journal gets a record. */
  dismiss(raw: Record<string, unknown>): { ok: true } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    const q = this.heldRequest(id);
    return this.tx(() => {
      const stop = (this.db.prepare(`SELECT stop FROM queue WHERE id = ?`).get(q.id) as { stop: number } | undefined)?.stop === 1;
      this.resolveQueue(q.pluginId, q.contentHash, "dismissed");
      this.log("dismissed", q.pluginId, q.contentHash, { review: q.id, version: q.version, ...(stop ? { stop: true } : {}) });
      // A stop means the plugin's hook saw something the window must not wave through (a new capability, a tainted tree).
      // Rejecting it does not lift the stop (see isStopped), and the plugin's window is closed too: tightening, journaled.
      if (stop) for (const w of this.unclosedWindows()) if (w.pluginId === q.pluginId) this.closeWindowInner(w, "dismissed-stop");
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
    const factor = this.verifyFactor(`window.open:${pluginId}`, this.normalizeAction({ op: "open-window", pluginId, minutes, ...(raw.scope !== undefined ? { scope: raw.scope } : {}) }), raw);
    return this.tx(() => {
      this.sweepInner();
      for (const old of this.unclosedWindows()) if (old.pluginId === pluginId) this.closeWindowInner(old, "reopened");
      const now = this.now();
      const hard = now + policy.capMin * 60_000;
      const info = this.db
        .prepare(`INSERT INTO windows (plugin_id, size_sec, cap_sec, mode, opened_at, expires_at, hard_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(pluginId, minutes * 60, policy.capMin * 60, policy.mode, now, Math.min(now + minutes * 60_000, hard), hard);
      const w = windowOf(this.db.prepare(`SELECT * FROM windows WHERE id = ?`).get(Number(info.lastInsertRowid)) as Raw);
      this.log("window.open", pluginId, null, { windowId: w.id, minutes, mode: w.mode, ceilingMin: policy.capMin, ...factorDetail(factor) });
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
    const factor = this.verifyFactor(`touch:${purpose}`, this.normalizeAction({ op: "touch", purpose }), raw);
    this.record("touch", null, null, { purpose, ...factorDetail(factor) });
    return { ok: true };
  }

  // ---- Passkeys -----------------------------------------------------------------------------------------------------
  // Why: a code typed on the page passes through bb's process, where a harmful plugin can take it and spend it first. A passkey
  // signature is made over a challenge the guard issued for ONE normalized action, so a captured signature is good for that action
  // only, once, for two minutes. Keys are registered only through the console (`passkey-enroll`), never through bb.
  private activePasskeys(): Array<Raw & { credential_id: string; public_key: string; label: string; sign_count: number; id: number }> {
    return this.db.prepare(`SELECT * FROM passkeys WHERE state = 'active' ORDER BY id`).all() as never;
  }
  private passkeyOf(r: Raw): PasskeyRow {
    return {
      id: Number(r.id),
      label: String(r.label),
      aaguid: String(r.aaguid),
      fingerprint: String(r.fingerprint),
      state: r.state as PasskeyRow["state"],
      createdAt: Number(r.created_at),
      confirmedAt: r.confirmed_at === null ? null : Number(r.confirmed_at),
      lastUsedAt: r.last_used_at === null ? null : Number(r.last_used_at),
    };
  }
  /** Console: every key (active, waiting for confirmation, removed). */
  listPasskeys(): PasskeyRow[] {
    return (this.db.prepare(`SELECT * FROM passkeys ORDER BY id`).all() as Raw[]).map((r) => this.passkeyOf(r));
  }

  /** Console: removes a key. The last way to touch cannot be removed (no active passkey and no TOTP would lock the owner out). */
  removePasskey(id: number): PasskeyRow {
    const row = this.db.prepare(`SELECT * FROM passkeys WHERE id = ? AND state IN ('active', 'pending')`).get(id) as Raw | undefined;
    if (!row) throw new GuardError("not_found", `no key #${id}`);
    const rest = this.activePasskeys().filter((k) => k.id !== id).length;
    if (row.state === "active" && rest === 0 && this.secret() === null) throw new GuardError("conflict", "this is the last way to touch: register a TOTP (`sbb-guard totp-register`) or another passkey first");
    return this.tx(() => {
      this.db.prepare(`UPDATE passkeys SET state = 'removed', removed_at = ? WHERE id = ?`).run(this.now(), id);
      this.log("passkey.removed", null, null, { key: String(row.label), id, via: "console" });
      return this.passkeyOf({ ...row, state: "removed" });
    });
  }

  // ---- enrollment (console) ----
  private enrollmentRow(id: number): Raw | undefined {
    return this.db.prepare(`SELECT * FROM enrollments WHERE id = ?`).get(id) as Raw | undefined;
  }
  private openEnrollment(): Raw | undefined {
    return this.db.prepare(`SELECT * FROM enrollments WHERE state = 'open' AND expires_at > ? ORDER BY id DESC LIMIT 1`).get(this.now()) as Raw | undefined;
  }

  /** Console only: opens the registration window (one at a time; an earlier one and its unconfirmed key are dropped) and returns the one-time token. */
  enrollStart(label: string): { id: number; token: string; label: string; expiresAt: number } {
    const name = str(label, "label", 64, 1);
    const token = newToken();
    return this.tx(() => {
      this.db.prepare(`UPDATE enrollments SET state = 'closed' WHERE state IN ('open', 'registered')`).run();
      this.db.prepare(`UPDATE passkeys SET state = 'removed', removed_at = ? WHERE state = 'pending'`).run(this.now());
      const now = this.now();
      const info = this.db
        .prepare(`INSERT INTO enrollments (token_digest, label, user_handle, opened_at, expires_at, state) VALUES (?, ?, ?, ?, ?, 'open')`)
        .run(tokenDigest(token), name, b64u(newNonce().subarray(0, 16)), now, now + ENROLL_WINDOW_MS);
      const id = Number(info.lastInsertRowid);
      this.log("passkey.enroll.open", null, null, { enrollment: id, label: name, expiresAt: now + ENROLL_WINDOW_MS, via: "console" });
      return { id, token, label: name, expiresAt: now + ENROLL_WINDOW_MS };
    });
  }

  /** Console: where the registration stands; `key` is what the page registered, waiting for the person at the console. */
  enrollmentStatus(id: number): { state: string; expiresAt: number; key: (PasskeyRow & { keyId: number }) | null } {
    const e = this.enrollmentRow(id);
    if (!e) throw new GuardError("not_found", "no such enrollment");
    let state = String(e.state);
    if (state === "open" && Number(e.expires_at) <= this.now()) state = "expired";
    const k = this.db.prepare(`SELECT * FROM passkeys WHERE enrollment_id = ? AND state = 'pending' ORDER BY id DESC LIMIT 1`).get(id) as Raw | undefined;
    return { state, expiresAt: Number(e.expires_at), key: k ? { ...this.passkeyOf(k), keyId: Number(k.id) } : null };
  }

  /** Console: the person saw the key (label, AAGUID, fingerprint) and said yes. Only now can it touch. */
  confirmEnrollment(id: number): PasskeyRow {
    return this.tx(() => {
      const e = this.enrollmentRow(id);
      if (!e || e.state !== "registered") throw new GuardError("conflict", "there is nothing registered to confirm in this enrollment");
      const k = this.db.prepare(`SELECT * FROM passkeys WHERE enrollment_id = ? AND state = 'pending' ORDER BY id DESC LIMIT 1`).get(id) as Raw | undefined;
      if (!k) throw new GuardError("conflict", "the registered key is gone");
      this.db.prepare(`UPDATE passkeys SET state = 'active', confirmed_at = ? WHERE id = ?`).run(this.now(), Number(k.id));
      this.db.prepare(`UPDATE enrollments SET state = 'confirmed' WHERE id = ?`).run(id);
      this.log("passkey.enrolled", null, null, { key: String(k.label), id: Number(k.id), aaguid: String(k.aaguid), fingerprint: String(k.fingerprint), via: "console" });
      return this.passkeyOf({ ...k, state: "active", confirmed_at: this.now() });
    });
  }

  /** Console: not confirmed (an answer of no, or the console gave up): the key is discarded and the window closes. */
  rejectEnrollment(id: number, why: string): void {
    this.tx(() => {
      const e = this.enrollmentRow(id);
      if (!e || (e.state !== "open" && e.state !== "registered")) return;
      const k = this.db.prepare(`SELECT id, label FROM passkeys WHERE enrollment_id = ? AND state = 'pending'`).get(id) as { id: number; label: string } | undefined;
      if (k) this.db.prepare(`UPDATE passkeys SET state = 'removed', removed_at = ? WHERE id = ?`).run(this.now(), k.id);
      this.db.prepare(`UPDATE enrollments SET state = 'closed' WHERE id = ?`).run(id);
      this.log("passkey.enroll.rejected", null, null, { enrollment: id, why, key: k?.label ?? null, via: "console" });
    });
  }

  // ---- registration (socket) ----
  private checkToken(token: unknown): Raw {
    const e = this.openEnrollment();
    if (!e) throw new GuardError("conflict", "no passkey registration is open; run `sbb-guard passkey-enroll` on the console");
    const given = typeof token === "string" ? tokenDigest(token) : "";
    const ok = given.length === String(e.token_digest).length && timingSafeEqual(Buffer.from(given), Buffer.from(String(e.token_digest)));
    if (!ok) {
      // Five wrong tokens close the window: a token is 60 bits, but whoever can reach the socket must not get to try without end.
      const fails = Number(e.fails) + 1;
      this.tx(() => {
        this.db.prepare(`UPDATE enrollments SET fails = ?, state = CASE WHEN ? >= ${MAX_FAILURES} THEN 'closed' ELSE state END WHERE id = ?`).run(fails, fails, Number(e.id));
        this.log("passkey.token.fail", null, null, { enrollment: Number(e.id), fails, ...(fails >= MAX_FAILURES ? { closed: true } : {}) });
      });
      throw new GuardError("invalid_code", fails >= MAX_FAILURES ? "wrong token; the registration window is closed" : "wrong token");
    }
    return e;
  }

  /**
   * Step 1 (`{token}`): the token is right and the window is open → the creation options for `navigator.credentials.create`, with a challenge
   * bound to this enrollment. Step 2 (`{token, clientDataJSON, attestationObject}`): checks them and stores the key as PENDING; the console decides.
   */
  passkeyRegister(raw: Record<string, unknown>): Record<string, unknown> {
    const e = this.checkToken(raw.token);
    const enrollment = Number(e.id);
    if (raw.clientDataJSON === undefined && raw.attestationObject === undefined) {
      if (e.state !== "open") throw new GuardError("conflict", "a key was already registered in this window; it waits for the console");
      const nonce = newNonce();
      this.tx(() => {
        this.trimChallenges();
        this.db.prepare(`INSERT INTO challenges (nonce, kind, enrollment_id, created_at, expires_at) VALUES (?, 'register', ?, ?, ?)`).run(b64u(nonce), enrollment, this.now(), Math.min(this.now() + CHALLENGE_TTL_MS, Number(e.expires_at)));
      });
      return {
        options: {
          challenge: b64u(nonce),
          rp: { id: this.rp.rpId, name: "secure-bb guard" },
          user: { id: String(e.user_handle), name: "secure-bb", displayName: String(e.label) },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
          attestation: "none",
          excludeCredentials: this.activePasskeys().map((k) => ({ type: "public-key", id: k.credential_id })),
          timeout: CHALLENGE_TTL_MS,
        },
      };
    }
    if (e.state !== "open") throw new GuardError("conflict", "a key was already registered in this window; it waits for the console");
    let cdj: Buffer;
    let att: ReturnType<typeof parseAttestationObject>;
    let clientChallenge: string;
    try {
      cdj = fromB64u(raw.clientDataJSON, "clientDataJSON");
      const cd = parseClientData(cdj);
      if (cd.type !== "webauthn.create") throw new PasskeyError("the client data is not for a registration");
      if (cd.origin !== this.rp.origin || cd.crossOrigin) throw new PasskeyError(`the page must be opened at ${this.rp.origin}`);
      clientChallenge = cd.challenge;
      att = parseAttestationObject(fromB64u(raw.attestationObject, "attestationObject"));
    } catch (err) {
      if (err instanceof PasskeyError) throw new GuardError("invalid_passkey", err.message);
      throw err;
    }
    const ch = this.db.prepare(`SELECT * FROM challenges WHERE nonce = ? AND kind = 'register'`).get(clientChallenge) as Raw | undefined;
    if (!ch || Number(ch.enrollment_id) !== enrollment) throw new GuardError("invalid_passkey", "this registration was not started here");
    if (Number(ch.used) === 1) throw new GuardError("invalid_passkey", "this challenge was already used");
    if (Number(ch.expires_at) <= this.now()) throw new GuardError("expired", "the challenge has expired; start again");
    if (!att.rpIdHash.equals(sha256(this.rp.rpId))) throw new GuardError("invalid_passkey", "the key was made for another RP ID");
    if ((att.flags & FLAG_UP) === 0 || (att.flags & FLAG_UV) === 0) throw new GuardError("invalid_passkey", "the key must be used with user presence and verification (Touch ID, PIN)");
    if (!att.attested) throw new GuardError("invalid_passkey", "no credential in the attestation");
    const cred = b64u(att.attested.credentialId);
    if (this.db.prepare(`SELECT 1 FROM passkeys WHERE credential_id = ?`).get(cred)) throw new GuardError("conflict", "this credential is already known");
    const label = String(e.label);
    const aaguid = att.attested.aaguid.toString("hex");
    const fingerprint = sha256(att.attested.publicKeySpki).toString("hex").slice(0, 32);
    return this.tx(() => {
      this.db.prepare(`UPDATE challenges SET used = 1 WHERE nonce = ?`).run(clientChallenge);
      this.db
        .prepare(`INSERT INTO passkeys (credential_id, public_key, label, aaguid, fingerprint, sign_count, state, enrollment_id, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`)
        .run(cred, b64u(att.attested!.publicKeySpki), label, aaguid, fingerprint, att.signCount, enrollment, this.now());
      this.db.prepare(`UPDATE enrollments SET state = 'registered' WHERE id = ?`).run(enrollment);
      this.log("passkey.registered", null, null, { key: label, aaguid, fingerprint, enrollment, note: "waits for confirmation on the console" });
      return { ok: true, label, note: "key registered; it is not active until you confirm it on the console" };
    });
  }

  // ---- actions: normalized, described, challenged ----
  /**
   * What a signature is bound to: the action with only the fields that matter, in a fixed order, defaults resolved. The same function
   * runs when the challenge is issued and when the command arrives, so the two are compared as strings.
   */
  private normalizeAction(raw: unknown): Record<string, unknown> {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new GuardError("invalid", "an action is a JSON object");
    const a = raw as Record<string, unknown>;
    switch (a.op) {
      case "approve":
        return { op: "approve", requestId: intOf(a.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER) };
      case "open-window": {
        const scope = a.scope;
        if (scope !== undefined && scope !== "tree" && scope !== "thread") throw new GuardError("invalid", "scope is tree or thread");
        return { op: "open-window", pluginId: pluginIdOf(a.pluginId), minutes: a.minutes === undefined ? this.policy().windowMin : intOf(a.minutes, "minutes", 1, 1440), ...(scope !== undefined ? { scope } : {}) };
      }
      case "policy": {
        if (typeof a.patch !== "object" || a.patch === null || Array.isArray(a.patch)) throw new GuardError("invalid", "patch is an object");
        const p = a.patch as Partial<Policy>;
        const patch: Partial<Policy> = {};
        if (p.windowMin !== undefined) patch.windowMin = intOf(p.windowMin, "windowMin", 1, 1440);
        if (p.capMin !== undefined) patch.capMin = intOf(p.capMin, "capMin", 1, 1440);
        if (p.mode !== undefined) {
          if (p.mode !== "sliding" && p.mode !== "fixed") throw new GuardError("invalid", "mode is sliding or fixed");
          patch.mode = p.mode;
        }
        return { op: "policy", patch };
      }
      case "touch":
        return { op: "touch", purpose: str(a.purpose, "purpose", 80, 1) };
      case "agents-accept":
        return { op: "agents-accept", ids: this.agentIds(a.ids) };
      default:
        throw new GuardError("invalid", "an action is approve, open-window, policy, touch or agents-accept");
    }
  }

  /** The sentence the page shows next to the touch button (in the journal after the fact too): what is about to be approved, in the guard's own words. */
  private describe(a: Record<string, unknown>): string {
    switch (a.op) {
      case "approve": {
        const q = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(Number(a.requestId)) as Raw | undefined;
        if (!q) throw new GuardError("not_found", `no request #${String(a.requestId)}`);
        if (q.status !== "held") throw new GuardError("conflict", `request #${String(a.requestId)} is already ${String(q.status)}`);
        return `Одобрить загрузку плагина «${String(q.plugin_id)}» версии ${String(q.version)} (запись #${String(q.id)}, источник ${String(q.source)}, хеш ${String(q.content_hash).slice(0, 16)}…)`;
      }
      case "open-window":
        return `Открыть окно доверия для плагина «${String(a.pluginId)}» на ${String(a.minutes)} мин${a.scope === "tree" ? " (охват: весь тред со всеми сабтредами)" : a.scope === "thread" ? " (охват: только этот тред)" : ""}: любые версии этого плагина будут загружаться без касания`;
      case "policy": {
        const cur = this.policy();
        const parts = Object.entries(a.patch as Record<string, unknown>).map(([k, v]) => `${k}: ${String(cur[k as keyof Policy])} → ${String(v)}`);
        return `Изменить политику окон доверия: ${parts.join(", ") || "без изменений"}`;
      }
      case "agents-accept": {
        if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
        const rows = this.openDrifts(a.ids as number[]);
        const by = (c: string): number => rows.filter((r) => String(r.class) === c).length;
        const first = rows.filter((r) => Number(r.initial) === 1).length;
        const list = rows.slice(0, 5).map((r) => `${String(r.path)} (${String(r.change)}, ${String(r.class)})`).join("; ");
        return `${first === rows.length ? "Первый эталон: принять всё как есть — " : ""}Принять в эталон наблюдателя за конфигурациями и памятью агентов ${rows.length} расхождений (критичных ${by("critical")}, инструкций ${by("instructions")}, прочих ${by("other")}): ${list}${rows.length > 5 ? ` и ещё ${rows.length - 5}` : ""}`;
      }
      default:
        return `Подтвердить действие плагина secure-bb: ${String(a.purpose)}`;
    }
  }

  private trimChallenges(): void {
    this.db.prepare(`DELETE FROM challenges WHERE expires_at < ?`).run(this.now() - HOUR_MS);
    this.db.prepare(`DELETE FROM challenges WHERE kind = 'action' AND nonce NOT IN (SELECT nonce FROM challenges WHERE kind = 'action' ORDER BY created_at DESC, rowid DESC LIMIT ?)`).run(MAX_OPEN_CHALLENGES);
  }

  /** `challenge {action}`: no secret needed (it decides nothing: only a signature made by a registered key on the console's side of Touch ID does). */
  challenge(raw: Record<string, unknown>): { challenge: string; allowCredentials: Array<{ type: "public-key"; id: string }>; description: string; rpId: string; origin: string; expiresAt: number } {
    const keys = this.activePasskeys();
    if (keys.length === 0) throw new GuardError("not_registered", "no passkey is registered; run `sbb-guard passkey-enroll` on the console");
    const action = this.normalizeAction(raw.action);
    const description = this.describe(action);
    const nonce = b64u(newNonce());
    const expiresAt = this.now() + CHALLENGE_TTL_MS;
    this.tx(() => {
      this.trimChallenges();
      this.db.prepare(`INSERT INTO challenges (nonce, kind, action_json, created_at, expires_at) VALUES (?, 'action', ?, ?, ?)`).run(nonce, JSON.stringify(action), this.now(), expiresAt);
    });
    return { challenge: nonce, allowCredentials: keys.map((k) => ({ type: "public-key" as const, id: k.credential_id })), description, rpId: this.rp.rpId, origin: this.rp.origin, expiresAt };
  }

  /**
   * Checks an assertion for `action` (the normalized command that just arrived). Order: shape → the challenge (unknown, used, expired: plain refusals,
   * not counted) → everything the signature covers (counted as a wrong code is: one counter) → the challenge is spent in one transaction with the key's counter.
   */
  private verifyPasskey(purpose: string, action: Record<string, unknown>, assertion: unknown): Factor {
    if (this.activePasskeys().length === 0) throw new GuardError("not_registered", "no passkey is registered; run `sbb-guard passkey-enroll` on the console");
    this.assertNotBlocked();
    if (typeof assertion !== "object" || assertion === null || Array.isArray(assertion)) throw new GuardError("invalid", "passkey is an object");
    const p = assertion as Record<string, unknown>;
    let credId: string;
    let cdj: Buffer;
    let authDataRaw: Buffer;
    let sig: Buffer;
    let clientChallenge: string;
    let cd: ReturnType<typeof parseClientData>;
    try {
      credId = b64u(fromB64u(p.credentialId, "credentialId", 1400));
      cdj = fromB64u(p.clientDataJSON, "clientDataJSON");
      authDataRaw = fromB64u(p.authenticatorData, "authenticatorData");
      sig = fromB64u(p.signature, "signature", 512);
      cd = parseClientData(cdj);
      clientChallenge = cd.challenge;
    } catch (err) {
      if (err instanceof PasskeyError) throw new GuardError("invalid", err.message);
      throw err;
    }
    const ch = this.db.prepare(`SELECT * FROM challenges WHERE nonce = ? AND kind = 'action'`).get(clientChallenge) as Raw | undefined;
    if (!ch) throw new GuardError("invalid_passkey", "unknown challenge (it was not issued by this guard, or it is long gone)");
    if (Number(ch.used) === 1) throw new GuardError("invalid_passkey", "this challenge was already used");
    if (Number(ch.expires_at) <= this.now()) throw new GuardError("expired", "the challenge has expired; ask for a new one");

    const fail = (reason: string): never => {
      this.recordFailure("passkey.fail", purpose, { reason });
      throw new GuardError("invalid_passkey", reason);
    };
    const key = this.activePasskeys().find((k) => k.credential_id === credId);
    if (!key) return fail("this key is not registered here");
    if (cd.type !== "webauthn.get") return fail("the client data is not for a touch");
    if (cd.origin !== this.rp.origin || cd.crossOrigin) return fail(`the touch was made on another origin than ${this.rp.origin}`);
    let auth: ReturnType<typeof parseAuthData>;
    try {
      auth = parseAuthData(authDataRaw);
    } catch {
      return fail("malformed authenticator data");
    }
    if (!auth.rpIdHash.equals(sha256(this.rp.rpId))) return fail("the touch was made for another RP ID");
    if ((auth.flags & FLAG_UP) === 0) return fail("no user presence");
    if ((auth.flags & FLAG_UV) === 0) return fail("no user verification (Touch ID or PIN)");
    if (!verifyEs256(Buffer.from(String(key.public_key), "base64url"), authDataRaw, cdj, sig)) return fail("invalid signature");
    // The signature is genuine. Is it for THIS action? A captured signature spent on another action stops here.
    if (String(ch.action_json) !== JSON.stringify(action)) return fail("the challenge was issued for another action");
    // Authenticators that count must count up; those that do not (synced passkeys report 0) stay at 0.
    if ((auth.signCount !== 0 || Number(key.sign_count) !== 0) && auth.signCount <= Number(key.sign_count)) return fail("the key's counter did not increase (a cloned key?)");

    this.tx(() => {
      const spent = this.db.prepare(`UPDATE challenges SET used = 1 WHERE nonce = ? AND used = 0`).run(clientChallenge);
      if (Number(spent.changes) !== 1) throw new GuardError("invalid_passkey", "this challenge was already used");
      this.db.prepare(`UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?`).run(auth.signCount, this.now(), key.id);
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose) VALUES (?, 1, ?)`).run(this.now(), purpose);
    });
    return { via: "passkey", key: String(key.label), action };
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
  // ---- agent watch: configurations and memory of the agents (design: secure-bb-agent-watch-design.md) ----------------------------
  // The guard reads the agents' files (read-only ACL for its user, granted by the installer) and compares them with the baseline a human
  // accepted. v1 consequences are signals, not blocks: the feed, the windows closed, and (by the plugin) the thread marked polluted.
  // Without a touch nothing here changes the baseline: `agents-accept` is a touch, `agents-scan` and `agents-state` carry no secret.

  agentsEnabled(): boolean {
    return this.agents !== null;
  }

  /** One pass over the files. `force` skips the rate limit (the timer of `serve` and tests); a request is served at most once in AGENTS_SCAN_GAP_MS. */
  agentsScan(opts: { force?: boolean } = {}): { scanned: boolean; throttled: boolean; at: number } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const t = this.now();
    if (!opts.force && this.lastAgentsScan !== 0 && t - this.lastAgentsScan < AGENTS_SCAN_GAP_MS) return { scanned: false, throttled: true, at: this.lastAgentsScan };
    this.lastAgentsScan = t;
    const res = scanAgents({ home: this.agents.home, extraRoots: this.agents.extraRoots, ...(this.agents.limits ? { limits: this.agents.limits } : {}), deny: [this.secretDir, this.headDir, ...(this.agents.deny ?? [])], ...(this.agents.hooks ? { hooks: this.agents.hooks } : {}) });
    this.tx(() => this.reconcileAgents(res));
    return { scanned: true, throttled: false, at: t };
  }

  private reconcileAgents(res: ScanResult): void {
    const now = this.now();
    const first = this.meta("agents_first_scan") === null;
    const baseline = new Map((this.db.prepare(`SELECT * FROM agent_baseline`).all() as Raw[]).map((r) => [String(r.path), r]));
    const open = new Map((this.db.prepare(`SELECT * FROM agent_drifts WHERE status = 'open'`).all() as Raw[]).map((r) => [String(r.path), r]));
    const alarms = [...res.alarms];
    const fresh: Array<{ id: number; path: string; rel: string; rootKind: string; root: string; cls: string; change: string; reasons: string[] }> = [];
    const counts = { added: 0, changed: 0, removed: 0, critical: 0, instructions: 0, other: 0 };
    let openCount = open.size;
    let capped = false;

    const close = (d: Raw, status: "reverted" | "superseded"): void => {
      this.db.prepare(`UPDATE agent_drifts SET status = ?, resolved_at = ? WHERE id = ?`).run(status, now, Number(d.id));
      open.delete(String(d.path));
      openCount--;
    };
    const create = (o: { path: string; root: string; rootKind: string; rel: string; kind: FileKind; change: Change; prev: string | null; oldSha: string | null; next: string | null; newSha: string | null; size: number | null; mtime: number | null }): void => {
      if (openCount >= MAX_OPEN_DRIFTS) {
        capped = true;
        return;
      }
      let a = analyzeAgents({ rel: o.rel, kind: o.kind, change: o.change, next: o.next, prev: o.prev });
      if (o.change !== "removed" && o.next === null) {
        // Too large to keep or to read in full: it cannot be judged, which is itself the reason (a config is held to the strict side).
        a = o.kind === "instructions" ? { cls: "instructions", reasons: [], findings: [{ rule: "too-large", severity: "review", file: o.rel, line: 0, excerpt: "файл слишком велик, чтобы разобрать его целиком" }] } : { cls: "critical", reasons: ["файл слишком велик для разбора: проверить вручную"], findings: [] };
      }
      const diff = o.change === "removed" ? unifiedDiff(o.prev, null) : o.next === null || (o.change === "changed" && o.prev === null && o.oldSha !== null) ? "(содержимое слишком велико для показа)" : unifiedDiff(o.prev, o.next);
      const info = this.db
        .prepare(`INSERT INTO agent_drifts (path, root, root_kind, rel, kind, change, class, reasons, findings, old_sha, new_sha, new_size, new_mtime, diff, new_content, initial, status, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`)
        .run(o.path, o.root, o.rootKind, o.rel, o.kind, o.change, a.cls, JSON.stringify(a.reasons), JSON.stringify(a.findings), o.oldSha, o.newSha, o.size, o.mtime, diff, o.next, first ? 1 : 0, now, now);
      openCount++;
      counts[o.change]++;
      counts[a.cls]++;
      if (a.cls === "critical" && !first) fresh.push({ id: Number(info.lastInsertRowid), path: o.path, rel: o.rel, rootKind: o.rootKind, root: o.root, cls: a.cls, change: o.change, reasons: a.reasons });
    };

    for (const o of res.observed.values()) {
      const b = baseline.get(o.path);
      const d = open.get(o.path);
      if (b && String(b.sha256) === o.sha256) {
        if (d) close(d, "reverted");
        continue;
      }
      const change: Change = b ? "changed" : "added";
      if (d && String(d.new_sha) === o.sha256 && String(d.change) === change) {
        this.db.prepare(`UPDATE agent_drifts SET last_seen = ? WHERE id = ?`).run(now, Number(d.id));
        continue;
      }
      if (d) close(d, "superseded");
      create({ path: o.path, root: o.root, rootKind: o.rootKind, rel: o.rel, kind: o.kind, change, prev: b ? ((b.content as string | null) ?? null) : null, oldSha: b ? String(b.sha256) : null, next: o.content, newSha: o.sha256, size: o.size, mtime: Math.round(o.mtimeMs) });
    }

    // A baseline file that was not seen has gone only if the file system says so; a file the walk did not reach (a limit) or cannot open is not "removed".
    for (const [path, b] of baseline) {
      if (res.observed.has(path)) continue;
      const gone = fileGone(path);
      if (gone === "denied") {
        // One alarm for the directory that cannot be entered says it all; each file under it would only repeat it.
        if (!alarms.some((a) => path.startsWith(`${a.path}/`))) alarms.push({ path, kind: "unreadable", error: "EACCES" });
        continue;
      }
      if (gone !== "gone") continue;
      const d = open.get(path);
      if (d && String(d.change) === "removed") {
        this.db.prepare(`UPDATE agent_drifts SET last_seen = ? WHERE id = ?`).run(now, Number(d.id));
        continue;
      }
      if (d) close(d, "superseded");
      create({ path, root: String(b.root), rootKind: rootKindOf(this.agents!, String(b.root)), rel: String(b.rel), kind: String(b.kind) as FileKind, change: "removed", prev: (b.content as string | null) ?? null, oldSha: String(b.sha256), next: null, newSha: null, size: null, mtime: null });
    }
    // An addition that disappeared before anybody looked: nothing to decide any more.
    for (const [path, d] of open) if (!res.observed.has(path) && !baseline.has(path) && String(d.change) === "added" && fileGone(path) === "gone") close(d, "reverted");

    // ---- consequences (v1: signals) ----
    if (first) this.log("agents.first-scan", null, null, { files: res.observed.size, roots: res.roots, drifts: counts.added });
    else if (counts.added + counts.changed + counts.removed > 0) this.log("agents.drift", null, null, { ...counts });
    if (fresh.length > 0) {
      // A critical change closes the windows of trust, as pollution does (the plugin also marks the thread whose working directory it is).
      let closed = 0;
      for (const w of this.unclosedWindows()) (this.closeWindowInner(w, "agents-critical"), closed++);
      for (const f of fresh.slice(0, 20)) this.log("agents.critical", null, null, { drift: f.id, path: f.path, rel: f.rel, rootKind: f.rootKind, change: f.change, reasons: f.reasons.slice(0, 5), windowsClosed: closed });
    }
    if (capped) this.log("agents.flood", null, null, { limit: MAX_OPEN_DRIFTS });

    // ---- alarms and notes: remembered for the page; a change in the set of alarms is journaled ----
    const sig = alarms.map((a) => `${a.path}\0${a.error}`).sort().join("\n");
    if (sig !== (this.meta("agents_alarm_sig") ?? "")) {
      this.setMeta("agents_alarm_sig", sig);
      this.log(alarms.length > 0 ? "agents.alarm" : "agents.alarm.clear", null, null, { count: alarms.length, paths: alarms.slice(0, 10).map((a) => ({ path: a.path, error: a.error })) });
    }
    const notes = capped ? [...res.notes, { kind: "limit", text: `открытых расхождений больше ${MAX_OPEN_DRIFTS}: новые не записываются, пока их не рассмотрят` }] : res.notes;
    this.setMeta("agents_last", JSON.stringify({ at: now, files: res.observed.size, roots: res.roots, alarms: alarms.slice(0, 100), notes: notes.slice(0, 50) }));
    if (first) this.setMeta("agents_first_scan", String(now));
    this.db.prepare(`DELETE FROM agent_drifts WHERE status != 'open' AND id NOT IN (SELECT id FROM agent_drifts ORDER BY id DESC LIMIT 2000)`).run();
  }

  /** What the page reads: the differences, the alarms, the notes. No secret: the diff and the excerpts are masked, the stored content never leaves. */
  agentsState(): Record<string, unknown> {
    if (this.agents === null) return { enabled: false };
    const last = ((): Record<string, unknown> | null => {
      const raw = this.meta("agents_last");
      try {
        return raw === null ? null : (JSON.parse(raw) as Record<string, unknown>);
      } catch {
        return null;
      }
    })();
    const view = (r: Raw): Record<string, unknown> => ({
      id: Number(r.id),
      path: String(r.path),
      root: String(r.root),
      rootKind: String(r.root_kind),
      rootName: basename(String(r.root)),
      rel: String(r.rel),
      kind: String(r.kind),
      change: String(r.change),
      class: String(r.class),
      reasons: JSON.parse(String(r.reasons)) as string[],
      findings: (JSON.parse(String(r.findings)) as Array<Record<string, unknown>>).map((f) => ({ ...f, excerpt: maskSecrets(String(f.excerpt ?? "")) })),
      oldSha: r.old_sha === null ? null : String(r.old_sha).slice(0, 16),
      newSha: r.new_sha === null ? null : String(r.new_sha).slice(0, 16),
      size: r.new_size === null ? null : Number(r.new_size),
      mtime: r.new_mtime === null ? null : Number(r.new_mtime),
      diff: String(r.diff),
      initial: Number(r.initial) === 1,
      status: String(r.status),
      firstSeen: Number(r.first_seen),
      lastSeen: Number(r.last_seen),
      resolvedAt: r.resolved_at === null ? null : Number(r.resolved_at),
    });
    const rank = `CASE class WHEN 'critical' THEN 0 WHEN 'instructions' THEN 1 ELSE 2 END`;
    const open = (this.db.prepare(`SELECT * FROM agent_drifts WHERE status = 'open' ORDER BY ${rank}, id DESC LIMIT 500`).all() as Raw[]).map(view);
    const recent = (this.db.prepare(`SELECT * FROM agent_drifts WHERE status != 'open' ORDER BY id DESC LIMIT 20`).all() as Raw[]).map(view);
    const baselineFiles = (this.db.prepare(`SELECT COUNT(*) AS n FROM agent_baseline`).get() as { n: number }).n;
    const total = (this.db.prepare(`SELECT COUNT(*) AS n FROM agent_drifts WHERE status = 'open'`).get() as { n: number }).n;
    return {
      enabled: true,
      home: this.agents.home,
      extraRoots: this.agents.extraRoots,
      lastScanAt: (last?.at as number | undefined) ?? null,
      scannedFiles: (last?.files as number | undefined) ?? 0,
      roots: (last?.roots as number | undefined) ?? 0,
      baselineFiles,
      // The first baseline: the first scan's differences, until a human accepts them as they are.
      initial: { pending: open.filter((d) => d.initial === true).length, baselineAt: this.meta("agents_first_scan") === null ? null : Number(this.meta("agents_first_scan")) },
      openTotal: total,
      drifts: open,
      recent,
      alarms: (last?.alarms as unknown[] | undefined) ?? [],
      notes: (last?.notes as unknown[] | undefined) ?? [],
    };
  }

  /** Accepts differences into the baseline. A touch (a code or a passkey signature over exactly these ids), like `approve`. */
  agentsAccept(raw: Record<string, unknown>): { accepted: number } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const ids = this.agentIds(raw.ids);
    // Everything that can be checked without a code is checked first, so that a spent code is not wasted on a refusal.
    this.openDrifts(ids);
    const factor = this.verifyFactor("agents.accept", this.normalizeAction({ op: "agents-accept", ids }), raw);
    return this.tx(() => {
      const rows = this.openDrifts(ids);
      const now = this.now();
      for (const r of rows) {
        if (String(r.change) === "removed") this.db.prepare(`DELETE FROM agent_baseline WHERE path = ?`).run(String(r.path));
        else
          this.db
            .prepare(`INSERT INTO agent_baseline (path, root, rel, kind, sha256, size, content, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET root = excluded.root, rel = excluded.rel, kind = excluded.kind, sha256 = excluded.sha256, size = excluded.size, content = excluded.content, accepted_at = excluded.accepted_at`)
            .run(String(r.path), String(r.root), String(r.rel), String(r.kind), String(r.new_sha), Number(r.new_size ?? 0), (r.new_content as string | null) ?? null, now);
        this.db.prepare(`UPDATE agent_drifts SET status = 'accepted', resolved_at = ? WHERE id = ?`).run(now, Number(r.id));
      }
      const by = (c: string): number => rows.filter((r) => String(r.class) === c).length;
      this.log("agents.accept", null, null, { count: rows.length, critical: by("critical"), instructions: by("instructions"), other: by("other"), initial: rows.filter((r) => Number(r.initial) === 1).length, drifts: rows.slice(0, 50).map((r) => ({ id: Number(r.id), path: String(r.path), change: String(r.change), class: String(r.class) })), ...factorDetail(factor) });
      return { accepted: rows.length };
    });
  }

  private agentIds(v: unknown): number[] {
    if (!Array.isArray(v) || v.length === 0 || v.length > MAX_ACCEPT_IDS) throw new GuardError("invalid", `ids is a list of 1..${MAX_ACCEPT_IDS} difference ids`);
    return [...new Set(v.map((x) => intOf(x, "id", 1, Number.MAX_SAFE_INTEGER)))].sort((a, b) => a - b);
  }
  /** The open differences with these ids; a missing one is not_found, one that is no longer open (superseded by a newer change, accepted) a conflict. */
  private openDrifts(ids: number[]): Raw[] {
    const rows: Raw[] = [];
    for (const id of ids) {
      const r = this.db.prepare(`SELECT * FROM agent_drifts WHERE id = ?`).get(id) as Raw | undefined;
      if (!r) throw new GuardError("not_found", `no difference #${id}`);
      if (String(r.status) !== "open") throw new GuardError("conflict", `difference #${id} is already ${String(r.status)}${String(r.status) === "superseded" ? " (the file changed again: look at the new one)" : ""}`);
      rows.push(r);
    }
    return rows;
  }

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
      totp: { registered: this.totpRegistered(), disabled: this.totpDisabled(), blockedUntil },
      passkeys: {
        rpId: this.rp.rpId,
        origin: this.rp.origin,
        keys: this.listPasskeys()
          .filter((k) => k.state === "active")
          .map((k) => ({ id: k.id, label: k.label, createdAt: k.createdAt, lastUsedAt: k.lastUsedAt })),
        enrollmentOpen: this.openEnrollment() !== undefined,
      },
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
