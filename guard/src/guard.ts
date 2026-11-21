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
import { readFileSync, renameSync, unlinkSync, writeFileSync, openSync, closeSync, writeSync, constants, lstatSync, realpathSync } from "node:fs";
import { basename, dirname, sep } from "node:path";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
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
import { memoryManifestCache, runChecks as runChecksPlain, runChecksVerified, type CheckResult, type RegistryFetch } from "./checks/index.ts";

/** What the guard's own checks may spend on comparing node_modules with the registry; the budget of one evaluation is {@link DEFAULT_BUDGET_MS}. */
const INTEGRITY_DEADLINE_MS = 2500;
const manifestCache = memoryManifestCache();
const runChecksOffline = (dir: string, o: { pluginId?: string } = {}): Promise<CheckResult> => runChecksPlain(dir, o.pluginId ? { pluginId: o.pluginId } : {});
const runChecks = (dir: string, o: { pluginId?: string } = {}): Promise<CheckResult> => runChecksVerified(dir, { fetch: globalThis.fetch as unknown as RegistryFetch, cache: manifestCache, deadlineMs: INTEGRITY_DEADLINE_MS }, o.pluginId);
import { readTree, TreeRefused, type TreeLimits } from "./tree-read.ts";
import {
  brief,
  DEFAULT_TRUST_MODE,
  grown,
  hardFlags,
  identityOf,
  levelOf,
  MAX_SOURCES,
  MODE_RANK,
  normalizeEntry,
  parseRights,
  rightsOf,
  TRUST_MODES,
  type Level,
  type Rights,
  type TrustMode,
} from "./trust.ts";
import { scan as scanAgents, type FileKind, type Limits, type ScanResult } from "./agents-scan.ts";
import { JSON_FILE, applyPathChange, watchedRel, type JsonKey } from "./restore.ts";
import { stable } from "./agents-scan.ts";
import { helperUp, sendRestore } from "./restore-client.ts";
import { applyForward, partAction, partDanger, partRestorable, rollbackDanger, shownValue, splitSettings, viewPart, type JsonPart, type PartView } from "./json-parts.ts";

export type GuardErrorCode = "invalid" | "not_found" | "conflict" | "not_registered" | "invalid_code" | "invalid_passkey" | "expired" | "blocked" | "unknown_op" | "no_restore" | "unavailable" | "restore_failed";

export class GuardError extends Error {
  readonly code: GuardErrorCode;
  constructor(code: GuardErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export const HOUR_MS = 3_600_000;
export const MAX_FAILURES = 5;
/**
 * Wrong signatures are never a reason to refuse a touch: an ES256 signature cannot be guessed, so a limit would protect nothing and
 * only let a process that reaches the socket lock the owner out. They are journaled, at most one summary record a minute (with the
 * number of refusals since the last one), so the journal cannot be flooded either.
 */
export const PASSKEY_FAIL_LOG_EVERY_MS = 60_000;
/** Approval sessions (the same numbers as without a guard): 15 minutes sliding, 1 hour ceiling. */
export const SESSION_IDLE_MS = 15 * 60_000;
export const SESSION_CAP_MS = 60 * 60_000;
/** A list for one touch lives this long; a few may wait at once. */
export const BATCH_TTL_MS = 10 * 60_000;
const MAX_PENDING_BATCHES = 20;
const MAX_BATCH_ITEMS = 50;
/** Troubleshooting mode: at most this long, and every decision is a journal record, so at most this many a minute (past it the guard holds again). */
export const MAX_TROUBLESHOOT_MIN = 240;
const MAX_TROUBLESHOOT_PASSES_PER_MIN = 1000;
/**
 * What a session covers besides `approve` (without acknowledgeBlock), `open-window` and `batch-approve`: the plugin's own routine touches.
 * Everything else (policy, trust mode, sources, agents, the session itself) needs a fresh touch; the plugin's table (src/approval.ts) says the same.
 */
export const ROUTINE_TOUCH_PURPOSES: ReadonlySet<string> = new Set(["watch.accept", "watch.acceptAll", "watch.rollback", "watch.window.open", "skills.approve"]);
/** The reasons the guard itself wrote into a queue entry (see `sourceVerdict`, `evaluate`). */
const isMismatchNote = (n: string | null): boolean => /не совпал с хешем/.test(n ?? "");
const isHardFlagNote = (n: string | null): boolean => /жёсткий флаг/.test(n ?? "");
const sha256hex = (t: string): string => createHash("sha256").update(t, "utf8").digest("hex");
/** The window the console opens for registering a passkey, and how long a challenge lives. */
export const ENROLL_WINDOW_MS = 5 * 60_000;
/** The purpose of the touch that `sbb-guard setup` waits for (the page's «Проверить касание»): it changes nothing, it is only written into the journal. */
export const SETUP_CHECK_PURPOSE = "setup-check";
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
export type Decision =
  | { action: "proceed"; via: "approval" | "window" | "source" | "troubleshoot" }
  | { action: "wait"; reason: string; requestId: number | null }
  | { action: "reject"; message: string };

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
  /** The source this approval is from (`github:owner/name`, `path:/dir`), or null. */
  sourceId: string | null;
  /** What the guard itself found in the version (the baseline for later versions of the same source), or null: not computed. */
  rights: Rights | null;
  /** Why it was let in: the guard's own words (what a person reads in the version history). Null: an approval from before this was recorded. */
  why: string | null;
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
  /** Why the version did not pass by itself (the guard's words), or null. */
  note: string | null;
  rights: Rights | null;
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
/** «касанием: <why the guard did not let it in by itself>» — the guard's note says it (new right, unknown source, strict mode…). */
const touchWhy = (note: string | null): string => (note ? `касанием: ${note}` : "касанием: вы одобрили сами");
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
  sourceId: (r.source_id as string | null) ?? null,
  rights: parseRights(r.rights),
  why: (r.why as string | null) ?? null,
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
  note: (r.note as string | null) ?? null,
  rights: parseRights(r.rights),
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
  /** Trust by source and rights. Absent: no plugin directory is read by the guard, nothing passes by itself. */
  trust?: TrustConfig;
  /** Agent watch: the agents' home (default /var/bbagent in `serve`) and the extra roots the console named. Absent: the watch is off. */
  agents?: AgentsConfig;
}
export interface TrustConfig {
  /** Where the core keeps plugins installed from git (read access for the guard's user): a version is read only from under one of them. */
  pluginsRoots?: string[];
  /** Sources of the official catalog (`github:owner/name`, `github:owner/*`): the level "known". */
  knownSources?: string[];
  /** Tests: the checks of a plugin directory (default: the checks module of this tree, the one the plugin uses). */
  checks?: (dir: string, opts?: { pluginId?: string }) => Promise<CheckResult>;
  /** No network: the checks do not compare node_modules with the npm registry (`--offline`). */
  offline?: boolean;
  /** How long a version may be read before the guard gives up and queues it (default 3.5 s: the core waits 5). */
  budgetMs?: number;
  /** Tests: smaller limits of the one pass over a directory. */
  treeLimits?: TreeLimits;
}
/** What the guard found in a version's directory by itself, or why it could not. */
/** `hash`: the core's hash of the directory, computed by the guard in the same pass that the checks ran on (it equals the request's contentHash, or the evaluation is not ok). */
export type Evaluation = { ok: true; hash: string; rights: Rights; blocks: string[] } | { ok: false; reason: string };
const MAX_CONCURRENT_EVALS = 2;
const MAX_EVALS_PER_MINUTE = 30;
const DEFAULT_BUDGET_MS = 3500;

interface JsonOp {
  key: JsonKey;
  /** The baseline's value of the section; null: the section is not in the baseline, it is removed. */
  value: Record<string, unknown> | null;
  sha: string;
}
type RestorePlan = { ok: true; action: "write" | "delete" | "json"; content: string | null; sha: string; ops?: JsonOp[] } | { ok: false; reason: string };

export interface AgentsConfig {
  home: string;
  extraRoots: string[];
  /** Tests lower the limits of a scan. */
  limits?: Partial<Limits>;
  /** More directories that are never read (the guard's data and its socket; its state directory is always one). */
  deny?: string[];
  /** Tests: a function called between looking at a file and opening it. */
  hooks?: { beforeOpen?: (path: string) => void };
  /** The restore helper's socket (restore.ts, a service of the agents' user). Absent: nothing can be put back by the guard, the page shows the manual way. */
  restore?: { socket: string; timeoutMs?: number };
}

/** What a touch is made of: a TOTP code, or (instead of it) a passkey assertion. */
export interface Proof {
  code?: unknown;
  passkey?: unknown;
  /** The token of an approval session: covers routine actions only, and only when neither a code nor a passkey came with it. */
  session?: unknown;
}
/** Who touched: how, with which key, and for what exactly (written into the journal). */
export interface Factor {
  via: "totp" | "passkey" | "session";
  key?: string;
  action?: Record<string, unknown>;
  sessionId?: number;
}
const factorDetail = (f: Factor): Record<string, unknown> => ({ via: f.via, ...(f.key !== undefined ? { key: f.key } : {}), ...(f.sessionId !== undefined ? { session: f.sessionId } : {}), ...(f.action !== undefined ? { action: f.action } : {}) });

/** Does a session cover this action? Routine ones only: lifting a block, widening, trusting a source, the session itself — never. */
export function isRoutineAction(a: Record<string, unknown>): boolean {
  switch (a.op) {
    case "approve":
      return a.acknowledgeBlock !== true;
    // A window while the agents' settings are under a critical alarm is never routine: a fresh touch, with the warning in the description.
    case "open-window":
      return a.alarm !== true;
    case "batch-approve":
      return true;
    case "touch":
      return typeof a.purpose === "string" && ROUTINE_TOUCH_PURPOSES.has(a.purpose);
    // Keeping a part of a settings file that does not make the agent more dangerous (the guard has checked the flag itself): routine. A dangerous one: never.
    case "agents-keep-part":
      return a.danger === false;
    default:
      return false;
  }
}

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

/** The approval to insert: the guard fills in the source id; the rights come from its own checks. */
type NewApproval = Omit<ApprovalRow, "id" | "approvedAt" | "revokedAt" | "sourceId" | "rights" | "why"> & { rights?: Rights | null; why?: string | null };

export class Guard {
  private readonly trustCfg: Required<Pick<TrustConfig, "pluginsRoots" | "budgetMs">> & { treeLimits?: TreeLimits } & { known: string[]; checks: (dir: string, opts?: { pluginId?: string }) => Promise<CheckResult> };
  private evalsRunning = 0;
  private evalTimes: number[] = [];
  private readonly db: DatabaseSync;
  private readonly now: () => number;
  private readonly secretPath: string;
  private readonly head: HeadFile;
  private readonly rp: RelyingParty;
  private readonly agents: AgentsConfig | null;
  private lastAgentsScan = 0;
  private troubleshootPasses: number[] = [];
  private passkeyFails = 0;
  private passkeyFailLoggedAt = -Infinity;
  private readonly secretDir: string;
  private readonly headDir: string;

  constructor(o: GuardOptions) {
    this.agents = o.agents ?? null;
    const known: string[] = [];
    for (const k of o.trust?.knownSources ?? []) {
      const n = normalizeEntry(k);
      if (n === null) throw new Error(`known source ${JSON.stringify(k)} is not github:owner/name, github:owner/* or path:/dir`);
      known.push(n);
    }
    this.trustCfg = { pluginsRoots: o.trust?.pluginsRoots ?? [], budgetMs: o.trust?.budgetMs ?? DEFAULT_BUDGET_MS, ...(o.trust?.treeLimits ? { treeLimits: o.trust.treeLimits } : {}), known, checks: o.trust?.checks ?? (o.trust?.offline ? runChecksOffline : runChecks) };
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
  /** Until when wrong CODES block codes (and sessions: a token is a secret like a code); 0: not blocked. */
  blockedUntil(): number {
    const until = Number(this.meta("blocked_until") ?? 0);
    return until > this.now() ? until : 0;
  }
  /** Blocked after too many wrong codes (or session tokens): five in an hour block codes for an hour. Signatures are not touched by it. */
  private assertCodesNotBlocked(): void {
    const until = this.blockedUntil();
    if (until > 0) throw new GuardError("blocked", `too many wrong codes; codes are blocked until ${new Date(until).toISOString()} (a passkey touch still works)`);
  }
  /**
   * A wrong code or session token (`totp.fail`: the fifth within an hour blocks codes for an hour), or a wrong signature (`passkey.fail`: counted
   * and journaled as a summary at most once a minute, never blocks). Always commits before the caller throws.
   */
  private recordFailure(kind: "totp.fail" | "passkey.fail", purpose: string, extra: Record<string, unknown> = {}): void {
    if (kind === "passkey.fail") {
      this.passkeyFails++;
      this.flushPasskeyFails(purpose, extra);
      return;
    }
    this.tx(() => {
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose, kind) VALUES (?, 0, ?, 'code')`).run(this.now(), purpose);
      const since = Math.max(this.now() - HOUR_MS, Number(this.meta("fail_epoch") ?? 0));
      const n = (this.db.prepare(`SELECT COUNT(*) AS n FROM attempts WHERE ok = 0 AND kind = 'code' AND ts > ?`).get(since) as { n: number }).n;
      this.log(kind, null, null, { purpose, ...extra });
      if (n >= MAX_FAILURES) {
        const until = this.now() + HOUR_MS;
        this.setMeta("blocked_until", String(until));
        this.setMeta("fail_epoch", String(this.now()));
        this.log("totp.blocked", null, null, { purpose, until });
      }
    });
  }
  /** The summary of wrong signatures: when a minute has passed since the last one (or on the background pass). */
  private flushPasskeyFails(purpose = "", extra: Record<string, unknown> = {}, inTx = false): void {
    if (this.passkeyFails === 0 || this.now() - this.passkeyFailLoggedAt < PASSKEY_FAIL_LOG_EVERY_MS) return;
    const failures = this.passkeyFails;
    this.passkeyFails = 0;
    this.passkeyFailLoggedAt = this.now();
    const write = (): unknown => this.log("passkey.fail", null, null, { ...(purpose ? { purpose } : {}), ...extra, failures });
    if (inTx) write();
    else this.tx(write);
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
    this.assertCodesNotBlocked();
    const given = typeof code === "string" ? code : "";
    const res = verifyTotp(secret, given, this.now(), Number(this.meta("last_step") ?? 0));
    if (!res.ok) {
      this.recordFailure("totp.fail", purpose);
      throw new GuardError("invalid_code", "invalid or already used code");
    }
    // The step is spent before the action runs, in a transaction of its own (a failure above also commits its record).
    // Callers check everything that can be checked without a code first, so a spent code is not wasted on a refusal.
    this.tx(() => {
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose, kind) VALUES (?, 1, ?, 'code')`).run(this.now(), purpose);
      this.setMeta("last_step", String(res.step));
    });
  }

  /**
   * One touch for one action: a passkey assertion when one is given (and then only that), else a TOTP code, else — for a routine action only —
   * the token of an approval session. A session offered for anything else is refused outright (not counted as a wrong code): it is the page asking
   * for something it must ask a human for.
   */
  private verifyFactor(purpose: string, action: Record<string, unknown>, proof: Proof): Factor {
    if (proof.passkey !== undefined) return this.verifyPasskey(purpose, action, proof.passkey);
    if (proof.code === undefined && proof.session !== undefined) {
      if (!isRoutineAction(action)) throw new GuardError("invalid_code", "this needs a fresh touch (a code or a passkey): a session does not cover it");
      return this.verifySession(purpose, proof.session);
    }
    this.verifyCode(purpose, proof.code);
    return { via: "totp" };
  }

  // ---- approval sessions ---------------------------------------------------------------------------------------------------
  // The token is made here, goes back once to the page that touched, and lives in that page's memory. Only its SHA-256 is kept (and it is never in
  // the journal or the state). A session covers routine actions (isRoutineAction); each use slides the end 15 minutes ahead, never past the ceiling.
  private verifySession(purpose: string, token: unknown): Factor {
    this.assertCodesNotBlocked();
    const row = typeof token === "string" && token.length >= 16 && token.length <= 256 ? (this.db.prepare(`SELECT * FROM sessions WHERE token_hash = ? AND closed_at IS NULL`).get(sha256hex(token)) as Raw | undefined) : undefined;
    const now = this.now();
    if (!row || now >= Number(row.expires_at) || now >= Number(row.hard_expires_at)) {
      if (row) this.tx(() => this.closeSessionInner(Number(row.id), "expired"));
      // A wrong, unknown, closed or expired token is a wrong code: the same counter.
      this.recordFailure("totp.fail", `session:${purpose}`, { via: "session" });
      throw new GuardError("invalid_code", "invalid or expired session");
    }
    this.tx(() => {
      // Sliding never takes time away: a session opened «на час» (its end is the ceiling from the start) keeps its hour.
      this.db.prepare(`UPDATE sessions SET expires_at = ?, uses = uses + 1 WHERE id = ?`).run(Math.max(Number(row.expires_at), Math.min(now + SESSION_IDLE_MS, Number(row.hard_expires_at))), Number(row.id));
    });
    return { via: "session", sessionId: Number(row.id) };
  }
  private closeSessionInner(id: number, reason: string): void {
    const done = this.db.prepare(`UPDATE sessions SET closed_at = ?, closed_reason = ? WHERE id = ? AND closed_at IS NULL`).run(this.now(), reason, id);
    if (Number(done.changes) === 1) this.log(reason === "expired" ? "session.expire" : "session.close", null, null, { session: id, reason });
  }
  private openSessions(): Raw[] {
    const now = this.now();
    return (this.db.prepare(`SELECT * FROM sessions WHERE closed_at IS NULL ORDER BY id`).all() as Raw[]).filter((r) => now < Number(r.expires_at) && now < Number(r.hard_expires_at));
  }

  /** `session-open`: a fresh touch (a session cannot open another). The old session, if any, is closed: there is one. */
  sessionOpen(raw: Record<string, unknown>): { token: string; idleMs: number; capMs: number; sessionId: number } {
    // «На 1 час»: the end is the ceiling from the start, nothing to keep alive; the ceiling is the same one, never more.
    const hour = raw.hour === true;
    const factor = this.verifyFactor("session.open", this.normalizeAction({ op: "session-open", ...(hour ? { hour: true } : {}) }), raw);
    const idleMs = hour ? SESSION_CAP_MS : SESSION_IDLE_MS;
    const token = randomBytes(32).toString("base64url");
    return this.tx(() => {
      for (const r of this.db.prepare(`SELECT id FROM sessions WHERE closed_at IS NULL`).all() as Array<{ id: number }>) this.closeSessionInner(Number(r.id), "replaced");
      const now = this.now();
      const info = this.db.prepare(`INSERT INTO sessions (token_hash, opened_at, expires_at, hard_expires_at) VALUES (?, ?, ?, ?)`).run(sha256hex(token), now, now + idleMs, now + SESSION_CAP_MS);
      const id = Number(info.lastInsertRowid);
      this.log("session.open", null, null, { session: id, idleMs, capMs: SESSION_CAP_MS, ...(hour ? { hour: true } : {}), ...factorDetail(factor) });
      return { token, idleMs, capMs: SESSION_CAP_MS, sessionId: id };
    });
  }
  /** "Lock": tightening, no touch. Closes every session. */
  sessionClose(reason = "locked"): { closed: number } {
    return this.tx(() => {
      let n = 0;
      for (const r of this.db.prepare(`SELECT id FROM sessions WHERE closed_at IS NULL`).all() as Array<{ id: number }>) {
        this.closeSessionInner(Number(r.id), reason);
        n++;
      }
      return { closed: n };
    });
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
  /**
   * An approval of this version that covers the request. One made by the source rule is bound to (plugin, hash, source): it counts only for a
   * caller that names the same source (a hash alone does not say where the code came from), so without a source it never counts.
   */
  private activeApproval(pluginId: string, contentHash: string, source: string | null = null): ApprovalRow | null {
    const rows = this.db.prepare(`SELECT * FROM approvals WHERE content_hash = ? AND plugin_id = ? AND revoked_at IS NULL ORDER BY id DESC`).all(contentHash, pluginId) as Raw[];
    return rows.map(approvalOf).find((a) => a.via !== "source" || (source !== null && a.source === source)) ?? null;
  }
  private addApproval(i: NewApproval): ApprovalRow {
    const sourceId = identityOf(i.sourceKind, i.source)?.id ?? null;
    const rights = i.rights ?? null;
    const info = this.db
      .prepare(`INSERT INTO approvals (content_hash, plugin_id, version, source, source_kind, git_commit, npm_integrity, via, window_id, approved_at, source_id, rights, why) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(i.contentHash, i.pluginId, i.version, i.source, i.sourceKind, i.gitCommit, i.npmIntegrity, i.via, i.windowId, this.now(), sourceId, rights === null ? null : JSON.stringify(rights), i.why ?? null);
    return { ...i, rights, sourceId, why: i.why ?? null, id: Number(info.lastInsertRowid), approvedAt: this.now(), revokedAt: null };
  }
  private resolveQueue(pluginId: string, contentHash: string, status: "approved" | "dismissed"): void {
    // Approving a version also undoes an earlier rejection of it by the person («Вернуть»); a rejection itself touches held entries only.
    const from = status === "approved" ? "('held', 'dismissed')" : "('held')";
    this.db.prepare(`UPDATE queue SET status = ? WHERE content_hash = ? AND plugin_id = ? AND status IN ${from}`).run(status, contentHash, pluginId);
  }

  /** A version the person rejected (dismissed) and has not brought back: no approval covers it. The core asks again at every start; the answer is "no" without a new entry. */
  private isRejected(pluginId: string, contentHash: string): boolean {
    return this.db.prepare(`SELECT 1 FROM queue WHERE content_hash = ? AND plugin_id = ? AND status = 'dismissed' LIMIT 1`).get(contentHash, pluginId) !== undefined;
  }

  /** The repeated question about a rejected version goes to the journal once an hour per version, not at every ask. */
  private logRepeatReject(pluginId: string, contentHash: string, version: string): void {
    const key = `rejected_logged:${pluginId}:${contentHash}`;
    if (Number(this.meta(key) ?? 0) > this.now() - HOUR_MS) return;
    this.setMeta(key, String(this.now()));
    this.log("reject.repeat", pluginId, contentHash, { version, note: "версия отклонена вами; плагин остаётся выключенным, пока вы не нажмёте «Вернуть» в Карантине" });
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
  private upsertHeld(req: DecideInput, stop: boolean, why: { rights: Rights | null; note: string | null } = { rights: null, note: null }): { id: number | null; created: boolean } {
    const held = this.db.prepare(`SELECT * FROM queue WHERE content_hash = ? AND plugin_id = ? AND status = 'held' ORDER BY id DESC LIMIT 1`).get(req.contentHash, req.pluginId) as Raw | undefined;
    const rightsJson = why.rights === null ? null : JSON.stringify(why.rights);
    if (held) {
      // The note and the rights are the guard's own latest reading; a call that could not read keeps the earlier one.
      this.db.prepare(`UPDATE queue SET last_seen = ?, seen_count = seen_count + 1, version = ?, source = ?, source_kind = ?, root_dir = ?, trigger = ?, stop = MAX(stop, ?), note = COALESCE(?, note), rights = COALESCE(?, rights) WHERE id = ?`).run(this.now(), req.version, req.source, req.sourceKind, req.rootDir, req.trigger, stop ? 1 : 0, why.note, rightsJson, Number(held.id));
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
      .prepare(`INSERT INTO queue (content_hash, plugin_id, version, source, source_kind, root_dir, trigger, status, first_seen, last_seen, stop, note, rights) VALUES (?, ?, ?, ?, ?, ?, ?, 'held', ?, ?, ?, ?, ?)`)
      .run(req.contentHash, req.pluginId, req.version, req.source, req.sourceKind, req.rootDir, req.trigger, this.now(), this.now(), stop ? 1 : 0, why.note, rightsJson);
    const id = Number(info.lastInsertRowid);
    this.db.prepare(`DELETE FROM queue WHERE status != 'held' AND status != 'dismissed' AND id NOT IN (SELECT id FROM queue ORDER BY id DESC LIMIT ?)`).run(MAX_QUEUE_ROWS);
    this.log("hold", req.pluginId, req.contentHash, { review: id, version: req.version, trigger: req.trigger, source: req.source, sourceKind: req.sourceKind, ...(why.note !== null ? { note: why.note } : {}), ...(stop ? { stop: true } : {}) });
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
      if (this.activeApproval(req.pluginId, req.contentHash, req.source)) return { requestId: null };
      // Rejected by the person: no new entry (the rejection stands until «Вернуть»).
      if (this.isRejected(req.pluginId, req.contentHash)) {
        this.logRepeatReject(req.pluginId, req.contentHash, req.version);
        return { requestId: null };
      }
      return { requestId: this.upsertHeld(req, raw.stop === true).id };
    });
  }

  /** An approval that covers this request. One made by the source rule covers only the source it was made for (the hash alone does not say where the code came from). */
  private coveringApproval(req: DecideInput): ApprovalRow | null {
    return this.activeApproval(req.pluginId, req.contentHash, req.source);
  }

  /**
   * What the core asks before it loads a plugin. Holds when nothing a human decided covers it. `ev`: what the guard itself read in the version's
   * directory (see `evaluate`); with it, a version of a trusted source whose rights did not grow passes by itself (`sourceVerdict`).
   */
  decide(raw: Record<string, unknown>, ev: Evaluation | null = null): Decision {
    const req = this.parseDecide(raw);
    return this.tx(() => {
      this.sweepInner();
      // Troubleshooting mode: everything passes, and every decision is a record (what it would have been is in it). Nothing is approved and nothing is queued.
      if (this.troubleshootUntil() > 0) {
        const wouldHave = this.coveringApproval(req) ? "approval" : this.openWindowOf(req.pluginId) ? "window" : "wait";
        const now = this.now();
        this.troubleshootPasses = this.troubleshootPasses.filter((t) => t > now - 60_000);
        // Every pass is journaled: past the limit the guard holds instead of passing without a record.
        if (this.troubleshootPasses.length >= MAX_TROUBLESHOOT_PASSES_PER_MIN) return { action: "wait", reason: "held by secure-bb guard: troubleshooting mode records too many decisions", requestId: null } as const;
        this.troubleshootPasses.push(now);
        this.log("troubleshoot.pass", req.pluginId, req.contentHash, { version: req.version, source: req.source, sourceKind: req.sourceKind, rootDir: req.rootDir, trigger: req.trigger, wouldHave });
        return { action: "proceed", via: "troubleshoot" } as const;
      }
      if (this.coveringApproval(req)) return { action: "proceed", via: "approval" } as const;

      // Rejected by the person and not brought back: "no", no new queue entry (the core keeps the plugin off), one journal line an hour per version.
      // Before windows and the source rule: a window or a trusted source must not undo what the person said "no" to; «Вернуть» does.
      if (this.isRejected(req.pluginId, req.contentHash)) {
        this.logRepeatReject(req.pluginId, req.contentHash, req.version);
        return { action: "reject", message: "secure-bb: версия отклонена вами; чтобы вернуть, нажмите «Вернуть» в Карантине" } as const;
      }

      // A stop survives a rejection: dismiss needs no code, so a process that can reach the guard could otherwise clear the stop and let the window in.
      const stopped = this.isStopped(req.pluginId, req.contentHash);
      const w = stopped ? null : this.openWindowOf(req.pluginId);
      if (w) {
        const a = this.addApproval({ contentHash: req.contentHash, pluginId: req.pluginId, version: req.version, source: req.source, sourceKind: req.sourceKind, gitCommit: null, npmIntegrity: null, via: "window", windowId: w.id, rights: ev?.ok && ev.hash === req.contentHash ? ev.rights : null, why: "в открытом окне доверия: окно пропускает версии, пока не просят нового" });
        this.db.prepare(`UPDATE windows SET uses = uses + 1 WHERE id = ?`).run(w.id);
        if (w.mode === "sliding") {
          const next = Math.min(this.now() + w.sizeSec * 1000, w.hardExpiresAt);
          if (next > w.expiresAt) this.db.prepare(`UPDATE windows SET expires_at = ? WHERE id = ?`).run(next, w.id);
        }
        this.resolveQueue(req.pluginId, req.contentHash, "approved");
        this.log("approved.window", req.pluginId, req.contentHash, { approval: a.id, windowId: w.id, version: req.version, source: req.source, sourceKind: req.sourceKind });
        return { action: "proceed", via: "window" } as const;
      }

      const verdict = this.sourceVerdict(req, ev, stopped);
      if (verdict.pass) {
        const a = this.addApproval({ contentHash: req.contentHash, pluginId: req.pluginId, version: req.version, source: req.source, sourceKind: req.sourceKind, gitCommit: null, npmIntegrity: null, via: "source", windowId: null, rights: verdict.rights, why: String(verdict.detail.why ?? "прошла сама: источник и права те же") });
        this.resolveQueue(req.pluginId, req.contentHash, "approved");
        this.log("approved.source", req.pluginId, req.contentHash, { approval: a.id, version: req.version, source: req.source, sourceKind: req.sourceKind, ...verdict.detail });
        return { action: "proceed", via: "source" } as const;
      }

      const h = this.upsertHeld(req, stopped, { rights: ev?.ok && ev.hash === req.contentHash ? ev.rights : null, note: verdict.note });
      return h.id === null ? ({ action: "wait", reason: "held by secure-bb guard: too many new holds", requestId: null } as const) : ({ action: "wait", reason: `held by secure-bb guard: review #${h.id}`, requestId: h.id } as const);
    });
  }

  /** `decide` with the guard's own reading of the version first (the checks run outside the transaction, within a time budget). */
  async decideChecked(raw: Record<string, unknown>): Promise<Decision> {
    const req = this.parseDecide(raw);
    if (this.coveringApproval(req) || this.troubleshootUntil() > 0) return this.decide(raw);
    return this.decide(raw, await this.evaluate(req));
  }

  // ---- trust by source and rights -------------------------------------------------------------------------------
  trustMode(): TrustMode {
    const m = this.meta("trust_mode");
    return TRUST_MODES.includes(m as TrustMode) ? (m as TrustMode) : DEFAULT_TRUST_MODE;
  }
  mySources(): string[] {
    try {
      const j = JSON.parse(this.meta("my_sources") ?? "[]") as unknown;
      return Array.isArray(j) ? j.filter((x): x is string => typeof x === "string" && normalizeEntry(x) === x) : [];
    } catch {
      return [];
    }
  }
  trustState(): { mode: TrustMode; mySources: string[]; known: string[]; pluginsRoots: number } {
    return { mode: this.trustMode(), mySources: this.mySources(), known: [...this.trustCfg.known], pluginsRoots: this.trustCfg.pluginsRoots.length };
  }

  /** Weakening the mode (Strict → Detailed → Simple) is a touch; the same or a stricter one is not. */
  setTrustMode(modeIn: unknown, proof: Proof): TrustMode {
    if (typeof modeIn !== "string" || !TRUST_MODES.includes(modeIn as TrustMode)) throw new GuardError("invalid", "mode is simple, detailed or strict");
    const mode = modeIn as TrustMode;
    const cur = this.trustMode();
    if (mode === cur) return cur;
    const weakens = MODE_RANK[mode] < MODE_RANK[cur];
    const factor = weakens ? this.verifyFactor("trust.mode", this.normalizeAction({ op: "trust-mode", mode }), proof) : null;
    return this.tx(() => {
      this.setMeta("trust_mode", mode);
      this.log("trust.mode", null, null, { from: cur, to: mode, touched: weakens, ...(factor ? factorDetail(factor) : {}) });
      return mode;
    });
  }

  /** Adding "my sources" is a touch (it widens what passes by itself). Entries already in the list need none. `migrated`: from the plugin's old list of trusted repositories. */
  addSources(raw: Record<string, unknown>): { mySources: string[]; added: string[] } {
    const entries = this.entriesOf(raw.entries);
    const cur = this.mySources();
    const fresh = entries.filter((e) => !cur.includes(e));
    if (fresh.length === 0) return { mySources: cur, added: [] };
    if (cur.length + fresh.length > MAX_SOURCES) throw new GuardError("invalid", `at most ${MAX_SOURCES} sources`);
    const factor = this.verifyFactor("sources.add", this.normalizeAction({ op: "sources-add", entries: fresh }), raw);
    return this.tx(() => {
      const next = [...cur, ...fresh].sort();
      this.setMeta("my_sources", JSON.stringify(next));
      this.log("sources.add", null, null, { entries: fresh, ...(raw.migrated === true ? { migrated: "trusted repositories of the plugin" } : {}), ...factorDetail(factor) });
      return { mySources: next, added: fresh };
    });
  }

  /** Removing one only tightens: no touch, and not blocked after wrong codes. Versions already approved stay approved; later ones are asked about. */
  removeSource(raw: Record<string, unknown>): { mySources: string[] } {
    const e = normalizeEntry(raw.entry);
    if (e === null) throw new GuardError("invalid", "entry is github:owner/name, github:owner/* or path:/dir");
    return this.tx(() => {
      const cur = this.mySources();
      if (!cur.includes(e)) throw new GuardError("not_found", "this source is not in the list");
      const next = cur.filter((x) => x !== e);
      this.setMeta("my_sources", JSON.stringify(next));
      this.log("sources.remove", null, null, { entry: e });
      return { mySources: next };
    });
  }

  private entriesOf(v: unknown): string[] {
    if (!Array.isArray(v) || v.length === 0 || v.length > MAX_SOURCES) throw new GuardError("invalid", `entries is a list of 1..${MAX_SOURCES} sources`);
    const out = new Set<string>();
    for (const x of v) {
      const n = normalizeEntry(x);
      if (n === null) throw new GuardError("invalid", `${JSON.stringify(typeof x === "string" ? x.slice(0, 80) : x)} is not github:owner/name, github:owner/* or path:/dir`);
      out.add(n);
    }
    return [...out].sort();
  }

  /**
   * The guard reads the version's directory ITSELF: what the plugin says about its own rights is not looked at (annotate is for display only).
   * Fails closed: a directory that cannot be read, is not where the source says, or checks that fail or run out of time → `ok: false`.
   * Checks are limited (two at a time, thirty a minute): whoever can reach the socket must not be able to make the guard read without end.
   */
  async evaluate(req: DecideInput): Promise<Evaluation> {
    const ident = identityOf(req.sourceKind, req.source);
    if (ident === null) return { ok: false, reason: "источник не назван (не github и не каталог на диске)" };
    let dir: string;
    try {
      dir = realpathSync(req.rootDir);
      if (ident.kind === "path") {
        if (dir !== realpathSync(ident.id.slice(5))) return { ok: false, reason: "каталог версии не тот, что назван источником" };
      } else if (!this.trustCfg.pluginsRoots.some((r) => this.within(dir, r))) {
        return { ok: false, reason: this.trustCfg.pluginsRoots.length === 0 ? "у сторожа не задан каталог плагинов (--plugins-root)" : "каталог версии вне каталогов плагинов ядра" };
      }
    } catch (err) {
      return { ok: false, reason: `каталог не прочитан: ${this.errText(err)}` };
    }
    const now = this.now();
    this.evalTimes = this.evalTimes.filter((t) => t > now - 60_000);
    if (this.evalsRunning >= MAX_CONCURRENT_EVALS || this.evalTimes.length >= MAX_EVALS_PER_MINUTE) return { ok: false, reason: "сторож занят чтением других версий, повторите позже" };
    this.evalTimes.push(now);
    this.evalsRunning++;
    let timer: NodeJS.Timeout | undefined;
    // ONE pass: the guard reads the directory once, hashes what it read the way the core does, and the checks run on a private copy of those same bytes.
    // The hash must be the request's: otherwise the request is about other code than the directory shows (a forged `decide`), and nothing is approved.
    const work = (async (): Promise<Evaluation> => {
      let tree;
      try {
        tree = await readTree(dir, this.trustCfg.treeLimits);
      } catch (err) {
        return { ok: false, reason: err instanceof TreeRefused ? `каталог не прочитан: ${err.message}` : `каталог не прочитан: ${this.errText(err)}` };
      }
      try {
        if (tree.hash !== req.contentHash) return { ok: false, reason: "хеш каталога, посчитанный сторожем, не совпал с хешем из запроса" };
        const res = await this.trustCfg.checks(tree.dir, { pluginId: req.pluginId });
        return { ok: true, hash: tree.hash, rights: rightsOf(res), blocks: hardFlags(res).map((f) => `${f.rule} ${f.file}${f.line ? `:${f.line}` : ""}`) };
      } finally {
        await tree.cleanup().catch(() => undefined);
      }
    })().finally(() => {
      // The slot is freed when the work ends, not when the budget does: a slow directory must not pile up readers.
      this.evalsRunning--;
    });
    try {
      return await Promise.race([work, new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Error("проверки не уложились во время")), this.trustCfg.budgetMs)))]);
    } catch (err) {
      work.catch(() => undefined);
      return { ok: false, reason: `проверки не выполнены: ${this.errText(err)}` };
    } finally {
      clearTimeout(timer);
    }
  }
  private within = (path: string, root: string): boolean => {
    try {
      const r = realpathSync(root);
      return path === r || path.startsWith(r.endsWith(sep) ? r : r + sep);
    } catch {
      return false;
    }
  };
  private errText = (err: unknown): string => (err instanceof Error ? err.message : String(err)).slice(0, 200);

  /** Does this version pass by itself? If not, the note says why in plain words. The rule is all of: source own or known · mode lets it · an approved version from the same source · rights did not grow · no hard flag. */
  /** A critical difference that is not part of the first baseline is open (the same fact the page's red bar and the hold of the agents use). */
  private criticalAgentsOpen(): boolean {
    if (this.agents === null) return false;
    return this.db.prepare(`SELECT 1 FROM agent_drifts WHERE status = 'open' AND class = 'critical' AND initial = 0 LIMIT 1`).get() !== undefined;
  }

  private sourceVerdict(req: DecideInput, ev: Evaluation | null, stopped: boolean): { pass: true; rights: Rights; detail: Record<string, unknown> } | { pass: false; note: string | null } {
    const no = (note: string | null) => ({ pass: false as const, note });
    if (stopped) return no(null); // the plugin's own check stopped this version for a human: its reason is in the queue already
    // A critical difference in the agents' settings is open: an agent that may be swapped must not carry a version of an "own" plugin through. Only a human's decision lets it in.
    if (this.criticalAgentsOpen()) return no("открыта критичная тревога по настройкам агентов: версии сами не проходят, пока вы её не разберёте");
    const mode = this.trustMode();
    const ident = identityOf(req.sourceKind, req.source);
    const { level, entry } = levelOf(ident, this.mySources(), this.trustCfg.known);
    if (mode === "strict") return no("режим «Строгий»: каждая версия ждёт вас");
    if (level === "unknown") return no(ident === null ? "источник нельзя назвать своим (не github и не каталог на диске)" : "неизвестный источник");
    if (ev === null) return no("права версии не посчитаны");
    if (!ev.ok) return no(ev.reason);
    if (ev.hash !== req.contentHash) return no("хеш каталога не совпал с хешем из запроса");
    const base = this.db
      .prepare(`SELECT * FROM approvals WHERE plugin_id = ? AND source_id = ? AND revoked_at IS NULL AND rights IS NOT NULL ORDER BY id DESC LIMIT 1`)
      .get(req.pluginId, ident!.id) as Raw | undefined;
    if (!base) return no("нет одобренной версии этого плагина из этого источника");
    if (ev.blocks.length > 0) return no(`жёсткий флаг: ${brief(ev.blocks)}`);
    const baseline = approvalOf(base);
    const g = grown(baseline.rights!, ev.rights);
    if (g.tokens.length > 0) return no(`новое право: ${brief(g.tokens)}`);
    if (g.review.length > 0) return no(`новое замечание проверок: ${brief(g.review)}`);
    const levelText = level === "own" ? "свой источник" : "известный источник";
    return { pass: true, rights: ev.rights, detail: { why: `прошла сама: ${levelText}, права те же`, level, entry, mode, baseline: { approval: baseline.id, version: baseline.version, source: baseline.sourceId }, rights: ev.rights.tokens.length } };
  }

  /** Read-only: is this version approved, is a window open, what is its queue entry. For the plugin's own hook. */
  lookup(raw: Record<string, unknown>): {
    approved: boolean;
    /** Who approved it: a window approval is the one a hook that holds the version for its own reasons withdraws (revoke, no code). */
    approval: { id: number; via: string; windowId: number | null } | null;
    window: { id: number; expiresAt: number; hardExpiresAt: number; mode: string; sizeSec: number } | null;
    requestId: number | null;
    /** Troubleshooting mode is on until this time (the plugin's hook passes too, and says so); 0: off. */
    troubleshootUntil: number;
    /** The person rejected this version and has not brought it back. */
    rejected: boolean;
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
      troubleshootUntil: this.troubleshootUntil(),
      rejected: a === null && this.isRejected(pluginId, contentHash),
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

  /** A held entry, or (when `orRejected`) one the person rejected: «Вернуть» approves it with a touch. */
  private heldRequest(id: number, orRejected = false): QueueRow {
    const row = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(id) as Raw | undefined;
    if (!row) throw new GuardError("not_found", `no request #${id}`);
    const q = queueOf(row);
    if (q.status !== "held" && !(orRejected && q.status === "dismissed")) throw new GuardError("conflict", `request #${id} is already ${q.status}`);
    return q;
  }

  /**
   * What the guard itself refuses about lifting a stop, before any touch is spent: a hash that did not match is never approved (the request may be about
   * other code than the directory shows), and in Strict mode nothing is lifted. `acknowledgeBlock` is the page's word for "I accept the risk".
   */
  private assertLiftable(q: QueueRow, acknowledgeBlock: boolean): void {
    if (isMismatchNote(q.note)) throw new GuardError("invalid", "the directory's hash did not match the request's: this version is never approved, with or without acknowledgeBlock (reinstall the plugin from its source)");
    if (acknowledgeBlock && this.trustMode() === "strict") throw new GuardError("invalid", "режим «Строгий»: остановку обойти нельзя (acknowledgeBlock отклонён сторожем); сначала ослабьте режим касанием");
    if (isHardFlagNote(q.note) && !acknowledgeBlock) throw new GuardError("invalid", "this version has a hard flag: it is approved only with acknowledgeBlock and a fresh touch (a session does not cover it)");
  }

  /**
   * Approves a held version with a touch (a session also covers it, unless `acknowledgeBlock` lifts a stop: that is always a fresh touch, and
   * never in Strict mode). The code is checked first, in the same transaction as the approval.
   */
  approve(raw: Record<string, unknown>): { approval: ApprovalRow } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    if (raw.acknowledgeBlock !== undefined && typeof raw.acknowledgeBlock !== "boolean") throw new GuardError("invalid", "acknowledgeBlock is true or false");
    const ack = raw.acknowledgeBlock === true;
    const q = this.heldRequest(id, true);
    this.assertLiftable(q, ack);
    const factor = this.verifyFactor(`approve:${q.pluginId}`, this.normalizeAction({ op: "approve", requestId: id, ...(ack ? { acknowledgeBlock: true } : {}) }), raw);
    return this.tx(() => {
      const a = this.addApproval({ contentHash: q.contentHash, pluginId: q.pluginId, version: q.version, source: q.source, sourceKind: q.sourceKind, gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, rights: q.rights, why: touchWhy(q.note) });
      this.resolveQueue(q.pluginId, q.contentHash, "approved");
      // The record says what exactly was approved: after the fact, this is what the owner reads.
      this.log("approved.touch", q.pluginId, q.contentHash, { approval: a.id, review: q.id, version: q.version, source: q.source, sourceKind: q.sourceKind, rootDir: q.rootDir, ...(ack ? { acknowledgeBlock: true } : {}), ...factorDetail(factor) });
      return { approval: a };
    });
  }

  /**
   * «Вернуть и доверять источнику»: ONE operation, ONE touch, ONE journal record — the version is approved and its source (as the guard names it
   * from the queue entry, not from the request) goes into "my sources". Never a session (adding a source is always a fresh touch), never a stop.
   */
  approveAndTrust(raw: Record<string, unknown>): { approval: ApprovalRow; entry: string; mySources: string[] } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    const q = this.heldRequest(id, true);
    this.assertLiftable(q, false);
    if (isHardFlagNote(q.note)) throw new GuardError("invalid", "a version with a hard flag cannot be returned together with trusting its source");
    const action = this.normalizeAction({ op: "approve-trust", requestId: id });
    const entry = action.entry as string;
    const cur = this.mySources();
    if (!cur.includes(entry) && cur.length + 1 > MAX_SOURCES) throw new GuardError("invalid", `at most ${MAX_SOURCES} sources`);
    const factor = this.verifyFactor(`approve-trust:${q.pluginId}`, action, raw);
    return this.tx(() => {
      const a = this.addApproval({ contentHash: q.contentHash, pluginId: q.pluginId, version: q.version, source: q.source, sourceKind: q.sourceKind, gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, rights: q.rights, why: touchWhy(q.note) });
      this.resolveQueue(q.pluginId, q.contentHash, "approved");
      const next = cur.includes(entry) ? cur : [...cur, entry].sort();
      this.setMeta("my_sources", JSON.stringify(next));
      this.log("approved.trust", q.pluginId, q.contentHash, { approval: a.id, review: q.id, version: q.version, source: q.source, sourceKind: q.sourceKind, rootDir: q.rootDir, trustedSource: entry, sourceWasTrusted: cur.includes(entry), ...factorDetail(factor) });
      return { approval: a, entry, mySources: next };
    });
  }

  // ---- batch: the list is fixed here before the touch ---------------------------------------------------------------------
  private batchHash(items: Array<{ kind: string; id: number; fingerprint: string }>): string {
    const canon = items.map((i) => [i.kind, i.id, i.fingerprint] as const).sort((a, b) => (a[0] === b[0] ? a[1] - b[1] : a[0] < b[0] ? -1 : 1));
    return sha256hex(JSON.stringify(canon));
  }
  /** What a held version is right now, as the guard sees it: if any part differs when the touch arrives, the version is not approved. */
  private queueFingerprint(q: QueueRow): string {
    const stop = (this.db.prepare(`SELECT stop FROM queue WHERE id = ?`).get(q.id) as { stop: number } | undefined)?.stop ?? 0;
    return sha256hex(JSON.stringify([q.pluginId, q.version, q.contentHash, q.source, q.sourceKind, q.rootDir, stop]));
  }

  /**
   * `batch-prepare {items: [{kind, id, fingerprint?, label?}]}`: fixes the list. `queue` items are the guard's own held versions: the guard computes
   * their fingerprint and label itself (what the caller says about them is ignored), and leaves out the ones that cannot go into a list (a hash that did
   * not match, a hard flag: blocks are lifted one by one). `skill` and `drift` items belong to the plugin: the guard keeps what the plugin said about
   * them, only to bind the touch to them. Nothing is approved here.
   */
  batchPrepare(raw: Record<string, unknown>): { batchId: string; setHash: string; expiresAt: number; items: Array<{ kind: string; id: number; label: string; fingerprint: string }>; skipped: Array<{ kind: string; id: number; reason: string }> } {
    if (!Array.isArray(raw.items) || raw.items.length === 0 || raw.items.length > MAX_BATCH_ITEMS) throw new GuardError("invalid", `items is a list of 1..${MAX_BATCH_ITEMS} entries`);
    const seen = new Set<string>();
    const items: Array<{ kind: string; id: number; label: string; fingerprint: string }> = [];
    const skipped: Array<{ kind: string; id: number; reason: string }> = [];
    for (const r of raw.items as unknown[]) {
      if (typeof r !== "object" || r === null || Array.isArray(r)) throw new GuardError("invalid", "an item is an object");
      const it = r as Record<string, unknown>;
      if (it.kind !== "queue" && it.kind !== "skill" && it.kind !== "drift") throw new GuardError("invalid", "kind is queue, skill or drift");
      const id = intOf(it.id, "id", 1, Number.MAX_SAFE_INTEGER);
      if (seen.has(`${it.kind}:${id}`)) continue;
      seen.add(`${it.kind}:${id}`);
      if (it.kind === "queue") {
        const row = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(id) as Raw | undefined;
        const q = row ? queueOf(row) : null;
        if (!q || q.status !== "held") skipped.push({ kind: "queue", id, reason: "уже не ждёт решения" });
        else if (isMismatchNote(q.note)) skipped.push({ kind: "queue", id, reason: "хеш не совпал: одобрить нельзя" });
        else if (isHardFlagNote(q.note)) skipped.push({ kind: "queue", id, reason: "жёсткий флаг: снимается отдельно, свежим касанием" });
        else items.push({ kind: "queue", id, label: `${q.pluginId}@${q.version}`, fingerprint: this.queueFingerprint(q) });
      } else {
        items.push({ kind: it.kind, id, label: str(it.label ?? `${it.kind} #${id}`, "label", 200), fingerprint: str(it.fingerprint, "fingerprint", 128, 1) });
      }
    }
    if (items.length === 0) throw new GuardError("invalid", `nothing in the list can be approved together${skipped.length > 0 ? `: ${skipped.map((s) => `${s.kind} #${s.id} — ${s.reason}`).join("; ")}` : ""}`);
    const setHash = this.batchHash(items);
    return this.tx(() => {
      const now = this.now();
      this.db.prepare(`DELETE FROM batches WHERE expires_at < ? OR used_at IS NOT NULL AND used_at < ?`).run(now, now - HOUR_MS);
      if ((this.db.prepare(`SELECT COUNT(*) AS n FROM batches WHERE used_at IS NULL`).get() as { n: number }).n >= MAX_PENDING_BATCHES) throw new GuardError("conflict", "too many lists are waiting; use or let them expire first");
      const batchId = randomBytes(12).toString("hex");
      const expiresAt = now + BATCH_TTL_MS;
      this.db.prepare(`INSERT INTO batches (id, set_hash, items, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`).run(batchId, setHash, JSON.stringify(items), now, expiresAt);
      this.log("batch.prepare", null, null, { batch: batchId, setHash, items: items.map((i) => `${i.kind}#${i.id}`) });
      return { batchId, setHash, expiresAt, items, skipped };
    });
  }

  private loadBatch(raw: Record<string, unknown>): { id: string; setHash: string; items: Array<{ kind: string; id: number; label: string; fingerprint: string }> } {
    const id = str(raw.batchId, "batchId", 64, 1);
    const shown = str(raw.setHash, "setHash", 64, 64);
    const row = this.db.prepare(`SELECT * FROM batches WHERE id = ?`).get(id) as Raw | undefined;
    if (!row) throw new GuardError("not_found", "no such list; prepare it again");
    if (row.used_at !== null) throw new GuardError("conflict", "this list was already approved");
    if (this.now() >= Number(row.expires_at)) throw new GuardError("conflict", "the list expired; prepare it again");
    const items = JSON.parse(String(row.items)) as Array<{ kind: string; id: number; label: string; fingerprint: string }>;
    // What the person saw (the hash they confirm), what is stored, and what the stored items add up to: all the same, or nothing.
    if (shown !== String(row.set_hash) || this.batchHash(items) !== String(row.set_hash)) throw new GuardError("conflict", "the list does not match the one that was shown; prepare it again");
    return { id, setHash: String(row.set_hash), items };
  }

  /**
   * `batch-approve {batchId, setHash, code | passkey | session}`: ONE touch for the whole stored list (the touch names the list's id and hash, never items;
   * a passkey signature is bound to that pair). Each `queue` item is approved only if it is still what it was when the list was shown. `skill` and
   * `drift` items are returned as `local`: the plugin approves its own, now that the touch was accepted.
   */
  batchApprove(raw: Record<string, unknown>): { results: Array<{ kind: string; id: number; label: string; ok: boolean; local: boolean; note: string }> } {
    const b = this.loadBatch(raw);
    const factor = this.verifyFactor("batch.approve", this.normalizeAction({ op: "batch-approve", batchId: b.id, setHash: b.setHash }), raw);
    return this.tx(() => {
      const spent = this.db.prepare(`UPDATE batches SET used_at = ? WHERE id = ? AND used_at IS NULL`).run(this.now(), b.id);
      if (Number(spent.changes) !== 1) throw new GuardError("conflict", "this list was already approved");
      this.log("batch.approve", null, null, { batch: b.id, setHash: b.setHash, items: b.items.map((i) => `${i.kind}#${i.id}`), ...factorDetail(factor) });
      const results: Array<{ kind: string; id: number; label: string; ok: boolean; local: boolean; note: string }> = [];
      for (const it of b.items) {
        if (it.kind !== "queue") {
          results.push({ kind: it.kind, id: it.id, label: it.label, ok: true, local: true, note: "касание принято; одобряет плагин" });
          continue;
        }
        const row = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(it.id) as Raw | undefined;
        const q = row ? queueOf(row) : null;
        if (!q || q.status !== "held" || this.queueFingerprint(q) !== it.fingerprint || isMismatchNote(q.note) || isHardFlagNote(q.note)) {
          results.push({ kind: "queue", id: it.id, label: it.label, ok: false, local: false, note: "изменилось после показа списка: не одобрено, посмотрите заново" });
          continue;
        }
        const a = this.addApproval({ contentHash: q.contentHash, pluginId: q.pluginId, version: q.version, source: q.source, sourceKind: q.sourceKind, gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, rights: q.rights, why: touchWhy(q.note) });
        this.resolveQueue(q.pluginId, q.contentHash, "approved");
        this.log("approved.touch", q.pluginId, q.contentHash, { approval: a.id, review: q.id, version: q.version, source: q.source, sourceKind: q.sourceKind, rootDir: q.rootDir, batch: b.id, ...factorDetail(factor) });
        results.push({ kind: "queue", id: it.id, label: it.label, ok: true, local: false, note: "одобрено" });
      }
      return { results };
    });
  }

  // ---- troubleshooting mode (console + a code; the guard has no off switch) ----------------------------------------------------
  /** Until when the guard passes everything and writes every decision down; 0: off. */
  troubleshootUntil(): number {
    const until = Number(this.meta("troubleshoot_until") ?? 0);
    return until > this.now() ? until : 0;
  }
  /**
   * Console only (there is no op for it on the socket): a code is spent, the guard passes everything for `minutes`, writes each decision into the
   * journal and returns by itself. It does not switch the guard off: approvals, windows, touches and the journal work as always.
   */
  troubleshootStart(minutes: unknown, code: unknown): { until: number; minutes: number } {
    const m = intOf(minutes, "minutes", 1, MAX_TROUBLESHOOT_MIN);
    this.verifyCode("troubleshoot", code);
    return this.tx(() => {
      const until = this.now() + m * 60_000;
      this.setMeta("troubleshoot_until", String(until));
      this.troubleshootPasses = [];
      this.log("troubleshoot.start", null, null, { minutes: m, until, via: "console" });
      return { until, minutes: m };
    });
  }
  /** Console only: back to normal now. Tightening: no code. */
  troubleshootStop(): boolean {
    return this.tx(() => {
      if (this.troubleshootUntil() === 0) return false;
      this.setMeta("troubleshoot_until", "0");
      this.log("troubleshoot.end", null, null, { reason: "stopped", via: "console" });
      return true;
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
    for (const r of this.db.prepare(`SELECT id, expires_at, hard_expires_at FROM sessions WHERE closed_at IS NULL`).all() as Array<{ id: number; expires_at: number; hard_expires_at: number }>) {
      if (now < Number(r.expires_at) && now < Number(r.hard_expires_at)) continue;
      this.closeSessionInner(Number(r.id), "expired");
      n++;
    }
    this.flushPasskeyFails("", {}, true);
    // Troubleshooting mode returns by itself.
    const until = Number(this.meta("troubleshoot_until") ?? 0);
    if (until > 0 && until <= now) {
      this.setMeta("troubleshoot_until", "0");
      this.log("troubleshoot.end", null, null, { reason: "expired", at: until });
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

  /** Console (`setup`): the id of the newest journal record, so that a later look can ask only for what happened after. */
  lastJournalId(): number {
    return Number((this.db.prepare(`SELECT COALESCE(MAX(id), 0) AS n FROM journal`).get() as { n: number }).n);
  }
  /**
   * Console (`setup`): the touches for `purpose` that were made by a PASSKEY after journal record `sinceId`, newest first. Only a signature counts: a code
   * passes through bb and could be spent by anything in it, a signature over this action could not.
   */
  passkeyTouches(purpose: string, sinceId = 0): Array<{ id: number; ts: number; key: string }> {
    const rows = this.db.prepare(`SELECT id, ts, detail FROM journal WHERE kind = 'touch' AND id > ? ORDER BY id DESC LIMIT 200`).all(sinceId) as Raw[];
    const out: Array<{ id: number; ts: number; key: string }> = [];
    for (const r of rows) {
      const d = JSON.parse(String(r.detail ?? "null")) as { purpose?: unknown; via?: unknown; key?: unknown } | null;
      if (d && d.purpose === purpose && d.via === "passkey" && typeof d.key === "string") out.push({ id: Number(r.id), ts: Number(r.ts), key: d.key });
    }
    return out;
  }
  /** Active keys, for the console. */
  activeKeys(): PasskeyRow[] {
    return this.listPasskeys().filter((k) => k.state === "active");
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
        if (a.acknowledgeBlock !== undefined && typeof a.acknowledgeBlock !== "boolean") throw new GuardError("invalid", "acknowledgeBlock is true or false");
        return { op: "approve", requestId: intOf(a.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER), ...(a.acknowledgeBlock === true ? { acknowledgeBlock: true } : {}) };
      case "approve-trust": {
        // The source comes from the queue entry, never from the caller: a touch for "trust THIS" is for what the guard names.
        const id = intOf(a.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
        const q = this.heldRequest(id);
        const ident = identityOf(q.sourceKind, q.source);
        const entry = ident === null ? null : normalizeEntry(ident.id);
        if (entry === null) throw new GuardError("invalid", "this version's source cannot be put into \"my sources\" (not github and not a directory on disk)");
        return { op: "approve-trust", requestId: id, entry };
      }
      case "session-open":
        return a.hour === true ? { op: "session-open", hour: true } : { op: "session-open" };
      case "batch-approve":
        return { op: "batch-approve", batchId: str(a.batchId, "batchId", 64, 1), setHash: str(a.setHash, "setHash", 64, 64) };
      case "open-window": {
        const scope = a.scope;
        if (scope !== undefined && scope !== "tree" && scope !== "thread") throw new GuardError("invalid", "scope is tree or thread");
        return { op: "open-window", pluginId: pluginIdOf(a.pluginId), minutes: a.minutes === undefined ? this.policy().windowMin : intOf(a.minutes, "minutes", 1, 1440), ...(scope !== undefined ? { scope } : {}), ...(this.criticalAgentsOpen() ? { alarm: true } : {}) };
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
      case "trust-mode":
        if (typeof a.mode !== "string" || !TRUST_MODES.includes(a.mode as TrustMode)) throw new GuardError("invalid", "mode is simple, detailed or strict");
        return { op: "trust-mode", mode: a.mode };
      case "sources-add":
        return { op: "sources-add", entries: this.entriesOf(a.entries) };
      case "agents-accept":
        return { op: "agents-accept", ids: this.agentIds(a.ids) };
      // Only the id: what is written comes from the guard's own baseline, never from the action.
      case "agents-restore":
        return { op: "agents-restore", id: intOf(a.id, "id", 1, Number.MAX_SAFE_INTEGER) };
      // One part of a settings file. `danger` is what the caller says; it is checked against the guard's own reading before anything is signed or spent.
      case "agents-keep-part": {
        const id = intOf(a.id, "id", 1, Number.MAX_SAFE_INTEGER);
        const partId = str(a.partId, "partId", 16, 16);
        const fileSha = str(a.fileSha, "fileSha", 16, 16);
        if (typeof a.danger !== "boolean") throw new GuardError("invalid", "danger is true or false");
        const { part, danger } = this.partOf(id, partId, fileSha);
        if (part && (danger !== null) !== a.danger) throw new GuardError("conflict", "the part is not what the page showed: look again");
        return { op: "agents-keep-part", id, partId, fileSha, danger: a.danger };
      }
      // «Вернуть» / «Отозвать»: a touch only when the RESULT makes the agent more dangerous (the guard looks at what the file would say, not at the button's name).
      case "agents-rollback-part":
        return { op: "agents-rollback-part", id: intOf(a.id, "id", 1, Number.MAX_SAFE_INTEGER), partId: str(a.partId, "partId", 16, 16), fileSha: str(a.fileSha, "fileSha", 16, 16) };
      case "agents-revoke-kept":
        return { op: "agents-revoke-kept", id: intOf(a.id, "id", 1, Number.MAX_SAFE_INTEGER) };
      default:
        throw new GuardError("invalid", "an action is approve, approve-trust, session-open, batch-approve, open-window, policy, touch, trust-mode, sources-add, agents-accept, agents-restore, agents-keep-part, agents-rollback-part or agents-revoke-kept");
    }
  }

  /** The sentence the page shows next to the touch button (in the journal after the fact too): what is about to be approved, in the guard's own words. */
  private describe(a: Record<string, unknown>): string {
    switch (a.op) {
      case "approve": {
        const q = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(Number(a.requestId)) as Raw | undefined;
        if (!q) throw new GuardError("not_found", `no request #${String(a.requestId)}`);
        if (q.status !== "held") throw new GuardError("conflict", `request #${String(a.requestId)} is already ${String(q.status)}`);
        return `${a.acknowledgeBlock === true ? "СНЯТЬ ОСТАНОВКУ и одобрить" : "Одобрить"} загрузку плагина «${String(q.plugin_id)}» версии ${String(q.version)} (запись #${String(q.id)}, источник ${String(q.source)}, хеш ${String(q.content_hash).slice(0, 16)}…)${a.acknowledgeBlock === true ? ": версию остановили проверки, вы берёте риск на себя" : ""}`;
      }
      case "approve-trust": {
        const q = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(Number(a.requestId)) as Raw | undefined;
        if (!q) throw new GuardError("not_found", `no request #${String(a.requestId)}`);
        return `Одобрить версию ${String(q.version)} плагина «${String(q.plugin_id)}» (запись #${String(q.id)}, хеш ${String(q.content_hash).slice(0, 16)}…) И добавить источник ${String(a.entry)} в «мои источники»: новые версии оттуда будут проходить без вопросов, пока плагин не попросит новых прав`;
      }
      case "session-open":
        if (a.hour === true) return `Открыть сессию подтверждения на ${SESSION_CAP_MS / 60_000} мин подряд (не продлевается). Рутину (одобрить версию, открыть окно, принять расхождение, одобрить скилл, пакет) она покрывает без касания; опасное — всегда со свежим касанием`;
        return `Открыть сессию подтверждения: ${SESSION_IDLE_MS / 60_000} мин скользящие, потолок ${SESSION_CAP_MS / 60_000} мин. Рутину (одобрить версию, открыть окно, принять расхождение, одобрить скилл, пакет) она покрывает без касания; опасное — всегда со свежим касанием`;
      case "batch-approve": {
        const row = this.db.prepare(`SELECT * FROM batches WHERE id = ? AND used_at IS NULL`).get(String(a.batchId)) as Raw | undefined;
        if (!row || String(row.set_hash) !== String(a.setHash)) throw new GuardError("not_found", "no such list (or it does not match the hash)");
        const items = JSON.parse(String(row.items)) as Array<{ kind: string; label: string }>;
        return `Одобрить пакетом ${items.length} ${items.length === 1 ? "элемент" : "элементов"} одним касанием (список зафиксирован у сторожа, хеш ${String(a.setHash).slice(0, 12)}…): ${items.slice(0, 8).map((i) => i.label).join("; ")}${items.length > 8 ? ` и ещё ${items.length - 8}` : ""}`;
      }
      case "open-window":
        return `Открыть окно доверия для плагина «${String(a.pluginId)}» на ${String(a.minutes)} мин${a.scope === "tree" ? " (охват: весь тред со всеми сабтредами)" : a.scope === "thread" ? " (охват: только этот тред)" : ""}${a.alarm === true ? ": ВНИМАНИЕ — в настройках агентов открыта критичная тревога, агент мог быть подменён; окно пропустит любые версии этого плагина без касания" : ": любые версии этого плагина будут загружаться без касания"}`;
      case "policy": {
        const cur = this.policy();
        const parts = Object.entries(a.patch as Record<string, unknown>).map(([k, v]) => `${k}: ${String(cur[k as keyof Policy])} → ${String(v)}`);
        return `Изменить политику окон доверия: ${parts.join(", ") || "без изменений"}`;
      }
      case "trust-mode": {
        const names: Record<TrustMode, string> = { simple: "Простой", detailed: "Подробный", strict: "Строгий" };
        return `Сменить режим доверия: «${names[this.trustMode()]}» → «${names[a.mode as TrustMode]}»${MODE_RANK[a.mode as TrustMode] < MODE_RANK[this.trustMode()] ? " (слабее: больше версий будет проходить без вопросов)" : ""}`;
      }
      case "sources-add":
        return `Добавить в «мои источники»: ${(a.entries as string[]).join(", ")}. Новые версии плагинов оттуда будут проходить без вопросов, если права те же, что у одобренной версии из того же источника, и нет жёстких флагов`;
      case "agents-accept": {
        if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
        const rows = this.openDrifts(a.ids as number[]);
        this.criticalAlone(rows);
        const by = (c: string): number => rows.filter((r) => String(r.class) === c).length;
        const first = rows.filter((r) => Number(r.initial) === 1).length;
        const list = rows.slice(0, 5).map((r) => `${String(r.path)} (${String(r.change)}, ${String(r.class)})`).join("; ");
        return `${first === rows.length ? "Первый эталон: принять всё как есть — " : ""}Принять в эталон наблюдателя за конфигурациями и памятью агентов ${rows.length} расхождений (критичных ${by("critical")}, инструкций ${by("instructions")}, прочих ${by("other")}): ${list}${rows.length > 5 ? ` и ещё ${rows.length - 5}` : ""}`;
      }
      case "agents-keep-part": {
        const { part, path } = this.partOf(Number(a.id), String(a.partId), String(a.fileSha));
        return `Оставить в настройках агента (${path}): ${this.partSentence(part)}. Это войдёт в одобренные настройки; остальное в файле решается отдельно${a.danger === true ? ". Это делает агента опаснее: нужно свежее касание" : ""}`;
      }
      case "agents-rollback-part": {
        const { part, path } = this.partOf(Number(a.id), String(a.partId), String(a.fileSha));
        return `Вернуть в настройках агента (${path}): ${this.partSentence(part)}. Это ослабляет агента (${rollbackDanger(part) ?? "?"}): нужно свежее касание`;
      }
      case "agents-revoke-kept": {
        const k = this.db.prepare(`SELECT * FROM agent_kept WHERE id = ? AND revoked_at IS NULL`).get(Number(a.id)) as Raw | undefined;
        if (!k) throw new GuardError("not_found", `no kept change #${String(a.id)}`);
        const part = JSON.parse(String(k.part)) as JsonPart;
        return `Отозвать оставленное в настройках агента (${String(k.path)}): ${this.partSentence(part)}. Отзыв ослабляет агента (${rollbackDanger(part) ?? "?"}): нужно свежее касание`;
      }
      case "agents-restore": {
        if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
        const [r] = this.openDrifts([Number(a.id)]);
        const plan = this.restorePlan(r!);
        if (!plan.ok) throw new GuardError("no_restore", plan.reason);
        return `Вернуть настройки агента как было: ${String(r!.path)} — ${plan.action === "delete" ? "файл будет удалён (в одобренных настройках его нет)" : plan.action === "json" ? `в общем файле состояния будут возвращены только разделы MCP-серверов (${plan.ops!.length}) в том виде, в каком вы их одобряли; остальное в файле не трогается` : `файл будет записан ровно в том виде, в каком вы его одобряли (хеш ${plan.sha.slice(0, 16)}…)`}. Содержимое берёт сам сторож из своих одобренных настроек; сразу после отката он просмотрит файл заново`;
      }
      case "touch":
        if (a.purpose === SETUP_CHECK_PURPOSE) return "Проверка касания при настройке: ничего не одобряется и не меняется, в журнал сторожа ляжет запись «касание сработало»";
        return `Подтвердить действие плагина secure-bb: ${String(a.purpose)}`;
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
   * not counted) → everything the signature covers (counted, on the counter of signatures: not the one of codes) → the challenge is spent in one transaction with the key's counter.
   */
  private verifyPasskey(purpose: string, action: Record<string, unknown>, assertion: unknown): Factor {
    if (this.activePasskeys().length === 0) throw new GuardError("not_registered", "no passkey is registered; run `sbb-guard passkey-enroll` on the console");
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
      this.db.prepare(`INSERT INTO attempts (ts, ok, purpose, kind) VALUES (?, 1, ?, 'passkey')`).run(this.now(), purpose);
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
      rejected: r.rejected_at !== null && r.rejected_at !== undefined,
      rejectedAt: r.rejected_at === null || r.rejected_at === undefined ? null : Number(r.rejected_at),
      // What «Вернуть как было» would do, or why it cannot be done (the page shows the manual way then).
      ...(String(r.status) === "open" ? { restorable: ((p) => (p.ok ? { ok: true, action: p.action } : { ok: false, reason: p.reason }))(this.restorePlan(r)) } : {}),
      // A settings file's difference split by the path inside the JSON (null: it cannot be split; the whole file is the only choice).
      ...(String(r.status) === "open" ? { parts: this.partsOf(r)?.map(viewPart) ?? null } : {}),
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
      restoreConfigured: this.agents.restore !== undefined,
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
      kept: this.keptParts(),
    };
  }

  // ---- putting a file back (design: secure-bb-agent-rollback-design.md) ----------------------------------------------------------
  // The guard only reads the agents' files. Writing is the job of the restore helper (restore.ts), a service of the agents' user whose socket only
  // the guard's user reaches. What the helper is told to write is the guard's OWN baseline, chosen by the id of a difference — never anything the
  // caller sends. A touch is needed (a code or a passkey, a session does not cover it): a harmful process of the bb user must not be able to
  // roll the owner's lawful changes back again and again.

  /** What putting this difference back means, from the baseline; or why it cannot be done. */
  /**
   * `.claude.json` is Claude Code's own state file, rewritten all the time: only the sections the watch looks at (the MCP servers, top-level and per
   * project) are put back, each by its own key; the rest of the file is not touched. The values come from the baseline's view of the file.
   */
  private jsonPlan(d: Raw, path: string): RestorePlan {
    if (String(d.change) === "removed") return { ok: false, reason: "общий файл состояния агента (.claude.json) целиком не создаётся: вернуть можно только вручную" };
    // A file that appeared (nothing was approved): what is put back is "no MCP servers" — the same helper operation as for a changed file. The rest of the file
    // (Claude Code's own state) is not touched, and the file itself is neither created nor deleted by the helper.
    const added = String(d.change) === "added";
    const b = added ? undefined : (this.db.prepare(`SELECT * FROM agent_baseline WHERE path = ?`).get(path) as Raw | undefined);
    const base = added ? "{}" : ((b?.content as string | null | undefined) ?? null);
    if (!added && (!b || base === null || sha256hex(base) !== String(b.sha256))) return { ok: false, reason: "эталон разделов MCP этого файла не сохранён: вернуть можно только вручную" };
    const view = (t: string | null): { mcp: unknown; projects: Record<string, unknown> } | null => {
      try {
        const o = t === null ? null : (JSON.parse(t) as { mcpServers?: unknown; projects?: Record<string, { mcpServers?: unknown }> });
        if (typeof o !== "object" || o === null) return null;
        const projects: Record<string, unknown> = {};
        for (const [dir, p] of Object.entries(o.projects ?? {})) projects[dir] = p?.mcpServers;
        return { mcp: o.mcpServers ?? {}, projects };
      } catch {
        return null;
      }
    };
    const was = view(base);
    const now = view((d.new_content as string | null) ?? null);
    if (was === null || now === null) return { ok: false, reason: "файл не разобран как JSON: вернуть можно только вручную" };
    const isEmpty = (v: unknown): boolean => v === undefined || (typeof v === "object" && v !== null && Object.keys(v).length === 0);
    const ops: JsonOp[] = [];
    const add = (key: JsonKey, want: unknown, have: unknown): void => {
      if (stable(want ?? {}) === stable(have ?? {})) return;
      if (isEmpty(want)) ops.push({ key, value: null, sha: "0".repeat(64) });
      else ops.push({ key, value: want as Record<string, unknown>, sha: sha256hex(JSON.stringify(want)) });
    };
    add(["mcpServers"], was.mcp, now.mcp);
    for (const dir of new Set([...Object.keys(was.projects), ...Object.keys(now.projects)])) add(["projects", dir, "mcpServers"], was.projects[dir], now.projects[dir]);
    if (ops.length === 0) return { ok: false, reason: "в разделах MCP расхождения не видно (изменилась другая часть файла): вернуть можно только вручную" };
    if (ops.length > 50) return { ok: false, reason: "слишком много разделов для отката (больше 50): вернуть можно только вручную" };
    return { ok: true, action: "json", content: null, sha: added ? "0".repeat(64) : String(b!.sha256), ops };
  }

  private restorePlan(d: Raw): RestorePlan {
    if (this.agents === null || this.agents.restore === undefined) return { ok: false, reason: "помощник отката не настроен у сторожа: вернуть файл можно только вручную" };
    const home = this.agents.home.replace(/(.)\/+$/, "$1");
    const path = String(d.path);
    if (!path.startsWith(home + sep)) return { ok: false, reason: "файл лежит вне домашнего каталога агентов: помощник сюда не пишет, вернуть можно только вручную" };
    const rel = path.slice(home.length + 1).split(sep).join("/");
    if (rel === JSON_FILE) return this.jsonPlan(d, path);
    if (!watchedRel(rel)) return { ok: false, reason: "этот файл помощник не возвращает: вернуть можно только вручную" };
    if (String(d.change) === "added") return { ok: true, action: "delete", content: null, sha: String(d.new_sha ?? "0".repeat(64)) };
    const b = this.db.prepare(`SELECT * FROM agent_baseline WHERE path = ?`).get(path) as Raw | undefined;
    if (!b) return { ok: false, reason: "в одобренных настройках нет эталона этого файла: возвращать нечего" };
    const content = (b.content as string | null) ?? null;
    if (content === null) return { ok: false, reason: "эталонного содержимого нет: файл больше лимита хранения (256 КБ), сторож помнит только его хеш. Вернуть можно только вручную" };
    if (sha256hex(content) !== String(b.sha256)) return { ok: false, reason: "эталон хранит не файл целиком, а его вид или ссылку: точно воспроизвести его нельзя, вернуть можно только вручную" };
    return { ok: true, action: "write", content, sha: String(b.sha256) };
  }

  /**
   * «Вернуть как было»: a fresh touch, then the helper puts the baseline's file back (or removes a file the baseline does not have), then the file
   * is looked at again at once, so that the alarm goes by itself. Everything is in the journal: what was, what became, who touched.
   */
  async agentsRestore(raw: Record<string, unknown>): Promise<{ restored: true; action: "write" | "delete" | "json"; result: string; resolved: boolean; path: string; rel: string }> {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const socket = this.agents.restore?.socket;
    const id = intOf(raw.id, "id", 1, Number.MAX_SAFE_INTEGER);
    // Everything that can be checked without a code is checked first, so that a spent code is not wasted on a refusal.
    const [before] = this.openDrifts([id]);
    const plan0 = this.restorePlan(before!);
    if (!plan0.ok) throw new GuardError("no_restore", plan0.reason);
    if (!(await helperUp(socket!, this.agents.restore?.timeoutMs))) throw new GuardError("unavailable", "помощник отката не отвечает (служба sbb-restore не запущена или сокет недоступен): ничего не записано, код не потрачен");
    const factor = this.verifyFactor("agents.restore", this.normalizeAction({ op: "agents-restore", id }), raw);
    // The difference may have moved on while we waited for the helper: what is done is what the baseline says NOW, for a difference that is still open.
    const [d] = this.openDrifts([id]);
    const plan = this.restorePlan(d!);
    if (!plan.ok) throw new GuardError("no_restore", plan.reason);
    const path = String(d!.path);
    const timeoutMs = this.agents.restore?.timeoutMs;
    const detail: Record<string, unknown> = { drift: id, path, rel: String(d!.rel), kind: String(d!.kind), change: String(d!.change), class: String(d!.class), action: plan.action, was: d!.new_sha === null || d!.new_sha === undefined ? null : String(d!.new_sha).slice(0, 16), becomes: plan.action === "delete" ? null : plan.sha.slice(0, 16) };
    let ans: Awaited<ReturnType<typeof sendRestore>>;
    if (plan.action === "json") {
      // One section at a time, each by its own key and each from the baseline's view; the first refusal stops the rest.
      detail.sections = plan.ops!.map((o) => o.key.slice(1, -1).join("") || "mcpServers");
      ans = { ok: true, result: "written" };
      for (const o of plan.ops!) {
        ans = await sendRestore(socket!, o.value === null ? { op: "restore-json-key", path, key: o.key, sha256: o.sha, delete: true } : { op: "restore-json-key", path, key: o.key, sha256: o.sha, value: o.value }, timeoutMs);
        if (!ans.ok) break;
      }
    } else ans = await sendRestore(socket!, plan.action === "delete" ? { path, sha256: plan.sha, delete: true } : { path, sha256: plan.sha, content: plan.content! }, timeoutMs);
    if (!ans.ok) {
      this.tx(() => this.log("agents.restore.fail", null, null, { ...detail, error: ans.code, message: ans.message.slice(0, 200), ...factorDetail(factor) }));
      throw new GuardError(ans.code === "unavailable" ? "unavailable" : "restore_failed", ans.code === "unavailable" ? "помощник отката не ответил: файл не изменён" : `помощник отказал: ${ans.message}`);
    }
    // Looked at again at once (not at the pace of the timer).
    this.agentsScan({ force: true });
    const now = this.db.prepare(`SELECT status FROM agent_drifts WHERE id = ?`).get(id) as { status: string } | undefined;
    const resolved = now !== undefined && now.status !== "open";
    this.tx(() => this.log("agents.restore", null, null, { ...detail, result: ans.result, resolved, ...factorDetail(factor) }));
    return { restored: true, action: plan.action, result: ans.result, resolved, path, rel: String(d!.rel) };
  }

  // ---- parts of a settings file: «Оставить» (mine) and «Вернуть» (theirs) --------------------------------------------------------------
  /** The parts of an open difference of a settings file, from the guard's own baseline and the file it read; null when it cannot be split. */
  private partsOf(d: Raw): JsonPart[] | null {
    if (String(d.kind) !== "claude-settings" || String(d.status) !== "open" || String(d.change) === "removed") return null;
    const next = (d.new_content as string | null | undefined) ?? null;
    if (next === null) return null;
    const base = this.baselineText(d);
    return base === undefined ? null : splitSettings(base, next);
  }
  /** The text the owner approved for this file: null for a file that is new (nothing was approved); undefined: there is a baseline, but it is not whole (too large, or not the file's text). */
  private baselineText(d: Raw): string | null | undefined {
    if (String(d.change) === "added") return null;
    const b = this.db.prepare(`SELECT * FROM agent_baseline WHERE path = ?`).get(String(d.path)) as Raw | undefined;
    const base = (b?.content as string | null | undefined) ?? null;
    return b && base !== null && sha256hex(base) === String(b.sha256) ? base : undefined;
  }
  /**
   * One part of one open difference, found by the id the page named; the page's `fileSha` (the first 16 digits of the hash it was shown) must be the file's
   * now, otherwise the file changed between the showing and the action: a conflict, the page draws again.
   */
  private partOf(id: number, partId: string, fileSha: string): { drift: Raw; part: JsonPart; parts: JsonPart[]; danger: string | null; path: string } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const [d] = this.openDrifts([id]);
    if (d!.new_sha === null || String(d!.new_sha).slice(0, 16) !== fileSha) throw new GuardError("conflict", "the file changed since it was shown: look again");
    const parts = this.partsOf(d!);
    if (parts === null) throw new GuardError("no_restore", "этот файл нельзя разобрать по частям: вернуть или принять можно только целиком");
    const part = parts.find((p) => p.id === partId);
    if (!part) throw new GuardError("conflict", "this part is not in the difference any more: look again");
    return { drift: d!, part, parts, danger: partDanger(part), path: String(d!.path) };
  }
  /**
   * A difference of a settings file that is left with no part: the file says the same as the approved text, only written another way (a final newline,
   * the order of keys). Nothing is left to decide, so it is recorded as the approved text and closed — never an alarm that has nothing in it.
   */
  private settleSemantic(path: string): void {
    const d = this.db.prepare(`SELECT * FROM agent_drifts WHERE path = ? AND status = 'open'`).get(path) as Raw | undefined;
    if (!d) return;
    const parts = this.partsOf(d);
    if (parts === null || parts.length > 0) return;
    this.tx(() => {
      const now = this.now();
      this.db
        .prepare(`INSERT INTO agent_baseline (path, root, rel, kind, sha256, size, content, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET sha256 = excluded.sha256, size = excluded.size, content = excluded.content, accepted_at = excluded.accepted_at`)
        .run(String(d.path), String(d.root), String(d.rel), String(d.kind), String(d.new_sha), Number(d.new_size ?? 0), String(d.new_content), now);
      this.db.prepare(`UPDATE agent_drifts SET status = 'reverted', resolved_at = ? WHERE id = ?`).run(now, Number(d.id));
    });
  }
  /** The parts the owner kept and has not taken back: the list of exceptions. Values are for the screen (secrets hidden). */
  private keptParts(): Array<{ id: number; path: string; rel: string; keptAt: number; danger: string | null; part: PartView }> {
    const rows = this.db.prepare(`SELECT * FROM agent_kept WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 200`).all() as Raw[];
    return rows.map((r) => ({ id: Number(r.id), path: String(r.path), rel: String(r.rel), keptAt: Number(r.kept_at), danger: (r.danger as string | null) ?? null, part: viewPart(JSON.parse(String(r.part)) as JsonPart) }));
  }

  /**
   * «Отозвать» a part that was kept: it goes out of the file (the helper, for this one path) and out of the approved text. Tightening, so no code. What was kept
   * is only what the owner chose with a touch; taking it back needs none, as taking back a window or an approval needs none.
   */
  async agentsRevokeKept(raw: Record<string, unknown>): Promise<{ revoked: true; inFile: boolean }> {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const socket = this.agents.restore?.socket;
    if (socket === undefined) throw new GuardError("no_restore", "помощник отката не настроен у сторожа: вернуть можно только вручную");
    const id = intOf(raw.id, "id", 1, Number.MAX_SAFE_INTEGER);
    const k = this.db.prepare(`SELECT * FROM agent_kept WHERE id = ? AND revoked_at IS NULL`).get(id) as Raw | undefined;
    if (!k) throw new GuardError("not_found", `no kept change #${id}`);
    const part = JSON.parse(String(k.part)) as JsonPart;
    const path = String(k.path);
    if (!partRestorable(part)) throw new GuardError("no_restore", "эту часть помощник не возвращает: вернуть можно только вручную");
    if (!(await helperUp(socket, this.agents.restore?.timeoutMs))) throw new GuardError("unavailable", "помощник отката не отвечает (служба sbb-restore не запущена или сокет недоступен): ничего не записано");
    // Taking back a kept ban (deny, ask, the sandbox) weakens the agent: a fresh touch, as for any other weakening.
    const revokeDanger = rollbackDanger(part);
    const factor = revokeDanger === null ? null : this.verifyFactor("agents.revokeKept", this.normalizeAction({ op: "agents-revoke-kept", id }), raw);
    this.agentsScan({ force: true });
    // The file as the guard sees it now: the open difference's hash, or the approved one when the file is as approved.
    const open = this.db.prepare(`SELECT * FROM agent_drifts WHERE path = ? AND status = 'open'`).get(path) as Raw | undefined;
    const base = this.db.prepare(`SELECT * FROM agent_baseline WHERE path = ?`).get(path) as Raw | undefined;
    const fileSha = open ? (open.new_sha === null ? null : String(open.new_sha)) : base ? String(base.sha256) : null;
    const back = partAction(part, "rollback");
    let inFile = false;
    if (fileSha !== null) {
      const ans = await sendRestore(socket, { op: "restore-json-path", path, fileSha256: fileSha, pointer: part.path, action: back.action, ...(back.action === "delete" ? {} : { value: back.value }) }, this.agents.restore?.timeoutMs);
      if (!ans.ok) {
        this.tx(() => this.log("agents.revoke-kept.fail", null, null, { kept: id, path, part: part.path.join("."), error: ans.code, message: ans.message.slice(0, 200) }));
        if (ans.code === "stale") throw new GuardError("conflict", "the file changed since it was shown: look again");
        throw new GuardError(ans.code === "unavailable" ? "unavailable" : "restore_failed", ans.code === "unavailable" ? "помощник отката не ответил: файл не изменён" : `помощник отказал: ${ans.message}`);
      }
      inFile = ans.result !== "absent";
    }
    this.tx(() => {
      // Out of the approved text too, or the file (without it) would show as a difference of its own.
      if (base) {
        const text = (base.content as string | null) ?? null;
        if (text !== null && sha256hex(text) === String(base.sha256)) {
          const doc = ((): Record<string, unknown> | null => {
            try {
              const v = JSON.parse(text) as unknown;
              return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
            } catch {
              return null;
            }
          })();
          if (doc) {
            applyPathChange(doc, part.path, back.action, back.value);
            const next = `${JSON.stringify(doc, null, 2)}\n`;
            this.db.prepare(`UPDATE agent_baseline SET sha256 = ?, size = ?, content = ?, accepted_at = ? WHERE path = ?`).run(sha256hex(next), Buffer.byteLength(next, "utf8"), next, this.now(), path);
          }
        }
      }
      this.db.prepare(`UPDATE agent_kept SET revoked_at = ? WHERE id = ?`).run(this.now(), id);
      this.log("agents.revoke-kept", null, null, { kept: id, path, rel: String(k.rel), part: part.path.join("."), kind: part.kind, inFile, ...(factor ? factorDetail(factor) : {}) });
    });
    this.agentsScan({ force: true });
    this.settleSemantic(path);
    return { revoked: true, inFile };
  }

  private partSentence(p: JsonPart): string {
    const at = p.path.join(".");
    switch (p.kind) {
      case "elem-added":
        return `добавлено в ${at}: ${shownValue(p.path, p.elem)}`;
      case "elem-removed":
        return `убрано из ${at}: ${shownValue(p.path, p.elem)}`;
      case "key-added":
        return `${at} задан: ${shownValue(p.path, p.after)}`;
      case "key-removed":
        return `${at} убран (было ${shownValue(p.path, p.before)})`;
      case "key-changed":
        return `${at}: было ${shownValue(p.path, p.before)}, стало ${shownValue(p.path, p.after)}`;
    }
  }

  /**
   * «Вернуть» one part: the helper takes this one change out of the file and leaves the rest. Tightening (what comes back is the approved state), so no
   * code. Only a part of an OPEN difference, only on a path the helper edits, and only against the file the page showed (`fileSha`) — the helper checks
   * the hash of the whole file again, so that a change that came in between is never overwritten.
   */
  async agentsRollbackPart(raw: Record<string, unknown>): Promise<{ restored: true; resolved: boolean; remaining: number; path: string; rel: string }> {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const socket = this.agents.restore?.socket;
    if (socket === undefined) throw new GuardError("no_restore", "помощник отката не настроен у сторожа: вернуть можно только вручную");
    const id = intOf(raw.id, "id", 1, Number.MAX_SAFE_INTEGER);
    const partId = str(raw.partId, "partId", 16, 16);
    const fileSha = str(raw.fileSha, "fileSha", 16, 16);
    // The file as it is right now (not as it was at the last timer).
    this.agentsScan({ force: true });
    const { drift: d, part, danger } = this.partOf(id, partId, fileSha);
    if (!partRestorable(part)) throw new GuardError("no_restore", "эту часть помощник не возвращает: вернуть можно только весь файл");
    if (!(await helperUp(socket, this.agents.restore?.timeoutMs))) throw new GuardError("unavailable", "помощник отката не отвечает (служба sbb-restore не запущена или сокет недоступен): ничего не записано");
    // Without a code only a tightening: when the result makes the agent more dangerous (a rule the owner removed comes back, a ban goes), a fresh touch is needed.
    const backDanger = rollbackDanger(part);
    const factor = backDanger === null ? null : this.verifyFactor("agents.rollbackPart", this.normalizeAction({ op: "agents-rollback-part", id, partId, fileSha }), raw);
    const a = partAction(part, "rollback");
    const path = String(d.path);
    const fileSha256 = String(d.new_sha);
    const ans = await sendRestore(socket, { op: "restore-json-path", path, fileSha256, pointer: part.path, action: a.action, ...(a.action === "delete" ? {} : { value: a.value }) }, this.agents.restore?.timeoutMs);
    const detail = { drift: id, path, rel: String(d.rel), part: part.path.join("."), kind: part.kind, action: a.action, danger: danger !== null, backDanger: backDanger !== null, ...(factor ? factorDetail(factor) : {}), was: fileSha256.slice(0, 16) };
    if (!ans.ok) {
      this.tx(() => this.log("agents.rollback-part.fail", null, null, { ...detail, error: ans.code, message: ans.message.slice(0, 200) }));
      // The file is not the one the part was worked out from: nothing was written and the page draws again.
      if (ans.code === "stale") throw new GuardError("conflict", "the file changed since it was shown: look again");
      throw new GuardError(ans.code === "unavailable" ? "unavailable" : "restore_failed", ans.code === "unavailable" ? "помощник отката не ответил: файл не изменён" : `помощник отказал: ${ans.message}`);
    }
    this.agentsScan({ force: true });
    this.settleSemantic(path);
    // Resolved: nothing of this file is left to decide.
    const rest = this.db.prepare(`SELECT * FROM agent_drifts WHERE path = ? AND status = 'open'`).get(path) as Raw | undefined;
    const remaining = rest ? (this.partsOf(rest)?.length ?? 1) : 0;
    const resolved = rest === undefined;
    this.tx(() => this.log("agents.rollback-part", null, null, { ...detail, result: ans.result, resolved, remaining }));
    return { restored: true, resolved, remaining, path, rel: String(d.rel) };
  }

  /**
   * «Оставить» one part: it goes into the approved text of the file; the rest stays a difference. A touch: a code or a key for a part that makes the agent
   * more dangerous (bypass, a shell or network permission, a hook, `env`…), and for the rest a session is enough. Nothing is written to the agents' file.
   */
  agentsKeepPart(raw: Record<string, unknown>): { kept: true; accepted: boolean; remaining: number; danger: boolean } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const id = intOf(raw.id, "id", 1, Number.MAX_SAFE_INTEGER);
    const partId = str(raw.partId, "partId", 16, 16);
    const fileSha = str(raw.fileSha, "fileSha", 16, 16);
    this.agentsScan({ force: true });
    // Everything that can be checked without a code is checked first, so that a spent code is not wasted on a refusal.
    const first = this.partOf(id, partId, fileSha);
    const dangerous = first.danger !== null;
    if (raw.danger !== undefined && raw.danger !== dangerous) throw new GuardError("conflict", "the part is not what the page showed: look again");
    const factor = this.verifyFactor("agents.keepPart", this.normalizeAction({ op: "agents-keep-part", id, partId, fileSha, danger: dangerous }), raw);
    const result = this.tx(() => {
      // Again, inside the transaction: the difference may have moved while the code was being checked.
      const { drift: d, part, parts } = this.partOf(id, partId, fileSha);
      const base = this.baselineText(d);
      const approved = base === undefined ? null : applyForward(base, part);
      if (approved === null) throw new GuardError("no_restore", "этот файл нельзя разобрать по частям: принять можно только целиком");
      const now = this.now();
      const done = parts.length === 1;
      // The last part: the file as it is becomes the approved one (what is kept is exactly what was seen). Otherwise a new approved text with this part in it.
      const content = done ? String(d.new_content) : approved;
      const sha = done ? String(d.new_sha) : sha256hex(content);
      this.db
        .prepare(`INSERT INTO agent_baseline (path, root, rel, kind, sha256, size, content, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET root = excluded.root, rel = excluded.rel, kind = excluded.kind, sha256 = excluded.sha256, size = excluded.size, content = excluded.content, accepted_at = excluded.accepted_at`)
        .run(String(d.path), String(d.root), String(d.rel), String(d.kind), sha, Buffer.byteLength(content, "utf8"), content, now);
      // The old difference is closed; the next look at the file makes the difference that is left (or finds none).
      this.db.prepare(`UPDATE agent_drifts SET status = ?, resolved_at = ? WHERE id = ?`).run(done ? "accepted" : "superseded", now, id);
      this.db.prepare(`INSERT INTO agent_kept (path, rel, part, danger, kept_at) VALUES (?, ?, ?, ?, ?)`).run(String(d.path), String(d.rel), JSON.stringify(part), first.danger === null ? null : first.danger.slice(0, 300), now);
      this.log("agents.keep-part", null, null, { drift: id, path: String(d.path), rel: String(d.rel), part: part.path.join("."), kind: part.kind, danger: dangerous, reason: first.danger === null ? null : first.danger.slice(0, 200), remaining: parts.length - 1, ...factorDetail(factor) });
      return { accepted: done, remaining: parts.length - 1 };
    });
    // The file is looked at again at once: what is left of the difference is drawn from the new approved text.
    this.agentsScan({ force: true });
    this.settleSemantic(first.path);
    return { kept: true, accepted: result.accepted, remaining: result.remaining, danger: dangerous };
  }

  /**
   * «Это не я — отклонить»: marks open differences as rejected. Tightening, so no code: nothing goes into the baseline, the difference stays open
   * (the alarm, the polluted thread and the closed windows stay until the file itself is fixed), and the journal gets a record. The guard itself only reads the agents' files; putting one back is
   * «Вернуть как было» (`agentsRestore`, a touch), accepting is also possible later, with a touch.
   */
  agentsReject(raw: Record<string, unknown>): { rejected: number } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const ids = this.agentIds(raw.ids);
    return this.tx(() => {
      const rows = this.openDrifts(ids);
      const now = this.now();
      let n = 0;
      for (const r of rows) {
        if (r.rejected_at !== null && r.rejected_at !== undefined) continue;
        this.db.prepare(`UPDATE agent_drifts SET rejected_at = ? WHERE id = ?`).run(now, Number(r.id));
        n++;
      }
      this.log("agents.reject", null, null, { count: n, drifts: rows.slice(0, 50).map((r) => ({ id: Number(r.id), path: String(r.path), change: String(r.change), class: String(r.class) })) });
      return { rejected: n };
    });
  }

  /** Accepts differences into the baseline. A touch (a code or a passkey signature over exactly these ids), like `approve`. */
  agentsAccept(raw: Record<string, unknown>): { accepted: number } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const ids = this.agentIds(raw.ids);
    // Everything that can be checked without a code is checked first, so that a spent code is not wasted on a refusal.
    this.criticalAlone(this.openDrifts(ids));
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

  /**
   * A critical difference (bypassPermissions, Bash(*), an MCP server, a hook, a *_BASE_URL…) is accepted ALONE: never in one call with another
   * difference, so that "select all" cannot carry it in. It is also never covered by a session (`agents-accept` is not a routine action),
   * so every critical one takes its own fresh touch whose description names exactly it.
   */
  private criticalAlone(rows: Raw[]): void {
    if (rows.length > 1 && rows.some((r) => String(r.class) === "critical")) throw new GuardError("invalid", "a critical difference is accepted on its own, with its own fresh touch: not together with others");
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
      sessions: this.openSessions().map((r) => ({ id: Number(r.id), openedAt: Number(r.opened_at), expiresAt: Number(r.expires_at), hardExpiresAt: Number(r.hard_expires_at), uses: Number(r.uses) })),
      troubleshoot: this.troubleshootUntil() > 0 ? { until: this.troubleshootUntil() } : null,
      passkeys: {
        rpId: this.rp.rpId,
        origin: this.rp.origin,
        keys: this.listPasskeys()
          .filter((k) => k.state === "active")
          .map((k) => ({ id: k.id, label: k.label, createdAt: k.createdAt, lastUsedAt: k.lastUsedAt, aaguid: k.aaguid })),
        enrollmentOpen: this.openEnrollment() !== undefined,
      },
      policy: this.policy(),
      trust: this.trustState(),
      queue: rows(`SELECT * FROM queue ORDER BY (status = 'held') DESC, id DESC LIMIT 100`, queueOf).map(withNotes),
      approvals: rows(`SELECT * FROM approvals WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 500`, approvalOf),
      revoked: rows(`SELECT * FROM approvals WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC LIMIT 20`, approvalOf),
      windows: this.unclosedWindows()
        .filter((w) => now < w.expiresAt && now < w.hardExpiresAt)
        .map((w) => ({ ...w, remainingSec: Math.max(0, Math.floor((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000)) })),
      closedWindows: rows(`SELECT * FROM windows WHERE closed_at IS NOT NULL ORDER BY id DESC LIMIT 10`, windowOf),
      journal: {
        head: head ? { id: head.id, hash: head.hash } : null,
        recent: (this.db.prepare(`SELECT id, ts, kind, plugin_id, content_hash, detail FROM journal ORDER BY id DESC LIMIT 200`).all() as Raw[]).map((r) => ({
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
