// The vocabulary of the guard: its errors, the rows it reads from its database, the requests it parses, its options, and the numbers that name its limits.
// Types and small pure helpers only: no class, no state. Every layer of the guard (guard-base.ts … agents-apply.ts) imports from here.
import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { type RelyingParty } from "./config.ts";
import { sha256 } from "./passkey.ts";
import { type CheckResult } from "./checks/index.ts";
import { type TreeLimits } from "./tree-read.ts";
import { isReasonKind, parseRights, type ReasonKind, type Rights } from "./trust.ts";
import { type GuardPolicy } from "./policy.ts";
import { type Limits } from "./agents-scan.ts";
import { type JsonKey } from "./restore.ts";

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

/** A list for one touch lives this long; a few may wait at once. */
export const BATCH_TTL_MS = 10 * 60_000;

export const MAX_PENDING_BATCHES = 20;

export const MAX_BATCH_ITEMS = 50;

/** Troubleshooting mode: at most this long, and every decision is a journal record, so at most this many a minute (past it the guard holds again). */
export const MAX_TROUBLESHOOT_MIN = 240;

export const MAX_TROUBLESHOOT_PASSES_PER_MIN = 1000;

/** A queue entry older than the `reason_kind` column: the only place a note's words are still read (its kind was never written). Nothing newer is decided by words. */
export const legacyKindOfNote = (n: string | null): ReasonKind | null => (/не совпал с хешем/.test(n ?? "") ? "mismatch" : null);

export const sha256hex = (t: string): string => createHash("sha256").update(t, "utf8").digest("hex");

/** The window the console opens for registering a passkey, and how long a challenge lives. */
export const ENROLL_WINDOW_MS = 5 * 60_000;

/** The purpose of the touch that `sbb-guard setup` waits for (the page's «Проверить касание»): it changes nothing, it is only written into the journal. */
export const SETUP_CHECK_PURPOSE = "setup-check";

export const CHALLENGE_TTL_MS = 2 * 60_000;

export const MAX_OPEN_CHALLENGES = 200;

export const MAX_HOLDS_PER_HOUR = 200;

export const MAX_QUEUE_ROWS = 1000;

export const MAX_ANNOTATIONS = 500;

export const MAX_FINDINGS_BYTES = 64 * 1024;

export const MAX_ACCEPT_IDS = 2000;


/** The guard's own part of the policy; what widens it is in policy.ts. */
export type Policy = GuardPolicy;

/** The plugin's pulse is fresh for this long (it calls every 15 s). */
export const PLUGIN_ALIVE_MS = 45_000;

export const WINDOW_PAUSED_NOTE = "окно приостановлено: страница защиты не работает";

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
  /** The hard flags of the guard's own reading of the version; null: it was not read (a block may be there). Decides what may lift the hold. */
  blocks: string[] | null;
  /** Why it is held, as a fact (see trust.ts `REASON_KINDS`); null in an entry older than the column. */
  reasonKind: ReasonKind | null;
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
  /** "tree" / "thread": bound to a thread (only the plugin knows the threads); "all": any version of the plugin. A window older than the column is "thread". */
  scope: "tree" | "thread" | "all";
  /** The rights of the held version the window was opened from, as the guard read them; null when none was waiting. */
  baseRights: Rights | null;
}


export type Raw = Record<string, unknown>;

/** «касанием: <why the guard did not let it in by itself>» — the guard's note says it (new right, unknown source, strict mode…). */
export const touchWhy = (note: string | null): string => (note ? `касанием: ${note}` : "касанием: вы одобрили сами");

export const approvalOf = (r: Raw): ApprovalRow => ({
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

export const queueOf = (r: Raw): QueueRow => ({
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
  blocks: parseBlocks(r.blocks),
  reasonKind: isReasonKind(r.reason_kind) ? r.reason_kind : legacyKindOfNote((r.note as string | null) ?? null),
});

export function parseBlocks(v: unknown): string[] | null {
  if (typeof v !== "string") return null;
  try {
    const j = JSON.parse(v) as unknown;
    return Array.isArray(j) && j.every((x) => typeof x === "string") ? (j as string[]) : null;
  } catch {
    return null;
  }
}

export const windowOf = (r: Raw): WindowRow => ({
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
  scope: r.scope === "tree" || r.scope === "all" ? r.scope : "thread",
  baseRights: typeof r.base_rights === "string" ? (JSON.parse(r.base_rights) as Rights) : null,
});


// ---- input validation: every string that reaches the database or the journal is checked here ---------
export const PLUGIN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;


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
export type Evaluation = { ok: true; hash: string; rights: Rights; blocks: string[] } | { ok: false; reason: string; /** The directory's hash is not the request's. */ mismatch?: true };

export const MAX_CONCURRENT_EVALS = 2;

export const MAX_EVALS_PER_MINUTE = 30;

export const DEFAULT_BUDGET_MS = 3500;


export interface JsonOp {
  key: JsonKey;
  /** The baseline's value of the section; null: the section is not in the baseline, it is removed. */
  value: Record<string, unknown> | null;
  sha: string;
}

export type RestorePlan = { ok: true; action: "write" | "delete" | "json"; content: string | null; sha: string; ops?: JsonOp[] } | { ok: false; reason: string };


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

export const factorDetail = (f: Factor): Record<string, unknown> => ({ via: f.via, ...(f.key !== undefined ? { key: f.key } : {}), ...(f.sessionId !== undefined ? { session: f.sessionId } : {}), ...(f.action !== undefined ? { action: f.action } : {}) });


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
export type NewApproval = Omit<ApprovalRow, "id" | "approvedAt" | "revokedAt" | "sourceId" | "rights" | "why"> & { rights?: Rights | null; why?: string | null; /** Where the version is loaded from: a git source is named by it too (`identityOf`). */ rootDir?: string | null };

