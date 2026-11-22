// The vocabulary of the gate: what the core hands the hook (`HookCtx`), what the hook answers (`Decision`), what the gate is built from (`GateDeps`), the reasons it records, and the
// few numbers and pure helpers its layers share. No class, no state. Every layer (gate-base.ts … decide-hook.ts) imports from here.
import { type CheckResult } from "./checks/index.js";
import { capabilityTokens, rightsOf, type Rights } from "../guard/src/trust.ts";
import { type PermIssue } from "./perms.js";
import type { TaintAssessment } from "./taint/monitor.js";
import type { GuardPort } from "./guardlink.js";
import type { ThreadTree } from "./thread-tree.js";
import type { ApprovalRow, Store, WindowRow } from "./store.js";

/** The rights of a result for a comparison here: `rightsOf` stores at most 400 tokens (the guard's database), a comparison must see all of them, as it always did in the hook. */
export const fullRights = (r: Parameters<typeof rightsOf>[0]): Rights => ({ tokens: capabilityTokens(r), review: rightsOf(r).review });

export interface HookCtx {
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  gitCommit: string | null;
  npmIntegrity: string | null;
  rootDir: string;
  contentHash: string;
  trigger: string;
}

export type Decision =
  | { action: "proceed" }
  | { action: "wait"; reason: string }
  | { action: "reject"; message: string };


/** Hold reason for a snapshot whose files differ from what was proposed. */
export const TAMPERED_REASON = "снимок изменён после предложения";

/** Prefix of a queue entry's reason when the directory could be changed by someone other than the server's user: such a version cannot be approved. */
export const UNSAFE_DIR_REASON = "каталог доступен на запись другим";


export interface GateDeps {
  store: Store;
  now: () => number;
  threads: ThreadTree;
  /** Third-party plugins that are running now (their UI code shares our origin). */
  thirdPartyRunning: () => Promise<string[]>;
  /** Who keeps the approval session closed: running plugins not from «мои источники» and/or with an interface. Absent: every running third-party plugin. */
  sessionBlockers?: () => Promise<string[]>;
  /** Path from `BB_SECURE_BB_TOTP_FILE`, or null. */
  externalTotpFile: string | null;
  /** Directory snapshots live in (no trailing slash needed); only plugins inside it can use windows or touch-approved proposals. */
  snapshotsRoot: string;
  /** Deterministic plugin checks; injectable for tests. */
  runChecks?: (dir: string, opts?: { pluginId?: string }) => Promise<CheckResult>;
  /**
   * The registry stage of the dependency checks (stage 2.3), run after the offline checks:
   * adds publish-age findings. Must not throw (it reports what it could not verify as a finding).
   * Absent: dependencies are listed but not looked up.
   */
  verifyDeps?: (result: CheckResult) => Promise<CheckResult>;
  /** Called after a check result was stored (the page refreshes, held versions are rechecked). */
  onChecked?: () => void;
  /** How long the hook waits for the checks before holding (the core gives the hook 10 s). Default 8000. */
  checkWaitMs?: number;
  /** Stage 3: why a stored AI scan of this version makes it suspect (null: no scan, or clean). Only ever adds a hold. */
  scanFlag?: (k: { contentHash: string; localHash: string | null }) => string | null;
  /** Stage 3: a trust window closed and `pin` stays pinned (the "scan on freeze" option). Must not throw. */
  onFreeze?: (pluginId: string, pin: ApprovalRow | null) => void;
  /** Stage 5: has a thread of the window's tree read untrusted content since `since`? Absent: windows are not closed by pollution. */
  taint?: { assessTree(rootThreadId: string, scope: "tree" | "thread", since: number): Promise<TaintAssessment> };
  /** Stage 5: who other than the server user can write to this directory (injectable for tests). Default: the real file system. */
  unsafeDirs?: (dir: string) => Promise<PermIssue[]>;
  /** Stage 4: `file://` repository addresses are accepted (tests only; the server never sets it). */
  publishAllowFile?: boolean;
  /** Stage 3: a version that did not come through `propose` is held (the "scan externals" option). Must not throw. */
  onExternal?: (ctx: HookCtx) => void;
  /**
   * Guard mode (`BB_SECURE_BB_GUARD_SOCKET`): approvals, windows and the second factor live in the decision guard.
   * The hook then only ADDS restrictions to what the guard allows; it never records an approval of its own.
   */
  guard?: GuardPort;
}


export type TotpState = "none" | "pending" | "locked" | "external" | "external-broken";


/** Guard mode: what a window of the guard needs from this plugin besides the guard's own record. */
export const GUARD_WINDOW_UNBOUND = "окно сторожа открыто не отсюда: к какому треду оно относится, неизвестно";


export const HOUR_MS = 3_600_000;

/** A stored result with unverified dependencies (no network at the time) is verified again after this long, when its version is next decided. */
export const DEP_RETRY_MS = 10 * 60_000;

export const MAX_FAILURES = 5;


export const isOpen = (w: WindowRow, now: number): boolean =>
  w.closedAt === null && now < w.expiresAt && now < w.hardExpiresAt;


export function secretFromFile(text: string): string | null {
  const trimmed = text.trim();
  const uri = /[?&]secret=([A-Za-z2-7=]+)/.exec(trimmed);
  const candidate = uri ? uri[1]! : (trimmed.split(/\s+/)[0] ?? "");
  return /^[A-Za-z2-7]{16,}=*$/.test(candidate) ? candidate.toUpperCase() : null;
}


export const REJECTED_BY_PERSON = "secure-bb: версия отклонена вами; чтобы вернуть, нажмите «Вернуть» в Карантине";

