// The gate: decides `plugin.activate`, owns approvals, trust windows and the
// touch (TOTP) rules. Pure logic over Store + injected clock; no bb imports,
// so it is testable without a server.
import { readFileSync } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { runChecks as defaultRunChecks, type CheckResult } from "./checks/index.js";
import { SESSION_CAP_MS, SESSION_IDLE_MS, groupOf, hashToken, mintListProof, mintSessionProof, newToken, SessionProof, ListProof, type Proof, type RpcName } from "./approval.js";
import { BLOCKED_REASON, bySeverity, capabilityTokens, localCheckKey, newTokens, summarize } from "./decision.js";
import { describeIssues, serverIds, writableByOthers, type PermIssue } from "./perms.js";
import { validateSecondModel } from "./scan/commands.js";
import type { TaintAssessment } from "./taint/monitor.js";
import type { AiSettings } from "./scan/types.js";
import { normalizePattern } from "./taint/repos.js";
import { checkBranch, checkRepoUrl, sameSettings } from "./publish/validate.js";
import type { PublishSettings } from "./publish/types.js";
import type { GuardLookup, GuardPort, GuardProof, GuardState } from "./guardlink.js";
import { T } from "./text.js";
import { generateSecret, otpauthUri, verifyTotp, stepAt } from "./totp.js";
import type { ApprovalRow, Policy, ProposalRow, QueueRow, Store, WindowRow } from "./store.js";
import { hashTree, isInsideSnapshots } from "./tree.js";

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

export type GateErrorCode =
  | "not_registered"
  | "blocked"
  | "invalid_code"
  | "conflict"
  | "not_found"
  | "invalid";

/** Hold reason for a snapshot whose files differ from what was proposed. */
export const TAMPERED_REASON = "снимок изменён после предложения";
/** Prefix of a queue entry's reason when the directory could be changed by someone other than the server's user: such a version cannot be approved. */
export const UNSAFE_DIR_REASON = "каталог доступен на запись другим";

export class GateError extends Error {
  constructor(
    readonly code: GateErrorCode,
    message: string,
    readonly extra?: unknown,
  ) {
    super(message);
  }
}

export interface ThreadTree {
  /** Ancestors of a thread, parent first. */
  ancestors(threadId: string): Promise<string[]>;
  /** Every thread below a thread. */
  descendants(threadId: string): Promise<string[]>;
}

export interface GateDeps {
  store: Store;
  now: () => number;
  threads: ThreadTree;
  /** Third-party plugins that are running now (their UI code shares our origin). */
  thirdPartyRunning: () => Promise<string[]>;
  /** Path from `BB_SECURE_BB_TOTP_FILE`, or null. */
  externalTotpFile: string | null;
  /** Directory snapshots live in (no trailing slash needed); only plugins inside it can use windows or touch-approved proposals. */
  snapshotsRoot: string;
  /** Deterministic plugin checks; injectable for tests. */
  runChecks?: (dir: string) => Promise<CheckResult>;
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

const HOUR_MS = 3_600_000;
/** A stored result with unverified dependencies (no network at the time) is verified again after this long, when its version is next decided. */
const DEP_RETRY_MS = 10 * 60_000;
const MAX_FAILURES = 5;

export const isOpen = (w: WindowRow, now: number): boolean =>
  w.closedAt === null && now < w.expiresAt && now < w.hardExpiresAt;

function secretFromFile(text: string): string | null {
  const trimmed = text.trim();
  const uri = /[?&]secret=([A-Za-z2-7=]+)/.exec(trimmed);
  const candidate = uri ? uri[1]! : (trimmed.split(/\s+/)[0] ?? "");
  return /^[A-Za-z2-7]{16,}=*$/.test(candidate) ? candidate.toUpperCase() : null;
}

export class Gate {
  constructor(private readonly d: GateDeps) {}

  private get now(): number {
    return this.d.now();
  }
  private get store(): Store {
    return this.d.store;
  }

  // ---- TOTP --------------------------------------------------------------
  /** Guard mode: whether the guard said, last time we asked, that it has a second factor (the secret itself is never here). */
  private guardRegistered = false;
  isGuarded(): boolean {
    return this.d.guard !== undefined;
  }
  noteGuardState(registered: boolean): void {
    this.guardRegistered = registered;
  }

  totpState(): TotpState {
    // The secret is held outside bb by the guard: for the page that is the same as an external secret file.
    if (this.d.guard) return this.guardRegistered ? "external" : "none";
    if (this.d.externalTotpFile !== null) return this.readExternal() === null ? "external-broken" : "external";
    return this.store.totp()?.state ?? "none";
  }

  private readExternal(): string | null {
    try {
      return secretFromFile(readFileSync(this.d.externalTotpFile!, "utf8"));
    } catch {
      return null;
    }
  }

  blockedUntil(): number {
    const until = Number(this.store.getMeta("blocked_until") ?? 0);
    return until > this.now ? until : 0;
  }

  private assertNotBlocked(): void {
    const until = this.blockedUntil();
    if (until > 0) throw new GateError("blocked", `too many wrong codes; approvals are blocked until ${new Date(until).toISOString()}`);
  }

  private recordFailure(purpose: string, message = "invalid or already used code"): never {
    this.store.recordAttempt(false, purpose);
    const epoch = Number(this.store.getMeta("fail_epoch") ?? 0);
    const since = Math.max(this.now - HOUR_MS, epoch);
    if (this.store.failuresSince(since) >= MAX_FAILURES) {
      this.store.setMeta("blocked_until", String(this.now + HOUR_MS));
      this.store.setMeta("fail_epoch", String(this.now));
      this.store.log("totp.blocked", null, null, { purpose });
    }
    this.store.log("totp.fail", null, null, { purpose });
    throw new GateError("invalid_code", message);
  }

  /**
   * A touch: proves a human holds the TOTP secret, or holds the token of a session that such a code opened.
   * A fresh code (a string) consumes one 30-second step; a step (or any older one) is never accepted twice.
   * A session proof is only ever made by `proofFor`, which looked at the RPC table first.
   */
  touch(purpose: string, proof: Proof): void {
    if (proof instanceof ListProof) return; // one code for a whole fixed list was accepted a moment ago (`approveList`), or the guard checked this one
    if (this.d.guard) throw new GateError("invalid_code", "in guard mode the guard checks every code; this one did not go through it");
    const code = proof instanceof SessionProof ? null : proof;
    const state = this.totpState();
    if (state === "none" || state === "pending") throw new GateError("not_registered", "no second factor is registered yet; register one on the secure-bb page");
    if (state === "external-broken") throw new GateError("not_registered", "the external TOTP secret file cannot be read");
    this.assertNotBlocked();
    if (proof instanceof SessionProof) return this.useSession(purpose, proof.token);
    const external = state === "external";
    const secret = external ? this.readExternal()! : this.store.totp()!.secret;
    const last = external ? this.store.externalLastStep() : this.store.totp()!.lastStep;
    const res = verifyTotp(secret, code!, this.now, last);
    if (!res.ok) this.recordFailure(purpose);
    this.store.recordAttempt(true, purpose);
    if (external) this.store.setExternalLastStep(res.step);
    else this.store.setLastStep(res.step);
  }

  // ---- approval session (docs: secure-bb-approval-ux.md §1) ------------------------------------------------------------
  /**
   * What an RPC may use as its proof. `escalate`: this call is the dangerous kind of an otherwise routine RPC (lifting a block,
   * widening); it then needs a fresh code, as every "dangerous" RPC does. A fresh code is always welcome, whatever the group.
   */
  proofFor(rpc: RpcName, cred: { code?: string; session?: string }, opts: { escalate?: boolean } = {}): Proof {
    if (cred.code !== undefined) return cred.code;
    if (cred.session !== undefined) {
      if (this.d.guard) throw new GateError("invalid_code", "there are no sessions in guard mode: the guard checks a fresh code for every approval");
      if (groupOf(rpc) !== "routine" || opts.escalate === true) throw new GateError("invalid_code", "this action needs a fresh code: a session does not cover it");
      return mintSessionProof(cred.session);
    }
    throw new GateError("invalid_code", "a code, or an open session, is needed");
  }

  /** A wrong, unknown, closed or expired token is a wrong code: same counter, same one-hour block. */
  private useSession(purpose: string, token: string): void {
    const row = this.store.sessionByHash(hashToken(token));
    if (!row || this.now >= row.expiresAt || this.now >= row.hardExpiresAt) {
      if (row && this.store.closeSession(row.id, "expired")) this.store.log("session.expire", null, null);
      this.recordFailure(`session:${purpose}`, "invalid or expired session");
    }
    // Sliding: every use moves the end 15 minutes ahead, never past the ceiling.
    this.store.slideSession(row.id, this.now, Math.min(this.now + SESSION_IDLE_MS, row.hardExpiresAt));
    this.store.log("session.use", null, null, { purpose });
  }

  /**
   * Opens a session with one fresh code. Refused while any third-party plugin runs: its interface code lives in the page's
   * origin and could read the token. The old session (if any) is closed: there is one.
   */
  async openSession(code: string): Promise<{ token: string; idleMs: number; capMs: number }> {
    const running = await this.d.thirdPartyRunning();
    if (running.length > 0)
      throw new GateError("conflict", `disable these third-party plugins first: their interface code could read the session token (${running.join(", ")})`, { plugins: running });
    this.touch("session.open", code);
    this.store.closeSessions("replaced");
    const token = newToken();
    this.store.insertSession(hashToken(token), this.now, this.now + SESSION_IDLE_MS, this.now + SESSION_CAP_MS);
    this.store.log("session.open", null, null, { idleMs: SESSION_IDLE_MS, capMs: SESSION_CAP_MS });
    return { token, idleMs: SESSION_IDLE_MS, capMs: SESSION_CAP_MS };
  }

  /** "Lock": tightening, needs nothing. Says nothing about whether a session existed. */
  closeSessions(reason: string): void {
    if (this.store.closeSessions(reason) > 0) this.store.log("session.close", null, null, { reason });
  }

  /**
   * A session is only opened while no third-party plugin runs (its interface code shares the page's origin and could read the
   * token). If one starts afterwards, the session is closed at once (threat model: an agent enables a plugin while a session
   * is open). The interface of a plugin is not visible to us, so every running third-party plugin counts. Returns who ran.
   */
  async closeSessionsForThirdParty(): Promise<string[]> {
    if (this.store.unclosedSessions().length === 0) return [];
    const running = await this.d.thirdPartyRunning();
    if (running.length === 0) return [];
    this.closeSessions(`third-party plugin running: ${running.slice(0, 5).join(", ")}`);
    return running;
  }

  /** Background pass: closes sessions whose time is up. */
  sweepSessions(): number {
    let n = 0;
    for (const row of this.store.unclosedSessions()) {
      if (this.now < row.expiresAt && this.now < row.hardExpiresAt) continue;
      if (this.store.closeSession(row.id, "expired")) {
        this.store.log("session.expire", null, null);
        n++;
      }
    }
    return n;
  }

  /** One code for a fixed list: the code (or session) is checked once, here; the items are then approved with the returned mark. */
  approveList(purpose: string, proof: Proof): ListProof {
    this.touch(purpose, proof);
    return mintListProof();
  }

  /**
   * Starts (or restarts) registration. Refused while any third-party plugin runs.
   * `attended` says the call came while the secure-bb page was open; a
   * registration started any other way cannot be confirmed (it must be
   * restarted from the page), so a process that merely calls the API cannot
   * quietly enrol its own authenticator.
   */
  async beginRegistration(opts: { attended: boolean; caller: string }): Promise<{ secret: string; uri: string }> {
    const state = this.totpState();
    if (state === "locked" || state === "external" || state === "external-broken")
      throw new GateError("conflict", "a second factor is already set up and cannot be shown again");
    const running = await this.d.thirdPartyRunning();
    if (running.length > 0)
      throw new GateError("conflict", "disable these third-party plugins before registering: their interface code could see the QR code", { plugins: running });
    const secret = generateSecret();
    this.store.putPendingTotp(secret);
    this.store.setMeta("pending_attended", opts.attended ? "1" : "0");
    this.store.log("totp.begin", null, null, { attended: opts.attended, caller: opts.caller });
    return { secret, uri: otpauthUri(secret) };
  }

  /** True while a registration was started without the page open. */
  pendingUnattended(): boolean {
    return this.totpState() === "pending" && this.store.getMeta("pending_attended") !== "1";
  }

  /** First valid code locks the secret: it is never returned again. */
  confirmRegistration(code: string): void {
    const row = this.store.totp();
    if (this.totpState() !== "pending" || !row) throw new GateError("conflict", "no registration in progress");
    if (this.pendingUnattended())
      throw new GateError("conflict", "this registration was not started from the secure-bb page; press \"Start again\" on the page");
    this.assertNotBlocked();
    const res = verifyTotp(row.secret, code, this.now, 0);
    if (!res.ok) this.recordFailure("register");
    this.store.recordAttempt(true, "register");
    this.store.lockTotp(res.step);
    this.store.log("totp.registered", null, null);
  }

  // ---- checks -------------------------------------------------------------
  private readonly checking = new Map<string, Promise<CheckResult | null>>();

  /**
   * The check result stored under `key`, or a fresh run on `dir` (one retry if it
   * throws), stored under `key`. Concurrent calls share one run. Null = the checks
   * failed twice; the caller must hold (fail closed).
   */
  private depsDueForRetry(stored: { ts: number; result: CheckResult }): boolean {
    return this.d.verifyDeps !== undefined && this.now - stored.ts >= DEP_RETRY_MS && stored.result.findings.some((f) => f.rule === "dep-unchecked");
  }

  private startCheck(key: string, pluginId: string, dir: string, logHash: string | null): Promise<CheckResult | null> {
    const stored = this.store.getCheck(key);
    if (stored && !this.depsDueForRetry(stored)) return Promise.resolve(stored.result);
    const running = this.checking.get(key);
    if (running) return running;
    const run = this.d.runChecks ?? defaultRunChecks;
    const job = (async (): Promise<CheckResult | null> => {
      try {
        let result: CheckResult;
        try {
          result = await run(dir);
        } catch {
          result = await run(dir); // one retry
        }
        if (this.d.verifyDeps) result = await this.d.verifyDeps(result);
        this.store.putCheck(key, pluginId, result);
        this.store.log("check", pluginId, logHash, {
          blocks: bySeverity(result, "block").length,
          reviews: bySeverity(result, "review").length,
          infos: bySeverity(result, "info").length,
          capabilities: result.capabilities.map((c) => c.kind),
          ...(result.dependencyStats ? { dependencies: result.dependencyStats.total, unverified: result.dependencyStats.unchecked, young: result.dependencyStats.young } : {}),
          key,
        });
        this.d.onChecked?.();
        return result;
      } catch (err) {
        this.store.log("check.error", pluginId, logHash, { message: err instanceof Error ? err.message : String(err), key });
        return null;
      } finally {
        this.checking.delete(key);
      }
    })();
    this.checking.set(key, job);
    return job;
  }

  /** Waits for a check, but never longer than the hook may take. Null on failure or timeout (the run goes on and is stored). */
  private async awaitCheck(job: Promise<CheckResult | null>): Promise<CheckResult | null> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), this.d.checkWaitMs ?? 8000);
    });
    try {
      return await Promise.race([job, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  /** Runs the checks for a content hash in the background, once. Never throws, never delays the hook. */
  scheduleCheck(ctx: Pick<HookCtx, "pluginId" | "contentHash" | "rootDir">): void {
    void this.startCheck(ctx.contentHash, ctx.pluginId, ctx.rootDir, ctx.contentHash);
  }

  /** `propose` runs the checks on the snapshot right away, keyed by the snapshot's own hash. */
  checkSnapshot(pluginId: string, localHash: string, dir: string): Promise<CheckResult | null> {
    return this.awaitCheck(this.startCheck(localCheckKey(localHash), pluginId, dir, null));
  }

  /** The stored result for a queue entry: by the core's hash, else by its proposal's snapshot hash. */
  checkForQueue(q: QueueRow): CheckResult | null {
    if (q.contentHash) {
      const c = this.store.getCheck(q.contentHash);
      if (c) return c.result;
    }
    const p = q.proposalId === null ? null : this.store.getProposal(q.proposalId);
    return p ? (this.store.getCheck(localCheckKey(p.localHash))?.result ?? null) : null;
  }

  /** Resolves when no background check is running (tests, shutdown). */
  async checksIdle(): Promise<void> {
    while (this.checking.size > 0) await Promise.all([...this.checking.values()]);
  }

  // ---- the hook -----------------------------------------------------------
  async decide(ctx: HookCtx): Promise<Decision> {
    try {
      return await this.decideUnsafe(ctx);
    } catch (err) {
      // Fail closed: any internal error holds the plugin.
      this.store.log("hook.error", ctx.pluginId, ctx.contentHash, { message: err instanceof Error ? err.message : String(err) });
      return { action: "wait", reason: T.agentHeldNoReview };
    }
  }

  /**
   * Is what lies in a snapshot directory right now exactly what was proposed
   * (and, once built, exactly what bb built)? Never trust a path alone: the
   * snapshots directory is writable by whoever shares our uid.
   */
  private async verifySnapshot(p: ProposalRow, dir: string): Promise<string | null> {
    if ((await hashTree(dir)) !== p.localHash) return TAMPERED_REASON;
    let hasDist = false;
    try {
      hasDist = (await stat(`${dir}/dist`)).isDirectory();
    } catch {
      hasDist = false;
    }
    if (!hasDist) return null; // first load: bb has not built anything yet
    if (p.builtHash === null) return "в снимке есть dist/, которого гейт не видел при сборке";
    if ((await hashTree(dir, { includeDist: true })) !== p.builtHash) return "собранный dist/ изменён после установки";
    return null;
  }

  private async decideUnsafe(ctx: HookCtx): Promise<Decision> {
    if (this.d.guard) return this.decideGuarded(ctx, this.d.guard);
    const approved = this.store.activeApproval(ctx.contentHash);
    if (approved) {
      this.scheduleCheck(ctx);
      this.store.touchApproval(approved.id);
      this.store.supersedeTampered(ctx.pluginId, ctx.contentHash);
      return { action: "proceed" };
    }

    let proposal: ProposalRow | null = null;
    let reason: string | null = null;
    let verifiedDir: string | null = null;
    const inSnapshots = await isInsideSnapshots(this.d.snapshotsRoot, ctx.rootDir);
    if (!inSnapshots) {
      // Not one of our snapshots (those are checked by hash): the directory must not be changeable by anyone but the server's user.
      const unsafe = await this.unsafeDirs(ctx.rootDir);
      if (unsafe !== null) {
        this.scheduleCheck(ctx);
        return this.hold(ctx, null, `${UNSAFE_DIR_REASON}: ${unsafe}`);
      }
      this.store.clearQueueReason(ctx.contentHash, UNSAFE_DIR_REASON); // fixed since the last look
    }
    if (inSnapshots) {
      const real = await realpath(ctx.rootDir);
      proposal = this.store.proposalByDir(real);
      if (proposal && proposal.pluginId === ctx.pluginId) {
        reason = await this.verifySnapshot(proposal, real);
        if (reason === null) {
          verifiedDir = real;
          if (proposal.loadedAt !== null) {
            // Already approved and loaded once: still pinned. (bb's own hash
            // changes after a build, so the same snapshot arrives under a new hash.)
            this.recordApproval(ctx, "pin", null, proposal);
            return { action: "proceed" };
          }
          if (proposal.touchApprovedAt !== null) {
            // A human approved this snapshot with a code (also lifting a block).
            this.recordApproval(ctx, "touch", null, proposal);
            return { action: "proceed" };
          }
        }
      }
    }

    // An AI scan (stage 3) can only add a hold: a flagged, failed or incomplete scan of this version.
    const aiFlag = this.d.scanFlag?.({ contentHash: ctx.contentHash, localHash: proposal?.localHash ?? null }) ?? null;

    // After-the-fact scans only record: the plugin already ran, nothing here can stop it.
    if (ctx.trigger === "afterfact") {
      this.scheduleCheck(ctx);
      return this.holdExternal(ctx, proposal, reason ?? aiFlag);
    }

    // Everything below needs the checks (spec §5.3). A snapshot proposed through
    // `propose` was checked then (by its own hash); link that result to the core's hash.
    const key = proposal && verifiedDir ? localCheckKey(proposal.localHash) : ctx.contentHash;
    const dir = verifiedDir ?? ctx.rootDir;
    const result = await this.awaitCheck(this.startCheck(key, ctx.pluginId, dir, ctx.contentHash));
    if (result === null) return this.hold(ctx, proposal, reason ?? "проверки не завершились");
    if (key !== ctx.contentHash) {
      // The core's hash gets the snapshot's result, and a newer one (dependencies verified again later) replaces an older one.
      const linked = this.store.getCheck(ctx.contentHash);
      const own = this.store.getCheck(key);
      if (!linked || (own && own.ts > linked.ts)) this.store.putCheck(ctx.contentHash, ctx.pluginId, result);
    }

    const blocks = bySeverity(result, "block");
    if (blocks.length > 0) {
      const why = `${BLOCKED_REASON}: ${summarize(blocks)}`;
      const q = this.queue(ctx, proposal, reason ?? why);
      this.store.logDecision("reject", ctx.pluginId, ctx.contentHash, { review: q.id, version: ctx.version, rules: blocks.map((f) => f.rule) });
      return { action: "reject", message: T.agentRejected(q.id) };
    }

    if (verifiedDir && proposal && reason === null) {
      const reviews = bySeverity(result, "review");
      const w = proposal.windowId === null ? null : this.store.getWindow(proposal.windowId);
      let windowOpen = w !== null && w.pluginId === ctx.pluginId && isOpen(w, this.now);
      if (windowOpen) {
        // Pollution is looked at right before the window is used, not only on the sweep: a tainted tree closes it now.
        const guard = await this.guardWindow(w!);
        if (guard === "unknown") return this.hold(ctx, proposal, "не удалось проверить загрязнение дерева тредов");
        if (guard === "closed") windowOpen = false;
      }
      if (windowOpen && w) {
        const fresh = newTokens(result, w.caps);
        if (reviews.length === 0 && fresh.length === 0 && aiFlag === null) {
          this.recordApproval(ctx, "window", w.id, proposal);
          this.slide(w);
          return { action: "proceed" };
        }
        // Held for one code; the window stays open (spec §0, §6).
        const why = fresh.length > 0 ? `новая возможность в окне: ${fresh.slice(0, 6).join(", ")}${fresh.length > 6 ? "…" : ""}` : reviews.length > 0 ? `проверки требуют ревью: ${summarize(reviews)}` : aiFlag!;
        return this.hold(ctx, proposal, why);
      }
      const safe = reviews.length === 0 && result.capabilities.length === 0 && aiFlag === null;
      if (safe && this.store.policy().autoSafe) {
        // Safe class (§5.2), our own immutable snapshot, clean checks, and a human turned the pass on with a code: no touch needed.
        this.recordApproval(ctx, "auto", null, proposal);
        return { action: "proceed" };
      }
      const why =
        safe
          ? T.autoSafeOff
          : result.capabilities.length > 0
          ? `вне безопасного класса: ${result.capabilities.map((c) => c.kind).join(", ")}`
          : reviews.length > 0
            ? `проверки требуют ревью: ${summarize(reviews)}`
            : aiFlag!;
      return this.hold(ctx, proposal, why);
    }
    return this.holdExternal(ctx, proposal, reason ?? aiFlag);
  }

  // ---- guard mode -----------------------------------------------------------------------------------------------
  /**
   * The hook in guard mode. The core asks the guard itself and the guard says yes or "held"; this hook can only make it stricter:
   *   proceed  — the guard has approved this exact version, or one of its windows is open on this plugin and this version
   *              came from the window's thread tree, is clean and has nothing new (the guard will then approve it by the window);
   *   reject   — hard findings (the same as without a guard);
   *   wait     — everything else, including "the guard has not approved it and no window covers it". The guard holds that too;
   *              holding here as well means a core that does not (yet) ask the guard still cannot load an unapproved version.
   * Findings and reasons go to the guard's queue entry as an annotation (for the page; nothing there decides anything).
   */
  private async decideGuarded(ctx: HookCtx, guard: GuardPort): Promise<Decision> {
    let look: GuardLookup;
    try {
      look = await guard.lookup(ctx.pluginId, ctx.contentHash);
    } catch (err) {
      // Fail closed, as the core does when the guard does not answer.
      this.store.logDecision("hold", ctx.pluginId, ctx.contentHash, { version: ctx.version, trigger: ctx.trigger, reason: "guard unreachable", message: err instanceof Error ? err.message : String(err) });
      return { action: "wait", reason: T.agentHeldNoReview };
    }
    // Not approved and no window: the guard may let it in by itself (an own source, rights not grown). The core runs the hooks before it asks the
    // guard, so without this question the hook would hold such a version once and it would wait for a recheck. What the guard decides is the guard's:
    // this only asks. A "wait" (or no answer) changes nothing here; the checks below hold as before.
    if (!look.approved && look.window === null) {
      const asked = await guard.decide({ pluginId: ctx.pluginId, version: ctx.version, contentHash: ctx.contentHash, rootDir: ctx.rootDir, source: ctx.source, sourceKind: ctx.sourceKind, trigger: ctx.trigger }).catch(() => null);
      if (asked?.action === "proceed") {
        this.scheduleCheck(ctx);
        return { action: "proceed" };
      }
    }
    // An approval a window made a moment ago, while that window is still open, is not final: the core may have asked the guard first, and
    // the guard approves by the window without knowing what this hook knows (a new capability, a tainted tree). Looked at again below;
    // if it must be held, the approval is withdrawn (tightening: no code). A human's approval, a pin of a closed window, an import: final.
    const byOpenWindow = look.approval?.via === "window" && look.window !== null && look.approval.windowId === look.window.id;
    if (look.approved && !byOpenWindow) {
      this.scheduleCheck(ctx);
      return { action: "proceed" };
    }
    const withdraw = byOpenWindow ? look.approval!.id : null;
    const hold = async (reason: string, extra: Record<string, unknown> = {}): Promise<Decision> => {
      if (withdraw !== null) await guard.revoke({ approvalId: withdraw }).catch(() => undefined);
      // The version is kept for a human at the guard even if the core never asks it (a hook that holds is enough for the core to stop),
      // and a window of the guard must not lift this hold: that is the stop on a new capability.
      await guard.hold({ pluginId: ctx.pluginId, version: ctx.version, contentHash: ctx.contentHash, rootDir: ctx.rootDir, source: ctx.source, sourceKind: ctx.sourceKind, trigger: ctx.trigger }, look.window !== null).catch(() => undefined);
      this.store.logDecision("hold", ctx.pluginId, ctx.contentHash, { version: ctx.version, trigger: ctx.trigger, reason });
      this.annotate(guard, ctx, { reason, ...extra });
      return { action: "wait", reason: T.agentHeldNoReview };
    };

    let proposal: ProposalRow | null = null;
    let tampered: string | null = null;
    let verifiedDir: string | null = null;
    if (!(await isInsideSnapshots(this.d.snapshotsRoot, ctx.rootDir))) {
      const unsafe = await this.unsafeDirs(ctx.rootDir);
      this.scheduleCheck(ctx);
      return hold(unsafe !== null ? `${UNSAFE_DIR_REASON}: ${unsafe}` : "не из снимка secure-bb: версия одобряется по хешу сторожем");
    }
    const real = await realpath(ctx.rootDir);
    proposal = this.store.proposalByDir(real);
    if (proposal && proposal.pluginId === ctx.pluginId) {
      tampered = await this.verifySnapshot(proposal, real);
      if (tampered === null) verifiedDir = real;
    } else proposal = null;

    const aiFlag = this.d.scanFlag?.({ contentHash: ctx.contentHash, localHash: proposal?.localHash ?? null }) ?? null;
    const key = proposal && verifiedDir ? localCheckKey(proposal.localHash) : ctx.contentHash;
    const result = await this.awaitCheck(this.startCheck(key, ctx.pluginId, verifiedDir ?? ctx.rootDir, ctx.contentHash));
    if (result === null) return hold(tampered ?? "проверки не завершились");
    if (key !== ctx.contentHash) {
      const linked = this.store.getCheck(ctx.contentHash);
      const own = this.store.getCheck(key);
      if (!linked || (own && own.ts > linked.ts)) this.store.putCheck(ctx.contentHash, ctx.pluginId, result);
    }
    const summary = { capabilities: capabilityTokens(result), findings: result.findings.slice(0, 40).map((f) => ({ rule: f.rule, severity: f.severity, file: f.file, line: f.line })) };

    const blocks = bySeverity(result, "block");
    if (blocks.length > 0) {
      if (withdraw !== null) await guard.revoke({ approvalId: withdraw }).catch(() => undefined);
      await guard.hold({ pluginId: ctx.pluginId, version: ctx.version, contentHash: ctx.contentHash, rootDir: ctx.rootDir, source: ctx.source, sourceKind: ctx.sourceKind, trigger: ctx.trigger }, true).catch(() => undefined);
      const why = `${BLOCKED_REASON}: ${summarize(blocks)}`;
      this.annotate(guard, ctx, { reason: why, blocked: true, ...summary });
      this.store.logDecision("reject", ctx.pluginId, ctx.contentHash, { version: ctx.version, rules: blocks.map((f) => f.rule) });
      return { action: "reject", message: "rejected by secure-bb" };
    }
    if (tampered !== null) return hold(tampered, summary);

    // No window of the guard covers this plugin: the guard holds it for a human, and so do we.
    if (look.window === null) {
      const reviews = bySeverity(result, "review");
      return hold(reviews.length > 0 ? `проверки требуют ревью: ${summarize(reviews)}` : result.capabilities.length > 0 ? `вне безопасного класса: ${result.capabilities.map((c) => c.kind).join(", ")}` : T.autoSafeOff, summary);
    }
    // A window is open at the guard. It knows the plugin id and the time; which thread opened it, and what the plugin could do then, is ours.
    const w = this.store.windowByGuardId(look.window.id);
    if (w === null || w.pluginId !== ctx.pluginId) return hold(GUARD_WINDOW_UNBOUND, summary);
    if (proposal === null || proposal.windowId !== w.id) return hold("версия пришла не из треда, для которого открыто окно", summary);
    const taint = await this.guardWindow(w);
    if (taint === "closed") {
      // The window is closed here and at the guard: closing only tightens, so the guard takes it without a code.
      await guard.closeWindow({ windowId: look.window.id }).catch(() => undefined);
      return hold("окно закрыто: в дереве тредов читали недоверенное", summary);
    }
    if (taint === "unknown") return hold("не удалось проверить загрязнение дерева тредов", summary);
    const reviews = bySeverity(result, "review");
    const fresh = newTokens(result, w.caps);
    if (reviews.length > 0 || fresh.length > 0 || aiFlag !== null) {
      const why = fresh.length > 0 ? `новая возможность в окне: ${fresh.slice(0, 6).join(", ")}${fresh.length > 6 ? "…" : ""}` : reviews.length > 0 ? `проверки требуют ревью: ${summarize(reviews)}` : aiFlag!;
      return hold(why, summary); // the window stays open (spec §0, §6)
    }
    return { action: "proceed" }; // the guard approves it by the window and journals that
  }

  /** Check results are put on the guard's queue entry for the page. Never awaited by the hook and never throws. */
  private annotate(guard: GuardPort, ctx: HookCtx, findings: Record<string, unknown>): void {
    void guard.annotate({ contentHash: ctx.contentHash }, { ...findings, from: "secure-bb", version: ctx.version }).catch(() => undefined);
  }

  /** Brings the shadow rows of windows in line with the guard's: its clock and its closing are the truth. */
  syncGuardWindows(state: GuardState): void {
    const live = new Map(state.windows.map((w) => [w.id, w]));
    for (const row of this.store.unclosedWindows()) {
      if (row.guardWindowId === null) continue;
      const g = live.get(row.guardWindowId);
      if (!g) {
        const closed = state.closedWindows.find((c) => c.id === row.guardWindowId);
        this.store.closeWindow(row.id, closed?.closedReason ?? "closed at the guard", closed?.closedAt ?? this.now);
        try {
          this.d.onFreeze?.(row.pluginId, null); // approvals are the guard's: there is no local pin to pass on
        } catch {
          /* optional */
        }
        continue;
      }
      if (g.expiresAt !== row.expiresAt) this.store.setWindowExpiry(row.id, g.expiresAt);
    }
  }

  /**
   * Opens a window at the guard (with a code, checked there), then remembers here which thread it belongs to and what the plugin could do at that moment.
   * The queue entry is the guard's; the thread comes from the proposal whose snapshot directory is the entry's directory.
   */
  async openGuardWindow(entry: { id: number; pluginId: string; contentHash: string; rootDir: string }, proof: GuardProof, scope?: "tree" | "thread"): Promise<WindowRow> {
    const guard = this.d.guard!;
    let proposal: ProposalRow | null = null;
    try {
      proposal = this.store.proposalByDir(await realpath(entry.rootDir));
    } catch {
      proposal = null;
    }
    if (!proposal || proposal.pluginId !== entry.pluginId || !proposal.threadId)
      throw new GateError("invalid", "this entry did not come from a thread, so a trust window cannot be bound to it; approve the version instead");
    const found = this.store.getCheck(entry.contentHash)?.result ?? this.store.getCheck(localCheckKey(proposal.localHash))?.result ?? null;
    if (found !== null && bySeverity(found, "block").length > 0)
      throw new GateError("invalid", "this version was blocked by the checks; a window cannot be opened on it (approve the version knowingly, or fix the plugin)");
    const policy = this.store.policy();
    // The thread scope travels with the touch (a passkey signature covers it): the page asked for a challenge with the same one.
    const gw = await guard.openWindow(entry.pluginId, undefined, proof, scope ?? policy.scope);
    for (const old of this.store.unclosedWindows()) if (old.pluginId === entry.pluginId) this.store.closeWindow(old.id, "reopened");
    const w = this.store.insertWindow({
      pluginId: entry.pluginId,
      threadId: proposal.threadId,
      scope: scope ?? policy.scope,
      mode: gw.mode,
      sizeSec: gw.sizeSec,
      capSec: gw.capSec,
      openedAt: gw.openedAt,
      expiresAt: gw.expiresAt,
      hardExpiresAt: gw.hardExpiresAt,
      caps: found ? capabilityTokens(found) : [],
      guardWindowId: gw.id,
    });
    this.store.setProposalWindow(proposal.id, w.id);
    this.store.log("window.open", entry.pluginId, null, { windowId: w.id, guardWindow: gw.id, thread: w.threadId, scope: w.scope, mode: w.mode, sizeSec: w.sizeSec });
    return w;
  }

  /** Closing only tightens: no code. */
  async closeGuardWindow(guardWindowId: number): Promise<void> {
    await this.d.guard!.closeWindow({ windowId: guardWindowId });
    const row = this.store.windowByGuardId(guardWindowId);
    if (row && row.closedAt === null) {
      this.store.closeWindow(row.id, "closed");
      this.store.log("window.close", row.pluginId, null, { windowId: row.id, guardWindow: guardWindowId });
      try {
        this.d.onFreeze?.(row.pluginId, null);
      } catch {
        /* optional */
      }
    }
  }

  /** Null: only the server's user can write there (or the check cannot run on this OS). Otherwise a description for the page. */
  private async unsafeDirs(dir: string): Promise<string | null> {
    let issues: PermIssue[];
    if (this.d.unsafeDirs) issues = await this.d.unsafeDirs(dir);
    else {
      const ids = serverIds();
      if (ids === null) return null;
      issues = await writableByOthers(dir, ids);
    }
    return issues.length === 0 ? null : describeIssues(issues);
  }

  private queue(ctx: HookCtx, proposal: ProposalRow | null, reason: string | null): QueueRow {
    return this.store.upsertQueue({
      kind: ctx.trigger === "afterfact" ? "afterfact" : proposal ? "proposal" : "hook",
      contentHash: ctx.contentHash,
      pluginId: ctx.pluginId,
      version: ctx.version,
      source: ctx.source,
      sourceKind: ctx.sourceKind,
      rootDir: ctx.rootDir,
      gitCommit: ctx.gitCommit,
      npmIntegrity: ctx.npmIntegrity,
      trigger: ctx.trigger,
      threadId: proposal?.threadId ?? null,
      proposalId: proposal?.id ?? null,
      reason,
    });
  }

  /** A hold of a version that did not come through `propose`: the optional scan of externals starts here. */
  private holdExternal(ctx: HookCtx, proposal: ProposalRow | null, reason: string | null): Decision {
    if (proposal === null) {
      try {
        this.d.onExternal?.(ctx);
      } catch {
        /* optional */
      }
    }
    return this.hold(ctx, proposal, reason);
  }

  private hold(ctx: HookCtx, proposal: ProposalRow | null, reason: string | null): Decision {
    const q = this.queue(ctx, proposal, reason);
    this.store.logDecision("hold", ctx.pluginId, ctx.contentHash, { review: q.id, version: ctx.version, trigger: ctx.trigger, ...(reason ? { reason } : {}) });
    return { action: "wait", reason: T.agentHeld(q.id) };
  }

  /** After bb installed (and built) a snapshot: remember the built tree so later loads can be verified. */
  async recordBuilt(dir: string): Promise<void> {
    const real = await realpath(dir);
    const p = this.store.proposalByDir(real);
    if (!p) return;
    if ((await hashTree(real)) !== p.localHash) return; // source changed: never bless it
    this.store.setProposalBuilt(p.id, await hashTree(real, { includeDist: true }));
  }

  private recordApproval(ctx: HookCtx, via: ApprovalRow["via"], windowId: number | null, proposal: ProposalRow | null): ApprovalRow {
    const a = this.store.addApproval({
      contentHash: ctx.contentHash,
      pluginId: ctx.pluginId,
      version: ctx.version,
      source: ctx.source,
      sourceKind: ctx.sourceKind,
      gitCommit: ctx.gitCommit,
      npmIntegrity: ctx.npmIntegrity,
      via,
      windowId,
      threadId: proposal?.threadId ?? null,
      localHash: proposal?.localHash ?? null,
    });
    if (proposal) this.store.markProposalLoaded(proposal.id);
    this.store.supersedeTampered(ctx.pluginId, ctx.contentHash);
    // The entry `propose` made has no content hash (the core had not hashed the plugin yet), so find it by the proposal.
    if (proposal) this.store.resolveQueueByProposal(proposal.id);
    this.store.resolveQueueByHash(ctx.contentHash);
    // A touch-approved proposal was already logged as "approved.touch" at approval time; its load is a separate event.
    this.store.log(via === "window" ? "approved.window" : via === "pin" ? "approved.pin" : via === "auto" ? "approved.auto" : "approved.load", ctx.pluginId, ctx.contentHash, {
      version: ctx.version,
      windowId,
      localHash: proposal?.localHash ?? null,
    });
    return a;
  }

  // ---- approvals ------------------------------------------------------------
  /**
   * Approves a held version with a touch. Returns what the server must do next:
   * install the snapshot (a proposal not yet seen by core) or just recheck.
   */
  approveQueue(queueId: number, code: Proof, opts: { acknowledgeBlock?: boolean } = {}): { installDir: string | null; pluginId: string; enable: boolean; proposalId: number | null } {
    const q = this.requireHeld(queueId);
    // No code lifts this: the directory itself must be fixed (nobody but the server's user may write there), then the version is looked at again.
    if (q.reason?.startsWith(UNSAFE_DIR_REASON))
      throw new GateError("invalid", "this version lies in a directory that others can write to; it cannot be approved from there (see the page)", { unsafeDir: true });
    const result = this.checkForQueue(q);
    const blocked = (q.reason?.startsWith(BLOCKED_REASON) ?? false) || (result !== null && bySeverity(result, "block").length > 0);
    // A block is lifted only knowingly: the page shows the findings and asks for explicit confirmation along with the code.
    if (blocked && !opts.acknowledgeBlock)
      throw new GateError("invalid", "this version was blocked by the checks; confirm that you accept the risk to approve it anyway", { blocked: true });
    this.touch(`approve:${q.pluginId}`, code);
    if (blocked) this.store.log("block.lifted", q.pluginId, q.contentHash, { review: q.id, version: q.version, rules: result ? bySeverity(result, "block").map((f) => f.rule) : [] });
    // A capability accepted with a code inside an open window becomes part of the window's set; the window stays open.
    const proposal = q.proposalId === null ? null : this.store.getProposal(q.proposalId);
    const w = proposal?.windowId == null ? null : this.store.getWindow(proposal.windowId);
    if (w && w.pluginId === q.pluginId && isOpen(w, this.now) && result) {
      this.store.setWindowCaps(w.id, [...new Set([...w.caps, ...capabilityTokens(result)])].sort());
      this.store.log("window.caps", q.pluginId, q.contentHash, { windowId: w.id, added: newTokens(result, w.caps) });
    }
    if (q.contentHash) {
      this.store.addApproval({
        contentHash: q.contentHash,
        pluginId: q.pluginId,
        version: q.version,
        source: q.source,
        sourceKind: q.sourceKind,
        gitCommit: q.gitCommit,
        npmIntegrity: q.npmIntegrity,
        via: "touch",
        windowId: null,
        threadId: q.threadId,
        localHash: proposal?.localHash ?? null,
      });
      this.store.resolveQueueByHash(q.contentHash);
    }
    this.store.setQueueStatus(q.id, "approved");
    if (q.proposalId !== null) this.store.resolveQueueByProposal(q.proposalId);
    this.store.log("approved.touch", q.pluginId, q.contentHash, { review: q.id, version: q.version });
    let installDir: string | null = null;
    if (q.proposalId !== null) {
      this.store.approveProposal(q.proposalId);
      // Not yet seen by the core, or rejected by the hook (a block): install the snapshot again.
      if (!q.contentHash || blocked) installDir = this.store.getProposal(q.proposalId)?.snapshotDir ?? null;
    }
    return { installDir, pluginId: q.pluginId, enable: q.kind === "afterfact", proposalId: q.proposalId };
  }

  /** Tightening: no proof, and no block after wrong codes (the owner must always be able to reject). The journal record stays. */
  dismissQueue(queueId: number): void {
    const q = this.requireHeld(queueId);
    this.store.setQueueStatus(q.id, "dismissed");
    this.store.log("dismissed", q.pluginId, q.contentHash, { review: q.id });
  }

  private requireHeld(queueId: number): QueueRow {
    const q = this.store.getQueue(queueId);
    if (!q) throw new GateError("not_found", `no review #${queueId}`);
    if (q.status !== "held") throw new GateError("conflict", `review #${queueId} is already ${q.status}`);
    return q;
  }

  /**
   * Withdraws an approval. This only tightens, so it needs no code and is not affected by the block after wrong codes
   * (threat model F8): whoever can call the API must not be able to keep the human from revoking. Every approval of the
   * version goes (by core hash and by reviewed-source hash), not just the row that was shown (F18).
   */
  revoke(approvalId: number): ApprovalRow {
    const a = this.store.getApproval(approvalId);
    if (!a || a.revokedAt !== null) throw new GateError("not_found", "no such active approval");
    const { revoked, localHashes } = this.store.revokeVersion(a);
    for (const h of localHashes) this.store.unpinProposals(a.pluginId, h);
    this.store.log("revoked", a.pluginId, a.contentHash, { version: a.version, approvals: revoked });
    return a;
  }

  // ---- windows ------------------------------------------------------------
  openWindows(): WindowRow[] {
    return this.store.unclosedWindows().filter((w) => isOpen(w, this.now));
  }

  /** Marks expired windows closed and logs the freeze (the last version stays pinned). */
  sweep(): number {
    let frozen = 0;
    for (const w of this.store.unclosedWindows()) {
      if (isOpen(w, this.now)) continue;
      const at = Math.min(w.expiresAt, w.hardExpiresAt);
      this.store.closeWindow(w.id, w.expiresAt >= w.hardExpiresAt ? "ceiling" : "expired", at);
      const pin = this.store.latestApproval(w.pluginId);
      this.store.log("window.freeze", w.pluginId, pin?.contentHash ?? null, {
        windowId: w.id,
        pinnedVersion: pin?.version ?? null,
        note: "последняя версия закреплена; следующие требуют нового окна",
      });
      try {
        this.d.onFreeze?.(w.pluginId, pin);
      } catch {
        /* an optional scan must never break the sweep */
      }
      frozen++;
    }
    return frozen;
  }

  openWindow(queueId: number, code: Proof, scope?: "tree" | "thread"): WindowRow {
    const q = this.store.getQueue(queueId);
    if (!q) throw new GateError("not_found", `no review #${queueId}`);
    if (!q.threadId) throw new GateError("invalid", "this entry did not come from a thread, so a trust window cannot be bound to it; approve the version instead");
    const found = this.checkForQueue(q);
    if ((q.reason?.startsWith(BLOCKED_REASON) ?? false) || (found !== null && bySeverity(found, "block").length > 0))
      throw new GateError("invalid", "this version was blocked by the checks; a window cannot be opened on it (approve the version knowingly, or fix the plugin)");
    this.touch(`window.open:${q.pluginId}`, code);
    this.sweep();
    for (const old of this.store.unclosedWindows()) {
      if (old.pluginId === q.pluginId) this.store.closeWindow(old.id, "reopened");
    }
    const policy = this.store.policy();
    const opening = this.checkForQueue(q);
    const now = this.now;
    const hard = now + policy.capMin * 60_000;
    const w = this.store.insertWindow({
      pluginId: q.pluginId,
      threadId: q.threadId,
      scope: scope ?? policy.scope,
      mode: policy.mode,
      sizeSec: policy.windowMin * 60,
      capSec: policy.capMin * 60,
      openedAt: now,
      expiresAt: Math.min(now + policy.windowMin * 60_000, hard),
      hardExpiresAt: hard,
      // The version the human looked at when opening: what it can do is the window's baseline.
      caps: opening ? capabilityTokens(opening) : [],
    });
    this.store.log("window.open", q.pluginId, null, { windowId: w.id, thread: w.threadId, scope: w.scope, mode: w.mode, sizeSec: w.sizeSec });
    return w;
  }

  /** Closing a window only tightens: no code, and the block after wrong codes does not apply (threat model F8). */
  closeWindow(windowId: number): void {
    const w = this.store.getWindow(windowId);
    if (!w || w.closedAt !== null) throw new GateError("not_found", "no such open window");
    this.store.closeWindow(windowId, "closed");
    const pin = this.store.latestApproval(w.pluginId);
    this.store.log("window.close", w.pluginId, null, { windowId });
    try {
      this.d.onFreeze?.(w.pluginId, pin); // closing by hand freezes the last version just like the clock does
    } catch {
      /* optional modules must never break closing */
    }
  }

  private slide(w: WindowRow): void {
    if (w.mode !== "sliding") return;
    const next = Math.min(this.now + w.sizeSec * 1000, w.hardExpiresAt);
    if (next > w.expiresAt) {
      this.store.setWindowExpiry(w.id, next);
      this.store.log("window.slide", w.pluginId, null, { windowId: w.id });
    }
  }

  /** The open window of `pluginId` that covers `threadId`, if any. */
  async windowCovering(pluginId: string, threadId: string | null): Promise<WindowRow | null> {
    const w = this.openWindows().find((x) => x.pluginId === pluginId);
    if (!w || threadId === null) return null;
    let covers = threadId === w.threadId;
    if (!covers && w.scope === "tree") covers = (await this.d.threads.ancestors(threadId)).includes(w.threadId);
    if (!covers) return null;
    // A window whose tree read untrusted content is closed, and one we cannot vouch for is not used.
    return (await this.guardWindow(w)) === "ok" ? w : null;
  }

  /**
   * Pollution (spec §6): if any thread of the window's tree has read untrusted content since the window opened,
   * the window is closed for good. "unknown": the history could not be read in full; the window stays open but is not used.
   */
  async guardWindow(w: WindowRow): Promise<"ok" | "closed" | "unknown"> {
    if (!this.d.taint || w.closedAt !== null) return "ok";
    let verdict: TaintAssessment;
    try {
      verdict = await this.d.taint.assessTree(w.threadId, w.scope, w.openedAt);
    } catch (err) {
      this.store.log("taint.error", w.pluginId, null, { windowId: w.id, message: err instanceof Error ? err.message : String(err) });
      return "unknown";
    }
    if (verdict.state === "tainted") {
      // The window may have been closed by someone else while we were reading.
      const now = this.store.getWindow(w.id);
      if (now && now.closedAt === null) {
        this.store.closeWindow(w.id, "tainted");
        const pin = this.store.latestApproval(w.pluginId);
        this.store.log("window.taint", w.pluginId, pin?.contentHash ?? null, { windowId: w.id, thread: w.threadId, kinds: verdict.kinds, threads: verdict.threads.slice(0, 10), lines: verdict.lines.slice(0, 5), pinnedVersion: pin?.version ?? null });
        try {
          this.d.onFreeze?.(w.pluginId, pin);
        } catch {
          /* optional */
        }
      }
      return "closed";
    }
    return verdict.state === "unknown" ? "unknown" : "ok";
  }

  /** Background pass: closes every open plugin window whose tree is tainted. Returns how many were closed. */
  async sweepTaint(): Promise<number> {
    let closed = 0;
    for (const w of this.openWindows()) if ((await this.guardWindow(w)) === "closed") closed++;
    return closed;
  }

  // ---- policy -------------------------------------------------------------
  setPolicy(patch: Partial<Policy>, code: string | undefined): Policy {
    const cur = this.store.policy();
    const next: Policy = { ...cur, ...patch };
    if (next.windowMin < 1 || next.capMin < 1 || next.capMin > 1440 || next.windowMin > next.capMin)
      throw new GateError("invalid", "window size must be at least 1 minute and not exceed the ceiling (at most 24 hours)");
    if (next.cfgWindowMin < 1 || next.cfgCapMin < 1 || next.cfgCapMin > 1440 || next.cfgWindowMin > next.cfgCapMin)
      throw new GateError("invalid", "configuration window size must be at least 1 minute and not exceed its ceiling (at most 24 hours)");
    const widens =
      next.windowMin > cur.windowMin ||
      next.capMin > cur.capMin ||
      (next.mode === "sliding" && cur.mode === "fixed") ||
      (next.scope === "tree" && cur.scope === "thread") ||
      next.cfgWindowMin > cur.cfgWindowMin ||
      next.cfgCapMin > cur.cfgCapMin ||
      (next.cfgMode === "sliding" && cur.cfgMode === "fixed") ||
      (next.autoSafe && !cur.autoSafe);
    if (widens) {
      if (code === undefined) throw new GateError("invalid_code", "widening the policy needs a code");
      this.touch("policy", code);
    }
    this.store.setPolicy(next);
    this.store.log("policy", null, null, { from: cur, to: next, touched: widens });
    return next;
  }

  // ---- trusted repositories (stage 5) -----------------------------------------------
  /** Adds or removes one pattern (`owner/name`, `owner/*`). Both directions need a code: a wider list means less pollution is noticed, a narrower one changes what windows survive. */
  setTrustedRepo(change: { add?: string; remove?: string }, code: string): string[] {
    if ((change.add === undefined) === (change.remove === undefined)) throw new GateError("invalid", "give exactly one of add / remove");
    const raw = (change.add ?? change.remove)!;
    const pattern = normalizePattern(raw);
    if (pattern === null) throw new GateError("invalid", "a trusted repository is `owner/name` or `owner/*` (github.com)");
    this.touch("trusted.repos", code);
    const changed = change.add !== undefined ? this.store.addTrustedRepo(pattern) : this.store.removeTrustedRepo(pattern);
    this.store.log(change.add !== undefined ? "trusted.add" : "trusted.remove", null, null, { pattern, changed });
    return this.store.trustedRepos();
  }

  // ---- AI scan settings (stage 3, spec §8) -------------------------------------
  /**
   * Changes the optional AI scan. Everything is off by default. Switching anything ON needs a code: it sends plugin code to a
   * cloud service (threat model F15). Switching an option OFF needs none: it only sends less (F8).
   */
  setAiSettings(patch: Partial<Omit<AiSettings, "freezePlugins">> & { freezePlugin?: { id: string; on: boolean } }, code: string | undefined): AiSettings {
    const cur = this.store.aiSettings();
    const next: AiSettings = { ...cur, freezePlugins: [...cur.freezePlugins] };
    for (const k of ["enabled", "autoFreeze", "autoExternal", "second"] as const) if (patch[k] !== undefined) next[k] = patch[k]!;
    if (patch.secondModel !== undefined) {
      const name = patch.secondModel.trim();
      const bad = name === "" ? null : validateSecondModel(name);
      if (bad) throw new GateError("invalid", bad);
      next.secondModel = name;
    }
    if (next.second && next.secondModel === "") throw new GateError("invalid", "укажите имя второй модели (не Anthropic) до того, как включать её");
    if (patch.freezePlugin) {
      const { id, on } = patch.freezePlugin;
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)) throw new GateError("invalid", "неверный id плагина");
      next.freezePlugins = on ? [...new Set([...next.freezePlugins, id])].sort() : next.freezePlugins.filter((x) => x !== id);
    }
    // Where code goes: a new option, a new plugin on the freeze list, or another second model while the second model is on.
    const switchedOn =
      (!cur.enabled && next.enabled) ||
      (!cur.autoFreeze && next.autoFreeze) ||
      (!cur.autoExternal && next.autoExternal) ||
      (!cur.second && next.second) ||
      (next.second && next.secondModel !== cur.secondModel) ||
      next.freezePlugins.some((id) => !cur.freezePlugins.includes(id));
    if (switchedOn) {
      if (code === undefined) throw new GateError("invalid_code", "включение ИИ-скана или его опции (код плагина уйдёт в облако) требует кода");
      this.touch("ai.settings", code);
    }
    this.store.setAiSettings(next);
    this.store.log("ai.settings", null, null, { from: cur, to: next, touched: switchedOn });
    return next;
  }

  // ---- publishing settings (stage 4, spec §14) ---------------------------------------
  /**
   * Turning publishing on, changing the address or the branch, and turning "on approval" on all need a code:
   * they decide where reviewed code is sent. Turning something off does not (it only publishes less).
   * The token is not a setting: it is a file named by an environment variable of the server.
   */
  setPublishSettings(patch: Partial<PublishSettings>, code: string | undefined): PublishSettings {
    const cur = this.store.publishSettings();
    const next: PublishSettings = { ...cur };
    if (patch.enabled !== undefined) next.enabled = patch.enabled;
    if (patch.onApprove !== undefined) next.onApprove = patch.onApprove;
    if (patch.repoUrl !== undefined) {
      const u = checkRepoUrl(patch.repoUrl, { allowFile: this.d.publishAllowFile });
      if (!u.ok) throw new GateError("invalid", u.error);
      next.repoUrl = u.url;
    }
    if (patch.branch !== undefined) {
      const bad = checkBranch(patch.branch);
      if (bad) throw new GateError("invalid", bad);
      next.branch = patch.branch.trim();
    }
    if (next.enabled && next.repoUrl === "") throw new GateError("invalid", "сначала задайте адрес репозитория");
    if (sameSettings(cur, next)) return cur;
    const widens = (next.enabled && !cur.enabled) || next.repoUrl !== cur.repoUrl || next.branch !== cur.branch || (next.onApprove && !cur.onApprove);
    if (widens) {
      if (code === undefined) throw new GateError("invalid_code", "включение публикации, смена адреса или ветки и публикация при одобрении требуют кода");
      this.touch("publish.settings", code);
    }
    this.store.setPublishSettings(next);
    this.store.log("publish.settings", null, null, { from: cur, to: next, touched: widens });
    return next;
  }

  // ---- views --------------------------------------------------------------
  currentStep(): number {
    return stepAt(this.now);
  }
}
