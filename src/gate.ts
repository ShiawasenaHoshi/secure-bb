// The gate: decides `plugin.activate`, owns approvals, trust windows and the
// touch (TOTP) rules. Pure logic over Store + injected clock; no bb imports,
// so it is testable without a server.
import { readFileSync } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { runChecks as defaultRunChecks, type CheckResult } from "./checks/index.js";
import { BLOCKED_REASON, bySeverity, capabilityTokens, localCheckKey, newTokens, summarize } from "./decision.js";
import { describeIssues, serverIds, writableByOthers, type PermIssue } from "./perms.js";
import { validateSecondModel } from "./scan/commands.js";
import type { TaintAssessment } from "./taint/monitor.js";
import type { AiSettings } from "./scan/types.js";
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
  /** Stage 3: a version that did not come through `propose` is held (the "scan externals" option). Must not throw. */
  onExternal?: (ctx: HookCtx) => void;
}

export type TotpState = "none" | "pending" | "locked" | "external" | "external-broken";

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
  totpState(): TotpState {
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

  private recordFailure(purpose: string): never {
    this.store.recordAttempt(false, purpose);
    const epoch = Number(this.store.getMeta("fail_epoch") ?? 0);
    const since = Math.max(this.now - HOUR_MS, epoch);
    if (this.store.failuresSince(since) >= MAX_FAILURES) {
      this.store.setMeta("blocked_until", String(this.now + HOUR_MS));
      this.store.setMeta("fail_epoch", String(this.now));
      this.store.log("totp.blocked", null, null, { purpose });
    }
    this.store.log("totp.fail", null, null, { purpose });
    throw new GateError("invalid_code", "invalid or already used code");
  }

  /**
   * A touch: proves a human holds the TOTP secret. Each call consumes one
   * 30-second step; a step (or any older one) is never accepted twice.
   */
  touch(purpose: string, code: string): void {
    const state = this.totpState();
    if (state === "none" || state === "pending") throw new GateError("not_registered", "no second factor is registered yet; register one on the secure-bb page");
    if (state === "external-broken") throw new GateError("not_registered", "the external TOTP secret file cannot be read");
    this.assertNotBlocked();
    const external = state === "external";
    const secret = external ? this.readExternal()! : this.store.totp()!.secret;
    const last = external ? this.store.externalLastStep() : this.store.totp()!.lastStep;
    const res = verifyTotp(secret, code, this.now, last);
    if (!res.ok) this.recordFailure(purpose);
    this.store.recordAttempt(true, purpose);
    if (external) this.store.setExternalLastStep(res.step);
    else this.store.setLastStep(res.step);
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
      if (reviews.length === 0 && result.capabilities.length === 0 && aiFlag === null) {
        // Safe class (§5.2), our own immutable snapshot, clean checks: no touch needed.
        this.recordApproval(ctx, "auto", null, proposal);
        return { action: "proceed" };
      }
      const why =
        result.capabilities.length > 0
          ? `вне безопасного класса: ${result.capabilities.map((c) => c.kind).join(", ")}`
          : reviews.length > 0
            ? `проверки требуют ревью: ${summarize(reviews)}`
            : aiFlag!;
      return this.hold(ctx, proposal, why);
    }
    return this.holdExternal(ctx, proposal, reason ?? aiFlag);
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
  approveQueue(queueId: number, code: string, opts: { acknowledgeBlock?: boolean } = {}): { installDir: string | null; pluginId: string; enable: boolean } {
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
    return { installDir, pluginId: q.pluginId, enable: q.kind === "afterfact" };
  }

  dismissQueue(queueId: number, code: string): void {
    const q = this.requireHeld(queueId);
    this.touch(`dismiss:${q.pluginId}`, code);
    this.store.setQueueStatus(q.id, "dismissed");
    this.store.log("dismissed", q.pluginId, q.contentHash, { review: q.id });
  }

  private requireHeld(queueId: number): QueueRow {
    const q = this.store.getQueue(queueId);
    if (!q) throw new GateError("not_found", `no review #${queueId}`);
    if (q.status !== "held") throw new GateError("conflict", `review #${queueId} is already ${q.status}`);
    return q;
  }

  revoke(approvalId: number, code: string): ApprovalRow {
    const a = this.store.getApproval(approvalId);
    if (!a || a.revokedAt !== null) throw new GateError("not_found", "no such active approval");
    this.touch(`revoke:${a.pluginId}`, code);
    this.store.revokeApproval(approvalId);
    if (a.localHash) this.store.unpinProposals(a.pluginId, a.localHash);
    this.store.log("revoked", a.pluginId, a.contentHash, { version: a.version });
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

  openWindow(queueId: number, code: string, scope?: "tree" | "thread"): WindowRow {
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

  closeWindow(windowId: number, code: string): void {
    const w = this.store.getWindow(windowId);
    if (!w || w.closedAt !== null) throw new GateError("not_found", "no such open window");
    this.touch(`window.close:${w.pluginId}`, code);
    this.store.closeWindow(windowId, "closed");
    this.store.log("window.close", w.pluginId, null, { windowId });
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
      (next.cfgMode === "sliding" && cur.cfgMode === "fixed");
    if (widens) {
      if (code === undefined) throw new GateError("invalid_code", "widening the policy needs a code");
      this.touch("policy", code);
    }
    this.store.setPolicy(next);
    this.store.log("policy", null, null, { from: cur, to: next, touched: widens });
    return next;
  }

  // ---- AI scan settings (stage 3, spec §8) -------------------------------------
  /**
   * Changes the optional AI scan. Everything is off by default; switching something on needs no code
   * (the module only adds suspicion), switching an enabled option off does: that is the direction that weakens the gate.
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
    const switchedOff =
      (cur.enabled && !next.enabled) ||
      (cur.autoFreeze && !next.autoFreeze) ||
      (cur.autoExternal && !next.autoExternal) ||
      (cur.second && !next.second) ||
      cur.freezePlugins.some((id) => !next.freezePlugins.includes(id));
    if (switchedOff) {
      if (code === undefined) throw new GateError("invalid_code", "выключение включённой опции ИИ-скана требует кода");
      this.touch("ai.settings", code);
    }
    this.store.setAiSettings(next);
    this.store.log("ai.settings", null, null, { from: cur, to: next, touched: switchedOff });
    return next;
  }

  // ---- views --------------------------------------------------------------
  currentStep(): number {
    return stepAt(this.now);
  }
}
