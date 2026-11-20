// The gate: decides `plugin.activate`, owns approvals, trust windows and the
// touch (TOTP) rules. Pure logic over Store + injected clock; no bb imports,
// so it is testable without a server.
import { readFileSync } from "node:fs";
import { realpath, stat } from "node:fs/promises";
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
}

export type TotpState = "none" | "pending" | "locked" | "external" | "external-broken";

const HOUR_MS = 3_600_000;
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

  // ---- the hook -----------------------------------------------------------
  async decide(ctx: HookCtx): Promise<Decision> {
    try {
      return await this.decideUnsafe(ctx);
    } catch (err) {
      // Fail closed: any internal error holds the plugin.
      this.store.log("hook.error", ctx.pluginId, ctx.contentHash, { message: err instanceof Error ? err.message : String(err) });
      return { action: "wait", reason: "held by secure-bb: internal error" };
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
      this.store.touchApproval(approved.id);
      this.store.supersedeTampered(ctx.pluginId, ctx.contentHash);
      return { action: "proceed" };
    }

    let proposal: ProposalRow | null = null;
    let reason: string | null = null;
    if (await isInsideSnapshots(this.d.snapshotsRoot, ctx.rootDir)) {
      const real = await realpath(ctx.rootDir);
      proposal = this.store.proposalByDir(real);
      if (proposal && proposal.pluginId === ctx.pluginId) {
        reason = await this.verifySnapshot(proposal, real);
        if (reason === null) {
          const w = proposal.windowId === null ? null : this.store.getWindow(proposal.windowId);
          const windowOpen = w !== null && w.pluginId === ctx.pluginId && isOpen(w, this.now);
          if (proposal.loadedAt !== null) {
            // Already approved and loaded once: still pinned. (bb's own hash
            // changes after a build, so the same snapshot arrives under a new hash.)
            this.recordApproval(ctx, "pin", null, proposal);
            return { action: "proceed" };
          }
          if (proposal.touchApprovedAt !== null) {
            this.recordApproval(ctx, "touch", null, proposal);
            return { action: "proceed" };
          }
          if (windowOpen) {
            this.recordApproval(ctx, "window", w!.id, proposal);
            this.slide(w!);
            return { action: "proceed" };
          }
        }
      }
    }

    const q = this.store.upsertQueue({
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
    this.store.log("hold", ctx.pluginId, ctx.contentHash, { review: q.id, version: ctx.version, trigger: ctx.trigger, ...(reason ? { reason } : {}) });
    return { action: "wait", reason: `held by secure-bb: review #${q.id}` };
  }

  /** After bb installed (and built) a snapshot: remember the built tree so later loads can be verified. */
  async recordBuilt(dir: string): Promise<void> {
    const real = await realpath(dir);
    const p = this.store.proposalByDir(real);
    if (!p) return;
    if ((await hashTree(real)) !== p.localHash) return; // source changed: never bless it
    this.store.setProposalBuilt(p.id, await hashTree(real, { includeDist: true }));
  }

  private recordApproval(ctx: HookCtx, via: "touch" | "window" | "pin", windowId: number | null, proposal: ProposalRow | null): ApprovalRow {
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
    this.store.resolveQueueByHash(ctx.contentHash);
    // A touch-approved proposal was already logged as "approved.touch" at approval time; its load is a separate event.
    this.store.log(via === "window" ? "approved.window" : via === "pin" ? "approved.pin" : "approved.load", ctx.pluginId, ctx.contentHash, {
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
  approveQueue(queueId: number, code: string): { installDir: string | null; pluginId: string; enable: boolean } {
    const q = this.requireHeld(queueId);
    this.touch(`approve:${q.pluginId}`, code);
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
    this.store.log("approved.touch", q.pluginId, q.contentHash, { review: q.id, version: q.version });
    let installDir: string | null = null;
    if (q.proposalId !== null) {
      this.store.approveProposal(q.proposalId);
      if (!q.contentHash) installDir = this.store.getProposal(q.proposalId)?.snapshotDir ?? null;
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
      frozen++;
    }
    return frozen;
  }

  openWindow(queueId: number, code: string, scope?: "tree" | "thread"): WindowRow {
    const q = this.store.getQueue(queueId);
    if (!q) throw new GateError("not_found", `no review #${queueId}`);
    if (!q.threadId) throw new GateError("invalid", "this entry did not come from a thread, so a trust window cannot be bound to it; approve the version instead");
    this.touch(`window.open:${q.pluginId}`, code);
    this.sweep();
    for (const old of this.store.unclosedWindows()) {
      if (old.pluginId === q.pluginId) this.store.closeWindow(old.id, "reopened");
    }
    const policy = this.store.policy();
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
    if (threadId === w.threadId) return w;
    if (w.scope === "thread") return null;
    const ancestors = await this.d.threads.ancestors(threadId);
    return ancestors.includes(w.threadId) ? w : null;
  }

  // ---- policy -------------------------------------------------------------
  setPolicy(patch: Partial<Policy>, code: string | undefined): Policy {
    const cur = this.store.policy();
    const next: Policy = { ...cur, ...patch };
    if (next.windowMin < 1 || next.capMin < 1 || next.capMin > 1440 || next.windowMin > next.capMin)
      throw new GateError("invalid", "window size must be at least 1 minute and not exceed the ceiling (at most 24 hours)");
    const widens =
      next.windowMin > cur.windowMin ||
      next.capMin > cur.capMin ||
      (next.mode === "sliding" && cur.mode === "fixed") ||
      (next.scope === "tree" && cur.scope === "thread");
    if (widens) {
      if (code === undefined) throw new GateError("invalid_code", "widening the policy needs a code");
      this.touch("policy", code);
    }
    this.store.setPolicy(next);
    this.store.log("policy", null, null, { from: cur, to: next, touched: widens });
    return next;
  }

  // ---- views --------------------------------------------------------------
  currentStep(): number {
    return stepAt(this.now);
  }
}
