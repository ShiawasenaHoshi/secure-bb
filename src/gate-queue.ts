// The queue of held versions and the approvals made from it: hold, record an approval, approve, dismiss, revoke, and a snapshot recorded as built.
import { realpath } from "node:fs/promises";
import { type Proof } from "./approval.js";
import { BLOCKED_REASON, bySeverity } from "./decision.js";
import { capabilityTokens, grown } from "../guard/src/trust.ts";
import { GateError } from "./errors.js";
import { T } from "./text.js";
import type { ApprovalRow, ProposalRow, QueueRow } from "./store.js";
import { hashTree } from "./tree.js";
import { fullRights, type HookCtx, type Decision, UNSAFE_DIR_REASON, isOpen } from "./gate-types.js";
import { GateWindows } from "./gate-windows.js";

export class GateQueue extends GateWindows {
  protected queue(ctx: HookCtx, proposal: ProposalRow | null, reason: string | null): QueueRow {
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
  protected holdExternal(ctx: HookCtx, proposal: ProposalRow | null, reason: string | null): Decision {
    if (proposal === null) {
      try {
        this.d.onExternal?.(ctx);
      } catch {
        /* optional */
      }
    }
    return this.hold(ctx, proposal, reason);
  }
  protected hold(ctx: HookCtx, proposal: ProposalRow | null, reason: string | null): Decision {
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
  protected recordApproval(ctx: HookCtx, via: ApprovalRow["via"], windowId: number | null, proposal: ProposalRow | null): ApprovalRow {
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
      this.store.log("window.caps", q.pluginId, q.contentHash, { windowId: w.id, added: grown({ tokens: w.caps, review: [] }, fullRights(result)).tokens });
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
  protected requireHeld(queueId: number): QueueRow {
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
}
