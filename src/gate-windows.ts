// Trust windows on this side: open, close, slide, sweep, the thread they cover and the pollution of its tree; with a guard, the shadow rows kept in step with the guard's windows.
import { realpath } from "node:fs/promises";
import { type CheckResult } from "./checks/index.js";
import { type Proof } from "./approval.js";
import { BLOCKED_REASON, bySeverity, localCheckKey } from "./decision.js";
import { capabilityTokens } from "../guard/src/trust.ts";
import type { TaintAssessment } from "./taint/monitor.js";
import type { GuardProof, GuardState } from "./guardlink.js";
import { GateError } from "./errors.js";
import type { ProposalRow, WindowRow } from "./store.js";
import { isOpen } from "./gate-types.js";
import { GateChecks } from "./gate-checks.js";

export class GateWindows extends GateChecks {
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
  protected slide(w: WindowRow): void {
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
    let proposal: ProposalRow | null = null;
    try {
      proposal = this.store.proposalByDir(await realpath(entry.rootDir));
    } catch {
      proposal = null;
    }
    if (!proposal || proposal.pluginId !== entry.pluginId || !proposal.threadId)
      throw new GateError("invalid", "this entry did not come from a thread, so a trust window cannot be bound to it; approve the version instead");
    return this.openGuardWindowFor(entry.pluginId, proposal, this.store.getCheck(entry.contentHash)?.result ?? null, proof, scope);
  }
  /**
   * «Открыть окно на N мин» on the plugin's own row (no waiting version): the window is bound to the thread of the plugin's latest proposal.
   * No such thread (the plugin was not put in by an agent through `propose`): no window, and the page says why.
   */
  async openGuardWindowForPlugin(pluginId: string, proof: GuardProof, scope?: "tree" | "thread"): Promise<WindowRow> {
    const proposal = this.store.latestThreadProposal(pluginId);
    if (!proposal) throw new GateError("invalid", "this plugin was not proposed from a thread, so a trust window cannot be bound to it");
    return this.openGuardWindowFor(pluginId, proposal, null, proof, scope);
  }
  protected async openGuardWindowFor(pluginId: string, proposal: ProposalRow, checked: CheckResult | null, proof: GuardProof, scope?: "tree" | "thread"): Promise<WindowRow> {
    const guard = this.d.guard!;
    const entry = { pluginId };
    const found = checked ?? this.store.getCheck(localCheckKey(proposal.localHash))?.result ?? null;
    if (found !== null && bySeverity(found, "block").length > 0)
      throw new GateError("invalid", "this version was blocked by the checks; a window cannot be opened on it (approve the version knowingly, or fix the plugin)");
    const policy = this.store.policy();
    // The thread scope travels with the touch (a passkey signature covers it): the page asked for a challenge with the same one.
    const gw = await guard.openWindow(entry.pluginId, undefined, proof, scope ?? policy.scope);
    for (const old of this.store.unclosedWindows()) if (old.pluginId === entry.pluginId) this.store.closeWindow(old.id, "reopened");
    const w = this.store.insertWindow({
      pluginId: entry.pluginId,
      threadId: proposal.threadId ?? "неизвестен",
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
}
