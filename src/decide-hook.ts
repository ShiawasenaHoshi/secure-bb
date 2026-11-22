// What the gate answers to `plugin.activate`: `decide`, without a guard (`decideUnsafe`) and over one (`decideGuarded`).
// Rights are compared by `windowAllows` (guard/src/trust.ts); here only what the guard cannot see is added: the thread, a damaged snapshot, a polluted tree, the AI flag.
import { realpath, stat } from "node:fs/promises";
import { BLOCKED_REASON, bySeverity, localCheckKey, summarize } from "./decision.js";
import { capabilityTokens, grown, windowAllows, type Rights } from "../guard/src/trust.ts";
import type { GuardLookup, GuardPort } from "./guardlink.js";
import { T } from "./text.js";
import type { ProposalRow } from "./store.js";
import { hashTree, isInsideSnapshots } from "./tree.js";
import { fullRights, type HookCtx, type Decision, TAMPERED_REASON, UNSAFE_DIR_REASON, GUARD_WINDOW_UNBOUND, isOpen, REJECTED_BY_PERSON } from "./gate-types.js";
import { GateQueue } from "./gate-queue.js";

export class GateHook extends GateQueue {
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
  protected async verifySnapshot(p: ProposalRow, dir: string): Promise<string | null> {
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
  protected async decideUnsafe(ctx: HookCtx): Promise<Decision> {
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
        // The same rule as the guard's (`windowAllows`); the baseline is the window's own set of tokens (what it was opened on, and what was accepted since).
        const verdict = windowAllows({ tokens: w.caps, review: [] }, fullRights(result));
        const fresh = verdict.newTokens;
        if (verdict.allowed && aiFlag === null) {
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
  protected readonly rejectLogged = new Map<string, number>();
  protected async decideGuarded(ctx: HookCtx, guard: GuardPort): Promise<Decision> {
    let look: GuardLookup;
    try {
      look = await guard.lookup(ctx.pluginId, ctx.contentHash);
    } catch (err) {
      // Fail closed, as the core does when the guard does not answer.
      this.store.logDecision("hold", ctx.pluginId, ctx.contentHash, { version: ctx.version, trigger: ctx.trigger, reason: "guard unreachable", message: err instanceof Error ? err.message : String(err) });
      return { action: "wait", reason: T.agentHeldNoReview };
    }
    // Troubleshooting mode (the owner switched it on at the guard's console): the guard passes everything and writes each decision down. This hook stands aside
    // for as long, with a record of its own: the core asks the guard itself, and a hook that held would keep out what the guard let in.
    if (look.troubleshootUntil > this.now) {
      this.store.logDecision("troubleshoot", ctx.pluginId, ctx.contentHash, { version: ctx.version, trigger: ctx.trigger, until: look.troubleshootUntil, approved: look.approved });
      return { action: "proceed" };
    }
    // The person rejected this version and has not brought it back: "no", no new queue entry, no hold at the guard, and a journal line once an hour per version
    // (the core asks again at every start).
    if (look.rejected && !look.approved) {
      const key = `${ctx.pluginId}:${ctx.contentHash}`;
      if ((this.rejectLogged.get(key) ?? 0) <= this.now - 3_600_000) {
        this.rejectLogged.set(key, this.now);
        this.store.logDecision("reject.repeat", ctx.pluginId, ctx.contentHash, { version: ctx.version, trigger: ctx.trigger, reason: "rejected by the person" });
      }
      return { action: "reject", message: REJECTED_BY_PERSON };
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
    // Rights are the guard's to compare (`windowAllows`, in its own `windowRefuses`: it reads the version itself and holds with a stop); this hook adds
    // only what the guard cannot see: the thread (above), a damaged snapshot, a polluted tree, and the AI scan's flag.
    if (aiFlag !== null) return hold(aiFlag, summary); // the window stays open (spec §0, §6)
    return { action: "proceed" }; // the guard approves it by the window and journals that
  }
  /** Check results are put on the guard's queue entry for the page. Never awaited by the hook and never throws. */
  protected annotate(guard: GuardPort, ctx: HookCtx, findings: Record<string, unknown>): void {
    void guard.annotate({ contentHash: ctx.contentHash }, { ...findings, from: "secure-bb", version: ctx.version }).catch(() => undefined);
  }
}
