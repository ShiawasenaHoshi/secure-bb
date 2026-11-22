// The helpers every RPC shares: `wrap` (a refusal for the page), and the helpers of guard mode — the guard's entry for an id, the proof a call carries, the approval at the guard,
// `withGuardTouch` (a code or touch is checked at the guard before the handler runs) and `policyPlan`. They decide nothing themselves: the guard does.
import { join } from "node:path";
import { experimental_PluginRpcRefusal } from "@get-bb/plugin-sdk";
import { GuardLink, GuardLinkError, type GuardPolicy, type GuardProof, type GuardQueueEntry, type PasskeyAssertion } from "../guardlink.js";
import { guardPolicyWidens, localPolicyWidens } from "../../guard/src/policy.ts";
import { capabilityTokens, liftBlock } from "../../guard/src/trust.ts";
import { localCheckKey } from "../decision.js";
import { mintListProof, type GuardTouched } from "../approval.js";
import { realpath } from "node:fs/promises";
import { BatchService, type BatchSource, type GuardBatch } from "../batch.js";
import { SkillError } from "../skills/guard.js";
import { createHash } from "node:crypto";
import { BLOCKED_REASON, bySeverity } from "../decision.js";
import { Gate, UNSAFE_DIR_REASON } from "../gate.js";
import { GateError } from "../errors.js";
import { ScanError } from "../scan/scanner.js";
import { SentinelError } from "../sentinel/sentinel.js";
import { WatchError } from "../watch/watchdog.js";
import type { Core } from "./core.js";
import type { Services } from "./services.js";

function refusal(err: unknown): never {
  if (err instanceof GateError) {
    const code = err.code === "invalid_code" || err.code === "blocked" ? "forbidden" : err.code === "not_registered" ? "conflict" : err.code;
    throw new experimental_PluginRpcRefusal({ code, message: err.message });
  }
  if (err instanceof GuardLinkError) {
    const code = err.code === "invalid_code" || err.code === "invalid_passkey" || err.code === "blocked" ? "forbidden" : err.code === "not_found" || err.code === "invalid" ? err.code : "conflict";
    throw new experimental_PluginRpcRefusal({ code, message: err.message });
  }
  if (err instanceof ScanError) throw new experimental_PluginRpcRefusal({ code: err.code === "invalid" ? "invalid" : "conflict", message: err.message });
  if (err instanceof SentinelError) throw new experimental_PluginRpcRefusal({ code: err.code === "invalid_code" ? "forbidden" : err.code, message: err.message });
  if (err instanceof WatchError) throw new experimental_PluginRpcRefusal({ code: err.code, message: err.message });
  if (err instanceof SkillError) throw new experimental_PluginRpcRefusal({ code: err.code, message: err.message });
  throw err;
}

export function createGuardHelpers(c: Core & Services) {
  const { agents, approveQueueFull, bb, changed, gate, guardLink, now, publisher, recheck, skillGuard, state, store, watch } = c;
  // ---- RPC ---------------------------------------------------------------
  const wrap = <A, R>(fn: (input: A) => R | Promise<R>) => async (input: A): Promise<R> => {
    try {
      return await fn(input);
    } catch (err) {
      return refusal(err);
    }
  };

  // ---- guard mode helpers ------------------------------------------------------------------------------------------
  /** A code the guard has already checked (once, for the call that carries it): the mark `Gate.touch` takes without looking at a secret. */
  const VERIFIED: GuardTouched = mintListProof();
  /** A `code` that is the mark of the guard's touch (the contract types it as a string; only this module has the mark). */
  const guardTouched = (code: unknown): code is GuardTouched => code === VERIFIED;
  /** Routes that always need a touch: with neither a code nor a passkey they are refused the way a wrong code is, but without counting it. */
  const needCode = (code: string | undefined): string => {
    if (code === undefined) throw new GateError("invalid_code", "a code is needed (in guard mode, a passkey touch works too)");
    return code;
  };
  const needGuard = (): GuardLink => {
    if (!guardLink) throw new GateError("invalid", "not in guard mode");
    return guardLink;
  };
  /** The held entry of the guard's queue with this id (the page's ids are the guard's in guard mode). */
  /** An entry waiting for a decision; with `orRejected` also one the person rejected («Вернуть» in Quarantine approves it with a touch). */
  const guardEntry = async (id: number, orRejected = false): Promise<GuardQueueEntry> => {
    const st = await needGuard().state();
    const q = st.queue.find((x) => x.id === id);
    if (!q) throw new GateError("not_found", `no review #${id}`);
    if (q.status !== "held" && !(orRejected && q.status === "dismissed")) throw new GateError("conflict", `review #${id} is already ${q.status}`);
    return q;
  };
  const proposalOfEntry = async (q: { rootDir: string; pluginId: string }) => {
    for (const dir of [q.rootDir, await realpath(q.rootDir).catch(() => null)]) {
      const p = dir ? store.proposalByDir(dir) : null;
      if (p && p.pluginId === q.pluginId) return p;
    }
    return null;
  };
  /** What the checks and the hook said about an entry (kept here, not at the guard: the guard cannot vouch for it). */
  const entryFacts = async (q: GuardQueueEntry) => {
    const proposal = await proposalOfEntry(q);
    const result = store.getCheck(q.contentHash)?.result ?? (proposal ? store.getCheck(localCheckKey(proposal.localHash))?.result : null) ?? null;
    const note = q.annotation?.findings as { reason?: unknown } | null | undefined;
    const reason = typeof note?.reason === "string" ? note.reason : null;
    return {
      proposal,
      result,
      unsafeDir: reason?.startsWith(UNSAFE_DIR_REASON) ?? false,
      blocked: (reason?.startsWith(BLOCKED_REASON) ?? false) || (result !== null && bySeverity(result, "block").length > 0),
    };
  };
  /** What a touch is spent on at the guard: a passkey assertion if the page sent one, else the code. */
  const proofOf = (code: string | undefined, passkey: PasskeyAssertion | undefined): GuardProof | undefined => (passkey !== undefined ? { passkey } : code);
  /**
   * What a routine RPC of the page may use at the guard: a passkey, else a code, else the token of an approval session (the guard checks which of them
   * covers the action: a session covers routine actions only, and lifting a block never). `fresh`: this call is the dangerous kind — a session is no good.
   */
  const proofOrSession = (input: { code?: string; passkey?: PasskeyAssertion; session?: string }, fresh = false): GuardProof | undefined => {
    const p = proofOf(input.code, input.passkey);
    if (p !== undefined) return p;
    if (input.session === undefined) return undefined;
    if (fresh) throw new GateError("invalid_code", "this action needs a fresh code or a touch: a session does not cover it");
    return { session: input.session };
  };
  /** Guard mode, lists: what the guard's own entry is, in the words of the list (and what to do after the guard approved it). */
  const guardBatchSeen = new Map<number, { q: GuardQueueEntry; facts: Awaited<ReturnType<typeof entryFacts>> }>();
  const describeGuardEntry = async (id: number) => {
    const q = await guardEntry(id).catch(() => null);
    if (!q) return null;
    const f = await entryFacts(q);
    if (f.unsafeDir) return { skip: "каталог доступен на запись другим: одобрить нельзя, пока его не исправят" };
    if (f.blocked) return { skip: "заблокировано проверками: снимается отдельно, с подтверждением риска и свежим касанием" };
    guardBatchSeen.set(id, { q, facts: f });
    return {
      fingerprint: fingerprint(q.pluginId, q.version, q.contentHash, q.source, q.rootDir),
      label: `${q.pluginId}@${q.version}`,
      detail: [q.note, f.result ? `возможности: ${f.result.capabilities.map((c) => c.kind).join(", ") || "нет"}` : "проверки не завершены"].filter(Boolean).join(" · "),
    };
  };
  /**
   * A proposal the core has not asked the guard about yet (nothing installed: the checks stopped it before install). What a human approves
   * is always the guard's entry for the hash the CORE computes, never a key of ours: so the snapshot is installed first, the guard's entry
   * (made when the core asks) is waited for, and that entry is what a touch is spent on. Nothing is spent before the entry exists.
   */
  const pendingEntry = async (localId: number, acknowledgeBlock: boolean | undefined): Promise<{ entry: GuardQueueEntry; localId: number }> => {
    const link = needGuard();
    const lq = store.getQueue(localId);
    if (!lq || lq.status !== "held" || lq.proposalId === null) throw new GateError("not_found", `no pending proposal #${localId}`);
    const proposal = store.getProposal(lq.proposalId);
    if (!proposal) throw new GateError("not_found", "the proposal is gone");
    const blocked = lq.reason?.startsWith(BLOCKED_REASON) ?? false;
    if (blocked && !acknowledgeBlock) throw new GateError("invalid", "this version was blocked by the checks; confirm that you accept the risk to approve it anyway", { blocked: true });
    const snap = await realpath(proposal.snapshotDir);
    const find = async (): Promise<GuardQueueEntry | null> => {
      for (const q of (await link.state()).queue) {
        if (q.status !== "held" || q.pluginId !== proposal.pluginId) continue;
        if ((await realpath(q.rootDir).catch(() => q.rootDir)) === snap) return q;
      }
      return null;
    };
    let entry = await find();
    if (!entry) {
      await bb.sdk.plugins.install({ source: proposal.snapshotDir });
      await gate.recordBuilt(proposal.snapshotDir).catch((e) => bb.log.warn(`recordBuilt failed: ${String(e)}`));
      for (let i = 0; i < 20 && !entry; i++) {
        entry = await find();
        if (!entry) await new Promise((r) => setTimeout(r, 250));
      }
    }
    if (!entry) throw new GateError("conflict", "the core has not asked the guard about this snapshot yet; try again in a moment (the touch was not spent)");
    return { entry, localId: lq.id };
  };
  const approvePendingProposal = async (localId: number, proof: GuardProof | undefined, acknowledgeBlock: boolean | undefined): Promise<{ ok: true; note: string }> => {
    if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
    const { entry, localId: lid } = await pendingEntry(localId, acknowledgeBlock);
    const res = await approveAtGuard(entry.id, proof, acknowledgeBlock);
    store.setQueueStatus(lid, "approved");
    return res;
  };
  const approveAtGuard = async (id: number, proof: GuardProof | undefined, acknowledgeBlock: boolean | undefined): Promise<{ ok: true; note: string }> => {
    const link = needGuard();
    if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
    const q = await guardEntry(id, true);
    const f = await entryFacts(q);
    if (f.unsafeDir) throw new GateError("invalid", "this version lies in a directory that others can write to; it cannot be approved from there (see the page)", { unsafeDir: true });
    if (f.blocked && !acknowledgeBlock) throw new GateError("invalid", "this version was blocked by the checks; confirm that you accept the risk to approve it anyway", { blocked: true });
    // The guard's own facts (the same function it applies): a hard flag it found, or a version it did not read, is lifted only with the page's «accept the risk» and a fresh touch.
    const lift = liftBlock(q, null);
    if (lift.never) throw new GateError("invalid", "the directory's hash did not match the request's: this version is never approved (reinstall the plugin from its source)");
    if (lift.needsAck && !acknowledgeBlock) throw new GateError("invalid", "the guard found a hard flag in this version or did not read it; confirm that you accept the risk to approve it anyway", { blocked: true });
    // Lifting a stop is always a fresh touch: the guard also refuses a session for it, in Strict mode, and on a hash mismatch (here only the way is shortened).
    if (acknowledgeBlock === true && typeof proof === "object" && "session" in proof) throw new GateError("invalid_code", "lifting a block needs a fresh code or a touch: a session does not cover it");
    await link.approve(id, proof, { acknowledgeBlock: acknowledgeBlock === true });
    await afterGuardApproval(q, f);
    return { ok: true as const, note: "approved at the guard" };
  };
  /** What follows an approval the guard made (one by one or in a list): the plugin's own records, the window's set, the publisher, the page. */
  const afterGuardApproval = async (q: GuardQueueEntry, f: Awaited<ReturnType<typeof entryFacts>>): Promise<void> => {
    if (f.blocked) store.log("block.lifted", q.pluginId, q.contentHash, { review: q.id, version: q.version, rules: f.result ? bySeverity(f.result, "block").map((x) => x.rule) : [] });
    // A capability accepted with a code inside an open window becomes part of the window's set; the window stays open.
    const w = store.unclosedWindows().find((x) => x.pluginId === q.pluginId && x.guardWindowId !== null);
    if (w && f.result) store.setWindowCaps(w.id, [...new Set([...w.caps, ...capabilityTokens(f.result)])].sort());
    store.log("approved.guard", q.pluginId, q.contentHash, { review: q.id, version: q.version });
    if (f.proposal) publisher.onApproved(f.proposal.id);
    recheck();
    changed();
  };

  /**
   * In guard mode a code that arrives with any RPC is checked by the guard first (it consumes the code there: the secret is not here),
   * and the handler then runs with the mark that says so. RPCs that need more than that (they act at the guard) do it themselves.
   */
  const OWN_GUARD_PATH = new Set(["queue.approve", "queue.approveTrust", "batch.approve", "window.open", "policy.set", "alive.review", "session.open", "totp.begin", "totp.confirm", "agents.accept", "agents.restore", "agents.keepPart", "agents.rollbackPart", "agents.revokeKept", "trust.mode", "trust.add", "trust.migrate"]);
  const withGuardTouch = <T extends object>(handlers: T): T => {
    const out: Record<string, unknown> = {};
    if (!guardLink) {
      // A passkey is the guard's: without one there is nothing to check it against, and it must not slip through as "no code".
      for (const [name, fn] of Object.entries(handlers) as Array<[string, (input: any) => unknown]>)
        out[name] = async (input: any) => {
          if (input && typeof input === "object" && input.passkey !== undefined) return refusal(new GateError("invalid", "passkeys need the decision guard; this bb has none (use a code)"));
          return fn(input);
        };
      return out as T;
    }
    for (const [name, fn] of Object.entries(handlers) as Array<[string, (input: any) => unknown]>) {
      out[name] = OWN_GUARD_PATH.has(name)
        ? fn
        : async (input: any) => {
            // A passkey touch is checked at the guard for the action "touch <this RPC>" and wins over a code that came with it.
            let proof: GuardProof | undefined = input && typeof input === "object" ? (input.passkey !== undefined ? { passkey: input.passkey as PasskeyAssertion } : typeof input.code === "string" ? input.code : undefined) : undefined;
            // A routine RPC of the plugin (accept a difference, approve a skill…) may use the approval session instead: the guard checks the token and that the action is
            // routine. The dangerous kind of it (lifting a block) never does. The schema already refuses a token on the RPCs that are not routine.
            if (proof === undefined && input && typeof input === "object" && typeof input.session === "string" && input.acknowledgeBlock !== true) proof = { session: input.session };
            if (proof !== undefined) {
              try {
                await guardLink.touch(name, proof);
              } catch (err) {
                return refusal(err);
              }
              const { passkey: _p, session: _s, ...rest } = input;
              return fn({ ...rest, code: VERIFIED });
            }
            return fn(input);
          };
    }
    return out as T;
  };

  /**
   * What a policy change means in guard mode. Window size, ceiling and mode are the guard's (widening needs a touch there); thread scope and the
   * configuration windows are this plugin's; "safe class passes without a touch" does not exist.
   */
  const policyPlan = async (patch: { windowMin?: number; capMin?: number; mode?: "sliding" | "fixed"; scope?: "tree" | "thread"; cfgWindowMin?: number; cfgCapMin?: number; cfgMode?: "sliding" | "fixed"; autoSafe?: boolean; flowDowngrade?: boolean }) => {
    if (patch.autoSafe === true) throw new GateError("invalid", "в режиме сторожа автопропуск безопасного класса не существует: каждое одобрение даёт человек");
    const cur = await needGuard().policy();
    const wanted: Partial<GuardPolicy> = {};
    if (patch.windowMin !== undefined && patch.windowMin !== cur.windowMin) wanted.windowMin = patch.windowMin;
    if (patch.capMin !== undefined && patch.capMin !== cur.capMin) wanted.capMin = patch.capMin;
    if (patch.mode !== undefined && patch.mode !== cur.mode) wanted.mode = patch.mode;
    const guardWidens = guardPolicyWidens(cur, { ...cur, ...wanted });
    const { windowMin: _w, capMin: _c, mode: _m, autoSafe: _a, ...local } = patch;
    const cp = store.policy();
    const next = { ...cp, ...local };
    const localWidens = localPolicyWidens(cp, next);
    return { wanted, guardWidens, local, localWidens };
  };

  // ---- batch approval: lists of held versions, skills and differences, one code each ----------------------------------
  const fingerprint = (...parts: Array<string | number | null>): string => createHash("sha256").update(JSON.stringify(parts), "utf8").digest("hex");
  const batchSources: Record<"queue" | "skill" | "drift", BatchSource> = {
    queue: {
      describe(id) {
        // Guard mode: the list is fixed at the guard and one touch is spent there on it; the versions are the guard's own entries.
        if (guardLink) return describeGuardEntry(id);
        const q = store.getQueue(id);
        if (!q || q.status !== "held") return null;
        if (q.reason?.startsWith(UNSAFE_DIR_REASON)) return { skip: "каталог доступен на запись другим: одобрить нельзя, пока его не исправят" };
        const result = gate.checkForQueue(q);
        if ((q.reason?.startsWith(BLOCKED_REASON) ?? false) || (result !== null && bySeverity(result, "block").length > 0))
          return { skip: "заблокировано проверками: снимается отдельно, с подтверждением риска и свежим кодом" };
        const proposal = q.proposalId === null ? null : store.getProposal(q.proposalId);
        return {
          fingerprint: fingerprint(q.pluginId, q.version, q.contentHash, q.proposalId, proposal?.localHash ?? null, q.source),
          label: `${q.pluginId}@${q.version}`,
          detail: [q.reason, result ? `возможности: ${result.capabilities.map((c) => c.kind).join(", ") || "нет"}` : "проверки не завершены"].filter(Boolean).join(" · "),
        };
      },
      approve: (id, mark) => approveQueueFull(id, mark),
      // The guard approved the version; the rest is the same as after a single approval at the guard.
      afterGuard: async (id) => {
        const seen = guardBatchSeen.get(id);
        guardBatchSeen.delete(id);
        if (seen) await afterGuardApproval(seen.q, seen.facts);
      },
    },
    skill: {
      describe(id) {
        const row = skillGuard.entry(id);
        if (!row || (row.state !== "held" && row.state !== "alarm" && row.state !== "removed")) return null;
        if (row.decision === "block") return { skip: "жёсткий признак в проверках: одобряется отдельно, с подтверждением риска и свежим кодом" };
        return { fingerprint: fingerprint(row.key, row.hash, row.state, row.decision), label: `${row.name} (${row.scope})`, detail: `${row.state}${row.decision ? ` · ${row.decision}` : ""}` };
      },
      approve: async (id, mark) => {
        const r = await skillGuard.approve(id, mark, {});
        changed();
        return r.note;
      },
    },
    drift: {
      describe(id) {
        const d = store.getDrift(id);
        if (!d || (d.status !== "open" && d.status !== "rollback-failed")) return null;
        return { fingerprint: fingerprint(d.key, d.kind, d.before, d.after), label: d.label, detail: `${d.kind}: ${d.source}` };
      },
      approve: async (id, mark) => {
        const d = store.getDrift(id);
        await watch.acceptDrift(id, mark, { after: d?.after ?? null });
        changed();
        return "принято";
      },
    },
  };
  const guardBatch: GuardBatch | undefined = guardLink
    ? { prepare: (items) => guardLink.batchPrepare(items), approve: (id, hash, proof) => guardLink.batchApprove(id, hash, proof), mark: () => mintListProof() }
    : undefined;
  const batches = new BatchService({ store, now, sources: batchSources, approveList: (purpose, proof) => gate.approveList(purpose, proof), ...(guardBatch ? { guard: guardBatch } : {}) });


  return { wrap, VERIFIED, guardTouched, needCode, needGuard, guardEntry, proposalOfEntry, entryFacts, proofOf, proofOrSession, guardBatchSeen, describeGuardEntry, pendingEntry, approvePendingProposal, approveAtGuard, afterGuardApproval, OWN_GUARD_PATH, withGuardTouch, policyPlan, fingerprint, batchSources, guardBatch, batches };
}
export type GuardHelpers = ReturnType<typeof createGuardHelpers>;
/** What every RPC module, the CLI and the background loop get: the core, the services and the helpers of guard mode. */
export type RpcCtx = Core & Services & GuardHelpers;
