// The RPCs of the queue of held versions: approve (one, with trust, or a batch), dismiss, the trust windows (open, close), and revoking an approval.
import { windowScopeWidens } from "../../guard/src/policy.ts";
import { rpcContract } from "../contract.js";
import { GateError } from "../errors.js";
import type { ExperimentalPluginRpcHandlersWithContext } from "@get-bb/plugin-sdk";
import type { RpcCtx } from "./guard-helpers.js";

export function queueRpc(c: RpcCtx) {
  const { afterGuardApproval, approveAtGuard, approvePendingProposal, approveQueueFull, batches, bb, changed, entryFacts, gate, guardEntry, guardLink, needGuard, proofOf, proofOrSession, recheck, state, store, wrap } = c;
  return {
    "queue.approve": wrap(async ({ id, code, passkey, session, acknowledgeBlock }) => {
      if (guardLink) {
        const proof = proofOrSession({ code, passkey, session }, acknowledgeBlock === true);
        return id < 0 ? approvePendingProposal(-id, proof, acknowledgeBlock) : approveAtGuard(id, proof, acknowledgeBlock);
      }
      // Lifting a block is the dangerous kind of this RPC: a fresh code, never a session.
      const proof = gate.proofFor("queue.approve", { code, session }, { escalate: acknowledgeBlock === true });
      const note = await approveQueueFull(id, proof, { acknowledgeBlock });
      return { ok: true as const, note };
    }),
    // «Вернуть и доверять источнику»: one operation at the guard — the version AND its source, one touch, one record. Never a session.
    "queue.approveTrust": wrap(async ({ id, code, passkey }) => {
      const link = needGuard();
      const proof = proofOf(code, passkey);
      if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
      if (id < 0) throw new GateError("invalid", "this proposal is not installed yet: approve it first (the source can be trusted from its entry then)");
      const q = await guardEntry(id, true);
      const f = await entryFacts(q);
      if (f.unsafeDir) throw new GateError("invalid", "this version lies in a directory that others can write to; it cannot be approved from there (see the page)", { unsafeDir: true });
      if (f.blocked) throw new GateError("invalid", "this version was stopped by the checks: it is returned on its own card, never together with trusting its source", { blocked: true });
      const r = await link.approveTrust(id, proof);
      await afterGuardApproval(q, f);
      store.log("trust.add", null, null, { entries: [r.entry], with: "approval", review: id, at: "guard" });
      return { ok: true as const, note: `версия одобрена, источник ${r.entry} добавлен в «мои источники»`, entry: r.entry };
    }),
    // Rejecting tightens: no code, in both modes, and no block after wrong codes.
    "queue.dismiss": wrap(async ({ id }) => {
      if (guardLink) {
        if (id < 0) {
          // A local proposal the core has not asked the guard about: only marked, the guard is not touched.
          const lq = store.getQueue(-id);
          if (!lq || lq.status !== "held") throw new GateError("not_found", `no pending proposal #${-id}`);
          store.setQueueStatus(lq.id, "dismissed");
          store.log("dismissed", lq.pluginId, lq.contentHash, { review: lq.id, proposal: true });
          changed();
          return { ok: true as const };
        }
        await guardEntry(id);
        await guardLink.dismiss(id);
        changed();
        return { ok: true as const };
      }
      gate.dismissQueue(id);
      changed();
      return { ok: true as const };
    }),
    "window.open": wrap(async ({ queueId, pluginId, code, passkey, session, scope }) => {
      if (pluginId !== undefined && queueId === undefined) {
        // From the plugin's own row (no waiting version): bound to the thread of its latest proposal.
        if (!guardLink) throw new GateError("invalid", "из строки плагина окно открывается только в режиме сторожа; без него — с карточки версии, которая ждёт решения");
        const proof = proofOrSession({ code, passkey, session }, windowScopeWidens(store.policy().scope, scope));
        if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
        await gate.openGuardWindowForPlugin(pluginId, proof, scope);
        recheck();
        changed();
        return { ok: true as const };
      }
      if (queueId === undefined) throw new GateError("invalid", "queueId or pluginId is needed");
      if (guardLink) {
        // "The whole tree" while the policy says "this thread only" widens the policy: a fresh touch, never a session.
        const proof = proofOrSession({ code, passkey, session }, windowScopeWidens(store.policy().scope, scope));
        if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
        if (queueId < 0) throw new GateError("invalid", "this proposal is not installed yet: approve it (or install it) first, then open a window from the guard's entry");
        await gate.openGuardWindow(await guardEntry(queueId), proof, scope);
        recheck();
        changed();
        return { ok: true as const };
      }
      // A window wider than the policy ("whole tree" when the policy says "this thread only") widens the policy: a fresh code.
      const proof = gate.proofFor("window.open", { code, session }, { escalate: windowScopeWidens(store.policy().scope, scope) });
      gate.openWindow(queueId, proof, scope);
      recheck();
      changed();
      return { ok: true as const };
    }),
    "window.close": wrap(async ({ windowId }) => {
      if (guardLink) {
        await gate.closeGuardWindow(windowId);
        changed();
        return { ok: true as const };
      }
      gate.closeWindow(windowId);
      changed();
      return { ok: true as const };
    }),
    "approval.revoke": wrap(async ({ approvalId }) => {
      let a: { pluginId: string };
      if (guardLink) {
        const found = (await guardLink.state()).approvals.find((x) => x.id === approvalId);
        if (!found) throw new GateError("not_found", "no such active approval");
        await guardLink.revoke({ approvalId });
        store.log("revoked", found.pluginId, found.contentHash, { version: found.version, at: "guard" });
        a = found;
      } else a = gate.revoke(approvalId);
      try {
        await bb.sdk.plugins.disable({ pluginId: a.pluginId });
      } catch (err) {
        bb.log.warn(`could not disable ${a.pluginId} after revoke: ${String(err)}`);
      }
      changed();
      return { ok: true as const };
    }),
    "batch.prepare": wrap(({ items }) => batches.prepare(items)),
    "batch.approve": wrap(async ({ batchId, setHash, code, session, passkey }) => {
      if (guardLink) {
        const proof = proofOrSession({ code, passkey, session });
        if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
        const results = await batches.approveGuarded(batchId, setHash, proof);
        recheck();
        changed();
        return { ok: true as const, results };
      }
      const results = await batches.approve(batchId, setHash, gate.proofFor("batch.approve", { code, session }));
      recheck();
      changed();
      return { ok: true as const, results };
    }),
  } satisfies Partial<ExperimentalPluginRpcHandlersWithContext<typeof rpcContract>>;
}
