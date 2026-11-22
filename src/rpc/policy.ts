// The policy of trust windows (`policy.set`) and the passkey touch: the registration of a key and the challenge for one action.
import { type GuardAction } from "../guardlink.js";
import { MODE_RANK, normalizeEntry } from "../../guard/src/trust.ts";
import { type GuardTouched } from "../approval.js";
import type { Proof } from "../approval.js";
import { rpcContract } from "../contract.js";
import { Gate } from "../gate.js";
import { GateError } from "../errors.js";
import type { ExperimentalPluginRpcHandlersWithContext } from "@get-bb/plugin-sdk";
import type { RpcCtx } from "./guard-helpers.js";

export function policyRpc(c: RpcCtx) {
  const { VERIFIED, agents, changed, gate, guardEntry, guardLink, needGuard, pendingEntry, policyPlan, proofOf, state, store, wrap } = c;
  return {
    "policy.set": wrap(async ({ code, passkey, ...patch }) => {
      if (!guardLink) {
        gate.setPolicy(patch, code);
        changed();
        return { ok: true as const };
      }
      const plan = await policyPlan(patch);
      const proof = proofOf(code, passkey);
      // The guard checks the touch for what it holds (window size, ceiling, mode: widening needs one there). A touch the guard did not
      // need for its part has not been checked by anybody yet; it is checked below if the local part widens.
      let verified = false;
      if (Object.keys(plan.wanted).length > 0) {
        await guardLink.policy(plan.wanted, proof);
        verified = plan.guardWidens && proof !== undefined;
      }
      let mark: GuardTouched | undefined = verified ? VERIFIED : undefined;
      if (!verified && plan.localWidens) {
        // Only the local part (thread scope, configuration windows) widens: then the guard checks the touch for "policy.set".
        if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: this widens the policy");
        await guardLink.touch("policy.set", proof);
        mark = VERIFIED;
      }
      // `Gate.setPolicy` still takes `string | undefined` for its code; the mark is passed as it was before. The signature belongs to the gate (another change): the cast goes when it takes a Proof.
      gate.setPolicy(plan.local, mark as unknown as string | undefined);
      changed();
      return { ok: true as const };
    }),
    "passkey.register": wrap(async (body) => {
      // The guard opens a registration window only when asked on the console; this relays the token and the browser's answer, nothing more.
      return needGuard().passkeyRegister(body);
    }),
    "passkey.challenge": wrap(async (q) => {
      const link = needGuard();
      const out = (action: GuardAction) => link.challenge(action).then((c) => ({ needed: true as const, ...c }));
      switch (q.kind) {
        case "approve": {
          if (q.queueId === undefined) throw new GateError("invalid", "queueId is needed");
          // A proposal the core has not asked the guard about yet is installed first (as approving it would): the touch is for the guard's entry.
          const entry = q.queueId < 0 ? (await pendingEntry(-q.queueId, q.acknowledgeBlock)).entry : await guardEntry(q.queueId);
          return out({ op: "approve", requestId: entry.id, ...(q.acknowledgeBlock === true ? { acknowledgeBlock: true as const } : {}) });
        }
        case "approve.trust": {
          if (q.queueId === undefined || q.queueId < 0) throw new GateError("invalid", "an installed entry of the guard's queue is needed");
          return out({ op: "approve-trust", requestId: (await guardEntry(q.queueId)).id });
        }
        case "session.open":
          return out(q.hour === true ? { op: "session-open", hour: true } : { op: "session-open" });
        case "batch.approve": {
          if (q.batchId === undefined || q.setHash === undefined) throw new GateError("invalid", "batchId and setHash are needed");
          return out({ op: "batch-approve", batchId: q.batchId, setHash: q.setHash });
        }
        case "window.open": {
          if (q.pluginId !== undefined && q.queueId === undefined) {
            if (!store.latestThreadProposal(q.pluginId)) throw new GateError("invalid", "a window is opened for a plugin that an agent put in from a thread");
            return out({ op: "open-window", pluginId: q.pluginId, scope: q.scope ?? store.policy().scope });
          }
          if (q.queueId === undefined || q.queueId < 0) throw new GateError("invalid", "a window is opened from an installed entry of the guard's queue");
          const entry = await guardEntry(q.queueId);
          return out({ op: "open-window", pluginId: entry.pluginId, scope: q.scope ?? store.policy().scope });
        }
        case "policy": {
          const plan = await policyPlan(q);
          if (plan.guardWidens) return out({ op: "policy", patch: plan.wanted });
          if (plan.localWidens) return out({ op: "touch", purpose: "policy.set" });
          return { needed: false as const };
        }
        case "agents.accept": {
          if (q.ids === undefined || q.ids.length === 0) throw new GateError("invalid", "ids are needed");
          return out({ op: "agents-accept", ids: q.ids });
        }
        case "agents.restore": {
          if (q.ids === undefined || q.ids.length !== 1) throw new GateError("invalid", "one difference id is needed");
          return out({ op: "agents-restore", id: q.ids[0]! });
        }
        case "agents.rollbackPart": {
          if (q.ids === undefined || q.ids.length !== 1 || q.partId === undefined || q.fileSha === undefined) throw new GateError("invalid", "the difference, the part and the file hash are needed");
          return out({ op: "agents-rollback-part", id: q.ids[0]!, partId: q.partId, fileSha: q.fileSha });
        }
        case "agents.revokeKept": {
          if (q.ids === undefined || q.ids.length !== 1) throw new GateError("invalid", "the kept change id is needed");
          return out({ op: "agents-revoke-kept", id: q.ids[0]! });
        }
        case "agents.keepPart": {
          if (q.ids === undefined || q.ids.length !== 1 || q.partId === undefined || q.fileSha === undefined || q.danger === undefined) throw new GateError("invalid", "the difference, the part, the file hash and the danger flag are needed");
          return out({ op: "agents-keep-part", id: q.ids[0]!, partId: q.partId, fileSha: q.fileSha, danger: q.danger });
        }
        case "trust.mode": {
          if (q.trustMode === undefined) throw new GateError("invalid", "trustMode is needed");
          const cur = (await link.state()).trust?.mode;
          // Only a weaker mode takes a touch; the guard decides, this only avoids asking for a challenge that will not be used.
          return cur !== undefined && MODE_RANK[q.trustMode] < MODE_RANK[cur] ? out({ op: "trust-mode", mode: q.trustMode }) : { needed: false as const };
        }
        case "trust.add":
        case "trust.migrate": {
          const asked = q.kind === "trust.migrate" ? store.trustedRepos().map((r) => `github:${r}`) : (q.entries ?? []);
          const mine = (await link.state()).trust?.mySources ?? [];
          // The touch is for what is new: the guard signs the entries that are not in the list yet.
          const fresh = [...new Set(asked.map(normalizeEntry).filter((e): e is string => e !== null && !mine.includes(e)))].sort();
          return fresh.length === 0 ? { needed: false as const } : out({ op: "sources-add", entries: fresh });
        }
        default:
          if (q.purpose === undefined) throw new GateError("invalid", "purpose is needed");
          return out({ op: "touch", purpose: q.purpose });
      }
    }),
  } satisfies Partial<ExperimentalPluginRpcHandlersWithContext<typeof rpcContract>>;
}
