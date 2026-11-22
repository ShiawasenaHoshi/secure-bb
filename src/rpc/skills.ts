// The RPCs about skills: scan, approve, remove, and the trusted sources of skills.
import { rpcContract } from "../contract.js";
import type { ExperimentalPluginRpcHandlersWithContext } from "@get-bb/plugin-sdk";
import type { RpcCtx } from "./guard-helpers.js";

export function skillsRpc(c: RpcCtx) {
  const { bb, changed, gate, needCode, skillGuard, watch, wrap } = c;
  return {
    "skills.scan": wrap(async () => {
      await watch.scan();
      changed();
      return { ok: true as const };
    }),
    "skills.approve": wrap(async ({ id, code, session, acknowledgeBlock }) => {
      const proof = gate.proofFor("skills.approve", { code, session }, { escalate: acknowledgeBlock === true });
      const r = await skillGuard.approve(id, proof, { acknowledgeBlock });
      await watch.scan().catch((e) => bb.log.warn(`scan after skill approval failed: ${String(e)}`));
      changed();
      return { ok: true as const, note: r.note };
    }),
    "skills.remove": wrap(async ({ id }) => {
      await skillGuard.removeQueued(id);
      changed();
      return { ok: true as const };
    }),
    "skills.removed": wrap(({ id }) => skillGuard.removedContent(id)),
    "skills.trusted": wrap(({ code, ...change }) => {
      const sources = skillGuard.setTrustedSource(change, needCode(code));
      changed();
      return { ok: true as const, sources };
    }),
  } satisfies Partial<ExperimentalPluginRpcHandlersWithContext<typeof rpcContract>>;
}
