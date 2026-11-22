// The RPCs of the config watchdog: scan, accept, roll back, the rollback mode and the «configuration» window.
import { rpcContract } from "../contract.js";
import type { ExperimentalPluginRpcHandlersWithContext } from "@get-bb/plugin-sdk";
import type { RpcCtx } from "./guard-helpers.js";

export function watchRpc(c: RpcCtx) {
  const { changed, gate, watch, wrap } = c;
  return {
    "watch.scan": wrap(async () => {
      await watch.scan();
      changed();
      return { ok: true as const };
    }),
    "watch.acceptAll": wrap(async ({ code, session }) => {
      const { items } = await watch.acceptAll(gate.proofFor("watch.acceptAll", { code, session }));
      changed();
      return { ok: true as const, items };
    }),
    "watch.accept": wrap(async ({ id, code, session }) => {
      await watch.acceptDrift(id, gate.proofFor("watch.accept", { code, session }));
      changed();
      return { ok: true as const };
    }),
    "watch.rollback": wrap(async ({ id, code, session }) => {
      await watch.rollbackDrift(id, gate.proofFor("watch.rollback", { code, session }));
      changed();
      return { ok: true as const };
    }),
    "watch.rollbackMode": wrap(({ enabled, code }) => {
      watch.setRollback(enabled, code);
      changed();
      return { ok: true as const };
    }),
    "watch.window.open": wrap(async ({ scopes, code, session }) => {
      await watch.openWindow(scopes, gate.proofFor("watch.window.open", { code, session }));
      changed();
      return { ok: true as const };
    }),
    "watch.window.close": wrap(async ({ windowId }) => {
      await watch.closeWindow(windowId);
      changed();
      return { ok: true as const };
    }),
  } satisfies Partial<ExperimentalPluginRpcHandlersWithContext<typeof rpcContract>>;
}
