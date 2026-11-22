// The RPCs about trust by source: «мои источники», the mode, the trusted repositories. Widening any of them is a touch, checked at the guard (or by the gate without one).
import { rpcContract } from "../contract.js";
import { GateError } from "../errors.js";
import type { ExperimentalPluginRpcHandlersWithContext } from "@get-bb/plugin-sdk";
import type { RpcCtx } from "./guard-helpers.js";

export function trustRpc(c: RpcCtx) {
  const { changed, gate, needCode, needGuard, proofOf, store, wrap } = c;
  return {
    "trusted.set": wrap(({ code, ...change }) => {
      const repos = gate.setTrustedRepo(change, needCode(code));
      changed();
      return { ok: true as const, repos };
    }),
    // ---- trust by source and rights (guard mode): the mode and "my sources" are the guard's; the guard checks every touch itself ----------------
    "trust.mode": wrap(async ({ mode, code, passkey }) => {
      const m = await needGuard().setTrustMode(mode, proofOf(code, passkey));
      changed();
      return { ok: true as const, mode: m };
    }),
    "trust.add": wrap(async ({ entries, code, passkey }) => {
      const mySources = await needGuard().addSources(entries, proofOf(code, passkey));
      changed();
      return { ok: true as const, mySources };
    }),
    "trust.remove": wrap(async ({ entry }) => {
      const mySources = await needGuard().removeSource(entry);
      changed();
      return { ok: true as const, mySources };
    }),
    "trust.migrate": wrap(async ({ code, passkey }) => {
      const moved = store.trustedRepos().map((r) => `github:${r}`);
      if (moved.length === 0) throw new GateError("invalid", "в старом списке репозиториев, которые не загрязняют тред, ничего нет");
      const mySources = await needGuard().addSources(moved, proofOf(code, passkey), true);
      changed();
      return { ok: true as const, mySources, moved };
    }),
  } satisfies Partial<ExperimentalPluginRpcHandlersWithContext<typeof rpcContract>>;
}
