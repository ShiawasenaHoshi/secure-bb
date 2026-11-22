// The RPCs that switch an optional module on or off or change its settings: the AI scan (and one scan), publishing a frozen version, and the sentinel. Turning one on is a touch.
import { rpcContract } from "../contract.js";
import { isThirdParty } from "../probe.js";
import { ScanError, type ScanTarget } from "../scan/scanner.js";
import type { ExperimentalPluginRpcHandlersWithContext } from "@get-bb/plugin-sdk";
import type { RpcCtx } from "./guard-helpers.js";

export function settingsRpc(c: RpcCtx) {
  const { aiScanner, changed, gate, guardEntry, guardLink, listPlugins, proposalOfEntry, publisher, sentinel, store, wrap } = c;
  return {
    "ai.settings": wrap(({ code, ...patch }) => {
      gate.setAiSettings(patch, code);
      changed();
      return { ok: true as const };
    }),
    "ai.scan": wrap(async ({ pluginId, queueId }) => {
      if ((pluginId === undefined) === (queueId === undefined)) throw new ScanError("invalid", "укажите плагин или запись очереди");
      let target: ScanTarget;
      if (queueId !== undefined && guardLink) {
        const g = await guardEntry(queueId).catch(() => null);
        if (!g) throw new ScanError("invalid", `нет записи #${queueId}`);
        const proposal = await proposalOfEntry(g);
        target = { pluginId: g.pluginId, version: g.version, dir: proposal?.snapshotDir ?? g.rootDir, contentHash: g.contentHash, trigger: "manual" };
      } else if (queueId !== undefined) {
        const q = store.getQueue(queueId);
        if (!q) throw new ScanError("invalid", `нет записи #${queueId}`);
        const proposal = q.proposalId === null ? null : store.getProposal(q.proposalId);
        const dir = proposal?.snapshotDir ?? q.rootDir;
        if (!dir) throw new ScanError("invalid", "у записи нет каталога с кодом");
        target = { pluginId: q.pluginId, version: q.version, dir, contentHash: q.contentHash, trigger: "manual" };
      } else {
        const installed = (await listPlugins()).find((p) => p.id === pluginId && isThirdParty(p));
        if (!installed) throw new ScanError("invalid", "такого стороннего плагина нет");
        target = { pluginId: installed.id, version: installed.version, dir: installed.rootDir, contentHash: null, trigger: "manual" };
      }
      const { row } = await aiScanner.start(target);
      changed();
      return { ok: true as const, scan: row.id, status: row.status };
    }),
    "publish.settings": wrap(({ code, ...patch }) => {
      gate.setPublishSettings(patch, code);
      changed();
      return { ok: true as const };
    }),
    "publish.run": wrap(async ({ pluginId }) => {
      const r = await publisher.publishPinned(pluginId);
      changed();
      return { ok: true as const, status: r.row?.status ?? "skipped", note: r.note };
    }),
    "sentinel.settings": wrap(({ code, ...patch }) => {
      sentinel.setSettings(patch, code);
      changed();
      return { ok: true as const };
    }),
  } satisfies Partial<ExperimentalPluginRpcHandlersWithContext<typeof rpcContract>>;
}
