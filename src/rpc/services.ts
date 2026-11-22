// The services that sit on the core: the skill guard, the config watchdog, the agent watch and the stopper, the journal check, the alive mark, the after-the-fact scanner and the batch service.
// Same rule as core.ts: it builds and wires, nothing here answers a request.
import { join } from "node:path";
import { Alive } from "../alive.js";
import { AgentWatchLink, type AgentThreadSource } from "../agents.js";
import { AgentStopper } from "../stop.js";
import type { Proof } from "../approval.js";
import { AfterFactScanner, NO_CORE_HASH_REASON } from "../afterfact.js";
import { SkillGuard } from "../skills/guard.js";
import { SkillStore } from "../skills/store.js";
import { buildOverview } from "../overview.js";
import { type InstalledPluginLite } from "../probe.js";
import { type JournalReport } from "../journal.js";
import { hashTree } from "../tree.js";
import { bbWatchActions } from "../watch/bb-source.js";
import { Watchdog } from "../watch/watchdog.js";
import { type Core } from "./core.js";

export async function createServices(c: Core) {
  const { aiScanner, bb, changed, db, declareHookDead, gate, guardLink, hookSeen, listPlugins, now, probe, publisher, recheck, sentinel, skillReader, skillSource, state, store, threadTitle, threads, watchSource } = c;
  // ---- skills guard (stage 6): after the fact, driven by the watchdog's scans -----------------------------
  const skillGuard = new SkillGuard({
    store,
    skills: new SkillStore(db, now),
    reader: skillReader,
    source: skillSource,
    builtinPlugins: async () => new Set((await listPlugins()).filter((p) => p.provenance === "builtin").map((p) => p.id)),
    now,
    touch: (purpose, code) => gate.touch(purpose, code),
    log: (m) => bb.log.warn(m),
  });

  // ---- config watchdog (spec §7) -----------------------------------------
  const watch = new Watchdog({
    store,
    now,
    source: watchSource,
    actions: bbWatchActions(bb.sdk),
    touch: (purpose, code) => gate.touch(purpose, code),
    skills: skillGuard,
    log: (m) => bb.log.warn(m),
  });
  // ---- agent watch (guard mode): the guard reads the agents' files; here the thread of a working directory is found through bb ----
  const agentSource: AgentThreadSource = {
    async environments() {
      const out: Array<{ id: string; path: string | null }> = [];
      for (let offset = 0; offset < 5000; offset += 500) {
        const page = await bb.sdk.environments.list({ limit: 500, offset });
        out.push(...page.map((e) => ({ id: e.id, path: e.path })));
        if (page.length < 500) break;
      }
      return out;
    },
    async threadsOf(environmentId) {
      const ids = new Set<string>();
      for (const archived of [false, true]) for (const t of await bb.sdk.threads.list({ environmentId, archived, includeHidden: true, limit: 200 })) ids.add(t.id);
      return [...ids];
    },
  };
  // ---- «Остановить агентов»: stop the running threads through the SDK, and hold new turns while a critical difference is open ----
  // The hold is the `message.dispatch` hook. Without it (bb has none) the page says honestly that agents may be started again.
  try {
    bb.experimental_hooks.on("message.dispatch", () => (state.holdNow() ? { action: "wait", reason: "secure-bb: агенты остановлены, пока настройки агента не исправлены (кнопка «Вернуть как было» на странице Secure BB)", sendAt: now() + 60_000 } : { action: "proceed" }));
    state.holdAvailable = true;
  } catch (err) {
    bb.log.warn(`no message.dispatch hook in this bb: «Остановить агентов» cannot hold new turns (${err instanceof Error ? err.message : String(err)})`);
  }
  const stopper = new AgentStopper({
    port: {
      listRunning: async () => (await bb.sdk.threads.listRunning()).map((t) => ({ id: t.id })),
      stop: async (threadId) => void (await bb.sdk.threads.stop({ threadId })),
    },
    store,
    now,
    holdAvailable: state.holdAvailable,
    log: (m) => bb.log.warn(m),
  });
  const agents = guardLink
    ? new AgentWatchLink({
        guard: guardLink,
        store,
        source: agentSource,
        now,
        log: (m) => bb.log.warn(m),
        // The guard closed its own windows; this plugin's configuration windows that were open before the change are closed too.
        closeWindowsOpenedBefore: (at, reason) => {
          let n = 0;
          for (const w of watch.openWindows()) if (w.openedAt < at) (store.closeCfgWindow(w.id, reason), store.log("watch.window.agents", null, null, { windowId: w.id, scopes: w.scopes, reason }), n++);
          return n;
        },
        onChange: () => changed(),
        stopper,
        // The hold ended: core is asked to try the held messages again at once (not at the next `sendAt`).
        onHoldReleased: () => void bb.experimental_hooks.recheck("message.dispatch").catch((e) => bb.log.warn(`recheck of held messages failed: ${String(e)}`)),
      })
    : null;
  state.holdNow = () => stopper.holding(agents?.criticalOpen() ?? false);

  // ---- journal integrity (stage 5): verified at start, on every tick, and on demand --------------------
  const journal = (fresh = false): JournalReport => {
    if (fresh || now() - state.journalReport.checkedAt > 30_000) {
      state.journalReport = store.verifyJournal();
      const signature = state.journalReport.ok ? "" : state.journalReport.problems.map((p) => `${p.kind}:${p.id}`).join(",");
      if (signature !== state.alarmed) {
        state.alarmed = signature;
        if (!state.journalReport.ok) {
          bb.log.error(`secure-bb journal chain is BROKEN: ${state.journalReport.problems.length} problem(s)`);
          store.log("journal.alarm", null, null, { problems: state.journalReport.problems.slice(0, 10).map((p) => ({ kind: p.kind, id: p.id })) });
          changed();
        }
      }
    }
    return state.journalReport;
  };
  journal(true);
  // The mark of life (threat model X3): written every tick; a gap at start, or bb's safe-mode, is an alarm on the page and a journal record.
  const alive = new Alive({
    store,
    now,
    safeMode: () => watchSource.safeMode().catch(() => null),
    log: (m) => bb.log.error(m),
    guardMode: guardLink !== null,
    coreHolds: (process.env.BB_PLUGIN_ACTIVATION_GUARDS ?? "").split(",").some((g) => g.trim() === "secure-bb"),
    serverStartedAt: () => Date.now() - process.uptime() * 1000,
  });
  if ((await alive.start()) !== null) changed();
  const overview = () =>
    buildOverview({ guard: guardLink ?? undefined, ...(agents ? { agents: () => agents.refresh(false) } : {}), alive, sentinel, scanner: aiScanner, publisher, store, gate, now, hookRegistered: state.hookRegistered, listPlugins, probe, descendants: threads.descendants, threadsUx: { ancestors: threads.ancestors, threadTitle }, watch, skills: skillGuard, journal: () => journal(), taintedThreads: () => store.taintedThreads(20) });

  // ---- after-the-fact mode ------------------------------------------------
  const scanner = new AfterFactScanner({
    store,
    gate,
    listPlugins,
    disable: async (id) => {
      await bb.sdk.plugins.disable({ pluginId: id });
    },
    hashDir: hashTree,
    now,
    log: (m) => bb.log.warn(m),
    // asked about by the hook since this start, or approved earlier (the plugin was reloaded and the in-memory set is empty)
    vetted: (id) => state.hookRegistered && (hookSeen.has(id) || store.latestApproval(id) !== null),
    onUnvetted: (ids) => declareHookDead(ids),
    ...(guardLink
      ? {
          guard: {
            coreHash: (id: string, version: string) => {
              try {
                const j = JSON.parse(store.getMeta(`corehash:${id}`) ?? "null") as { version?: unknown; hash?: unknown } | null;
                return j && j.version === version && typeof j.hash === "string" && j.hash.startsWith("sha256:") ? j.hash : null;
              } catch {
                return null;
              }
            },
            guardApproved: async (id: string, hash: string) => (await guardLink.lookup(id, hash)).approved,
            noCoreHash: (p: InstalledPluginLite) => {
              store.upsertQueue({ kind: "afterfact", contentHash: null, pluginId: p.id, version: p.version, source: p.source, sourceKind: p.source.split(":")[0] ?? "path", rootDir: p.rootDir, gitCommit: null, npmIntegrity: null, trigger: "afterfact", threadId: null, proposalId: null, reason: NO_CORE_HASH_REASON });
              store.log("afterfact.nohash", p.id, null, { version: p.version, note: "the core's hash is unknown; nothing was sent to the guard" });
            },
          },
        }
      : {}),
  });

  // ---- approving a held version (one code, a session, or one code for a whole list) ----------------------------------
  const approveQueueFull = async (id: number, proof: Proof, opts: { acknowledgeBlock?: boolean } = {}): Promise<string> => {
    const res = gate.approveQueue(id, proof, opts);
    let note = "approved";
    if (res.installDir) {
      const installed = await bb.sdk.plugins.install({ source: res.installDir });
      await gate.recordBuilt(res.installDir).catch((e) => bb.log.warn(`recordBuilt failed: ${String(e)}`));
      note = `installed ${installed.id}@${installed.version}: ${installed.status}`;
    } else if (res.enable) {
      await bb.sdk.plugins.enable({ pluginId: res.pluginId });
      note = `enabled ${res.pluginId}`;
    }
    recheck();
    changed();
    publisher.onApproved(res.proposalId);
    return note;
  };


  return { skillGuard, watch, agentSource, stopper, agents, journal, alive, overview, scanner, approveQueueFull };
}
export type Services = Awaited<ReturnType<typeof createServices>>;
