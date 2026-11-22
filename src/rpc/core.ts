// The plugin's services, built once at start: the store, the gate with its hook, the guard link, the taint monitor, the AI scanner, the publisher, the sentinel and the probe.
// What changes while it runs (the hook, the journal check, the page's ping) is `state`; the modules that read it all see the same object.
// It builds and wires; the RPC handlers (`src/rpc/*.ts`), the CLI and the background loop use what it returns.
import { dirname, join } from "node:path";
import { mkdirSync, realpathSync } from "node:fs";
import { type BbPluginApi } from "@get-bb/plugin-sdk";
import { GuardLink, guardSocketFromEnv } from "../guardlink.js";
import { bbSkillSource } from "../skills/bb-source.js";
import { SkillReader } from "../skills/reader.js";
import { Gate, type HookCtx } from "../gate.js";
import type { ThreadTree } from "../thread-tree.js";
import { collectProbe, isThirdParty, runningThirdParty, sessionBlockersFromGuard, type InstalledPluginLite } from "../probe.js";
import { runChecksVerified } from "../checks/index.js";
import type { FetchLike } from "../deps/registry.js";
import { verifyDependencies } from "../deps/verify.js";
import { fileAnchor } from "../journal.js";
import { Publisher } from "../publish/publisher.js";
import { PUBLISH_TOKEN_FILE_ENV } from "../publish/types.js";
import { runProcess } from "../scan/process.js";
import { flagReason, Scanner, type ScanTarget } from "../scan/scanner.js";
import { MIGRATIONS, Store, type ApprovalRow } from "../store.js";
import { bbSentinelSource } from "../sentinel/bb-source.js";
import { JEV_KEY_FILE_ENV, JevSolver, type JevFetch } from "../sentinel/jev.js";
import { Sentinel } from "../sentinel/sentinel.js";
import { SentinelStore } from "../sentinel/store.js";
import { bbTaintSource } from "../taint/bb-source.js";
import { TaintMonitor } from "../taint/monitor.js";
import { bbWatchSource } from "../watch/bb-source.js";

export async function createCore(bb: BbPluginApi) {
  const now = () => Date.now();
  const db = bb.storage.database();
  bb.storage.migrate(db, MIGRATIONS);
  const dataDir = dirname(db.name);
  // The journal head is also kept in a file next to the database: a database rolled back or cut at the tail no longer matches it.
  const store = new Store(db, now, fileAnchor(join(dataDir, "journal.head")));
  // What changes while the plugin runs (the hook, the journal check, the page's ping): one object, so that the modules that read it see the same value.
  const state = {
    hookRegistered: false,
    sweepTaintNow: (() => undefined) as () => void,
    holdAvailable: false,
    holdNow: (() => false) as () => boolean,
    journalReport: store.verifyJournal(),
    alarmed: "",
    lastPagePing: 0,
  };
  const snapshotsDir = join(dataDir, "snapshots");
  mkdirSync(snapshotsDir, { recursive: true });
  const snapshotsRoot = realpathSync(snapshotsDir);

  // ---- bb-facing adapters ------------------------------------------------
  const listPlugins = async (): Promise<InstalledPluginLite[]> => {
    const { plugins } = await bb.sdk.plugins.list();
    return plugins.map((p) => ({
      id: p.id,
      provenance: p.provenance,
      enabled: p.enabled,
      status: p.status,
      statusDetail: (p as unknown as { statusDetail?: string | null }).statusDetail ?? null,
      version: p.version,
      source: p.source,
      rootDir: p.rootDir,
    }));
  };

  const threads: ThreadTree = {
    async ancestors(threadId) {
      const res = await bb.sdk.threads.experimental_listAncestors({ threadIds: [threadId] });
      return res.threads.find((t) => t.threadId === threadId)?.ancestorIds ?? [];
    },
    async descendants(threadId) {
      const res = await bb.sdk.threads.experimental_listDescendants({ threadIds: [threadId], includeArchived: true, includeHidden: true });
      return res.threads.find((t) => t.threadId === threadId)?.descendantIds ?? [];
    },
  };

  const threadTitle = async (threadId: string): Promise<string | null> => {
    const t = (await bb.sdk.threads.get({ threadId })) as unknown as { title?: unknown } | null;
    return typeof t?.title === "string" ? t.title : null;
  };

  // ---- skills (stage 6): read whole through bb's API, pinned and checked by the guard below ---------------
  const skillSource = bbSkillSource(bb.sdk);
  const skillReader = new SkillReader(skillSource);

  // ---- pollution tracker (stage 5, spec §6): threads that read untrusted content ----------------
  const watchSource = bbWatchSource({
    sdk: bb.sdk,
    listPlugins,
    loopbackBaseUrl: () => bb.server.loopbackBaseUrl,
    dataDir: () => bb.server.experimental_dataDir,
    skillReader,
  });
  const taint = new TaintMonitor({ store, source: bbTaintSource(bb.sdk, (projectId) => watchSource.envSetup(projectId)), tree: threads, now, trustedRepos: () => store.trustedRepos() });

  // Registry lookups for dependencies (stage 2.3) are made here, by the server process; answers are cached in our database.
  // The packages in node_modules are compared with the registry's tarballs here too (same process, same cache).
  const runChecks = (dir: string, o: { pluginId?: string } = {}) => runChecksVerified(dir, { fetch: globalThis.fetch as unknown as FetchLike, deadlineMs: 5000, cache: { get: (k) => store.getManifest(k), put: (k, v) => store.putManifest(k, v) } }, o.pluginId);
  const verifyDeps = (result: Parameters<typeof verifyDependencies>[0]) => verifyDependencies(result, { cache: store, fetch: globalThis.fetch as unknown as FetchLike, now });

  // ---- optional AI scan (stage 3, spec §8): off until a human turns it on ------------------
  store.interruptRunningScans();
  const aiScanner = new Scanner({
    store,
    now,
    run: runProcess,
    env: process.env,
    log: (m) => bb.log.warn(m),
    onDone: () => {
      changed();
      recheck(); // a flagged or failed scan may now hold a version that waited for it
    },
  });
  const backgroundScan = (t: ScanTarget) =>
    void aiScanner.scan(t).catch((err) => bb.log.warn(`scan of ${t.pluginId} not started: ${err instanceof Error ? err.message : String(err)}`));
  /** The directory and version a freeze scan should look at: the snapshot that was reviewed, else the installed copy. */
  const freezeTarget = async (pluginId: string, pin: ApprovalRow | null): Promise<{ dir: string; version: string } | null> => {
    const proposal = pin?.localHash ? store.proposalByLocalHash(pluginId, pin.localHash) : null;
    if (proposal && pin) return { dir: proposal.snapshotDir, version: pin.version };
    const installed = (await listPlugins()).find((p) => p.id === pluginId && isThirdParty(p));
    return installed ? { dir: installed.rootDir, version: installed.version } : null;
  };

  // ---- publishing frozen versions (stage 4, spec §14): off until a human turns it on with a code -----
  store.interruptRunningPublications();
  const publisher = new Publisher({
    store,
    now,
    run: runProcess,
    // The path only; the token is read from the file at the moment of a push and goes to one git child's environment.
    tokenFile: process.env[PUBLISH_TOKEN_FILE_ENV]?.trim() || null,
    snapshotsRoot,
    serverEnv: process.env,
    log: (m) => bb.log.warn(m),
    onDone: () => changed(),
  });

  // Guard mode: only when the server's environment names the guard's socket. Without it, everything below behaves as it always did.
  const guardSocket = guardSocketFromEnv(process.env);
  const guardLink = guardSocket ? new GuardLink(guardSocket) : null;
  if (guardLink) bb.log.info("guard mode: approvals, trust windows and the second factor are held by the decision guard; this plugin only adds restrictions");

  const gate = new Gate({
    guard: guardLink ?? undefined,
    store,
    runChecks,
    scanFlag: (k) => flagReason(store.latestScanFor(k)),
    onFreeze: (pluginId, pin) => {
      publisher.onFreeze(pluginId, pin);
      const ai = store.aiSettings();
      if (!ai.enabled || !(ai.autoFreeze || ai.freezePlugins.includes(pluginId))) return;
      void freezeTarget(pluginId, pin)
        .then((t) => (t ? backgroundScan({ pluginId, version: t.version, dir: t.dir, contentHash: pin?.contentHash ?? null, trigger: "freeze" }) : undefined))
        .catch((err) => bb.log.warn(`freeze scan failed: ${String(err)}`));
    },
    onExternal: (ctx) => {
      const ai = store.aiSettings();
      if (!ai.enabled || !ai.autoExternal || store.latestScanFor({ contentHash: ctx.contentHash })) return;
      backgroundScan({ pluginId: ctx.pluginId, version: ctx.version, dir: ctx.rootDir, contentHash: ctx.contentHash, trigger: "external" });
    },
    now,
    verifyDeps,
    threads,
    taint,
    thirdPartyRunning: async () => runningThirdParty(await listPlugins()),
    sessionBlockers: async () => sessionBlockersFromGuard(await listPlugins(), guardLink ? await guardLink.state().catch(() => null) : null).map((b) => b.id),
    externalTotpFile: process.env.BB_SECURE_BB_TOTP_FILE?.trim() || null,
    snapshotsRoot,
    onChecked: () => {
      changed();
      recheck(); // a check that outlived the hook's wait may now decide the held version
    },
  });

  // ---- the hook ----------------------------------------------------------
  // Registered exactly once. `on()` not throwing is not proof that the core will ever call the handler: a bb without the patch
  // refuses it with a misleading message (its SDK reports "already registered" for a hook name it does not know), and another
  // could accept any name silently. A plugin that runs has, on a bb that works, been through the hook first, so the handler
  // records every plugin id it is asked about (`hookSeen`). The scanner below (every few seconds, in both modes) looks at the
  // plugins that are running, enabled and that the hook never mentioned: on a bb with a working hook there are none; on one
  // without it, each such plugin is held at once and the first of them declares the hook dead (`state.hookRegistered` turns false,
  // with a journal record and an error in the plugin log, and the page says "after the fact").
  const hookSeen = new Set<string>();
  try {
    bb.experimental_hooks.on("plugin.activate", (ctx) => {
      const c = ctx as HookCtx;
      hookSeen.add(c.pluginId);
      // The core's own hash of what it loads: kept (it survives a restart) so that «after the fact» can ask the guard about THIS hash.
      try {
        store.setMeta(`corehash:${c.pluginId}`, JSON.stringify({ version: c.version, hash: c.contentHash }));
      } catch {
        /* a convenience for the scanner; the decision below does not depend on it */
      }
      return gate.decide(c);
    });
    state.hookRegistered = true;
    bb.log.info("plugin.activate hook registered: gating before load (confirmed per plugin when the core asks about it)");
  } catch (err) {
    bb.log.warn(`no plugin.activate hook in this bb; running after-the-fact (${err instanceof Error ? err.message : String(err)})`);
  }
  const declareHookDead = (ids: string[]): void => {
    if (!state.hookRegistered) return;
    state.hookRegistered = false;
    store.log("hook.dead", null, null, { plugins: ids.slice(0, 10), note: "the hook was accepted but never called for a running plugin; after-the-fact mode" });
    bb.log.error(`plugin.activate was accepted but never called for ${ids.join(", ")}; treating this bb as having no hook (after the fact)`);
    changed();
  };
  const recheck = () => {
    if (state.hookRegistered) void bb.experimental_hooks.recheck("plugin.activate").catch((e) => bb.log.warn(`recheck failed: ${String(e)}`));
  };
  const changed = () => bb.realtime.publish("changed", {});

  // ---- sentinel (stage 7, spec §9): observation only, off until a human turns it on with a code -------
  const sentinelStore = new SentinelStore(db, now);
  sentinelStore.failEvaluating();
  const jev = new JevSolver({
    // Only the path comes from the environment; the key is read from the file at each call and goes into one header.
    keyFile: process.env[JEV_KEY_FILE_ENV]?.trim() || null,
    provider: () => sentinelStore.settings().provider,
    fetch: ((url, init) => globalThis.fetch(url, init)) as JevFetch,
  });
  const sentinel = new Sentinel({
    store: sentinelStore,
    now,
    solver: jev,
    source: bbSentinelSource(bb.sdk, threads),
    windowCovering: async (threadId) => {
      for (const w of gate.openWindows()) if (await gate.windowCovering(w.pluginId, threadId)) return w.pluginId;
      return null;
    },
    touch: (purpose, code) => gate.touch(purpose, code),
    log: (m) => bb.log.warn(m),
    keyConfigured: () => jev.keyConfigured(),
    onChange: changed,
  });
  // Every provider's approval card arrives as this one event. The handler only records and scores: it never answers a card.
  bb.events.on("interaction.pending", (payload) => sentinel.handle(payload));

  const safeDataDir = (): string | null => {
    try {
      return bb.server.experimental_dataDir;
    } catch {
      return null;
    }
  };
  const probe = () =>
    collectProbe({
      hookRegistered: state.hookRegistered,
      loopbackBaseUrl: () => bb.server.loopbackBaseUrl,
      dataDir: () => bb.server.experimental_dataDir,
      listPlugins,
      telemetryEnabled: async () => {
        const cfg = (await bb.sdk.system.config()) as { generalSettings?: { telemetryEnabled?: boolean } };
        return cfg.generalSettings?.telemetryEnabled ?? null;
      },
    });


  return { bb, now, db, dataDir, store, snapshotsDir, snapshotsRoot, listPlugins, threads, threadTitle, skillSource, skillReader, watchSource, taint, runChecks, verifyDeps, aiScanner, backgroundScan, freezeTarget, publisher, guardSocket, guardLink, gate, hookSeen, declareHookDead, recheck, changed, sentinelStore, jev, sentinel, safeDataDir, probe, state };
}
export type Core = Awaited<ReturnType<typeof createCore>>;
