// secure-bb — gate for other plugins' code. Backend entry.
//
// Zero runtime dependencies (node:* and the bb SDK only): this plugin is the
// root of trust, so it ships no third-party code. Policy and secrets live in
// its own SQLite database, never in plugin settings (anyone can change those
// through the unauthenticated API, and secret settings are plain files).
import { dirname, join, resolve as resolvePath } from "node:path";
import { mkdirSync, realpathSync } from "node:fs";
import {
  PluginCliError,
  cliCommand,
  defineCli,
  experimental_PluginRpcRefusal,
  type BbPluginApi,
} from "@get-bb/plugin-sdk";
import { AfterFactScanner } from "./src/afterfact.js";
import { rpcContract } from "./src/contract.js";
import { Gate, GateError, type HookCtx, type ThreadTree } from "./src/gate.js";
import { buildOverview } from "./src/overview.js";
import { collectProbe, isThirdParty, runningThirdParty, type InstalledPluginLite } from "./src/probe.js";
import { formatReport, runChecks } from "./src/checks/index.js";
import type { FetchLike } from "./src/deps/registry.js";
import { verifyDependencies } from "./src/deps/verify.js";
import { fileAnchor, agentLine, type JournalReport } from "./src/journal.js";
import { propose } from "./src/propose.js";
import { runProcess } from "./src/scan/process.js";
import { flagReason, ScanError, Scanner, type ScanTarget } from "./src/scan/scanner.js";
import { scanLine, scanView } from "./src/scan/view.js";
import { encodeQr } from "./src/qr.js";
import { MIGRATIONS, Store, type ApprovalRow } from "./src/store.js";
import { hashTree } from "./src/tree.js";
import { bbTaintSource } from "./src/taint/bb-source.js";
import { TaintMonitor } from "./src/taint/monitor.js";
import { bbWatchActions, bbWatchSource } from "./src/watch/bb-source.js";
import { formatWatch } from "./src/watch/format.js";
import { WatchError, Watchdog } from "./src/watch/watchdog.js";

export { rpcContract };
export type SecureBbRpc = typeof rpcContract;

const SWEEP_MS = 15_000;
const PAGE_PING_TTL_MS = 45_000;
const AFTER_FACT_MS = 60_000;
const WATCH_MS = 60_000;
const WATCH_DEBOUNCE_MS = 1_500;

function refusal(err: unknown): never {
  if (err instanceof GateError) {
    const code = err.code === "invalid_code" || err.code === "blocked" ? "forbidden" : err.code === "not_registered" ? "conflict" : err.code;
    throw new experimental_PluginRpcRefusal({ code, message: err.message });
  }
  if (err instanceof ScanError) throw new experimental_PluginRpcRefusal({ code: err.code === "invalid" ? "invalid" : "conflict", message: err.message });
  if (err instanceof WatchError) throw new experimental_PluginRpcRefusal({ code: err.code, message: err.message });
  throw err;
}

const sleep = (ms: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => (clearTimeout(timer), resolve()), { once: true });
  });

export default async function plugin(bb: BbPluginApi) {
  const now = () => Date.now();
  const db = bb.storage.database();
  bb.storage.migrate(db, MIGRATIONS);
  const dataDir = dirname(db.name);
  // The journal head is also kept in a file next to the database: a database rolled back or cut at the tail no longer matches it.
  const store = new Store(db, now, fileAnchor(join(dataDir, "journal.head")));
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

  // ---- pollution tracker (stage 5, spec §6): threads that read untrusted content ----------------
  const watchSource = bbWatchSource({
    sdk: bb.sdk,
    listPlugins,
    loopbackBaseUrl: () => bb.server.loopbackBaseUrl,
    dataDir: () => bb.server.experimental_dataDir,
  });
  const taint = new TaintMonitor({ store, source: bbTaintSource(bb.sdk, (projectId) => watchSource.envSetup(projectId)), tree: threads, now, trustedRepos: () => store.trustedRepos() });

  // Registry lookups for dependencies (stage 2.3) are made here, by the server process; answers are cached in our database.
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

  const gate = new Gate({
    store,
    scanFlag: (k) => flagReason(store.latestScanFor(k)),
    onFreeze: (pluginId, pin) => {
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
    externalTotpFile: process.env.BB_SECURE_BB_TOTP_FILE?.trim() || null,
    snapshotsRoot,
    onChecked: () => {
      changed();
      recheck(); // a check that outlived the hook's wait may now decide the held version
    },
  });

  // ---- the hook ----------------------------------------------------------
  let hookRegistered = false;
  try {
    bb.experimental_hooks.on("plugin.activate", (ctx) => gate.decide(ctx as HookCtx));
    hookRegistered = true;
    bb.log.info("plugin.activate hook registered: gating before load");
  } catch (err) {
    bb.log.warn(`no plugin.activate hook in this bb; running after-the-fact (${err instanceof Error ? err.message : String(err)})`);
  }
  const recheck = () => {
    if (hookRegistered) void bb.experimental_hooks.recheck("plugin.activate").catch((e) => bb.log.warn(`recheck failed: ${String(e)}`));
  };
  const changed = () => bb.realtime.publish("changed", {});

  const probe = () =>
    collectProbe({
      hookRegistered,
      loopbackBaseUrl: () => bb.server.loopbackBaseUrl,
      dataDir: () => bb.server.experimental_dataDir,
      listPlugins,
      telemetryEnabled: async () => {
        const cfg = (await bb.sdk.system.config()) as { generalSettings?: { telemetryEnabled?: boolean } };
        return cfg.generalSettings?.telemetryEnabled ?? null;
      },
    });

  // ---- config watchdog (spec §7) -----------------------------------------
  const watch = new Watchdog({
    store,
    now,
    source: watchSource,
    actions: bbWatchActions(bb.sdk),
    touch: (purpose, code) => gate.touch(purpose, code),
    log: (m) => bb.log.warn(m),
  });
  // ---- journal integrity (stage 5): verified at start, on every tick, and on demand --------------------
  let journalReport: JournalReport = store.verifyJournal();
  let alarmed = "";
  const journal = (fresh = false): JournalReport => {
    if (fresh || now() - journalReport.checkedAt > 30_000) {
      journalReport = store.verifyJournal();
      const signature = journalReport.ok ? "" : journalReport.problems.map((p) => `${p.kind}:${p.id}`).join(",");
      if (signature !== alarmed) {
        alarmed = signature;
        if (!journalReport.ok) {
          bb.log.error(`secure-bb journal chain is BROKEN: ${journalReport.problems.length} problem(s)`);
          store.log("journal.alarm", null, null, { problems: journalReport.problems.slice(0, 10).map((p) => ({ kind: p.kind, id: p.id })) });
          changed();
        }
      }
    }
    return journalReport;
  };
  journal(true);
  const overview = () =>
    buildOverview({ scanner: aiScanner, store, gate, now, hookRegistered, listPlugins, probe, descendants: threads.descendants, watch, journal: () => journal(), taintedThreads: () => store.taintedThreads(20) });

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
  });

  // ---- RPC ---------------------------------------------------------------
  let lastPagePing = 0;
  const wrap = <A, R>(fn: (input: A) => R | Promise<R>) => async (input: A): Promise<R> => {
    try {
      return await fn(input);
    } catch (err) {
      return refusal(err);
    }
  };

  bb.rpc.register(rpcContract, {
    overview: () => overview(),
    "journal.verify": () => {
      const r = journal(true);
      changed();
      return r;
    },
    "trusted.set": wrap(({ code, ...change }) => {
      const repos = gate.setTrustedRepo(change, code);
      changed();
      return { ok: true as const, repos };
    }),
    "page.ping": () => {
      lastPagePing = now();
      return { ok: true as const };
    },
    "totp.begin": wrap(async () => {
      // "Attended" = the secure-bb page pinged us moments ago. A registration
      // started without it must be restarted from the page before it can be confirmed.
      const attended = now() - lastPagePing < PAGE_PING_TTL_MS;
      const { secret, uri } = await gate.beginRegistration({ attended, caller: "client" });
      changed();
      return { secret, uri, matrix: encodeQr(uri) };
    }),
    "totp.confirm": wrap(({ code }) => {
      gate.confirmRegistration(code);
      changed();
      return { ok: true as const };
    }),
    "queue.approve": wrap(async ({ id, code, acknowledgeBlock }) => {
      const res = gate.approveQueue(id, code, { acknowledgeBlock });
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
      return { ok: true as const, note };
    }),
    "queue.dismiss": wrap(({ id, code }) => {
      gate.dismissQueue(id, code);
      changed();
      return { ok: true as const };
    }),
    "window.open": wrap(({ queueId, code, scope }) => {
      gate.openWindow(queueId, code, scope);
      recheck();
      changed();
      return { ok: true as const };
    }),
    "window.close": wrap(({ windowId, code }) => {
      gate.closeWindow(windowId, code);
      changed();
      return { ok: true as const };
    }),
    "approval.revoke": wrap(async ({ approvalId, code }) => {
      const a = gate.revoke(approvalId, code);
      try {
        await bb.sdk.plugins.disable({ pluginId: a.pluginId });
      } catch (err) {
        bb.log.warn(`could not disable ${a.pluginId} after revoke: ${String(err)}`);
      }
      changed();
      return { ok: true as const };
    }),
    "watch.scan": wrap(async () => {
      await watch.scan();
      changed();
      return { ok: true as const };
    }),
    "watch.acceptAll": wrap(async ({ code }) => {
      const { items } = await watch.acceptAll(code);
      changed();
      return { ok: true as const, items };
    }),
    "watch.accept": wrap(async ({ id, code }) => {
      await watch.acceptDrift(id, code);
      changed();
      return { ok: true as const };
    }),
    "watch.rollback": wrap(async ({ id, code }) => {
      await watch.rollbackDrift(id, code);
      changed();
      return { ok: true as const };
    }),
    "watch.rollbackMode": wrap(({ enabled, code }) => {
      watch.setRollback(enabled, code);
      changed();
      return { ok: true as const };
    }),
    "watch.window.open": wrap(async ({ scopes, code }) => {
      await watch.openWindow(scopes, code);
      changed();
      return { ok: true as const };
    }),
    "watch.window.close": wrap(async ({ windowId, code }) => {
      await watch.closeWindow(windowId, code);
      changed();
      return { ok: true as const };
    }),
    "ai.settings": wrap(({ code, ...patch }) => {
      gate.setAiSettings(patch, code);
      changed();
      return { ok: true as const };
    }),
    "ai.scan": wrap(async ({ pluginId, queueId }) => {
      if ((pluginId === undefined) === (queueId === undefined)) throw new ScanError("invalid", "укажите плагин или запись очереди");
      let target: ScanTarget;
      if (queueId !== undefined) {
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
    "policy.set": wrap(({ code, ...patch }) => {
      gate.setPolicy(patch, code);
      changed();
      return { ok: true as const };
    }),
  });

  // ---- CLI for agents ------------------------------------------------------
  bb.cli.register(
    defineCli({
      name: "secure-bb",
      summary: "Gate for plugin code: install plugins only through `propose`",
      commands: {
        status: cliCommand({
          summary: "Is the gate on, and is a trust window open for this thread",
          options: {},
          async run(_input, ctx) {
            // Deliberately terse: no stage, no second-factor state, no reasons.
            const open = ctx.threadId
              ? (await Promise.all(gate.openWindows().map(async (w) => ((await gate.windowCovering(w.pluginId, ctx.threadId ?? null)) ? w : null)))).filter((w) => w !== null)
              : [];
            const lines = [
              `gate before load: ${hookRegistered ? "yes" : "no (after the fact)"}`,
              `trust window for this thread: ${open.length > 0 ? `open (${open.map((w) => `${w.pluginId}, ${Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now()) / 60_000)} min`).join("; ")})` : "closed"}`,
              agentLine(journal()),
              `trusted repositories: ${store.trustedRepos().length}`,
            ];
            return { exitCode: 0, stdout: lines.join("\n") };
          },
        }),
        log: cliCommand({
          summary: "Recent gate decisions; --verify checks the integrity of the journal (hash chain)",
          options: {
            limit: { type: "integer", min: 1, max: 100, default: 20, description: "How many entries (1-100)" },
            verify: { type: "boolean", description: "Check the hash chain of the journal instead of listing it; exit code 2 when it is broken" },
          },
          async run(input) {
            if (input.options.verify) {
              const report = journal(true);
              if (!report.ok) changed();
              // For an agent: only whether it holds. Which record, and how, is for the human on the page.
              return { exitCode: report.ok ? 0 : 2, stdout: agentLine(report) };
            }
            const rows = store.listLog(input.options.limit);
            // No reasons here: agents read this too (spec §11). The page has them.
            const text = rows
              .map((r) => {
                const d = (r.detail && typeof r.detail === "object" ? r.detail : {}) as Record<string, unknown>;
                const parts = [new Date(r.ts).toISOString(), r.kind];
                if (r.pluginId) parts.push(d.version ? `${r.pluginId}@${String(d.version)}` : r.pluginId);
                if (d.review !== undefined) parts.push(`review #${String(d.review)}`);
                return parts.join(" ");
              })
              .join("\n");
            return { exitCode: 0, stdout: text || "(empty)" };
          },
        }),
        config: cliCommand({
          summary: "Config watchdog: differences from the approved configuration snapshot",
          options: {
            scan: { type: "boolean", description: "Check right now before printing" },
            limit: { type: "integer", min: 1, max: 100, default: 20, description: "How many entries (1-100)" },
          },
          async run(input) {
            if (input.options.scan) await watch.scan().then((r) => (r.found + r.accepted + r.rolledBack > 0 ? changed() : undefined));
            return { exitCode: 0, stdout: formatWatch(watch.view(), now(), input.options.limit) };
          },
        }),
        scan: cliCommand({
          summary: "Optional AI scan: print the settings and the latest results, or start a scan of an installed third-party plugin (off unless a human turned it on)",
          positionals: [{ name: "plugin", description: "Plugin id to scan; omit to only print", required: false }],
          options: {},
          async run(input) {
            const ai = store.aiSettings();
            const lines: string[] = [`AI scan: ${ai.enabled ? "on" : "off"}${ai.enabled ? `; on freeze: ${ai.autoFreeze ? "yes" : "no"}; externals: ${ai.autoExternal ? "yes" : "no"}; second model: ${ai.second ? ai.secondModel : "no"}` : ""}`];
            const id = input.positionals.plugin;
            if (id) {
              if (!ai.enabled) throw new PluginCliError("AI scan is off; a human turns it on in the secure-bb page", { code: "scan_off" });
              const installed = (await listPlugins()).find((p) => p.id === id && isThirdParty(p));
              if (!installed) throw new PluginCliError(`no installed third-party plugin ${id}`, { code: "not_found" });
              try {
                const { row } = await aiScanner.start({ pluginId: installed.id, version: installed.version, dir: installed.rootDir, contentHash: null, trigger: "cli" });
                changed();
                lines.push(`scan #${row.id} of ${installed.id}@${installed.version}: ${row.status === "running" ? "started (takes a few minutes)" : row.status}`);
              } catch (err) {
                if (err instanceof ScanError) throw new PluginCliError(err.message, { code: "scan_failed" });
                throw err;
              }
            } else {
              const recent = store.listScans(5).map((r) => scanLine(scanView(r)));
              lines.push(...(recent.length > 0 ? recent : ["no scans yet"]));
            }
            return { exitCode: 0, stdout: lines.join("\n") };
          },
        }),
        check: cliCommand({
          summary: "Run the checks on a plugin directory without installing it (dependencies are looked up on the npm registry by the server)",
          positionals: [{ name: "path", description: "Plugin directory on this machine", required: true }],
          options: {},
          async run(input, ctx) {
            const dir = resolvePath(ctx.cwd ?? process.cwd(), input.positionals.path);
            let result;
            try {
              result = await verifyDeps(await runChecks(dir));
            } catch (err) {
              throw new PluginCliError(`cannot check ${dir}: ${err instanceof Error ? err.message : String(err)}`, { code: "check_failed" });
            }
            return { exitCode: 0, stdout: formatReport(result) };
          },
        }),
        propose: cliCommand({
          summary: "Install or update a plugin through the gate (the only allowed way)",
          positionals: [{ name: "path", description: "Plugin directory on this machine", required: true }],
          options: {},
          async run(input, ctx) {
            const res = await propose(
              {
                gate,
                store,
                snapshotsRoot,
                invokerIsServerMachine: async (threadId) => {
                  if (!threadId) return true; // a human in a terminal: the CLI runs where they are
                  try {
                    const th = (await bb.sdk.threads.get({ threadId })) as unknown as { environmentId?: string | null };
                    if (!th.environmentId) return false;
                    const env = (await bb.sdk.environments.get({ environmentId: th.environmentId })) as unknown as { hostId?: string | null };
                    const cfg = (await bb.sdk.system.config()) as unknown as { primaryHostId?: string | null };
                    if (!env.hostId || !cfg.primaryHostId) return false;
                    return env.hostId === cfg.primaryHostId;
                  } catch {
                    // Fail closed: reading a path on the wrong machine is worse than refusing.
                    return false;
                  }
                },
                install: async (dir) => {
                  const p = await bb.sdk.plugins.install({ source: dir });
                  return { id: p.id, version: p.version, status: p.status, statusDetail: p.statusDetail };
                },
                afterInstall: (dir) => gate.recordBuilt(dir),
                changed,
              },
              { path: input.positionals.path, cwd: ctx.cwd, threadId: ctx.threadId ?? null },
            );
            if (res.exitCode === 1 && res.stderr && !res.stdout) throw new PluginCliError(res.stderr, { code: "propose_failed" });
            return res;
          },
        }),
      },
    }),
  );

  // ---- background ------------------------------------------------------------
  bb.background.service("watch", {
    async start(signal) {
      let unsubscribe: (() => void) | null = null;
      const debounced = (fn: () => void) => {
        let timer: ReturnType<typeof setTimeout> | null = null;
        return () => {
          if (timer) clearTimeout(timer);
          timer = setTimeout(fn, WATCH_DEBOUNCE_MS);
        };
      };
      const scanAfterFact = () => void scanner.scan().then((d) => d.length && changed()).catch((e) => bb.log.error(String(e)));
      const scanConfig = () =>
        void watch
          .scan()
          .then((r) => (r.found + r.accepted + r.rolledBack + r.rollbackFailed > 0 ? changed() : undefined))
          .catch((e) => bb.log.error(`config watch failed: ${String(e)}`));
      const sweepTaint = () =>
        void Promise.all([gate.sweepTaint(), watch.taintSweep((since) => taint.assessAll(since))])
          .then(([a, b]) => (a + b > 0 ? changed() : undefined))
          .catch((e) => bb.log.error(`taint sweep failed: ${String(e)}`));
      const kickTaint = debounced(sweepTaint);
      const kickAfterFact = debounced(scanAfterFact);
      const kickConfig = debounced(scanConfig);
      try {
        unsubscribe = bb.sdk.subscribe({
          event: "system:changed",
          callback: (event) => {
            if (!hookRegistered && event.changes?.includes("plugins-changed")) kickAfterFact();
            if (event.changes?.includes("plugins-changed") || event.changes?.includes("config-changed")) kickConfig();
          },
        });
      } catch (err) {
        bb.log.warn(`cannot subscribe to system changes: ${String(err)}`);
      }
      let unsubscribeThreads: (() => void) | null = null;
      try {
        // New events in any thread: remember which, and look at the open windows soon (spec §6: pollution closes them).
        unsubscribeThreads = bb.sdk.subscribe({
          event: "thread:changed",
          callback: (event) => {
            if (!event.changes?.includes("events-appended") || !event.id) return;
            taint.note(event.id);
            if (gate.openWindows().length > 0 || watch.openWindows().length > 0) kickTaint();
          },
        });
      } catch (err) {
        bb.log.warn(`cannot subscribe to thread changes (windows are then checked once a tick): ${String(err)}`);
      }
      if (!hookRegistered) kickAfterFact();
      kickConfig();
      let lastScan = now();
      let lastWatch = now();
      while (!signal.aborted) {
        await sleep(SWEEP_MS, signal);
        if (signal.aborted) break;
        try {
          if (gate.sweep() > 0) changed();
          if (watch.sweep() > 0) changed();
          if (gate.openWindows().length > 0 || watch.openWindows().length > 0) sweepTaint();
          journal(now() - journalReport.checkedAt > 60_000);
          if (!hookRegistered && now() - lastScan >= AFTER_FACT_MS) {
            lastScan = now();
            if ((await scanner.scan()).length > 0) changed();
          }
          if (now() - lastWatch >= WATCH_MS) {
            lastWatch = now();
            scanConfig();
          }
        } catch (err) {
          bb.log.error(`watch tick failed: ${String(err)}`);
        }
      }
      unsubscribe?.();
      unsubscribeThreads?.();
    },
  });

  bb.onDispose(() => {
    // The database handle is closed by the host; nothing else is held.
  });
}
