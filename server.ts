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
import { Alive } from "./src/alive.js";
import { AgentWatchLink, type AgentThreadSource } from "./src/agents.js";
import { GuardLink, GuardLinkError, guardSocketFromEnv, type GuardAction, type GuardPolicy, type GuardProof, type GuardQueueEntry, type PasskeyAssertion } from "./src/guardlink.js";
import { MODE_RANK, normalizeEntry } from "./guard/src/trust.ts";
import { buildExport, writeExport } from "./src/export.js";
import { localCheckKey } from "./src/decision.js";
import { mintListProof } from "./src/approval.js";
import { realpath } from "node:fs/promises";
import { BatchService, type BatchSource } from "./src/batch.js";
import type { Proof } from "./src/approval.js";
import { AfterFactScanner } from "./src/afterfact.js";
import { bbSkillSource } from "./src/skills/bb-source.js";
import { SkillError, SkillGuard } from "./src/skills/guard.js";
import { SkillReader } from "./src/skills/reader.js";
import { SkillStore } from "./src/skills/store.js";
import { rpcContract } from "./src/contract.js";
import { createHash } from "node:crypto";
import { BLOCKED_REASON, bySeverity, capabilityTokens } from "./src/decision.js";
import { Gate, GateError, UNSAFE_DIR_REASON, type HookCtx, type ThreadTree } from "./src/gate.js";
import { buildOverview } from "./src/overview.js";
import { collectProbe, isThirdParty, runningThirdParty, type InstalledPluginLite } from "./src/probe.js";
import { runChecks } from "./src/checks/index.js";
import { checkPathRefusal, checkSummary } from "./src/checkpath.js";
import type { FetchLike } from "./src/deps/registry.js";
import { verifyDependencies } from "./src/deps/verify.js";
import { fileAnchor, agentLine, type JournalReport } from "./src/journal.js";
import { propose } from "./src/propose.js";
import { Publisher } from "./src/publish/publisher.js";
import { PUBLISH_TOKEN_FILE_ENV } from "./src/publish/types.js";
import { publishLine } from "./src/publish/view.js";
import { runProcess } from "./src/scan/process.js";
import { flagReason, ScanError, Scanner, type ScanTarget } from "./src/scan/scanner.js";
import { scanLine, scanView } from "./src/scan/view.js";
import { encodeQr } from "./src/qr.js";
import { MIGRATIONS, Store, type ApprovalRow } from "./src/store.js";
import { hashTree } from "./src/tree.js";
import { bbSentinelSource } from "./src/sentinel/bb-source.js";
import { JEV_KEY_FILE_ENV, JevSolver, type JevFetch } from "./src/sentinel/jev.js";
import { Sentinel, SentinelError } from "./src/sentinel/sentinel.js";
import { SentinelStore } from "./src/sentinel/store.js";
import { feedText, verdictText } from "./src/sentinel/view.js";
import { bbTaintSource } from "./src/taint/bb-source.js";
import { TaintMonitor } from "./src/taint/monitor.js";
import { bbWatchActions, bbWatchSource } from "./src/watch/bb-source.js";
import { formatWatch } from "./src/watch/format.js";
import { WatchError, Watchdog } from "./src/watch/watchdog.js";

export { rpcContract };
export type SecureBbRpc = typeof rpcContract;

const SWEEP_MS = 15_000;
const PAGE_PING_TTL_MS = 45_000;
/** Plugins the hook did not vet are scanned this often: their code is already running, so every second counts. */
const SCAN_TICK_MS = 5_000;
const WATCH_MS = 60_000;
const WATCH_DEBOUNCE_MS = 1_500;

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
  // without it, each such plugin is held at once and the first of them declares the hook dead (`hookRegistered` turns false,
  // with a journal record and an error in the plugin log, and the page says "after the fact").
  let hookRegistered = false;
  const hookSeen = new Set<string>();
  try {
    bb.experimental_hooks.on("plugin.activate", (ctx) => {
      hookSeen.add((ctx as HookCtx).pluginId);
      return gate.decide(ctx as HookCtx);
    });
    hookRegistered = true;
    bb.log.info("plugin.activate hook registered: gating before load (confirmed per plugin when the core asks about it)");
  } catch (err) {
    bb.log.warn(`no plugin.activate hook in this bb; running after-the-fact (${err instanceof Error ? err.message : String(err)})`);
  }
  const declareHookDead = (ids: string[]): void => {
    if (!hookRegistered) return;
    hookRegistered = false;
    store.log("hook.dead", null, null, { plugins: ids.slice(0, 10), note: "the hook was accepted but never called for a running plugin; after-the-fact mode" });
    bb.log.error(`plugin.activate was accepted but never called for ${ids.join(", ")}; treating this bb as having no hook (after the fact)`);
    changed();
  };
  const recheck = () => {
    if (hookRegistered) void bb.experimental_hooks.recheck("plugin.activate").catch((e) => bb.log.warn(`recheck failed: ${String(e)}`));
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
      hookRegistered,
      loopbackBaseUrl: () => bb.server.loopbackBaseUrl,
      dataDir: () => bb.server.experimental_dataDir,
      listPlugins,
      telemetryEnabled: async () => {
        const cfg = (await bb.sdk.system.config()) as { generalSettings?: { telemetryEnabled?: boolean } };
        return cfg.generalSettings?.telemetryEnabled ?? null;
      },
    });

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
  let sweepTaintNow: () => void = () => undefined;
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
      })
    : null;

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
  // The mark of life (threat model X3): written every tick; a gap at start, or bb's safe-mode, is an alarm on the page and a journal record.
  const alive = new Alive({ store, now, safeMode: () => watchSource.safeMode().catch(() => null), log: (m) => bb.log.error(m) });
  if ((await alive.start()) !== null) changed();
  const overview = () =>
    buildOverview({ guard: guardLink ?? undefined, ...(agents ? { agents: () => agents.refresh(false) } : {}), alive, sentinel, scanner: aiScanner, publisher, store, gate, now, hookRegistered, listPlugins, probe, descendants: threads.descendants, watch, skills: skillGuard, journal: () => journal(), taintedThreads: () => store.taintedThreads(20) });

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
    vetted: (id) => hookRegistered && (hookSeen.has(id) || store.latestApproval(id) !== null),
    onUnvetted: (ids) => declareHookDead(ids),
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

  // ---- batch approval: lists of held versions, skills and differences, one code each ----------------------------------
  const fingerprint = (...parts: Array<string | number | null>): string => createHash("sha256").update(JSON.stringify(parts), "utf8").digest("hex");
  const batchSources: Record<"queue" | "skill" | "drift", BatchSource> = {
    queue: {
      describe(id) {
        // Guard mode: one code approves one version at the guard (a code is never accepted twice), so versions are not batched.
        if (guardLink) return { skip: "в режиме сторожа версии плагинов одобряются по одной: у сторожа один код — одно одобрение" };
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
  const batches = new BatchService({ store, now, sources: batchSources, approveList: (purpose, proof) => gate.approveList(purpose, proof) });

  // ---- RPC ---------------------------------------------------------------
  let lastPagePing = 0;
  const wrap = <A, R>(fn: (input: A) => R | Promise<R>) => async (input: A): Promise<R> => {
    try {
      return await fn(input);
    } catch (err) {
      return refusal(err);
    }
  };

  // ---- guard mode helpers ------------------------------------------------------------------------------------------
  /** A code the guard has already checked (once, for the call that carries it): the mark `Gate.touch` takes without looking at a secret. */
  const VERIFIED = mintListProof() as unknown as string;
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
  const guardEntry = async (id: number): Promise<GuardQueueEntry> => {
    const st = await needGuard().state();
    const q = st.queue.find((x) => x.id === id);
    if (!q) throw new GateError("not_found", `no review #${id}`);
    if (q.status !== "held") throw new GateError("conflict", `review #${id} is already ${q.status}`);
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
    const q = await guardEntry(id);
    const f = await entryFacts(q);
    if (f.unsafeDir) throw new GateError("invalid", "this version lies in a directory that others can write to; it cannot be approved from there (see the page)", { unsafeDir: true });
    if (f.blocked && !acknowledgeBlock) throw new GateError("invalid", "this version was blocked by the checks; confirm that you accept the risk to approve it anyway", { blocked: true });
    await link.approve(id, proof);
    if (f.blocked) store.log("block.lifted", q.pluginId, q.contentHash, { review: id, version: q.version, rules: f.result ? bySeverity(f.result, "block").map((x) => x.rule) : [] });
    // A capability accepted with a code inside an open window becomes part of the window's set; the window stays open.
    const w = store.unclosedWindows().find((x) => x.pluginId === q.pluginId && x.guardWindowId !== null);
    if (w && f.result) store.setWindowCaps(w.id, [...new Set([...w.caps, ...capabilityTokens(f.result)])].sort());
    store.log("approved.guard", q.pluginId, q.contentHash, { review: id, version: q.version });
    if (f.proposal) publisher.onApproved(f.proposal.id);
    recheck();
    changed();
    return { ok: true as const, note: "approved at the guard" };
  };

  /**
   * In guard mode a code that arrives with any RPC is checked by the guard first (it consumes the code there: the secret is not here),
   * and the handler then runs with the mark that says so. RPCs that need more than that (they act at the guard) do it themselves.
   */
  const OWN_GUARD_PATH = new Set(["queue.approve", "window.open", "policy.set", "session.open", "totp.begin", "totp.confirm", "agents.accept", "trust.mode", "trust.add", "trust.migrate"]);
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
            const proof = input && typeof input === "object" ? (input.passkey !== undefined ? { passkey: input.passkey as PasskeyAssertion } : typeof input.code === "string" ? input.code : undefined) : undefined;
            if (proof !== undefined) {
              try {
                await guardLink.touch(name, proof);
              } catch (err) {
                return refusal(err);
              }
              const { passkey: _p, ...rest } = input;
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
  const policyPlan = async (patch: { windowMin?: number; capMin?: number; mode?: "sliding" | "fixed"; scope?: "tree" | "thread"; cfgWindowMin?: number; cfgCapMin?: number; cfgMode?: "sliding" | "fixed"; autoSafe?: boolean }) => {
    if (patch.autoSafe === true) throw new GateError("invalid", "в режиме сторожа автопропуск безопасного класса не существует: каждое одобрение даёт человек");
    const cur = await needGuard().policy();
    const wanted: Partial<GuardPolicy> = {};
    if (patch.windowMin !== undefined && patch.windowMin !== cur.windowMin) wanted.windowMin = patch.windowMin;
    if (patch.capMin !== undefined && patch.capMin !== cur.capMin) wanted.capMin = patch.capMin;
    if (patch.mode !== undefined && patch.mode !== cur.mode) wanted.mode = patch.mode;
    const guardWidens = (wanted.windowMin ?? cur.windowMin) > cur.windowMin || (wanted.capMin ?? cur.capMin) > cur.capMin || (wanted.mode === "sliding" && cur.mode === "fixed");
    const { windowMin: _w, capMin: _c, mode: _m, autoSafe: _a, ...local } = patch;
    const cp = store.policy();
    const next = { ...cp, ...local };
    const localWidens = (next.scope === "tree" && cp.scope === "thread") || next.cfgWindowMin > cp.cfgWindowMin || next.cfgCapMin > cp.cfgCapMin || (next.cfgMode === "sliding" && cp.cfgMode === "fixed");
    return { wanted, guardWidens, local, localWidens };
  };

  bb.rpc.register(rpcContract, withGuardTouch({
    overview: () => overview(),
    "journal.verify": () => {
      const r = journal(true);
      changed();
      return r;
    },
    "guard.verify": async () => {
      if (!guardLink) return { error: "not in guard mode" };
      try {
        const r = await guardLink.verifyJournal();
        changed();
        return r;
      } catch (err) {
        return { error: err instanceof Error ? err.message : String(err) };
      }
    },
    "approvals.export": wrap(({ code }) => {
      // The code was checked by the guard (guard mode) or is checked here (without a guard): either way `touch` takes it.
      gate.touch("approvals.export", needCode(code));
      const result = buildExport(store.listApprovals(5000), now());
      const path = writeExport(dataDir, result, now());
      store.log("approvals.export", null, null, { count: result.count, digest: result.digest });
      return { path, digest: result.digest, count: result.count };
    }),
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
      if (moved.length === 0) throw new GateError("invalid", "в старом списке доверенных репозиториев ничего нет");
      const mySources = await needGuard().addSources(moved, proofOf(code, passkey), true);
      changed();
      return { ok: true as const, mySources, moved };
    }),
    "page.ping": () => {
      lastPagePing = now();
      return { ok: true as const };
    },
    "totp.begin": wrap(async () => {
      if (guardLink) throw new GateError("conflict", "в режиме сторожа второй фактор регистрируется только на консоли: `sudo sbb-guard totp-register`; через bb секрет не проходит");
      // "Attended" = the secure-bb page pinged us moments ago. A registration
      // started without it must be restarted from the page before it can be confirmed.
      const attended = now() - lastPagePing < PAGE_PING_TTL_MS;
      const { secret, uri } = await gate.beginRegistration({ attended, caller: "client" });
      changed();
      return { secret, uri, matrix: encodeQr(uri) };
    }),
    "totp.confirm": wrap(({ code }) => {
      if (guardLink) throw new GateError("conflict", "в режиме сторожа второй фактор регистрируется только на консоли: `sudo sbb-guard totp-register`");
      gate.confirmRegistration(code);
      changed();
      return { ok: true as const };
    }),
    "agents.scan": wrap(async () => {
      if (!agents) throw new GateError("invalid", "наблюдение за конфигурациями агентов работает в режиме сторожа: наблюдатель живёт в нём");
      const view = await agents.refresh(true);
      sweepTaintNow();
      return view;
    }),
    // A touch for exactly these differences: the guard checks the code or the signature (bound to the ids) and moves its baseline. Nothing is accepted here.
    "agents.accept": wrap(async ({ ids, code, passkey }) => {
      if (!agents || !guardLink) throw new GateError("invalid", "принять расхождения можно только через сторожа");
      if (ids.length === 0) throw new GateError("invalid", "нет расхождений для принятия");
      const proof = proofOf(code, passkey);
      if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
      const r = await guardLink.agentsAccept(ids, proof);
      await agents.refresh(false);
      changed();
      return { ok: true as const, accepted: r.accepted, note: `принято в эталон: ${r.accepted}` };
    }),
    "queue.approve": wrap(async ({ id, code, passkey, session, acknowledgeBlock }) => {
      if (guardLink) return id < 0 ? approvePendingProposal(-id, proofOf(code, passkey), acknowledgeBlock) : approveAtGuard(id, proofOf(code, passkey), acknowledgeBlock);
      // Lifting a block is the dangerous kind of this RPC: a fresh code, never a session.
      const proof = gate.proofFor("queue.approve", { code, session }, { escalate: acknowledgeBlock === true });
      const note = await approveQueueFull(id, proof, { acknowledgeBlock });
      return { ok: true as const, note };
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
    "window.open": wrap(async ({ queueId, code, passkey, session, scope }) => {
      if (guardLink) {
        const proof = proofOf(code, passkey);
        if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
        if (queueId < 0) throw new GateError("invalid", "this proposal is not installed yet: approve it (or install it) first, then open a window from the guard's entry");
        await gate.openGuardWindow(await guardEntry(queueId), proof, scope);
        recheck();
        changed();
        return { ok: true as const };
      }
      // A window wider than the policy ("whole tree" when the policy says "this thread only") widens the policy: a fresh code.
      const proof = gate.proofFor("window.open", { code, session }, { escalate: scope === "tree" && store.policy().scope === "thread" });
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
    "session.open": wrap(async ({ code }) => {
      if (guardLink) throw new GateError("conflict", "в режиме сторожа сессий нет: сторож проверяет свежий код для каждого одобрения");
      const opened = await gate.openSession(code);
      changed();
      return opened;
    }),
    "session.close": () => {
      gate.closeSessions("locked");
      changed();
      return { ok: true as const };
    },
    "batch.prepare": wrap(({ items }) => batches.prepare(items)),
    "batch.approve": wrap(async ({ batchId, setHash, code, session }) => {
      const results = await batches.approve(batchId, setHash, gate.proofFor("batch.approve", { code, session }));
      recheck();
      changed();
      return { ok: true as const, results };
    }),
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
      let mark: string | undefined = verified ? VERIFIED : undefined;
      if (!verified && plan.localWidens) {
        // Only the local part (thread scope, configuration windows) widens: then the guard checks the touch for "policy.set".
        if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: this widens the policy");
        await guardLink.touch("policy.set", proof);
        mark = VERIFIED;
      }
      gate.setPolicy(plan.local, mark);
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
          return out({ op: "approve", requestId: entry.id });
        }
        case "window.open": {
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
  }));

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
            // Whether an approval session is open is not for agents: its records stay on the page.
            const rows = store.listLog(input.options.limit, "session.");
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
        skills: cliCommand({
          summary: "Skills guard: which installed skills are pinned, which wait for a human or were removed (no reasons: they are for the person on the page)",
          options: {
            scan: { type: "boolean", description: "Check right now before printing" },
          },
          async run(input) {
            if (input.options.scan) await watch.scan().then((r) => (r.found + r.accepted > 0 ? changed() : undefined));
            const v = skillGuard.view();
            const lines = [
              `skills pinned: ${v.pinned.total} (${v.pinned.builtin} built-in, ${v.pinned.baseline} existing before the module, ${v.pinned.approved} approved)`,
              `waiting for a human: ${v.open.length}`,
              ...v.open.map((r) => `  #${r.id} ${r.name} (${r.scope}): ${r.state === "alarm" ? "alarm" : "held by secure-bb"}`),
            ];
            const removed = v.recent.filter((r) => r.state === "removed").slice(0, 5);
            if (removed.length > 0) lines.push("removed by secure-bb:", ...removed.map((r) => `  #${r.id} ${r.name} (${r.scope})`));
            return { exitCode: 0, stdout: lines.join("\n") };
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
        publish: cliCommand({
          summary: "Publishing of frozen versions of our plugins to the plugins repository: state and latest results (settings and the token are for the person on the page)",
          options: { limit: { type: "integer", min: 1, max: 20, default: 5, description: "How many results (1-20)" } },
          async run(input) {
            const lines = [publishLine(store.publishSettings(), publisher.state()), ...store.listPublications(input.options.limit).map((r) => `${new Date(r.startedAt).toISOString()} ${r.pluginId}@${r.version} ${r.status}`)];
            return { exitCode: 0, stdout: lines.join("\n") };
          },
        }),
        check: cliCommand({
          summary: "Run the checks on a plugin directory without installing it; prints a summary only (details are for the page). Not for bb's own data or directories private to the server user",
          positionals: [{ name: "path", description: "Plugin directory on this machine", required: true }],
          options: {},
          async run(input, ctx) {
            const dir = resolvePath(ctx.cwd ?? process.cwd(), input.positionals.path);
            // Runs as the server's user: not for bb's own data or what is private to that user (threat model F9). The reason stays in the log.
            const refused = checkPathRefusal(dir, { dataDir: safeDataDir(), serverUid: typeof process.getuid === "function" ? process.getuid() : null });
            if (refused !== null) {
              store.log("check.refused", null, null, { reason: refused });
              throw new PluginCliError("this directory cannot be checked from here", { code: "check_refused" });
            }
            let result;
            try {
              result = await verifyDeps(await runChecks(dir));
            } catch (err) {
              throw new PluginCliError(`cannot check ${dir}: ${err instanceof Error ? err.message : String(err)}`, { code: "check_failed" });
            }
            return { exitCode: 0, stdout: checkSummary(result) };
          },
        }),
        watchman: cliCommand({
          summary: "Sentinel feed (observation only; it never answers approval cards): recent actions, categories that fired, what the human did with the card",
          options: { limit: { type: "integer", min: 1, max: 50, default: 10, description: "How many entries (1-50)" } },
          async run(input) {
            await sentinel.refreshOutcomes().catch(() => 0);
            const s = sentinel.settings();
            const head = `watchman: ${s.enabled ? `on (${s.allThreads ? "all threads" : "threads with an open trust window"}); observation only, cards are not answered` : "off"}${jev.keyConfigured() ? "" : "; solver key not set"}`;
            const rows = sentinelStore.list(input.options.limit);
            return { exitCode: 0, stdout: [head, ...(rows.length > 0 ? rows.map((r) => feedText(r, s.riskThreshold)) : ["(feed is empty)"])].join("\n") };
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
                guarded: guardLink !== null,
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
      const scanAfterFact = () =>
        void scanner
          .scan()
          .then((d) => {
            if (d.length > 0) {
              bb.log.warn(`after the fact: disabled ${d.join(", ")}`);
              changed();
            }
          })
          .catch((e) => {
            bb.log.error(`after-the-fact scan failed: ${String(e)}`);
            try {
              store.log("afterfact.error", null, null, { message: String(e instanceof Error ? e.message : e).slice(0, 300) });
            } catch {
              /* the journal must not hide the error above */
            }
          });
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
      sweepTaintNow = sweepTaint;
      const kickAfterFact = debounced(scanAfterFact);
      const kickConfig = debounced(scanConfig);
      try {
        unsubscribe = bb.sdk.subscribe({
          event: "system:changed",
          callback: (event) => {
            if (!hookRegistered && event.changes?.includes("plugins-changed")) kickAfterFact();
            if (event.changes?.includes("plugins-changed")) void gate.closeSessionsForThirdParty().then((r) => (r.length > 0 ? changed() : undefined)).catch((e) => bb.log.warn(`session guard failed: ${String(e)}`));
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
            if (event.changes?.includes("interactions-changed") && event.id) void sentinel.refreshOutcomes(event.id).catch((e) => bb.log.warn(`sentinel outcomes: ${String(e)}`));
            if (!event.changes?.includes("events-appended") || !event.id) return;
            taint.note(event.id);
            if (gate.openWindows().length > 0 || watch.openWindows().length > 0) kickTaint();
          },
        });
      } catch (err) {
        bb.log.warn(`cannot subscribe to thread changes (windows are then checked once a tick): ${String(err)}`);
      }
      // The baseline (what was here before us) is taken at once, in either mode, before anything can be installed behind our back:
      // if the hook turns out to be dead later, whatever is not in it is new. It reads no code, so it is fast.
      try {
        await scanner.snapshotBaseline();
      } catch (e) {
        bb.log.error(`baseline failed: ${String(e)}`);
      }
      if (!hookRegistered) kickAfterFact();
      kickConfig();
      let lastWatch = now();
      // Every task of a tick is isolated: one that throws (a sentinel call, a journal check) must not starve the others,
      // the after-the-fact scan above all (it did, once: the scan came last in the tick).
      const task = async (name: string, fn: () => unknown): Promise<void> => {
        try {
          await fn();
        } catch (err) {
          bb.log.error(`${name} failed: ${String(err)}`);
        }
      };
      let lastSlow = now();
      let lastAgentsScan = 0;
      while (!signal.aborted) {
        // Short tick: a plugin the hook did not vet is already running and should be stopped within seconds.
        await sleep(SCAN_TICK_MS, signal);
        if (signal.aborted) break;
        await task("scan of plugins the hook did not vet", async () => {
          if ((await scanner.scan()).length > 0) changed();
        });
        if (now() - lastSlow < SWEEP_MS) continue;
        lastSlow = now();
        await task("heartbeat", () => alive.beat());
        await task("guard windows", async () => {
          if (!guardLink) return;
          try {
            gate.syncGuardWindows(await guardLink.state());
          } catch {
            /* the guard is not answering: the core holds everything unbuilt-in meanwhile, and the page says so */
          }
        });
        await task("window sweep", () => {
          if (gate.sweep() > 0) changed();
          if (gate.sweepSessions() > 0) changed();
          if (watch.sweep() > 0) changed();
        });
        await task("session guard", async () => {
          if ((await gate.closeSessionsForThirdParty()).length > 0) changed();
        });
        await task("taint sweep", () => {
          if (gate.openWindows().length > 0 || watch.openWindows().length > 0) sweepTaint();
        });
        // Agent watch: what the guard saw in the agents' files. A scan is asked for once a minute (the guard has its own timer and a 10 s limit).
        await task("agent watch", async () => {
          if (!agents) return;
          const scanNow = now() - lastAgentsScan >= WATCH_MS;
          if (scanNow) lastAgentsScan = now();
          const before = store.taintedThreads(1000).length;
          await agents.refresh(scanNow);
          if (store.taintedThreads(1000).length !== before) sweepTaint();
        });
        await task("sentinel outcomes", () => sentinel.refreshOutcomes());
        await task("journal", () => journal(now() - journalReport.checkedAt > 60_000));
        await task("config scan", () => {
          if (now() - lastWatch >= WATCH_MS) {
            lastWatch = now();
            scanConfig();
          }
        });
      }
      unsubscribe?.();
      unsubscribeThreads?.();
    },
  });

  bb.onDispose(() => {
    // The database handle is closed by the host; the only thing left is the note that this was an orderly stop.
    try {
      alive.stop();
    } catch {
      /* the database may already be closed */
    }
  });
}
