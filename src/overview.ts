// Builds the single view the Plugin Gate page renders (one RPC, one shape).
import type { Alive, AliveView } from "./alive.js";
import type { CheckResult } from "./checks/types.js";
import { assess, type Assessment, type Probe } from "./detect.js";
import type { Gate, TotpState } from "./gate.js";
import type { AgentsView } from "./agents.js";
import type { GuardApproval, GuardJournalReport, GuardPort, GuardState, GuardTrust } from "./guardlink.js";
import { realpath } from "node:fs/promises";
import type { JournalReport } from "./journal.js";
import type { InstalledPluginLite } from "./probe.js";
import { isThirdParty, runningThirdParty } from "./probe.js";
import type { Availability, Scanner } from "./scan/scanner.js";
import { scanView, type ScanView } from "./scan/view.js";
import type { AiSettings } from "./scan/types.js";
import { normalizeSettings } from "./sentinel/store.js";
import type { Sentinel } from "./sentinel/sentinel.js";
import { questionViews, type SentinelView } from "./sentinel/view.js";
import type { Publisher } from "./publish/publisher.js";
import type { PublishRow, PublishSettings, PublishState } from "./publish/types.js";
import type { SkillGuard, SkillsView } from "./skills/guard.js";
import type { Watchdog, WatchView } from "./watch/watchdog.js";
import type { ApprovalRow, LogRow, Policy, QueueRow, Store, WindowRow } from "./store.js";

export interface WindowView {
  id: number;
  pluginId: string;
  threadId: string;
  scope: "tree" | "thread";
  mode: "sliding" | "fixed";
  openedAt: number;
  expiresAt: number;
  hardExpiresAt: number;
  remainingSec: number;
  /** Threads below the window's thread that it also covers (tree scope only). */
  subthreads: number;
}
export interface PluginView {
  id: string;
  version: string;
  status: string;
  enabled: boolean;
  source: string;
  /** Latest active approval = the pinned version. */
  pin: ApprovalRow | null;
  history: ApprovalRow[];
  window: WindowView | null;
  /** No window is open and the pin came from one: this is the version frozen when the window closed. */
  frozenPin: boolean;
  /** Installed before secure-bb and never reviewed. */
  unreviewedBaseline: boolean;
}
export interface AiView {
  settings: AiSettings;
  availability: Availability;
  /** Latest scan of each installed third-party plugin; `current` = it covers the pinned version. */
  pluginScans: Record<string, ScanView & { current: boolean }>;
  /** Scan of the version a queue entry holds. */
  queueScans: Record<number, ScanView>;
  recent: ScanView[];
}
export interface PublishView {
  settings: PublishSettings;
  state: PublishState;
  /** Latest attempts, newest first (the page picks the plugin's own by id and version). */
  recent: PublishRow[];
}
/** Guard mode (`BB_SECURE_BB_GUARD_SOCKET`): what the page shows about the guard itself. Approvals, windows and the queue are in the usual fields, taken from the guard. */
export interface GuardView {
  connected: boolean;
  /** Why the guard cannot be reached (the page says that the core holds everything unbuilt-in meanwhile). */
  error: string | null;
  /** The guard's own journal: verified by the guard, checked again at most every 30 s. */
  journal: { valid: boolean; entries: number; head: string | null; problems: Array<{ kind: string; id: number | null; detail: string }> } | null;
  recent: GuardState["journal"]["recent"];
  revoked: GuardApproval[];
  /** Passkeys: where the page must be opened for them to work, the keys that can touch, whether the console has a registration window open. */
  /** Trust by source and rights: the mode and "my sources", as the guard holds them. Null: a guard that predates it. */
  trust: GuardTrust | null;
  passkey: { rpId: string; origin: string; keys: Array<{ id: number; label: string; createdAt: number; lastUsedAt: number | null }>; enrollmentOpen: boolean; totpOff: boolean } | null;
}
export interface Overview {
  /** Present in guard mode only. */
  guard?: GuardView;
  now: number;
  assessment: Assessment;
  totp: { state: TotpState; blockedUntil: number; pendingUnattended: boolean };
  hookRegistered: boolean;
  policy: Policy;
  thirdPartyRunning: string[];
  queue: QueueRow[];
  plugins: PluginView[];
  windows: WindowView[];
  log: LogRow[];
  /** Stage 2.1 check results by content hash (held queue entries and approved versions). */
  checks: Record<string, CheckResult>;
  /** Check results by queue entry id (proposals have them before the core hashes the plugin). */
  queueChecks: Record<number, CheckResult>;
  /** Stage 2a: config watchdog (approved snapshot, differences, configuration windows). */
  watch: WatchView;
  /** Stage 6: skills (pins, queue, removals). */
  skills: SkillsView;
  /** Stage 3: the optional AI scan. */
  ai: AiView;
  /** Stage 4: publishing frozen versions to the plugins repository. */
  publish: PublishView;
  /** Stage 5: integrity of the decision journal; anything but ok is an alarm. */
  journal: JournalView;
  /** Stage 5: threads known to have read untrusted content (closes trust windows of their tree). */
  tainted: Array<{ threadId: string; kinds: string[]; first: number; last: number }>;
  /** Repositories whose use does not taint a thread. */
  trustedRepos: string[];
  /** Stage 7: the sentinel (observation only). */
  sentinel: SentinelView;
  /** Threat model X3: gaps in the gate's own running and bb's safe-mode. */
  alive: AliveView;
  /** Agent watch (guard mode only): what the guard found in the agents' configurations and memory. */
  agents?: AgentsView;
}
const EMPTY_SKILLS: SkillsView = { baselineAt: null, lastScanAt: null, pinned: { total: 0, builtin: 0, baseline: 0, approved: 0 }, open: [], recent: [], trusted: [], blind: [], unchecked: [] };

export interface JournalView {
  ok: boolean;
  entries: number;
  head: string | null;
  checkedAt: number;
  problems: Array<{ kind: string; id: number | null; detail: string }>;
  /** Records that existed before the chain began: their history before that cannot be proven. */
  sealedLegacy: number;
}

export interface OverviewDeps {
  /** Absent in tests that do not touch the sentinel. */
  sentinel?: Sentinel;
  /** Absent in tests that do not touch the AI scan. */
  scanner?: Scanner;
  /** Absent in tests that do not touch publishing. */
  publisher?: Publisher;
  watch: Watchdog;
  /** Absent in tests that do not touch skills. */
  skills?: SkillGuard;
  store: Store;
  gate: Gate;
  now: () => number;
  hookRegistered: boolean;
  listPlugins: () => Promise<InstalledPluginLite[]>;
  probe: () => Promise<Probe>;
  descendants: (threadId: string) => Promise<string[]>;
  journal?: () => JournalReport;
  /** Absent in tests that do not touch the mark of life. */
  alive?: Alive;
  /** Guard mode: the link to the guard (the gate must have been built with the same one). */
  guard?: GuardPort;
  taintedThreads?: () => Array<{ threadId: string; kinds: string[]; first: number; last: number }>;
  /** Guard mode: the agent watch's view (asked fresh at each overview: one cheap request to the guard). */
  agents?: () => Promise<AgentsView>;
}

export async function windowView(d: Pick<OverviewDeps, "descendants" | "now">, w: WindowRow): Promise<WindowView> {
  let subthreads = 0;
  if (w.scope === "tree") {
    try {
      subthreads = (await d.descendants(w.threadId)).length;
    } catch {
      subthreads = 0;
    }
  }
  const end = Math.min(w.expiresAt, w.hardExpiresAt);
  return {
    id: w.id,
    pluginId: w.pluginId,
    threadId: w.threadId,
    scope: w.scope,
    mode: w.mode,
    openedAt: w.openedAt,
    expiresAt: w.expiresAt,
    hardExpiresAt: w.hardExpiresAt,
    remainingSec: Math.max(0, Math.ceil((end - d.now()) / 1000)),
    subthreads,
  };
}

function journalView(d: OverviewDeps): JournalView {
  const r = d.journal?.() ?? d.store.verifyJournal();
  return {
    ok: r.ok,
    entries: r.entries,
    head: r.head ? r.head.hash.slice(0, 16) : null,
    checkedAt: r.checkedAt,
    problems: r.problems.slice(0, 20),
    sealedLegacy: d.store.journalSealedLegacy(),
  };
}

const GUARD_VERIFY_EVERY_MS = 30_000;
const verified = new WeakMap<GuardPort, { at: number; report: GuardJournalReport }>();

/** Approvals, queue and windows of the guard, in the shapes the page already knows (ids are the guard's). */
async function guardOverlay(d: OverviewDeps, port: GuardPort): Promise<{ view: GuardView; state: GuardState | null }> {
  let state: GuardState;
  try {
    state = await port.state();
  } catch (err) {
    return { view: { connected: false, error: err instanceof Error ? err.message : String(err), journal: null, recent: [], revoked: [], trust: null, passkey: null }, state: null };
  }
  // A second factor exists if either kind does: a guard with passkeys only (codes switched off) is as registered as one with a TOTP secret.
  const keys = state.passkeys?.keys ?? [];
  d.gate.noteGuardState(state.totp.registered || keys.length > 0);
  d.gate.syncGuardWindows(state);
  let cached = verified.get(port);
  if (!cached || d.now() - cached.at > GUARD_VERIFY_EVERY_MS) {
    try {
      cached = { at: d.now(), report: await port.verifyJournal() };
      verified.set(port, cached);
    } catch {
      cached = undefined;
    }
  }
  const r = cached?.report;
  return {
    view: {
      connected: true,
      error: null,
      journal: r ? { valid: r.valid, entries: r.entries, head: r.head ? r.head.hash.slice(0, 16) : null, problems: r.problems.slice(0, 20) } : null,
      recent: state.journal.recent,
      revoked: state.revoked,
      trust: state.trust ?? null,
      passkey: state.passkeys ? { rpId: state.passkeys.rpId, origin: state.passkeys.origin, keys, enrollmentOpen: state.passkeys.enrollmentOpen, totpOff: state.totp.disabled === true } : null,
    },
    state,
  };
}

async function proposalOf(d: OverviewDeps, rootDir: string, pluginId: string) {
  for (const dir of [rootDir, await realpath(rootDir).catch(() => null)]) {
    if (!dir) continue;
    const p = d.store.proposalByDir(dir);
    if (p && p.pluginId === pluginId) return p;
  }
  return null;
}

export async function buildOverview(d: OverviewDeps): Promise<Overview> {
  const guarded = d.guard ? await guardOverlay(d, d.guard) : null;
  if (!guarded?.state) d.gate.sweep(); // with a guard that answers, its windows are synced instead (the guard's clock is the truth)
  const [plugins, probe] = await Promise.all([d.listPlugins().catch(() => [] as InstalledPluginLite[]), d.probe()]);
  let windows: WindowView[];
  let approvals: ApprovalRow[];
  let queue: QueueRow[];
  if (guarded?.state) {
    const gs = guarded.state;
    windows = await Promise.all(
      gs.windows.map(async (g) => {
        const shadow = d.store.windowByGuardId(g.id);
        const base = shadow ?? { id: 0, pluginId: g.pluginId, threadId: "неизвестен", scope: "thread" as const, mode: g.mode, sizeSec: g.sizeSec, capSec: g.capSec, openedAt: g.openedAt, expiresAt: g.expiresAt, hardExpiresAt: g.hardExpiresAt, closedAt: null, closedReason: null, caps: [], guardWindowId: g.id };
        // The guard's clock is the truth; the id is the guard's too (the page closes windows by it).
        return windowView(d, { ...base, id: g.id, expiresAt: g.expiresAt, hardExpiresAt: g.hardExpiresAt, mode: g.mode });
      }),
    );
    approvals = gs.approvals.map((a) => ({ id: a.id, contentHash: a.contentHash, pluginId: a.pluginId, version: a.version, source: a.source, sourceKind: a.sourceKind, gitCommit: null, npmIntegrity: null, via: a.via as ApprovalRow["via"], windowId: a.windowId, threadId: null, approvedAt: a.approvedAt, revokedAt: a.revokedAt, lastSeen: null, localHash: null }));
    queue = [];
    // The guard's queue is the list; what this plugin knows (checks, thread) explains its entries.
    // Proposals the core has not asked the guard about yet are listed after them, with negative ids (approving one installs it first).
    const known = new Set<string>();
    for (const g of gs.queue) known.add(await realpath(g.rootDir).catch(() => g.rootDir));
    for (const g of gs.queue) {
      const proposal = await proposalOf(d, g.rootDir, g.pluginId);
      const note = g.annotation?.findings as { reason?: unknown } | null | undefined;
      queue.push({
        id: g.id,
        kind: "hook",
        contentHash: g.contentHash,
        pluginId: g.pluginId,
        version: g.version,
        source: g.source,
        sourceKind: g.sourceKind,
        rootDir: g.rootDir,
        gitCommit: null,
        npmIntegrity: null,
        trigger: g.trigger,
        threadId: proposal?.threadId ?? null,
        proposalId: proposal?.id ?? null,
        status: g.status,
        reason: g.note ?? (typeof note?.reason === "string" ? note.reason : null),
        firstSeen: g.firstSeen,
        lastSeen: g.lastSeen,
      });
    }
    for (const lq of d.store.listQueue(50)) {
      if (lq.kind !== "proposal" || lq.status !== "held" || lq.contentHash !== null || lq.proposalId === null) continue;
      const p = d.store.getProposal(lq.proposalId);
      if (!p || known.has(await realpath(p.snapshotDir).catch(() => p.snapshotDir))) continue;
      queue.push({ ...lq, id: -lq.id, reason: lq.reason ? `не установлен: ${lq.reason.replace(/^заблокировано проверками/, "заблокирован проверками secure-bb")}` : "не установлен" });
    }
  } else if (guarded) {
    windows = [];
    approvals = [];
    queue = [];
  } else {
    windows = await Promise.all(d.gate.openWindows().map((w) => windowView(d, w)));
    approvals = d.store.listApprovals(500).filter((a) => a.revokedAt === null);
    queue = d.store.listQueue(50);
  }
  const baseline = new Map(d.store.listBaseline().map((b) => [b.pluginId, b.localHash]));

  const views: PluginView[] = plugins.filter(isThirdParty).map((p) => {
    const mine = approvals.filter((a) => a.pluginId === p.id);
    return {
      id: p.id,
      version: p.version,
      status: p.status,
      enabled: p.enabled,
      source: p.source,
      pin: mine[0] ?? null,
      history: mine.slice(0, 5),
      window: windows.find((w) => w.pluginId === p.id) ?? null,
      frozenPin: mine[0] !== undefined && mine[0].via !== "touch" && !windows.some((w) => w.pluginId === p.id),
      unreviewedBaseline: baseline.has(p.id) && mine.length === 0,
    };
  });

  const checks: Record<string, CheckResult> = {};
  const hashes = [...queue.map((q) => q.contentHash), ...approvals.slice(0, 200).map((a) => a.contentHash)];
  for (const h of hashes) {
    if (!h || checks[h]) continue;
    const c = d.store.getCheck(h);
    if (c) checks[h] = c.result;
  }

  const queueChecks: Record<number, CheckResult> = {};
  for (const q of queue) {
    const c = d.gate.checkForQueue(q);
    if (c) queueChecks[q.id] = c;
  }

  const settings = d.store.aiSettings();
  const pluginScans: AiView["pluginScans"] = {};
  for (const v of views) {
    const row = d.store.latestScanOfPlugin(v.id);
    if (!row) continue;
    const current = v.pin !== null && (row.contentHash === v.pin.contentHash || (v.pin.localHash !== null && v.pin.localHash === row.localHash));
    pluginScans[v.id] = { ...scanView(row), current };
  }
  const queueScans: AiView["queueScans"] = {};
  for (const q of queue) {
    const proposal = q.proposalId === null ? null : d.store.getProposal(q.proposalId);
    const row = d.store.latestScanFor({ contentHash: q.contentHash, localHash: proposal?.localHash ?? null });
    if (row) queueScans[q.id] = scanView(row);
  }
  const ai: AiView = {
    settings,
    availability: d.scanner?.availability(settings) ?? { claude: { mode: "unavailable", detail: "скан не подключён" }, cursor: null },
    pluginScans,
    queueScans,
    recent: d.store.listScans(8).map(scanView),
  };

  return {
    now: d.now(),
    assessment: assess(probe),
    ...(guarded ? { guard: guarded.view } : {}),
    ...(d.agents ? { agents: await d.agents() } : {}),
    totp: guarded?.state
      ? { state: guarded.state.totp.registered || (guarded.state.passkeys?.keys.length ?? 0) > 0 ? ("external" as const) : ("none" as const), blockedUntil: guarded.state.totp.blockedUntil, pendingUnattended: false }
      : { state: d.gate.totpState(), blockedUntil: d.gate.blockedUntil(), pendingUnattended: d.gate.pendingUnattended() },
    hookRegistered: d.hookRegistered,
    // Guard mode: window size, ceiling and mode are the guard's; "safe class passes" does not exist there.
    policy: guarded?.state ? { ...d.store.policy(), ...guarded.state.policy, autoSafe: false } : d.store.policy(),
    thirdPartyRunning: runningThirdParty(plugins),
    queue,
    queueChecks,
    plugins: views,
    windows,
    log: d.store.listLog(40),
    checks,
    watch: d.watch.view(),
    skills: d.skills?.view() ?? EMPTY_SKILLS,
    ai,
    publish: { settings: d.store.publishSettings(), state: d.publisher?.state() ?? "off", recent: d.store.listPublications(60) },
    journal: journalView(d),
    tainted: d.taintedThreads?.() ?? [],
    trustedRepos: d.store.trustedRepos(),
    sentinel: sentinelView(d),
    alive: d.alive?.view() ?? { lastBeat: null, gaps: [], safeMode: null, safeModeSeen: false },
  };
}

function sentinelView(d: OverviewDeps): SentinelView {
  const settings = d.sentinel?.settings() ?? normalizeSettings({});
  return {
    settings,
    keyConfigured: d.sentinel?.keyConfigured() ?? false,
    solver: d.sentinel ? "jev" : "—",
    questions: questionViews(settings),
    feed: d.sentinel?.recent(30) ?? [],
  };
}
