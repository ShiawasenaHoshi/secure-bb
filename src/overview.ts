// Builds the single view the Plugin Gate page renders (one RPC, one shape).
import type { Alive, AliveView } from "./alive.js";
import type { CheckResult } from "./checks/types.js";
import { assess, type Assessment, type Probe } from "./detect.js";
import type { Gate, TotpState } from "./gate.js";
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
export interface Overview {
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
  taintedThreads?: () => Array<{ threadId: string; kinds: string[]; first: number; last: number }>;
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

export async function buildOverview(d: OverviewDeps): Promise<Overview> {
  d.gate.sweep();
  const [plugins, probe] = await Promise.all([d.listPlugins().catch(() => [] as InstalledPluginLite[]), d.probe()]);
  const windows = await Promise.all(d.gate.openWindows().map((w) => windowView(d, w)));
  const approvals = d.store.listApprovals(500).filter((a) => a.revokedAt === null);
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
  const hashes = [...d.store.listQueue(50).map((q) => q.contentHash), ...approvals.slice(0, 200).map((a) => a.contentHash)];
  for (const h of hashes) {
    if (!h || checks[h]) continue;
    const c = d.store.getCheck(h);
    if (c) checks[h] = c.result;
  }

  const queue = d.store.listQueue(50);
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
    totp: { state: d.gate.totpState(), blockedUntil: d.gate.blockedUntil(), pendingUnattended: d.gate.pendingUnattended() },
    hookRegistered: d.hookRegistered,
    policy: d.store.policy(),
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
