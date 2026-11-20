// Builds the single view the Plugin Gate page renders (one RPC, one shape).
import type { CheckResult } from "./checks/types.js";
import { assess, type Assessment, type Probe } from "./detect.js";
import type { Gate, TotpState } from "./gate.js";
import type { InstalledPluginLite } from "./probe.js";
import { isThirdParty, runningThirdParty } from "./probe.js";
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
}

export interface OverviewDeps {
  watch: Watchdog;
  store: Store;
  gate: Gate;
  now: () => number;
  hookRegistered: boolean;
  listPlugins: () => Promise<InstalledPluginLite[]>;
  probe: () => Promise<Probe>;
  descendants: (threadId: string) => Promise<string[]>;
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
  };
}
