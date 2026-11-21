// Agent watch, the plugin's part (design: secure-bb-agent-watch-design.md). The watcher itself is in the guard (guard/src/agents-*.ts):
// it reads the files of the agents and compares them with the baseline a human accepted. Here: the page's view of what the guard
// found, and the consequences that need bb — which thread a working directory belongs to (through bb's environments API), and the
// plugin's own windows. Everything here only TIGHTENS: a critical difference marks threads polluted and closes windows; it never
// accepts anything (that is a touch at the guard).
import type { AgentDrift, AgentsState, GuardPort } from "./guardlink.js";
import type { Store } from "./store.js";
import type { AgentStopper, StopView } from "./stop.js";

/** What bb tells about environments and the threads in them (real SDK calls: bb-source side). */
export interface AgentThreadSource {
  /** Environments with a directory: `path` is where the checkout or the working directory is. */
  environments(): Promise<Array<{ id: string; path: string | null }>>;
  /** Threads that run in an environment (archived and hidden ones too: the file is there for any of them). */
  threadsOf(environmentId: string): Promise<string[]>;
}

export interface AgentsView {
  enabled: boolean;
  /** The guard could not be asked (the page says so; nothing is accepted meanwhile). */
  error?: string;
  state: AgentsState | null;
  /** Working directory → threads (by the environments API; a thread-shaped directory name is the fallback). */
  threads: Record<string, string[]>;
  /** Threads marked polluted because of a critical difference (id → the difference ids). */
  marked: Record<string, number[]>;
  /** «Остановить агентов»: whether agents were stopped, and whether new turns are held (set by the plugin, not the guard). */
  stop?: StopView;
}

/** The pseudo-sequence of a pollution hit made by a difference: unique per difference, below every real event's seq and the env-setup one. */
export const AGENT_SEQ_BASE = -1_000_000;
const THREADS_TTL_MS = 60_000;
const THREAD_DIR = /^thr_[A-Za-z0-9]+$/;

const within = (child: string, parent: string): boolean => child === parent || child.startsWith(parent.endsWith("/") ? parent : `${parent}/`);

export class AgentWatchLink {
  private state: AgentsState | null = null;
  private error: string | undefined;
  private readonly cache = new Map<string, { at: number; threads: string[] }>();
  private envs: { at: number; list: Array<{ id: string; path: string | null }> } | null = null;

  constructor(
    private readonly d: {
      guard: GuardPort;
      store: Store;
      source: AgentThreadSource;
      now: () => number;
      log: (m: string) => void;
      /** The plugin's own windows opened before `at` are closed (configuration windows; the guard closes its own). */
      closeWindowsOpenedBefore: (at: number, reason: string) => number;
      onChange: () => void;
      /** «Остановить агентов»: the stopper (its hold ends when no critical difference is open) and what to do when it ends (core re-asks the held messages). */
      stopper?: AgentStopper;
      onHoldReleased?: () => void;
    },
  ) {}

  /** A critical difference that is not part of the first baseline is open. */
  criticalOpen(): boolean {
    return (this.state?.drifts ?? []).some((x) => x.class === "critical" && !x.initial);
  }

  /** Asks the guard (a scan when `scan`; the guard rate-limits it) and applies the consequences. Never throws: the guard being away is an `error` on the page. */
  async refresh(scan: boolean): Promise<AgentsView> {
    try {
      this.state = scan ? await this.d.guard.agentsScan() : await this.d.guard.agentsState();
      this.error = undefined;
      await this.consequences(this.state);
      // Only a state the guard really gave may end the hold: an unreachable guard keeps it.
      if (this.d.stopper?.release(this.criticalOpen())) this.d.onHoldReleased?.();
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
      this.d.log(`agent watch: ${this.error}`);
    }
    return this.view();
  }

  view(): AgentsView {
    const s = this.state;
    const threads: Record<string, string[]> = {};
    const marked: Record<string, number[]> = {};
    for (const drift of s?.drifts ?? []) {
      if (drift.rootKind === "global") continue;
      const known = this.cache.get(drift.root)?.threads;
      if (known) threads[drift.root] = known;
      if (drift.class === "critical" && !drift.initial) for (const t of known ?? []) (marked[t] ??= []).push(drift.id);
    }
    return { enabled: s?.enabled ?? false, ...(this.error ? { error: this.error } : {}), state: s, threads, marked, ...(this.d.stopper ? { stop: this.d.stopper.view(this.criticalOpen()) } : {}) };
  }

  /** Threads whose working directory this is. */
  async threadsFor(root: string, rootName: string): Promise<string[]> {
    const hit = this.cache.get(root);
    if (hit && this.d.now() - hit.at < THREADS_TTL_MS) return hit.threads;
    const found = new Set<string>();
    try {
      if (!this.envs || this.d.now() - this.envs.at > THREADS_TTL_MS) this.envs = { at: this.d.now(), list: await this.d.source.environments() };
      // An environment owns a directory; the working directory (or the file) is inside it, or the environment sits inside the working directory.
      for (const env of this.envs.list) if (env.path && (within(root, env.path) || within(env.path, root))) for (const t of await this.d.source.threadsOf(env.id)) found.add(t);
    } catch (err) {
      this.d.log(`agent watch: threads of ${root} not read: ${err instanceof Error ? err.message : String(err)}`);
    }
    // The personal workspace names its directories after the thread; used only when bb's answer had nothing.
    if (found.size === 0 && THREAD_DIR.test(rootName)) found.add(rootName);
    const threads = [...found].sort();
    this.cache.set(root, { at: this.d.now(), threads });
    return threads;
  }

  /** A new critical difference (not part of the first baseline): the threads of its working directory are polluted, the plugin's windows opened before it are closed. */
  private async consequences(s: AgentsState): Promise<void> {
    let touched = false;
    for (const drift of s.drifts ?? []) {
      if (drift.class !== "critical" || drift.initial) continue;
      if (this.d.closeWindowsOpenedBefore(drift.firstSeen, "agents-critical") > 0) touched = true;
      if (drift.rootKind === "global") continue;
      const threads = await this.threadsFor(drift.root, drift.rootName);
      for (const t of threads) {
        // INSERT OR IGNORE by (thread, seq): the same difference marks a thread once, however many times it is seen.
        const fresh = this.d.store.addTaintHit({ threadId: t, seq: AGENT_SEQ_BASE - drift.id, kind: "agent-config", at: drift.firstSeen, note: note(drift) });
        if (fresh) {
          this.d.store.log("agents.taint", null, null, { thread: t, drift: drift.id, rel: drift.rel, rootKind: drift.rootKind, reasons: drift.reasons.slice(0, 3) });
          touched = true;
        }
      }
    }
    if (touched) this.d.onChange();
  }
}

const note = (d: AgentDrift): string => `${d.rel}: ${d.reasons[0] ?? d.change}`.slice(0, 200);
