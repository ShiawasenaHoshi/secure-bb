// Pollution tracker: finds threads that read untrusted content and answers, for a trust window,
// "has anything in my thread tree been tainted since I opened?" (spec §0, §6).
//
// The source is the thread event history of bb (`threads.events.list`); events are read once and
// remembered by a per-thread cursor, so a scan of an unchanged tree is one cheap call per thread.
import type { ThreadTree } from "../gate.js";
import type { Store, TaintHitRow } from "../store.js";
import { classifyEvent, TAINT_EVENT_TYPES, type EventLike, type TaintKind } from "./classify.js";

export interface TaintSource {
  /** Events of a thread after `afterSeq` (exclusive), oldest first. */
  events(threadId: string, afterSeq: number | null, limit: number): Promise<EventLike[]>;
  projectOf(threadId: string): Promise<string | null>;
  /** True when the project has a `.bb-env-setup.sh`; false when it has none or has no local folder. Throws when it cannot be read. */
  hasEnvSetup(projectId: string): Promise<boolean>;
}

export interface TaintAssessment {
  state: "clean" | "tainted" | "unknown";
  /** Distinct kinds seen (for the log and the page). */
  kinds: TaintKind[];
  threads: string[];
  /** One line per hit, for the page: `thread kind note`. */
  lines: string[];
  /** Why the state is `unknown` (some thread could not be read in full). */
  unknownWhy?: string;
}

const PAGE = 500;
const MAX_PAGES = 20;
const MAX_THREADS = 200;
const ENV_TTL_MS = 60_000;
export const ENV_SETUP_SEQ = -1;

export interface TaintDeps {
  store: Store;
  source: TaintSource;
  tree: ThreadTree;
  now: () => number;
  /** Trusted repository patterns, read at every scan (a change applies to events read afterwards). */
  trustedRepos?: () => readonly string[];
}

export class TaintMonitor {
  private readonly projects = new Map<string, string | null>();
  private readonly envCache = new Map<string, { at: number; present: boolean }>();
  /** Threads the realtime feed said changed; scanned by the next whole-bb assessment. */
  private readonly dirty = new Set<string>();

  constructor(private readonly d: TaintDeps) {}

  /** The realtime feed saw new events in this thread. */
  note(threadId: string): void {
    this.dirty.add(threadId);
  }

  /** Reads the thread's new events. Returns whether it reached the end of the history. */
  async scanThread(threadId: string): Promise<{ complete: boolean; fresh: number }> {
    const { store, source } = this.d;
    let cursor = store.taintCursor(threadId);
    let fresh = 0;
    for (let page = 0; page < MAX_PAGES; page++) {
      const rows = await source.events(threadId, cursor, PAGE);
      for (const ev of rows) {
        if (cursor === null || ev.seq > cursor) cursor = ev.seq;
        const hit = classifyEvent(ev, this.d.trustedRepos?.() ?? []);
        if (hit && store.addTaintHit({ threadId, seq: ev.seq, kind: hit.kind, at: ev.createdAt, note: hit.note })) fresh++;
      }
      if (cursor !== null) store.setTaintCursor(threadId, cursor);
      if (rows.length < PAGE) {
        await this.checkEnvSetup(threadId);
        return { complete: true, fresh };
      }
    }
    return { complete: false, fresh };
  }

  /** A project with `.bb-env-setup.sh` taints every thread in it for as long as the file is there. */
  private async checkEnvSetup(threadId: string): Promise<void> {
    let project = this.projects.get(threadId);
    if (project === undefined) {
      project = await this.d.source.projectOf(threadId);
      this.projects.set(threadId, project);
    }
    if (project === null) return;
    const cached = this.envCache.get(project);
    let present: boolean;
    if (cached && this.d.now() - cached.at < ENV_TTL_MS) present = cached.present;
    else {
      present = await this.d.source.hasEnvSetup(project);
      this.envCache.set(project, { at: this.d.now(), present });
    }
    if (present) this.d.store.addTaintHit({ threadId, seq: ENV_SETUP_SEQ, kind: "env-setup", at: this.d.now(), note: "проект с .bb-env-setup.sh" });
    else this.d.store.clearTaintHit(threadId, ENV_SETUP_SEQ);
  }

  private verdict(hits: TaintHitRow[], unknownWhy: string | undefined): TaintAssessment {
    if (hits.length > 0)
      return {
        state: "tainted",
        kinds: [...new Set(hits.map((h) => h.kind as TaintKind))],
        threads: [...new Set(hits.map((h) => h.threadId))],
        lines: hits.slice(0, 20).map((h) => `${h.threadId} · ${h.kind} · ${h.note}`),
      };
    return unknownWhy ? { state: "unknown", kinds: [], threads: [], lines: [], unknownWhy } : { state: "clean", kinds: [], threads: [], lines: [] };
  }

  /**
   * The tree under `rootId` (the thread alone for scope "thread"): any taint since `since`?
   * A hit that is already known wins over a read failure: it is tainted whatever else is unknown.
   */
  async assessTree(rootId: string, scope: "tree" | "thread", since: number): Promise<TaintAssessment> {
    let threads = [rootId];
    let unknownWhy: string | undefined;
    if (scope === "tree") {
      try {
        threads = [rootId, ...(await this.d.tree.descendants(rootId))];
      } catch (err) {
        unknownWhy = `дерево тредов не прочитано: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
    if (threads.length > MAX_THREADS) {
      unknownWhy = `в дереве больше ${MAX_THREADS} тредов`;
      threads = threads.slice(0, MAX_THREADS);
    }
    for (const t of threads) {
      try {
        const r = await this.scanThread(t);
        if (!r.complete && !unknownWhy) unknownWhy = `история треда ${t} прочитана не до конца`;
      } catch (err) {
        unknownWhy ??= `тред ${t}: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
    return this.verdict(this.d.store.taintHits(threads, since), unknownWhy);
  }

  /** A window that is not bound to a tree (configuration): anything tainted anywhere since `since`. */
  async assessAll(since: number): Promise<TaintAssessment> {
    let unknownWhy: string | undefined;
    for (const t of [...this.dirty]) {
      this.dirty.delete(t);
      try {
        const r = await this.scanThread(t);
        if (!r.complete) {
          this.dirty.add(t);
          unknownWhy ??= `история треда ${t} прочитана не до конца`;
        }
      } catch (err) {
        this.dirty.add(t);
        unknownWhy ??= `тред ${t}: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
    return this.verdict(this.d.store.taintHits(null, since), unknownWhy);
  }
}

export { TAINT_EVENT_TYPES };
