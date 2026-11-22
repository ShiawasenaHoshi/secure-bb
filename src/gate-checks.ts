// Running the checks on a version (one job per key, a result kept in the store, dependencies verified again after a while) and handing the result to whoever asks.
import { CHECKS_VERSION, runChecks as defaultRunChecks, type CheckResult } from "./checks/index.js";
import { bySeverity, localCheckKey } from "./decision.js";
import type { QueueRow } from "./store.js";
import { type HookCtx, DEP_RETRY_MS } from "./gate-types.js";
import { GateSettings } from "./gate-settings.js";

export class GateChecks extends GateSettings {
  // ---- checks -------------------------------------------------------------
  protected readonly checking = new Map<string, Promise<CheckResult | null>>();
  /**
   * The check result stored under `key`, or a fresh run on `dir` (one retry if it
   * throws), stored under `key`. Concurrent calls share one run. Null = the checks
   * failed twice; the caller must hold (fail closed).
   */
  protected depsDueForRetry(stored: { ts: number; result: CheckResult }): boolean {
    return this.d.verifyDeps !== undefined && this.now - stored.ts >= DEP_RETRY_MS && stored.result.findings.some((f) => f.rule === "dep-unchecked");
  }
  protected startCheck(key: string, pluginId: string, dir: string, logHash: string | null): Promise<CheckResult | null> {
    const stored = this.store.getCheck(key);
    // A result made by an older analysis (it counted other things) is made again; until then the old one is what is shown.
    if (stored && stored.result.v === CHECKS_VERSION && !this.depsDueForRetry(stored)) return Promise.resolve(stored.result);
    const running = this.checking.get(key);
    if (running) return running;
    const run = this.d.runChecks ?? defaultRunChecks;
    const job = (async (): Promise<CheckResult | null> => {
      try {
        let result: CheckResult;
        try {
          result = await run(dir, { pluginId });
        } catch {
          result = await run(dir, { pluginId }); // one retry
        }
        // The clock stopped the flow analysis: the result is not finished. It is not kept, and the version is held («проверка не успела») until a later check finishes.
        if (result.flowsTimedOut) {
          this.store.log("check.error", pluginId, logHash, { message: "проверка не успела: анализ потока данных остановлен по времени", key });
          return null;
        }
        if (this.d.verifyDeps) result = await this.d.verifyDeps(result);
        // What the gate ran now is of the current analysis (a result of a stand-in without the stamp too).
        result = { ...result, v: result.v ?? CHECKS_VERSION };
        this.store.putCheck(key, pluginId, result);
        this.store.log("check", pluginId, logHash, {
          blocks: bySeverity(result, "block").length,
          reviews: bySeverity(result, "review").length,
          infos: bySeverity(result, "info").length,
          capabilities: result.capabilities.map((c) => c.kind),
          ...(result.dependencyStats ? { dependencies: result.dependencyStats.total, unverified: result.dependencyStats.unchecked, young: result.dependencyStats.young } : {}),
          key,
        });
        this.d.onChecked?.();
        return result;
      } catch (err) {
        this.store.log("check.error", pluginId, logHash, { message: err instanceof Error ? err.message : String(err), key });
        return null;
      } finally {
        this.checking.delete(key);
      }
    })();
    this.checking.set(key, job);
    return job;
  }
  /** Waits for a check, but never longer than the hook may take. Null on failure or timeout (the run goes on and is stored). */
  protected async awaitCheck(job: Promise<CheckResult | null>): Promise<CheckResult | null> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), this.d.checkWaitMs ?? 8000);
    });
    try {
      return await Promise.race([job, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }
  /** Runs the checks for a content hash in the background, once. Never throws, never delays the hook. */
  scheduleCheck(ctx: Pick<HookCtx, "pluginId" | "contentHash" | "rootDir">): void {
    void this.startCheck(ctx.contentHash, ctx.pluginId, ctx.rootDir, ctx.contentHash);
  }
  /** `propose` runs the checks on the snapshot right away, keyed by the snapshot's own hash. */
  checkSnapshot(pluginId: string, localHash: string, dir: string): Promise<CheckResult | null> {
    return this.awaitCheck(this.startCheck(localCheckKey(localHash), pluginId, dir, null));
  }
  /** The stored result for a queue entry: by the core's hash, else by its proposal's snapshot hash. */
  checkForQueue(q: QueueRow): CheckResult | null {
    if (q.contentHash) {
      const c = this.store.getCheck(q.contentHash);
      if (c) return c.result;
    }
    const p = q.proposalId === null ? null : this.store.getProposal(q.proposalId);
    return p ? (this.store.getCheck(localCheckKey(p.localHash))?.result ?? null) : null;
  }
  /** Resolves when no background check is running (tests, shutdown). */
  async checksIdle(): Promise<void> {
    while (this.checking.size > 0) await Promise.all([...this.checking.values()]);
  }
}
