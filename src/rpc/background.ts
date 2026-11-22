// The background loop: scan the plugins the hook did not vet, the heartbeat, the windows, the pollution sweep, the agent watch, the journal and the config scan.
import { join } from "node:path";
import type { RpcCtx } from "./guard-helpers.js";

const SWEEP_MS = 15_000;

/** Plugins the hook did not vet are scanned this often: their code is already running, so every second counts. */
const SCAN_TICK_MS = 5_000;

const WATCH_MS = 60_000;

const WATCH_DEBOUNCE_MS = 1_500;

const sleep = (ms: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => (clearTimeout(timer), resolve()), { once: true });
  });

export function startBackground(c: RpcCtx) {
  const { agents, alive, bb, changed, gate, guardLink, journal, now, scanner, sentinel, state, store, taint, watch } = c;
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
      state.sweepTaintNow = sweepTaint;
      const kickAfterFact = debounced(scanAfterFact);
      const kickConfig = debounced(scanConfig);
      try {
        unsubscribe = bb.sdk.subscribe({
          event: "system:changed",
          callback: (event) => {
            if (!state.hookRegistered && event.changes?.includes("plugins-changed")) kickAfterFact();
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
      if (!state.hookRegistered) kickAfterFact();
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
      void guardLink?.beat().catch(() => undefined);
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
          await guardLink.beat().catch(() => undefined);
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
        await task("journal", () => journal(now() - state.journalReport.checkedAt > 60_000));
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

}
