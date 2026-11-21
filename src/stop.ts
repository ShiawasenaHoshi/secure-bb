// «Остановить агентов» (design: secure-bb-agent-rollback-design.md). A tightening, so no code: the plugin stops every running thread through the SDK
// (`threads.stop`) and, until the critical difference in the agents' settings is dealt with, asks core to hold new turns (the `message.dispatch` hook).
//
// What this can and cannot do, said honestly on the page:
//  - stopping ends the work of the threads that run NOW; it does not undo what a changed setting already did, nor tell whether data left;
//  - holding new turns works only while this plugin answers the hook, and a person can still send a held message by hand («отправить сейчас»);
//  - where the SDK has no such hook, there is no holding at all: the page says «агенты могут быть запущены снова».
import type { Store } from "./store.js";

/** The slice of bb's SDK this needs (the tests give a fake). */
export interface StopPort {
  listRunning(): Promise<Array<{ id: string }>>;
  stop(threadId: string): Promise<void>;
}

export interface StopResult {
  /** Threads the stop was delivered to. */
  stopped: string[];
  /** Threads that could not be stopped (with what bb said). */
  failed: Array<{ id: string; error: string }>;
  at: number;
}

/** What the page shows about stopping and holding. */
export interface StopView {
  /** When agents were stopped by the button and the hold has not ended yet; null: not stopped. */
  stoppedAt: number | null;
  /** The hook that holds new turns is in place (bb has it and the plugin registered). */
  holdAvailable: boolean;
  /** New turns are being held right now (stopped, and a critical difference is still open). */
  holding: boolean;
  last: StopResult | null;
}

const META_AT = "agents.stoppedAt";
const MAX_STOP = 200;

export class AgentStopper {
  private last: StopResult | null = null;
  constructor(
    private readonly d: {
      port: StopPort;
      store: Store;
      now: () => number;
      /** The `message.dispatch` hook was accepted by bb. */
      holdAvailable: boolean;
      log: (m: string) => void;
    },
  ) {}

  stoppedAt(): number | null {
    const v = this.d.store.getMeta(META_AT);
    const n = v === null ? NaN : Number(v);
    return Number.isFinite(n) && n > 0 ? n : null;
  }

  /** Stops what runs now and starts holding new turns. Never throws for a thread that would not stop: it is listed. */
  async stopAll(): Promise<StopResult> {
    const at = this.d.now();
    // The hold starts first: a turn that starts while we stop the others must not slip through.
    this.d.store.setMeta(META_AT, String(at));
    const running = await this.d.port.listRunning();
    const stopped: string[] = [];
    const failed: Array<{ id: string; error: string }> = [];
    for (const t of running.slice(0, MAX_STOP)) {
      try {
        await this.d.port.stop(t.id);
        stopped.push(t.id);
      } catch (err) {
        failed.push({ id: t.id, error: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200) });
      }
    }
    this.last = { stopped, failed, at };
    this.d.store.log("agents.stop", null, null, { stopped: stopped.length, failed: failed.length, holdAvailable: this.d.holdAvailable, threads: stopped.slice(0, 20), errors: failed.slice(0, 5) });
    return this.last;
  }

  /** Should core hold a new turn now? Stopped by the button, and a critical difference is still there. */
  holding(criticalOpen: boolean): boolean {
    return this.d.holdAvailable && this.stoppedAt() !== null && criticalOpen;
  }

  /**
   * The settings are dealt with (no critical difference is open any more): the hold ends. Returns true when it did, so that the caller asks core to re-ask the
   * messages it held.
   */
  release(criticalOpen: boolean): boolean {
    if (criticalOpen || this.stoppedAt() === null) return false;
    this.d.store.setMeta(META_AT, "");
    this.d.store.log("agents.stop.released", null, null, { note: "no critical difference is open any more: new turns are no longer held" });
    return true;
  }

  view(criticalOpen: boolean): StopView {
    return { stoppedAt: this.stoppedAt(), holdAvailable: this.d.holdAvailable, holding: this.holding(criticalOpen), last: this.last };
  }
}
