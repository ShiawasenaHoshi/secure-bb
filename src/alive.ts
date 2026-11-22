// A trace of the gate being switched off (threat model X3). Disabling and enabling secure-bb through bb's API leaves no trace
// of its own: while it is off, nothing is held and nothing is looked at, and afterwards everything looks as before.
// So the gate writes a mark of life into its own database every few seconds, and at start it compares: a gap longer than the
// threshold (or a start after a stop) is a journal record and an alarm on the page ("the gate was not running from … to …").
// The same goes for bb's safe-mode, which also stops other plugins and which an attacker can switch around the gate.
import type { Store } from "./store.js";

/** How often the mark is written (the background loop's tick). */
export const ALIVE_INTERVAL_MS = 15_000;
/** A gap longer than this is an alarm: three missed marks. */
export const GAP_THRESHOLD_MS = 3 * ALIVE_INTERVAL_MS;
/** How long an alarm stays on the page. */
export const ALARM_KEEP_MS = 7 * 24 * 3_600_000;

const META_ALIVE = "alive_at";
const META_STOP = "alive_stop";
const META_SAFE = "alive_safe_mode";
const META_GAP_ACK = "alive_gap_ack";

export interface GapAlarm {
  from: number;
  to: number;
  ms: number;
  /** The plugin was stopped in an orderly way (disabled, bb shut down) rather than the process dying. */
  stopped: boolean;
  safeMode: boolean | null;
  at: number;
  /** What was known at the start that found the gap. Records written before these fields existed lack them. */
  mode?: "guard" | "hook";
  /** Why it was down, as far as the plugin can tell at the next start: the server restarted, or it cannot be told. */
  cause?: "server" | "unknown";
  /** The core holds every unvetted plugin while the gate plugin is down (BB_PLUGIN_ACTIVATION_GUARDS names secure-bb). */
  coreHolds?: boolean;
  /** The text the core gave for the failure, when the plugin could learn it. Not learnable at a start today; kept so the text can use it. */
  errorText?: string | null;
}
export interface AliveView {
  /** Last mark of life, or null on the very first run. */
  lastBeat: number | null;
  /** Gaps found at recent starts, newest first. */
  gaps: GapAlarm[];
  safeMode: boolean | null;
  /** The safe-mode was on at the last start, or switched on while the gate ran. */
  safeModeSeen: boolean;
  /** The newest gap was set aside with «Понятно». */
  gapsAckedAt: number | null;
  /** The core holds the unvetted plugins while the gate plugin is down (now, from the environment). */
  coreHolds: boolean;
}

export interface AliveDeps {
  store: Store;
  now: () => number;
  /** bb's safe-mode: true / false, null when it cannot be read. Must not throw. */
  safeMode: () => Promise<boolean | null>;
  log?: (message: string) => void;
  /** The plugin runs next to a guard (BB_PLUGIN_ACTIVATION_GUARD_SOCKET). */
  guardMode?: boolean;
  /** BB_PLUGIN_ACTIVATION_GUARDS names secure-bb. */
  coreHolds?: boolean;
  /** When the bb server process started (ms), if known: a gap that ends right after it is the server being stopped. */
  serverStartedAt?: () => number | null;
}

/** The plugin starts with the server or soon after it; a gap that ends within this of the server's start is a stopped server. */
export const SERVER_START_SLACK_MS = 2 * 60_000;
export const gapCause = (from: number, to: number, serverStartedAt: number | null): "server" | "unknown" =>
  serverStartedAt !== null && serverStartedAt >= from && to - serverStartedAt <= SERVER_START_SLACK_MS ? "server" : "unknown";

export class Alive {
  private safeModeNow: boolean | null = null;
  constructor(private readonly d: AliveDeps) {}

  /** Call once at start, before the first mark. Writes the journal records and returns the gap if it is an alarm. */
  async start(): Promise<GapAlarm | null> {
    const { store } = this.d;
    const now = this.d.now();
    const prevRaw = store.getMeta(META_ALIVE);
    const prev = prevRaw === null ? null : Number(prevRaw);
    const stopRaw = store.getMeta(META_STOP);
    const stopped = stopRaw !== null && prev !== null && Number(stopRaw) >= prev;
    const safeMode = await this.d.safeMode().catch(() => null);
    this.safeModeNow = safeMode;
    const wasSafe = store.getMeta(META_SAFE) === "1";

    let alarm: GapAlarm | null = null;
    if (prev !== null && Number.isFinite(prev) && now - prev > GAP_THRESHOLD_MS) {
      alarm = { from: prev, to: now, ms: now - prev, stopped, safeMode, at: now, mode: this.d.guardMode ? "guard" : "hook", cause: gapCause(prev, now, this.d.serverStartedAt?.() ?? null), coreHolds: this.d.coreHolds === true, errorText: null };
      store.log("gate.gap", null, null, { ...alarm });
      this.d.log?.(`secure-bb was not running from ${new Date(prev).toISOString()} to ${new Date(now).toISOString()}${stopped ? " (stopped in an orderly way)" : ""}${safeMode ? "; bb safe-mode is ON" : ""}`);
    }
    store.log("gate.start", null, null, { previous: prev, gapMs: prev === null ? null : now - prev, stopped, safeMode });
    if (safeMode === true) {
      store.log("safe-mode.on", null, null, { at: "start", wasOnBefore: wasSafe });
      this.d.log?.("bb safe-mode is ON: other plugins do not run");
    } else if (wasSafe && safeMode === false) store.log("safe-mode.off", null, null, { at: "start" });
    if (safeMode !== null) store.setMeta(META_SAFE, safeMode ? "1" : "0");
    store.setMeta(META_ALIVE, String(now));
    return alarm;
  }

  /** The mark of life; also notices safe-mode being switched while the gate runs. */
  async beat(): Promise<void> {
    const { store } = this.d;
    store.setMeta(META_ALIVE, String(this.d.now()));
    const safeMode = await this.d.safeMode().catch(() => null);
    if (safeMode !== null && safeMode !== this.safeModeNow) {
      store.log(safeMode ? "safe-mode.on" : "safe-mode.off", null, null, { at: "running" });
      store.setMeta(META_SAFE, safeMode ? "1" : "0");
    }
    if (safeMode !== null) this.safeModeNow = safeMode;
  }

  /** Orderly stop (the plugin is disposed). A start after it is still a gap if it was long enough, but says so. */
  stop(): void {
    this.d.store.setMeta(META_STOP, String(this.d.now()));
  }

  view(): AliveView {
    const { store } = this.d;
    const now = this.d.now();
    const beat = store.getMeta(META_ALIVE);
    const since = now - ALARM_KEEP_MS;
    const gaps = store.listLogKinds(["gate.gap"], since, 5).map((r) => r.detail as unknown as GapAlarm);
    const safeModeSeen = store.listLogKinds(["safe-mode.on"], since, 1).length > 0;
    const ack = store.getMeta(META_GAP_ACK);
    return { lastBeat: beat === null ? null : Number(beat), gaps, safeMode: this.safeModeNow, safeModeSeen, gapsAckedAt: ack === null ? null : Number(ack), coreHolds: this.d.coreHolds === true };
  }

  /** «Понятно»: the gaps up to now are set aside (the journal keeps them). */
  ackGaps(): void {
    this.d.store.setMeta(META_GAP_ACK, String(this.d.now()));
    this.d.store.log("gate.gap.ack", null, null, {});
  }
}
