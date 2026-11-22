// How often the person approves: a hint with ready buttons, not a nag.
import { friendlySource } from "./modes.js";
import { sourceLabel } from "./words.js";

/** The person approved versions of one plugin or one source at least this many times within the window: the hint is due. */
export const FREQ_LIMIT = 3;

export const FREQ_WINDOW_MS = 3_600_000;

/** After the hint was used or put away it is silent for a day. */
export const FREQ_QUIET_MS = 24 * 3_600_000;

export const FREQ_KEY = "secure-bb.freq.at";

export const FREQ_OFF_KEY = "secure-bb.freq.off";

export const FREQ_SETTING_LABEL = "Подсказывать, когда я слишком часто одобряю одно и то же";

export interface ApprovalEvent {
  ts: number;
  pluginId: string | null;
  /** The source the guard wrote with the approval (`github:o/r`, `path:/x`); null where the journal has none. */
  source: string | null;
}

/** What the journal counts as «the person approved a version»: a touch (also in a pack) or the guard's own record of it. A pass by itself or by a window is not asking anybody. */
const FREQ_KINDS = new Set(["approved.touch", "approved.guard"]);

export function approvalEventsOf(rows: Array<{ ts: number; kind: string; pluginId: string | null; detail?: unknown }>): ApprovalEvent[] {
  return rows
    .filter((r) => FREQ_KINDS.has(r.kind))
    .map((r) => {
      const src = (r.detail as { source?: unknown } | null | undefined)?.source;
      return { ts: r.ts, pluginId: r.pluginId, source: typeof src === "string" ? src : null };
    });
}

export interface FreqHint {
  scope: "source" | "plugin";
  count: number;
  /** The question, in the owner's words. */
  text: string;
  /** What the ready buttons are, main first. */
  offer: Array<"trust" | "window">;
}

export interface FreqCard {
  pluginId: string;
  source: string;
  /** The source can go into «мои источники» from this card. */
  canTrust: boolean;
  /** A window can be opened from this card. */
  canWindow: boolean;
}

export interface FreqState {
  off: boolean;
  /** When the hint was last used or put away. */
  lastAt: number | null;
}

const recentIn = (events: ApprovalEvent[], now: number, match: (e: ApprovalEvent) => boolean): number => events.filter((e) => now - e.ts >= 0 && now - e.ts <= FREQ_WINDOW_MS && match(e)).length;

export function frequentHint(events: ApprovalEvent[], now: number, card: FreqCard, state: FreqState, windowMin: number): FreqHint | null {
  if (state.off || (state.lastAt !== null && now - state.lastAt < FREQ_QUIET_MS)) return null;
  const bySource = card.source === "" ? 0 : recentIn(events, now, (e) => e.source === card.source);
  const byPlugin = recentIn(events, now, (e) => e.pluginId === card.pluginId);
  const offer: FreqHint["offer"] = [];
  if (card.canTrust) offer.push("trust");
  if (card.canWindow) offer.push("window");
  if (offer.length === 0) return null;
  if (bySource >= FREQ_LIMIT && card.canTrust)
    return { scope: "source", count: bySource, offer, text: `Вы часто одобряете ${/^(?:github|path):/.test(card.source) ? friendlySource(card.source) : sourceLabel("git", card.source)}. Доверять этому источнику (новые версии — без вопросов, пока права не растут)?` };
  if (byPlugin >= FREQ_LIMIT) {
    const first = card.canWindow ? "window" : "trust";
    return { scope: "plugin", count: byPlugin, offer: [first, ...offer.filter((o) => o !== first)], text: card.canWindow ? `Вы часто одобряете ${card.pluginId}. Открыть окно на ${windowMin} мин (новые версии — без вопросов, пока права не растут)?` : `Вы часто одобряете ${card.pluginId}. Доверять этому источнику (новые версии — без вопросов, пока права не растут)?` };
  }
  return null;
}

/** The first card, in the order the page shows them, that the hint is due on: it goes on ONE card, not on all. */
export function pickFrequent(cards: FreqCard[], events: ApprovalEvent[], now: number, state: FreqState, windowMin: number): { pluginId: string; hint: FreqHint } | null {
  for (const c of cards) {
    const hint = frequentHint(events, now, c, state, windowMin);
    if (hint) return { pluginId: c.pluginId, hint };
  }
  return null;
}

export const parseFreqAt = (raw: string | null): number | null => {
  const n = raw === null ? NaN : Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
};

export const FREQ_NOT_NOW = "Не сейчас";

export const FREQ_BUTTON: Record<"trust" | "window", (windowMin: number) => string> = { trust: () => "Доверять источнику", window: (m) => `Окно на ${m} мин` };
