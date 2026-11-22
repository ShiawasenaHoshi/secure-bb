// What the person decided about cards (put aside, kept, hidden) and the plan of cards per plugin, the words of the decisions and of the approval history.
import { approvalWhy } from "./phrases.js";
import { plural, clockText } from "./words.js";

export const AWAY_KEY = "secure-bb.away.seenAt";

export const DEFERRED_KEY = "secure-bb.deferred";

export const KEPT_KEY = "secure-bb.kept";

export const WIZARD_KEY = "secure-bb.wizard.done";

/** Cards the person put aside («Решить позже») or kept in quarantine: remembered by the page only. The key has the id of the queue entry: the same code held again later is a NEW entry and comes back as a new question (a stale mark of an earlier session must not show «Вы отложили» on a card nobody put aside). */
export const deferKey = (pluginId: string, contentHash: string | null, id: number): string => `${pluginId}:${contentHash ?? "-"}:#${id}`;

export function parseDeferred(raw: string | null): string[] {
  if (raw === null) return [];
  try {
    const j = JSON.parse(raw) as unknown;
    return Array.isArray(j) ? j.filter((x): x is string => typeof x === "string").slice(0, 500) : [];
  } catch {
    return [];
  }
}

/** What the page keeps about a card the person has acted on without the guard being asked. */
export interface Decisions {
  /** «Решить позже»: still unresolved (the status counts it), only folded away. */
  deferred: string[];
  /** «Оставить в карантине»: DECIDED. The plugin stays held at the guard, but the person has answered: it is not a question and not a red status. */
  kept: string[];
}

export interface HeldLike {
  id: number;
  pluginId: string;
  version: string;
  contentHash: string | null;
  /** When the entry first appeared: a mark made BEFORE this is about an earlier entry of the same number (the data was reset), not about this one. */
  firstSeen?: number;
}

export type CardDecision = "open" | "deferred" | "kept";

/** A mark as the page stores it: the key, and when the person made it (`key@ms`). */
export const stampMark = (key: string, at: number): string => `${key}@${Math.round(at)}`;

/** The marks that stand for `key`: a stamped one counts only if it was made at or after `since` (when the entry appeared); an unstamped (older) one always counts. */
export function hasMark(list: string[], key: string, since?: number): boolean {
  return list.some((m) => {
    if (m === key) return true;
    if (!m.startsWith(`${key}@`)) return false;
    const at = Number(m.slice(key.length + 1));
    return !Number.isFinite(at) || since === undefined || at >= since;
  });
}

/** The list without the marks of `key` (stamped or not). */
export const withoutMark = (list: string[], key: string): string[] => list.filter((m) => m !== key && !m.startsWith(`${key}@`));

/** The stored list with the old unstamped marks dropped: they cannot be told from a mark about an entry of an earlier data set. Only marks the person made on this version of the page stay. */
export const dropUnstamped = (list: string[]): string[] => list.filter((m) => /@\d+$/.test(m));

export const decisionOf = (e: HeldLike, d: Decisions): CardDecision => {
  const k = deferKey(e.pluginId, e.contentHash, e.id);
  return hasMark(d.kept, k, e.firstSeen) ? "kept" : hasMark(d.deferred, k, e.firstSeen) ? "deferred" : "open";
};

/** Dotted versions compared by number («0.0.10» after «0.0.9»); what is not a number compares as text. Negative: a before b. */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/i, "").split(/[.+-]/);
  const pb = b.replace(/^v/i, "").split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      if (Number(x) !== Number(y)) return Number(x) - Number(y);
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** One plugin's card: the latest version is shown; the others wait folded away under it. */
export interface PluginCard<E extends HeldLike> {
  pluginId: string;
  shown: E;
  others: E[];
  /** All of its versions that are unresolved (shown first). */
  all: E[];
}

export interface CardPlan<E extends HeldLike> {
  /** Cards to decide now (at least one open version). */
  active: Array<PluginCard<E>>;
  /** Cards folded away with «Решить позже» (every unresolved version of the plugin is deferred). */
  later: Array<PluginCard<E>>;
  /** Kept in quarantine: decided, not in the list and not in the status. */
  kept: E[];
  /** What the status counts: everything not decided (open and deferred). */
  unresolved: E[];
}

/** From the held entries to the cards: ONE per plugin (the latest version; «ещё N версий ждут» for the rest). Kept entries leave the list and the status. */
export function planCards<E extends HeldLike>(held: E[], d: Decisions): CardPlan<E> {
  const kept: E[] = [];
  const byPlugin = new Map<string, E[]>();
  for (const e of held) {
    if (decisionOf(e, d) === "kept") {
      kept.push(e);
      continue;
    }
    byPlugin.set(e.pluginId, [...(byPlugin.get(e.pluginId) ?? []), e]);
  }
  const latestFirst = (a: E, b: E): number => compareVersions(b.version, a.version) || b.id - a.id;
  const active: Array<PluginCard<E>> = [];
  const later: Array<PluginCard<E>> = [];
  const unresolved: E[] = [];
  for (const [pluginId, list] of byPlugin) {
    const open = list.filter((e) => decisionOf(e, d) === "open").sort(latestFirst);
    const deferred = list.filter((e) => decisionOf(e, d) === "deferred").sort(latestFirst);
    const all = [...open, ...deferred];
    unresolved.push(...all);
    const card = { pluginId, shown: all[0]!, others: all.slice(1), all };
    (open.length > 0 ? active : later).push(card);
  }
  return { active, later, kept, unresolved };
}

/** «ещё 1 версия ждёт» / «ещё 2 версии ждут» / «ещё 5 версий ждут». */
export const moreVersionsText = (n: number): string => `ещё ${n} ${plural(n, "версия ждёт", "версии ждут", "версий ждут")}`;

/**
 * What a card IS, for React and for its folds: the plugin, the version and its hash, not the number of the queue entry. The same version held again
 * gets a new entry number (after a rejection, a restart, a second ask of the core); a key made of the number would build the card anew at every such change and
 * lose what the person had just opened. A version of another content is another card.
 */
export const cardKey = (q: { pluginId: string; version: string; contentHash: string | null; id: number }): string => `${q.pluginId}@${q.version}#${q.contentHash ?? `n${q.id}`}`;

/** The id of a fold on a card: the same for the same version, whatever the entry's number. */
export const cardFoldId = (q: { pluginId: string; version: string; contentHash: string | null; id: number }, part: string): string => `card:${cardKey(q)}:${part}`;

/** «Готово: удалён плагин X 1.0.0»: what the page says for a few seconds where the card was. */
export const doneMessage = (what: string): string => `Готово: ${what.replace(/[.\s]+$/, "")}`;

/** The action on a card names the version it is about. */
export const actionLabel = (verb: string, pluginId: string, version: string): string => `${verb} ${pluginId} ${version}`;

export const deleteConfirmText = (pluginId: string, version: string): string => `Удалить плагин ${pluginId} ${version}? Чтобы вернуть, установите плагин снова`;

/** Where the buttons were, after «Разрешить»: the same kind of line as «Удалён: …». */
export const approvedNote = (pluginId: string, version: string): string => `Разрешено: плагин ${pluginId} ${version}.`;

export const deletedNote = (pluginId: string, version: string): string => `Удалён: плагин ${pluginId} ${version}.`;

/** When the person rejected a version: the guard's journal knows (a `dismissed` record of this entry), the entry itself only knows when it last saw it. */
export function rejectedAtOf(q: { id: number; pluginId: string; version: string; lastSeen: number }, events: Array<{ ts: number; kind: string; pluginId: string | null; detail?: unknown }>): number {
  let best: number | null = null;
  for (const e of events) {
    if (e.kind !== "dismissed" || e.pluginId !== q.pluginId) continue;
    const d = e.detail !== null && typeof e.detail === "object" ? (e.detail as Record<string, unknown>) : {};
    if (d.review !== q.id && d.version !== q.version) continue;
    if (best === null || e.ts > best) best = e.ts;
  }
  return best ?? q.lastSeen;
}

/** «отклонено вами 21:20». */
export const rejectedByText = (at: number, now: number): string => `отклонено вами ${clockText(at, now)}`;

/** «вы, касанием, 21:26» / «прошла сама: свой источник, 21:20»: who let the version in, how, when. */
export function approvedByText(a: { via: string; why?: string | null; approvedAt: number }, now: number): string {
  return `${approvalWhy(a)}, ${clockText(a.approvedAt, now)}`;
}

/** The buttons of «Удалить плагин …?», in the order they are always drawn, on their own line under the question. */
export const DELETE_CONFIRM_BUTTONS = ["Да, удалить", "Нет"] as const;

/** The marks the owner can give a decision afterwards, in the page's words. The keys are the guard's (`MARKS`). */
export const MARK_LABEL = { false_alarm: "ложная тревога", was_dangerous: "правда было опасно", unknown: "не знаю" } as const;
export type MarkKey = keyof typeof MARK_LABEL;
export const MARK_REVOKE_REASON = "Почему отозвали (одной строкой, можно пропустить)";
/** Journal kinds of the guard that are decisions: the ones that can be marked. Same list as the guard's `DECISION_KINDS`. */
export const MARKABLE_KINDS = ["approved.touch", "approved.trust", "approved.window", "approved.source", "approved.import", "dismissed", "revoked", "window.open"];
