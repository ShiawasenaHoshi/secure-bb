// A page that holds still: open folds, selections, the order of lists, the stubs that stand where a card was.
import { doneMessage } from "./decisions.js";

/** A fold's state is kept by the element's id, so that a refresh (even one that rebuilds the list) leaves it as the person left it. */
export function setFold(state: Record<string, boolean>, id: string, open: boolean): Record<string, boolean> {
  return state[id] === open ? state : { ...state, [id]: open };
}

/** One checkbox changed: the others are not touched. */
export function toggleId(ids: number[], id: number, on: boolean): number[] {
  const has = ids.includes(id);
  return on ? (has ? ids : [...ids, id]) : ids.filter((x) => x !== id);
}

/** Two overviews that differ only by the server's clock say the same: the page keeps the old object and draws nothing again. */
export function sameData(a: unknown, b: unknown): boolean {
  // Only the TOP-level clock is ignored: everything else, the guard's data about the agents included, counts.
  const strip = (x: unknown): string => {
    if (typeof x === "object" && x !== null && !Array.isArray(x)) {
      const { now: _now, ...rest } = x as Record<string, unknown>;
      return JSON.stringify(rest);
    }
    return JSON.stringify(x);
  };
  return strip(a) === strip(b);
}

/** A resolved card is replaced by a stub of the same height, and the stub stays until the person closes it. */
export interface Stub {
  key: string;
  text: string;
  height: number;
  /** A stub of a card put aside: the entry to bring back («Вернуть»). Absent on the «Готово» stub of a decided card. */
  restore?: { id: number; pluginId: string; version: string; contentHash: string | null };
}

export const MIN_STUB_HEIGHT = 56;

export function makeStub(key: string, what: string, height: number): Stub {
  return { key, text: doneMessage(what), height: Number.isFinite(height) ? Math.max(MIN_STUB_HEIGHT, Math.round(height)) : MIN_STUB_HEIGHT };
}

/**
 * The order of a list while the page is open: what was there keeps its place, what is new goes to the end and is marked «новое». The first call (`prev` null)
 * takes the list as it comes, and marks nothing. Keys in `keep` (a stub stands there) keep their place though the entry is gone.
 */
export function stableOrder(prev: string[] | null, cur: string[], keep: string[] = []): { order: string[]; fresh: string[] } {
  if (prev === null) return { order: [...cur], fresh: [] };
  const alive = new Set([...cur, ...keep]);
  const order = prev.filter((k) => alive.has(k));
  const have = new Set(order);
  const fresh = cur.filter((k) => !have.has(k));
  return { order: [...order, ...fresh], fresh };
}

export interface ListItem {
  key: string;
  stub?: Stub;
}

/** The list as drawn: a card where there is one, the stub where it was resolved. */
export function layoutItems(order: string[], present: ReadonlySet<string>, stubs: Stub[]): ListItem[] {
  const out: ListItem[] = [];
  for (const key of order) {
    if (present.has(key)) out.push({ key });
    else {
      const stub = stubs.find((s) => s.key === key);
      if (stub) out.push({ key, stub });
    }
  }
  return out;
}

export interface DeferStubSource {
  id: number;
  pluginId: string;
  version: string;
  contentHash: string | null;
}

/** The stub that stands where a card was put aside: the card's height, «Отложено: X · Вернуть». The next card does not slide under the cursor. */
export function makeDeferStub(q: DeferStubSource, height: number): Stub {
  return { key: q.pluginId, text: `Отложено: ${q.pluginId} ${q.version}`, height: Number.isFinite(height) ? Math.max(MIN_STUB_HEIGHT, Math.round(height)) : MIN_STUB_HEIGHT, restore: { id: q.id, pluginId: q.pluginId, version: q.version, contentHash: q.contentHash } };
}

export const DEFER_STUB_RESTORE = "Вернуть";
