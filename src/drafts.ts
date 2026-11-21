// What a person has typed into a field, kept OUTSIDE the components and keyed by the card's id: a refresh of the data (even one that builds the list again)
// does not take it away. A code lives for seconds, so a draft is forgotten after a short while, and always after the action it was typed for.

/** A one-time code is valid for about a minute; a draft that old is a stale one and is not given back. */
export const DRAFT_TTL_MS = 90_000;

export interface Drafts {
  get(key: string, now?: number): string;
  set(key: string, value: string, now?: number): void;
  clear(key: string): void;
}
export function createDrafts(ttlMs = DRAFT_TTL_MS): Drafts {
  const map = new Map<string, { value: string; at: number }>();
  return {
    get(key, now = Date.now()) {
      const e = map.get(key);
      if (!e) return "";
      if (now - e.at > ttlMs) {
        map.delete(key);
        return "";
      }
      return e.value;
    },
    set(key, value, now = Date.now()) {
      if (value === "") map.delete(key);
      else map.set(key, { value, at: now });
    },
    clear(key) {
      map.delete(key);
    },
  };
}
