// The link `sbb-guard setup` prints: <origin>/plugins/secure-bb/gate#enroll=TOKEN.
//
// The token is in the FRAGMENT, not in the query: a browser never sends a fragment to a server, so it is not in any request line, proxy or server log
// of bb. The page reads it once, puts it into the "add a passkey" field and clears the fragment from the address bar at once. From there the token
// goes one way only: `passkey.register` to the guard (which checks it itself; a token alone registers nothing: the key is active after `y` on the console).
//
// Pure functions: the page passes `location.hash`, `history` and `location`; tests pass plain objects.

/** The shape of a token the guard prints (`XXXX-XXXX-XXXX`, letters and digits); anything else in the fragment is ignored. */
const TOKEN = /^[A-Za-z0-9-]{4,40}$/;

/** `#enroll=TOKEN` (also `#a=1&enroll=TOKEN`) → the token, else null. */
export function parseEnrollFragment(hash: string): string | null {
  const body = hash.startsWith("#") ? hash.slice(1) : hash;
  for (const part of body.split("&")) {
    const eq = part.indexOf("=");
    if (eq < 0 || part.slice(0, eq) !== "enroll") continue;
    const value = part.slice(eq + 1);
    return TOKEN.test(value) ? value : null;
  }
  return null;
}

/** What `history.replaceState` needs to drop the fragment and keep everything else of the address. */
export interface HistoryLike {
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}
export interface LocationLike {
  pathname: string;
  search: string;
  hash: string;
}

/** Removes the fragment from the address bar without adding a history entry and without a reload. True when there was one to remove. */
export function clearFragment(history: HistoryLike, location: LocationLike): boolean {
  if (location.hash === "" || location.hash === "#") return false;
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  return true;
}

/** Reads the token from the address and clears the fragment (always, whatever it held: it is not for anyone else). */
export function takeEnrollToken(history: HistoryLike, location: LocationLike): string | null {
  const token = parseEnrollFragment(location.hash);
  if (token !== null) clearFragment(history, location);
  return token;
}
