// The touch and the code the person types: what is kept of a typed code between draws, whether a key can touch, and the touch itself (ask the guard for a challenge, sign it).
// No page parts here: both the confirmation dialog and the action runner stand on it.
import { useCallback, useEffect, useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { getAssertion, originProblem } from "../src/webauthn";
import type { PasskeyAssertion } from "../src/guardlink";
import { startTouchNote } from "../src/ux";
import { createDrafts } from "../src/drafts";

// What was typed in a code field lives OUTSIDE the components, by the id of the card: a refresh of the data, or a card that is built again, does not take it away.
export const drafts = createDrafts();

export function useDraftCode(key: string): [string, (v: string) => void] {
  const [value, setValue] = useState<string>(() => drafts.get(key));
  const set = useCallback(
    (v: string) => {
      drafts.set(key, v);
      setValue(v);
    },
    [key],
  );
  // The same key may be drawn by a new component (the card was rebuilt): it takes the draft up again.
  useEffect(() => setValue(drafts.get(key)), [key]);
  return [value, set];
}

export type Rpc = ReturnType<typeof useRpc<SecureBbRpc>>;

// Guard mode only. The guard issues a challenge bound to ONE action and describes it in its own words; the browser signs it with a key
// that never leaves the device (Touch ID); the signature goes with the command in place of a code. A captured signature is good for that
// action only, once. The touch dialog of the system does not say what is signed, so the guard's sentence is shown here, before and after.
export interface PasskeyState {
  /** At least one key can touch. */
  has: boolean;
  /** Codes are switched off at the guard: only keys work. */
  keyOnly: boolean;
  /** Why a touch cannot be made from this page right now (wrong address, no WebAuthn), or null. */
  problem: string | null;
}

export function usePasskey(ov: Overview): PasskeyState {
  const pk = ov.guard?.passkey ?? null;
  if (!pk) return { has: false, keyOnly: false, problem: null };
  const supported = typeof navigator !== "undefined" && typeof navigator.credentials?.get === "function";
  const problem = !supported ? "В этом браузере нет WebAuthn." : originProblem(window.location.origin, pk.origin);
  return { has: pk.keys.length > 0, keyOnly: pk.keys.length > 0 && pk.totpOff, problem };
}

export type TouchQuery = Record<string, unknown>;

/**
 * Asks the guard for a challenge for this action, shows its description, and gets the touch. `null`: the change needs no touch.
 * `shown` gets the whole sentence for the person; if the touch is not done in 12 s it gets it again with the hint about the password manager
 * (a manager's extension may be the one waiting for the answer, not the system).
 */
export async function touchFor(rpc: Rpc, query: TouchQuery, shown: (text: string) => void): Promise<{ passkey: PasskeyAssertion; description: string } | null> {
  const c = await rpc.call("passkey.challenge", query as never);
  if (!c.needed) return null;
  const stopTimer = startTouchNote(c.description, shown);
  try {
    const passkey = await getAssertion(c, navigator.credentials as never, window.location.origin);
    return { passkey, description: c.description };
  } finally {
    stopTimer();
  }
}
