import { useCallback, useContext, useEffect, useRef, useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { getAssertion, originProblem } from "../src/webauthn";
import { takeEnrollToken } from "../src/enroll-link";
import type { PasskeyAssertion } from "../src/guardlink";
import { humanError, firstButtonAfter, startTouchNote } from "../src/ux";
import { createDrafts } from "../src/drafts";
import { pressTracker } from "../src/stable-view";
import { ConfirmCancelled } from "./confirm-dialog";
import { card, input, muted, DoneContext, LOCK_MS } from "./ui";

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

// Where the person pressed last: the result of the action is shown there.
export const press = typeof document !== "undefined" ? pressTracker(document) : null;

export const PRESS_MAX_AGE_MS = 120_000;

/** A one-shot action that needs a fresh TOTP code. `done` (a short phrase: «удалён плагин X 1.0») is announced as «Готово: …» where the cards are. */
export function useCodeAction(refetch: () => void, opts: { pin?: boolean; slot?: { key: string; elId: string } } = {}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  // A decision that made the card go (`done` given): its buttons stay dead until the card is gone — or, if it is not gone, for a few seconds.
  const [locked, setLocked] = useState(false);
  const { announce } = useContext(DoneContext);
  const alive = useRef(true);
  useEffect(() => () => void (alive.current = false), []);
  const run = async (fn: () => Promise<unknown>, done?: string) => {
    // The place of the press is taken now: the answer may take a while, and the person may press elsewhere meanwhile.
    const anchor = press?.last(PRESS_MAX_AGE_MS) ?? null;
    setBusy(true);
    setError(null);
    setOk(null);
    try {
      const res = (await fn()) as { note?: string } | undefined;
      // A card that leaves a line of its own («Готово: …») says the result there: a second plate with the same news is not shown.
      const leavesLine = done !== undefined && opts.slot !== undefined;
      if (res?.note) {
        if (leavesLine) undefined;
        else if (opts.pin) announce(res.note, { kind: "info", anchor });
        else setOk(res.note);
      }
      if (done) {
        const height = opts.slot ? (document.getElementById(opts.slot.elId)?.offsetHeight ?? 0) : 0;
        announce(done, { ...(opts.slot ? { slot: { key: opts.slot.key, height } } : {}), anchor });
        setLocked(true);
        window.setTimeout(() => { if (alive.current) setLocked(false); }, LOCK_MS);
      }
      refetch();
    } catch (e) {
      // The person closed the confirmation dialog: they changed their mind, nothing went wrong.
      if (e instanceof ConfirmCancelled) return;
      // The server's words are English and have inner names in them: the person reads a Russian sentence; the original goes to the console for whoever looks.
      const raw = e instanceof Error ? e.message : String(e);
      console.error("[secure-bb]", raw);
      if (opts.pin) announce(humanError(raw), { kind: "error", anchor });
      else setError(humanError(raw));
    } finally {
      setBusy(false);
    }
  };
  return { busy: busy || locked, error, ok, run };
}

/** Enter in a code field presses the action that stands next to it: the first button after the field that is not disabled (the code is checked by the server anyway). */
export function nextButton(field: HTMLElement): HTMLButtonElement | null {
  return firstButtonAfter(field);
}

export function CodeField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <input
      className={input}
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={6}
      placeholder="код"
      aria-label="Код из приложения-аутентификатора"
      value={value}
      onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 6))}
      onKeyDown={(e) => {
        if (e.key !== "Enter") return;
        e.preventDefault();
        nextButton(e.currentTarget)?.click();
      }}
    />
  );
}

export type Rpc = ReturnType<typeof useRpc<SecureBbRpc>>;

/** The token of the link `sbb-guard setup` printed: taken from the fragment once per page load (a re-render, or React's double call in development, must not lose it). */
export let enrollSeen: { token: string | null } | undefined;

export const enrollTokenOnce = (): string | null => {
  if (typeof window === "undefined") return null;
  enrollSeen ??= { token: takeEnrollToken(window.history, window.location) };
  return enrollSeen.token;
};

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

/** Under a button that touches: what the guard says is being approved (before the touch), and what it said after. */
export function TouchNote({ text }: { text: string | null }) {
  return text ? <p className={`mt-1 text-sm ${muted}`}>{text}</p> : null;
}
