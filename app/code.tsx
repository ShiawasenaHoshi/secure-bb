import { useContext, useEffect, useRef, useState } from "react";
import { takeEnrollToken } from "../src/enroll-link";
import { humanError, firstButtonAfter } from "../src/ux";
import type { Box } from "../src/stable-view";
import { ConfirmCancelled } from "./confirm-error";
import { PRESS_MAX_AGE_MS, press } from "./press";
import type { Rpc } from "./touch";
import { card, input, muted, DoneContext, LOCK_MS } from "./ui";

export const SETTLE_REFETCH_MS = [1_500, 4_000];

type Announce = (text: string, o?: { kind?: "done" | "info" | "error"; slot?: { key: string; height: number }; anchor?: Box | null }) => void;
interface ActionOpts {
  pin?: boolean;
  slot?: { key: string; elId: string };
}

/** What the person is told when an action went through: the server's note, and the line that takes the card's place. */
function reportDone(announce: Announce, opts: ActionOpts, anchor: Box | null, res: { note?: string } | undefined, done: string | undefined): { setOk: string | null; lock: boolean } {
  // A card that leaves a line of its own («Готово: …») says the result there: a second plate with the same news is not shown.
  const leavesLine = done !== undefined && opts.slot !== undefined;
  let setOk: string | null = null;
  if (res?.note && !leavesLine) {
    if (opts.pin) announce(res.note, { kind: "info", anchor });
    else setOk = res.note;
  }
  if (!done) return { setOk, lock: false };
  const height = opts.slot ? (document.getElementById(opts.slot.elId)?.offsetHeight ?? 0) : 0;
  announce(done, { ...(opts.slot ? { slot: { key: opts.slot.key, height } } : {}), anchor });
  return { setOk, lock: true };
}

/** What is told when it failed: the server's words are English and have inner names in them; the person reads a Russian sentence, the original goes to the console. */
function failureText(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  console.error("[secure-bb]", raw);
  return humanError(raw);
}

/** A one-shot action that needs a fresh TOTP code. `done` (a short phrase: «удалён плагин X 1.0») is announced as «Готово: …» where the cards are. */
export function useCodeAction(refetch: () => void, opts: ActionOpts = {}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  // A decision that made the card go (`done` given): its buttons stay dead until the card is gone — or, if it is not gone, for a few seconds.
  const [locked, setLocked] = useState(false);
  const { announce } = useContext(DoneContext);
  const alive = useRef(true);
  useEffect(() => () => void (alive.current = false), []);
  const lockForAWhile = () => {
    setLocked(true);
    window.setTimeout(() => { if (alive.current) setLocked(false); }, LOCK_MS);
  };
  const run = async (fn: () => Promise<unknown>, done?: string) => {
    // The place of the press is taken now: the answer may take a while, and the person may press elsewhere meanwhile.
    const anchor = press?.last(PRESS_MAX_AGE_MS) ?? null;
    setBusy(true);
    setError(null);
    setOk(null);
    try {
      const told = reportDone(announce, opts, anchor, (await fn()) as { note?: string } | undefined, done);
      if (told.setOk) setOk(told.setOk);
      if (told.lock) lockForAWhile();
      refetch();
      // The core takes a moment to start or stop what was decided: asked again, so the statuses on the page are the settled ones, not those of the first instant.
      for (const ms of SETTLE_REFETCH_MS) window.setTimeout(refetch, ms);
    } catch (e) {
      // The person closed the confirmation dialog: they changed their mind, nothing went wrong.
      if (e instanceof ConfirmCancelled) return;
      if (opts.pin) announce(failureText(e), { kind: "error", anchor });
      else setError(failureText(e));
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

/** The token of the link `sbb-guard setup` printed: taken from the fragment once per page load (a re-render, or React's double call in development, must not lose it). */
export let enrollSeen: { token: string | null } | undefined;

export const enrollTokenOnce = (): string | null => {
  if (typeof window === "undefined") return null;
  enrollSeen ??= { token: takeEnrollToken(window.history, window.location) };
  return enrollSeen.token;
};

/** Under a button that touches: what the guard says is being approved (before the touch), and what it said after. */
export function TouchNote({ text }: { text: string | null }) {
  return text ? <p className={`mt-1 text-sm ${muted}`}>{text}</p> : null;
}
