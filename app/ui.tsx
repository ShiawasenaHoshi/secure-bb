import { createContext, useCallback, useContext, useEffect, useReducer, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useRealtime, useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { T } from "../src/text";
import { doneMessage, sameData } from "../src/ux";
import { splitNotes, toastPosition, type Box } from "../src/stable-view";
import { isFoldOpen, toggleFold } from "../src/fold";
import { press } from "./code";

export const card = "rounded-lg border border-border bg-card p-4 text-sm text-card-foreground";

export const btn =
  "rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted disabled:opacity-50";

export const btnPrimary =
  "rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50";

export const input = "w-28 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm tracking-widest";

export const muted = "text-muted-foreground";

export const cardBlocked = "rounded-lg border-2 border-red-600 bg-red-50 p-4 text-sm text-red-950 dark:border-red-500 dark:bg-red-950/40 dark:text-red-100";

export const btnDanger = "rounded-md border border-red-600 bg-transparent px-3 py-1.5 text-sm text-red-700 hover:bg-red-100 disabled:opacity-50 dark:border-red-400 dark:text-red-300 dark:hover:bg-red-950";

export const minutes = (sec: number): string => (sec < 60 ? `${sec} с` : `${Math.ceil(sec / 60)} мин`);

export const when = (ms: number): string => new Date(ms).toLocaleString();

export function useOverview() {
  const rpc = useRpc<SecureBbRpc>();
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The rpc object of the host may be a new one at every render: the timer and the subscription must not restart with it (that was a refetch at every
  // draw), so the call goes through a ref.
  const rpcRef = useRef(rpc);
  rpcRef.current = rpc;
  const refetch = useCallback(() => {
    rpcRef.current.call("overview").then(
      (ov) => {
        // Data that differs only by the server's clock changes nothing: the old object stays, nothing is drawn again, nothing jumps.
        setData((cur) => (cur !== null && sameData(cur, ov) ? cur : ov));
        setError(null);
      },
      (e: unknown) => setError(e instanceof Error ? e.message : String(e)),
    );
  }, []);
  useEffect(() => {
    refetch();
    const timer = setInterval(refetch, 20_000);
    return () => clearInterval(timer);
  }, [refetch]);
  useRealtime("changed", refetch);
  return { rpc, data, error, refetch };
}

// Open or closed folds and ticked boxes live OUTSIDE the components, keyed by the element's id: a refresh, or even a list that is built again,
// leaves them as the person left them.
export const stickyValues = new Map<string, unknown>();

export function useSticky<T>(key: string, initial: T): [T, (v: T | ((cur: T) => T)) => void] {
  const [v, setV] = useState<T>(() => (stickyValues.has(key) ? (stickyValues.get(key) as T) : initial));
  const set = useCallback(
    (next: T | ((cur: T) => T)) =>
      setV((cur) => {
        const n = typeof next === "function" ? (next as (c: T) => T)(cur) : next;
        stickyValues.set(key, n);
        return n;
      }),
    [key],
  );
  return [v, set];
}

/** A <details> that remembers by `id` whether it is open. `defaultOpen`: until the person touches it. */
export function Fold({ id, summary, children, defaultOpen = false, className, summaryClassName }: { id: string; summary: ReactNode; children: ReactNode; defaultOpen?: boolean; className?: string; summaryClassName?: string }) {
  // The fold's state is OURS, not the browser's: a click is taken over (preventDefault), the state is written at once and drawn at once. The browser's own
  // toggle plus a `toggle` event that came later could lose a click against a redraw (an overview arriving between the click and the event), which looked like
  // «нажимаю, ничего не открывается».
  const [, redraw] = useReducer((n: number) => n + 1, 0);
  const open = isFoldOpen(id, defaultOpen);
  return (
    <details className={className} open={open}>
      <summary
        className={summaryClassName ?? "cursor-pointer"}
        onClick={(e) => {
          e.preventDefault();
          toggleFold(id, defaultOpen);
          redraw();
        }}
      >
        {summary}
      </summary>
      {children}
    </details>
  );
}

/** Counts down locally between refetches. */
export function useNow(): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

/** A message under a button. `reserve`: the line's place stays when there is no message, so that nothing below it jumps when one appears. */
export function Msg({ error, ok, reserve }: { error?: string | null; ok?: string | null; reserve?: boolean }) {
  if (error) return <p className={`mt-2 text-sm text-destructive${reserve ? " min-h-5" : ""}`}>{error}</p>;
  if (ok) return <p className={`mt-2 text-sm ${muted}${reserve ? " min-h-5" : ""}`} role="status">{ok}</p>;
  return reserve ? <p className="mt-2 min-h-5 text-sm" aria-hidden /> : null;
}

export function Section({ title, children, id }: { title: string; children: ReactNode; id?: string }) {
  return (
    <section className="space-y-2" id={id}>
      <h2 className="text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

// «Готово: …»: after a card is gone (deleted, allowed, accepted) a short message stays where the cards are for a few seconds, so that a press is seen to have worked.
export const DONE_MS = 3000;

export const LOCK_MS = 8000;

export interface Note { id: number; text: string; kind: "done" | "info" | "error"; /** Where the button that was pressed stood: the toast goes by it. */ anchor?: Box | null }

export interface AnnounceOpts { kind?: Note["kind"]; slot?: { key: string; height: number }; anchor?: Box | null }

export const DoneContext = createContext<{ notes: Note[]; announce: (what: string, opts?: AnnounceOpts) => void; dismiss: (id: number) => void }>({ notes: [], announce: () => undefined, dismiss: () => undefined });

export const TOAST_SIZE = { width: 320, height: 44 };

/** The result of an action, by the button that was pressed (fixed in the window, so the page under it does not move): «Готово: …» goes by itself, an error stays until it is closed. */
export function AnchoredNotes() {
  const { notes, dismiss } = useContext(DoneContext);
  const placed = splitNotes(notes).placed;
  if (placed.length === 0) return null;
  const viewport = { width: window.innerWidth, height: window.innerHeight };
  return (
    <>
      {placed.map((n, i) => {
        const pos = toastPosition(n.anchor!, viewport, { ...TOAST_SIZE, height: TOAST_SIZE.height * (i + 1) });
        return (
          <p key={n.id} role="status" aria-live="polite" data-secure-bb-toast style={{ position: "fixed", left: pos.left, top: pos.top + i * TOAST_SIZE.height, maxWidth: TOAST_SIZE.width }} className={`z-30 flex items-start justify-between gap-2 rounded-md border px-3 py-2 text-sm font-semibold shadow ${n.kind === "error" ? "border-red-600/60 bg-red-50 text-red-900 dark:bg-red-950 dark:text-red-100" : "border-green-600/50 bg-green-50 text-green-900 dark:bg-green-950 dark:text-green-100"}`}>
            <span>{n.kind === "done" ? doneMessage(n.text) : n.text}</span>
            {n.kind === "error" ? <button type="button" className="underline" onClick={() => dismiss(n.id)}>Закрыть</button> : null}
          </p>
        );
      })}
    </>
  );
}

/**
 * Messages live in a strip pinned to the top of the window and take no room in the flow: when one appears or goes, nothing under it moves.
 * «Готово» and information go by themselves; an error stays until it is closed.
 */
export function PinnedNotes() {
  const { notes: all, dismiss } = useContext(DoneContext);
  // A note of an action with a known place stands by the button that was pressed (AnchoredNotes); the rest are pinned to the top.
  const notes = splitNotes(all).pinned;
  if (notes.length === 0) return null;
  return (
    <div className="pointer-events-none fixed inset-x-0 top-2 z-30 mx-auto w-full max-w-3xl px-4" data-secure-bb-pinned>
      <div className="space-y-1" role="status" aria-live="polite">
        {notes.map((n) => (
          <p key={n.id} className={`pointer-events-auto flex items-start justify-between gap-2 rounded-md border px-3 py-2 text-sm font-semibold shadow ${n.kind === "error" ? "border-red-600/60 bg-red-50 text-red-900 dark:bg-red-950 dark:text-red-100" : "border-green-600/50 bg-green-50 text-green-900 dark:bg-green-950 dark:text-green-100"}`}>
            <span>{n.kind === "done" ? doneMessage(n.text) : n.text}</span>
            {n.kind === "error" ? <button type="button" className="underline" onClick={() => dismiss(n.id)}>Закрыть</button> : null}
          </p>
        ))}
      </div>
    </div>
  );
}
