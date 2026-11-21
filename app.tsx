// secure-bb — frontend: the secure-bb page (the plugin gate is a section of it) and an always-visible banner
// for open trust windows. Plain React + host theme tokens; no vendored UI,
// no third-party code (this bundle runs in bb's origin, so it stays minimal).
import { createContext, useCallback, useContext, useEffect, useId, useMemo, useReducer, useRef, useState } from "react";
import type { ReactNode } from "react";
import { definePluginApp, useBbNavigate, useRealtime, useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "./server";
import type { Overview, PluginView, WindowView } from "./src/overview";
import type { ScanView } from "./src/scan/view";
import type { QueueRow } from "./src/store";
import type { CheckResult } from "./src/checks/types";
import type { ConfigWindowView } from "./src/watch/watchdog";
import { CATEGORY_LABEL, WINDOW_SCOPES, SCOPE_LABEL } from "./src/watch/model";
import { NOT_OBSERVED, TAINT_LABEL } from "./src/taint/classify";
import type { TaintKind } from "./src/taint/classify";
import type { Drift, WindowScope } from "./src/watch/model";
import type { SkillQueueView } from "./src/skills/guard";
import { OUTCOME_LABEL, firedText, verdictText } from "./src/sentinel/view";
import type { QuestionView } from "./src/sentinel/view";
import type { FeedRow } from "./src/sentinel/types";
import { T } from "./src/text";
import { buildPolicyChange, buildPolicySetInput, buildPolicyTouchQuery, defined } from "./src/rpc-input";
import { createCredential, getAssertion, originProblem, type CreationOptions } from "./src/webauthn";
import { takeEnrollToken } from "./src/enroll-link";
import type { AgentDrift, PasskeyAssertion } from "./src/guardlink";
import type { QueueUx } from "./src/uxview";
import type { TrustMode } from "./src/guardlink";
import {
  AWAY_KEY, DEFERRED_KEY, glossSegments, skillsSummary, doneMessage, approvedNote, uniqueSentences, humanError, approvedByText, canRestore, rejectedAtOf, rejectedByText, clockText, firstButtonAfter, sessionClosedText, sessionEndReason, slideIdle, type SessionCloseReason, capsWithPaths, redWhere, cardFoldId, cardKey, sessionBlockText, KEPT_KEY, MODE_DESCRIPTIONS, MODE_NAMES, SAVED_NARROWING, TOUCH_SLOW_MS, WIZARD_KEY,
  aaguidName, approvalWhy, awayAlarms, awayInfoEvents, awaySince, capabilitySegments, cardColor, deferKey, detailLevel, groupAway, isBlockedEntry, isPasswordManager, pageStatus,
  MISMATCH_HINT, alarmCount, bypassAllowed, mismatchText, parseDeferred, redText, touchWithHint, wizardNeeded, yellowText, GUARD_DOWN_TEXT,
  actionLabel, emphasize, agentAcceptProblem, agentsSectionTab, awaySeenMark, criticalAcceptTitle, manualRollback, criticalMeanings, decisionOf, deleteConfirmText, deletedNote,
  isCriticalDrift, launchProblem, moreVersionsText, planCards, proofHint, reconcileSelection, sameData, selectableDriftIds, sessionText, setFold,
  toggleId, trustButton, windowAvailability,
} from "./src/ux";
import { isMismatch, riskHeadline, approveVerb, enabledWhat, agentConfigNote, scopeText, makeStub, stableOrder, layoutItems, friendlySource, WIZARD_SOURCES_TEXT, secondFactorText, AWAY_HIDE_LABEL, type Stub } from "./src/ux";
import { checksSummary, countsLine, DEFER_STUB_RESTORE, DELETE_CONFIRM_BUTTONS, dropUnstamped, hasNoGuardRecord, makeDeferStub, NO_RECORD_FIX, NO_RECORD_HEADLINE, NO_RECORD_LINE, pageCounts, restoreNote, significantFindings, stampMark, withoutMark } from "./src/ux";
import { attachFlow, capabilityPhrase } from "./src/ux";
import { createDrafts } from "./src/drafts";
import { isFoldOpen, openFold, toggleFold } from "./src/fold";
import type { AwayEvent, CapLike, HeldNow, ProblemRef, TabId } from "./src/ux";

// ---------------------------------------------------------------- helpers --

const card = "rounded-lg border border-border bg-card p-4 text-sm text-card-foreground";
const btn =
  "rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted disabled:opacity-50";
const btnPrimary =
  "rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50";
const input = "w-28 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm tracking-widest";
const muted = "text-muted-foreground";
const cardBlocked = "rounded-lg border-2 border-red-600 bg-red-50 p-4 text-sm text-red-950 dark:border-red-500 dark:bg-red-950/40 dark:text-red-100";
const btnDanger = "rounded-md border border-red-600 bg-transparent px-3 py-1.5 text-sm text-red-700 hover:bg-red-100 disabled:opacity-50 dark:border-red-400 dark:text-red-300 dark:hover:bg-red-950";

const minutes = (sec: number): string => (sec < 60 ? `${sec} с` : `${Math.ceil(sec / 60)} мин`);
const when = (ms: number): string => new Date(ms).toLocaleString();

function useOverview() {
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
const stickyValues = new Map<string, unknown>();
function useSticky<T>(key: string, initial: T): [T, (v: T | ((cur: T) => T)) => void] {
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
function Fold({ id, summary, children, defaultOpen = false, className, summaryClassName }: { id: string; summary: ReactNode; children: ReactNode; defaultOpen?: boolean; className?: string; summaryClassName?: string }) {
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
function useNow(): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

/** A message under a button. `reserve`: the line's place stays when there is no message, so that nothing below it jumps when one appears. */
function Msg({ error, ok, reserve }: { error?: string | null; ok?: string | null; reserve?: boolean }) {
  if (error) return <p className={`mt-2 text-sm text-destructive${reserve ? " min-h-5" : ""}`}>{error}</p>;
  if (ok) return <p className={`mt-2 text-sm ${muted}${reserve ? " min-h-5" : ""}`} role="status">{ok}</p>;
  return reserve ? <p className="mt-2 min-h-5 text-sm" aria-hidden /> : null;
}

function Section({ title, children, id }: { title: string; children: ReactNode; id?: string }) {
  return (
    <section className="space-y-2" id={id}>
      <h2 className="text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

// «Готово: …»: after a card is gone (deleted, allowed, accepted) a short message stays where the cards are for a few seconds, so that a press is seen to have worked.
const DONE_MS = 3000;
const LOCK_MS = 8000;
interface Note { id: number; text: string; kind: "done" | "info" | "error" }
interface AnnounceOpts { kind?: Note["kind"]; slot?: { key: string; height: number } }
const DoneContext = createContext<{ notes: Note[]; announce: (what: string, opts?: AnnounceOpts) => void; dismiss: (id: number) => void }>({ notes: [], announce: () => undefined, dismiss: () => undefined });
/**
 * Messages live in a strip pinned to the top of the window and take no room in the flow: when one appears or goes, nothing under it moves.
 * «Готово» and information go by themselves; an error stays until it is closed.
 */
function PinnedNotes() {
  const { notes, dismiss } = useContext(DoneContext);
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

// What was typed in a code field lives OUTSIDE the components, by the id of the card: a refresh of the data, or a card that is built again, does not take it away.
const drafts = createDrafts();
function useDraftCode(key: string): [string, (v: string) => void] {
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

/** A one-shot action that needs a fresh TOTP code. `done` (a short phrase: «удалён плагин X 1.0») is announced as «Готово: …» where the cards are. */
function useCodeAction(refetch: () => void, opts: { pin?: boolean; slot?: { key: string; elId: string } } = {}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  // A decision that made the card go (`done` given): its buttons stay dead until the card is gone — or, if it is not gone, for a few seconds.
  const [locked, setLocked] = useState(false);
  const { announce } = useContext(DoneContext);
  const alive = useRef(true);
  useEffect(() => () => void (alive.current = false), []);
  const run = async (fn: () => Promise<unknown>, done?: string) => {
    setBusy(true);
    setError(null);
    setOk(null);
    try {
      const res = (await fn()) as { note?: string } | undefined;
      if (res?.note) {
        if (opts.pin) announce(res.note, { kind: "info" });
        else setOk(res.note);
      }
      if (done) {
        const height = opts.slot ? (document.getElementById(opts.slot.elId)?.offsetHeight ?? 0) : 0;
        announce(done, opts.slot ? { slot: { key: opts.slot.key, height } } : undefined);
        setLocked(true);
        window.setTimeout(() => { if (alive.current) setLocked(false); }, LOCK_MS);
      }
      refetch();
    } catch (e) {
      // The server's words are English and have inner names in them: the person reads a Russian sentence; the original goes to the console for whoever looks.
      const raw = e instanceof Error ? e.message : String(e);
      console.error("[secure-bb]", raw);
      if (opts.pin) announce(humanError(raw), { kind: "error" });
      else setError(humanError(raw));
    } finally {
      setBusy(false);
    }
  };
  return { busy: busy || locked, error, ok, run };
}

/** Enter in a code field presses the action that stands next to it: the first button after the field that is not disabled (the code is checked by the server anyway). */
function nextButton(field: HTMLElement): HTMLButtonElement | null {
  return firstButtonAfter(field);
}
function CodeField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
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

type Rpc = ReturnType<typeof useRpc<SecureBbRpc>>;

/** The token of the link `sbb-guard setup` printed: taken from the fragment once per page load (a re-render, or React's double call in development, must not lose it). */
let enrollSeen: { token: string | null } | undefined;
const enrollTokenOnce = (): string | null => {
  if (typeof window === "undefined") return null;
  enrollSeen ??= { token: takeEnrollToken(window.history, window.location) };
  return enrollSeen.token;
};

// ------------------------------------------------------------------ passkey --
// Guard mode only. The guard issues a challenge bound to ONE action and describes it in its own words; the browser signs it with a key
// that never leaves the device (Touch ID); the signature goes with the command in place of a code. A captured signature is good for that
// action only, once. The touch dialog of the system does not say what is signed, so the guard's sentence is shown here, before and after.
interface PasskeyState {
  /** At least one key can touch. */
  has: boolean;
  /** Codes are switched off at the guard: only keys work. */
  keyOnly: boolean;
  /** Why a touch cannot be made from this page right now (wrong address, no WebAuthn), or null. */
  problem: string | null;
}
function usePasskey(ov: Overview): PasskeyState {
  const pk = ov.guard?.passkey ?? null;
  if (!pk) return { has: false, keyOnly: false, problem: null };
  const supported = typeof navigator !== "undefined" && typeof navigator.credentials?.get === "function";
  const problem = !supported ? "В этом браузере нет WebAuthn." : originProblem(window.location.origin, pk.origin);
  return { has: pk.keys.length > 0, keyOnly: pk.keys.length > 0 && pk.totpOff, problem };
}
type TouchQuery = Record<string, unknown>;
/**
 * Asks the guard for a challenge for this action, shows its description, and gets the touch. `null`: the change needs no touch.
 * `shown` gets the whole sentence for the person; if the touch is not done in 15 s it gets it again with the hint about the password manager
 * (a manager's extension may be the one waiting for the answer, not the system).
 */
async function touchFor(rpc: Rpc, query: TouchQuery, shown: (text: string) => void): Promise<{ passkey: PasskeyAssertion; description: string } | null> {
  const c = await rpc.call("passkey.challenge", query as never);
  if (!c.needed) return null;
  shown(touchWithHint(c.description, false));
  const timer = setTimeout(() => shown(touchWithHint(c.description, true)), TOUCH_SLOW_MS);
  try {
    const passkey = await getAssertion(c, navigator.credentials as never, window.location.origin);
    return { passkey, description: c.description };
  } finally {
    clearTimeout(timer);
  }
}
/** Under a button that touches: what the guard says is being approved (before the touch), and what it said after. */
function TouchNote({ text }: { text: string | null }) {
  return text ? <p className={`mt-1 text-sm ${muted}`}>{text}</p> : null;
}

// ----------------------------------------------------- approval session ----
// The session token lives ONLY in this component's memory (state): not localStorage, not a cookie, not the URL. Reloading the page
// forgets it, and so does leaving it. The server keeps only a hash. Routine actions use it instead of a code; dangerous ones never do.
type Proof = { code: string } | { session: string };
interface SessionLocal {
  token: string;
  /** When this page stops using the token (a little before the server does: the server's clock decides, this only avoids a wasted call). */
  idleUntil: number;
  hardUntil: number;
}
interface Approval {
  session: SessionLocal | null;
  /** Can an action run with what is typed now? `dangerous`: it needs a fresh code whatever the session says. */
  ready: (code: string, dangerous?: boolean) => boolean;
  /** Runs a routine action: with the code when six digits are typed, else with the session; slides the local clock on success. */
  routine: <T>(code: string, fn: (proof: Proof) => Promise<T>, dangerous?: boolean) => Promise<T>;
}
const MARGIN_MS = 5_000;
const noApproval: Approval = {
  session: null,
  ready: (code) => code.length === 6,
  routine: (code, fn) => fn({ code }),
};
const ApprovalContext = createContext<Approval>(noApproval);
const useApproval = () => useContext(ApprovalContext);

/** A code field that gives way to the session note while a session covers the action. */
function RoutineCode({ value, onChange, dangerous }: { value: string; onChange: (v: string) => void; dangerous?: boolean }) {
  const ap = useApproval();
  if (ap.session && !dangerous) return <span className={`text-xs ${muted}`}>сессия открыта: код не нужен</span>;
  return <CodeField value={value} onChange={onChange} />;
}

function useApprovalSession(rpc: Rpc, refetch: () => void): { approval: Approval; open: (proof: { code?: string; passkey?: PasskeyAssertion }, hour?: boolean) => Promise<void>; lock: () => Promise<void>; closed: SessionCloseReason | null } {
  const [session, setSession] = useState<SessionLocal | null>(null);
  const [closed, setClosed] = useState<SessionCloseReason | null>(null);
  const ref = useRef<SessionLocal | null>(null);
  ref.current = session;
  const now = useNow();
  /** The session ends: the page forgets the token AND says so (a session that goes quietly looks like «my click did nothing»). */
  const end = (reason: SessionCloseReason) => {
    setSession(null);
    setClosed(reason);
  };
  // Time is up for this page: forget the token (the server stops accepting it at about the same moment).
  useEffect(() => {
    if (session && now >= Math.min(session.idleUntil, session.hardUntil)) end(sessionEndReason(session, now));
  }, [now, session]);
  // Leaving the page locks the session on the server too (best effort; the token is gone with the page anyway).
  useEffect(() => {
    const lockOnLeave = () => {
      if (ref.current) void rpc.call("session.close").catch(() => undefined);
    };
    window.addEventListener("pagehide", lockOnLeave);
    return () => {
      window.removeEventListener("pagehide", lockOnLeave);
      lockOnLeave();
    };
  }, [rpc]);
  const approval: Approval = {
    session,
    ready: (code, dangerous = false) => code.length === 6 || (session !== null && !dangerous),
    routine: async (code, fn, dangerous = false) => {
      const started = Date.now();
      const useSession = code.length !== 6 && !dangerous && ref.current !== null;
      const proof: Proof = useSession ? { session: ref.current!.token } : { code };
      try {
        const result = await fn(proof);
        if (useSession) setSession((cur) => (cur ? { ...cur, idleUntil: slideIdle(cur, started, 15 * 60_000, MARGIN_MS) } : cur));
        return result;
      } catch (e) {
        // The server no longer knows this token: forget it here too, and say why.
        if (useSession && e instanceof Error && /expired session|blocked|too many/.test(e.message)) end("server");
        throw e;
      }
    },
  };
  const open = async (proof: { code?: string; passkey?: PasskeyAssertion }, hour = false) => {
    const started = Date.now();
    const r = await rpc.call("session.open", { ...proof, ...(hour ? { hour: true } : {}) } as never);
    setClosed(null);
    setSession({ token: r.token, idleUntil: started + r.idleMs - MARGIN_MS, hardUntil: started + r.capMs - MARGIN_MS });
    refetch();
  };
  const lock = async () => {
    end("locked");
    await rpc.call("session.close");
    refetch();
  };
  return { approval, open, lock, closed };
}

/** The strip at the top: open a session with one touch (a code, or a key at the guard), or see how long it lasts and lock it. */
function SessionBar({ ov, rpc, session, open, lock, closed }: { ov: Overview; rpc: Rpc; session: SessionLocal | null; open: (proof: { code?: string; passkey?: PasskeyAssertion }, hour?: boolean) => Promise<void>; lock: () => Promise<void>; closed: SessionCloseReason | null }) {
  const now = useNow();
  const proof = useProof(ov, rpc, "session");
  const act = useCodeAction(() => undefined);
  if (!proof.registered) return null;
  if (session) {
    const left = Math.max(0, Math.ceil((Math.min(session.idleUntil, session.hardUntil) - now) / 60_000));
    const ceiling = Math.max(0, Math.ceil((session.hardUntil - now) / 60_000));
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted px-3 py-2 text-sm" role="status">
        <span className="min-w-0 flex-1">Сессия открыта, осталось {left} мин (потолок — через {ceiling} мин; 15-минутная продлевается от каждого действия). Опасное всё равно требует свежего {ov.guard ? "касания" : "кода"}.</span>
        <button className={btnPrimary} onClick={() => void act.run(() => lock())}>Заблокировать</button>
      </div>
    );
  }
  const blockers = ov.sessionBlockers.map((b) => b.id);
  const st = sessionText(ov.guard?.trust?.mode ?? null, ov.guard !== undefined);
  const blocked = ov.guard && proof.pk.has ? false : ov.totp.blockedUntil > 0;
  return (
    <div className={card}>
      <h3 className="font-semibold">Сессия подтверждения</h3>
      {closed ? <p className="mt-1 rounded-md border border-yellow-500/60 bg-yellow-500/10 px-2 py-1" role="status" data-secure-bb-session-closed>{sessionClosedText(closed)}</p> : null}
      <p className={muted}>{st.line}</p>
      {st.foldDetails ? (
        <Fold id="session-details" summary="Подробнее" summaryClassName={`cursor-pointer text-xs ${muted}`}><p className={`mt-1 text-xs ${muted}`}>{st.details}</p></Fold>
      ) : (
        <p className={`mt-1 text-xs ${muted}`}>{st.details}</p>
      )}
      {blockers.length > 0 ? (
        <p className={`mt-2 rounded-md border border-border bg-muted p-2 ${muted}`} data-secure-bb-session-block>{sessionBlockText(ov.sessionBlockers)}</p>
      ) : null}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <ProofField proof={proof} />
        <button className={btn} disabled={act.busy || !proof.ready() || blockers.length > 0 || blocked} onClick={() => void act.run(async () => { await proof.run({ kind: "session.open" }, (p) => open(p as { code?: string; passkey?: PasskeyAssertion })); })}>
          Открыть на 15 минут
        </button>
        <button className={btn} disabled={act.busy || !proof.ready() || blockers.length > 0 || blocked} title="Один час подряд, без продления. Дольше потолка политики сессия не живёт." onClick={() => void act.run(async () => { await proof.run({ kind: "session.open", hour: true }, (p) => open(p as { code?: string; passkey?: PasskeyAssertion }, true)); })}>
          Открыть на 1 час
        </button>
      </div>
      <ProofNotes proof={proof} />
      <Msg error={act.error} />
    </div>
  );
}

/** "Approve the selected": the list is fixed on the server and shown with its hash BEFORE the code; one code approves the whole list. */
type BatchKindUi = "queue" | "skill" | "drift";
function BatchCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const [picked, setPicked] = useState<string[]>([]);
  const [prepared, setPrepared] = useState<Awaited<ReturnType<Rpc["call"]>> | null>(null);
  const [results, setResults] = useState<Array<{ kind: string; id: number; label: string; ok: boolean; note: string }> | null>(null);
  const proof = useProof(ov, rpc);
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const candidates: Array<{ key: string; kind: BatchKindUi; id: number; label: string }> = [
    ...ov.queue.filter((q) => q.status === "held").map((q) => ({ key: `queue:${q.id}`, kind: "queue" as const, id: q.id, label: `версия ${q.pluginId}@${q.version}` })),
    ...ov.skills.open.map((q) => ({ key: `skill:${q.id}`, kind: "skill" as const, id: q.id, label: `скилл ${q.name} (${q.scope})` })),
    ...ov.watch.drifts.filter((d) => d.status === "open" || d.status === "rollback-failed").map((d) => ({ key: `drift:${d.id}`, kind: "drift" as const, id: d.id, label: `расхождение: ${d.label}` })),
  ];
  const prep = prepared as null | { batchId: string; setHash: string; expiresAt: number; items: Array<{ kind: string; id: number; label: string; detail: string }>; skipped: Array<{ kind: string; id: number; reason: string }> };
  if (candidates.length < 2 && !prep && !results) return null;
  const toggle = (k: string) => setPicked((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]));
  const reset = () => { setPrepared(null); proof.setCode(""); };
  return (
    <div className={card}>
      <h3 className="font-semibold">Пакетное одобрение</h3>
      {!prep ? (
        <>
          <p className={muted}>Отметьте, что одобрить разом: одно {ov.guard ? "касание" : "подтверждение"} на весь список. Список фиксируется {ov.guard ? "у сторожа" : "на сервере"} до касания; элементы с блоком проверок в пакет не входят.</p>
          <ul className="mt-2 space-y-1">
            {candidates.map((c) => (
              <li key={c.key}><label className="flex items-center gap-2"><input type="checkbox" checked={picked.includes(c.key)} onChange={() => toggle(c.key)} /> {c.label} <span className={`text-xs ${muted}`}>#{c.id}</span></label></li>
            ))}
          </ul>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button className={btn} disabled={act.busy || picked.length === 0 || !registered} onClick={() => void act.run(async () => {
              setResults(null);
              const items = picked.map((k) => ({ kind: k.split(":")[0] as BatchKindUi, id: Number(k.split(":")[1]) }));
              setPrepared((await rpc.call("batch.prepare", { items })) as never);
            })}>
              Показать список ({picked.length})
            </button>
            <button className={btn} onClick={() => setPicked(candidates.map((c) => c.key))}>Выбрать всё</button>
          </div>
        </>
      ) : (
        <>
          <p className="mt-1">Будет одобрено ({prep.items.length}) — список зафиксирован, хеш набора <span className="font-mono">{prep.setHash.slice(0, 12)}</span>:</p>
          <ul className="mt-1 list-disc pl-5">
            {prep.items.map((i) => <li key={`${i.kind}${i.id}`}>{i.label} <span className={`text-xs ${muted}`}>({i.kind} #{i.id}{i.detail ? ` · ${i.detail}` : ""})</span></li>)}
          </ul>
          {prep.skipped.length > 0 ? (
            <div className="mt-1">
              <p className={muted}>Не вошли (одобряются по одному):</p>
              <ul className="list-disc pl-5 text-xs">{prep.skipped.map((i) => <li key={`${i.kind}${i.id}`}>{i.kind} #{i.id}: {i.reason}</li>)}</ul>
            </div>
          ) : null}
          <p className={`mt-1 text-xs ${muted}`}>Список действует 10 минут и одобряется один раз. Если что-то изменится до касания, это не будет одобрено.</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <ProofField proof={proof} routine />
            <button className={btnPrimary} disabled={act.busy || !proof.ready({ routine: true })} onClick={() => void act.run(async () => {
              // One touch for the whole list: the touch is for this list's id and hash (the guard holds the list), never for items.
              const r = await proof.run({ kind: "batch.approve", batchId: prep.batchId, setHash: prep.setHash }, (p) => rpc.call("batch.approve", { batchId: prep.batchId, setHash: prep.setHash, ...p } as never), { routine: true });
              setResults(r.results);
              setPicked([]);
              reset();
              return { note: `Одобрено: ${r.results.filter((x) => x.ok).length} из ${r.results.length}` };
            })}>
              Одобрить список ({prep.items.length})
            </button>
            <button className={btn} onClick={reset}>Отмена</button>
          </div>
          <ProofNotes proof={proof} />
        </>
      )}
      {results ? <ul className="mt-2 list-disc pl-5 text-xs">{results.map((r) => <li key={`${r.kind}${r.id}`} className={r.ok ? muted : "text-red-600"}>{r.label}: {r.ok ? "одобрено" : "не одобрено"} — {r.note}</li>)}</ul> : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

// ------------------------------------------------------------- AI scan ----

const MODEL_STATUS: Record<string, string> = { clean: "чисто", flag: "флаг", refusal: "отказ", invalid: "невалидный ответ", timeout: "таймаут", error: "ошибка", unavailable: "недоступна" };

/** Result of a scan next to the version it belongs to: not run / clean (date, models) / flags (what and where). */
function ScanResultView({ scan, other }: { scan: ScanView | undefined; other?: string }) {
  if (!scan) return <p className={`mt-1 ${muted}`}>ИИ-скан: не запускался</p>;
  const asked = scan.models.filter((m) => m.status !== "unavailable").map((m) => m.label).join(", ");
  const head =
    scan.status === "running" ? "идёт…" : scan.status === "clean" ? `чисто (${when(scan.finishedAt ?? scan.startedAt)}, ${asked})` : scan.status === "suspect" ? `ПОДОЗРЕНИЕ (${when(scan.finishedAt ?? scan.startedAt)})` : `недоступен${scan.note ? `: ${scan.note}` : ""}`;
  return (
    <div className="mt-1">
      <p className={scan.status === "suspect" ? "font-semibold text-red-600" : muted}>ИИ-скан #{scan.id}, версия {scan.version}: {head}{other ? ` · ${other}` : ""}</p>
      {scan.flags.length > 0 ? <ul className="list-disc pl-5 text-red-600">{scan.flags.map((f, i) => <li key={i}>{f}</li>)}</ul> : null}
      {scan.models.some((m) => m.status === "unavailable") ? <p className={muted}>Не отвечала: {scan.models.filter((m) => m.status === "unavailable").map((m) => `${m.label} (${m.detail})`).join("; ")}</p> : null}
      {scan.models.some((m) => m.report) ? (
        <Fold id={`scan-${scan.id}-models`} className="mt-1" summary="Что нашли модели">
          {scan.models.map((m) => (
            <div key={m.model} className="mt-1">
              <h4 className="font-medium">{m.label} — {MODEL_STATUS[m.status] ?? m.status}</h4>
              {m.report ? (
                <div className={muted}>
                  <p>{m.report.summary}</p>
                  <p>Совпадает с описанием: {m.report.matchesDescription ? "да" : "нет"}{m.report.descriptionNote ? ` — ${m.report.descriptionNote}` : ""}</p>
                  {m.report.capabilities.length > 0 ? <ul className="list-disc pl-5">{m.report.capabilities.map((c, i) => <li key={i}>{c.kind}: {c.detail} ({c.file}{c.line ? `:${c.line}` : ""})</li>)}</ul> : null}
                  {m.report.dataFlows.length > 0 ? <ul className="list-disc pl-5">{m.report.dataFlows.map((f, i) => <li key={i}>{f.from} → {f.to} ({f.file}{f.line ? `:${f.line}` : ""}){f.note ? ` — ${f.note}` : ""}</li>)}</ul> : null}
                </div>
              ) : <p className={muted}>{m.detail}</p>}
            </div>
          ))}
          <p className={muted}>Отправлено файлов: {scan.files}, {scan.chars} знаков (без комментариев). Модели одобрить версию не могут.</p>
        </Fold>
      ) : null}
    </div>
  );
}

const PUBLISH_STATE: Record<string, string> = {
  off: "публикация выключена",
  "no-address": "публикация включена, но адрес репозитория не задан",
  "not-configured": "публикация не настроена: на сервере не задана переменная BB_SECURE_BB_PUBLISH_TOKEN_FILE",
  ready: "публикация готова",
};
const PUBLISH_STATUS: Record<string, string> = { running: "идёт", published: "опубликовано", unchanged: "уже было опубликовано", failed: "ошибка", skipped: "пропущено" };

/** Where this version of this plugin went (or why it did not): the result of the last attempts, with the reason. */
function PublicationLine({ ov, pluginId, version, rpc, refetch }: { ov: Overview; pluginId: string; version: string | null; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const mine = ov.publish.recent.filter((r) => r.pluginId === pluginId && (version === null || r.version === version || r.version === "—"));
  const last = mine[0];
  if (!ov.publish.settings.enabled && !last) return null;
  return (
    <div className="mt-1 text-xs">
      {last ? (
        <p className={last.status === "failed" ? "text-destructive" : muted}>
          Публикация {last.version}: {PUBLISH_STATUS[last.status] ?? last.status}
          {last.commit ? ` · коммит ${last.commit.slice(0, 10)}` : ""}{last.tag ? ` · тег ${last.tag}` : ""} · {when(last.finishedAt ?? last.startedAt)}
          {last.detail && last.status !== "published" ? ` — ${last.detail}` : ""}
        </p>
      ) : (
        <p className={muted}>Публикация: ещё не было ({PUBLISH_STATE[ov.publish.state]}).</p>
      )}
      {ov.publish.state === "ready" && version ? (
        <button className={`${btn} mt-1`} disabled={act.busy} onClick={() => void act.run(async () => { const r = await rpc.call("publish.run", { pluginId }); return { note: r.note }; })}>
          Опубликовать закреплённую версию
        </button>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function PublishCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const cur = ov.publish.settings;
  const [url, setUrl] = useState(cur.repoUrl);
  const [branch, setBranch] = useState(cur.branch);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  useEffect(() => setUrl(cur.repoUrl), [cur.repoUrl]);
  useEffect(() => setBranch(cur.branch), [cur.branch]);
  const set = (patch: Record<string, unknown>) =>
    void act.run(async () => {
      await rpc.call("publish.settings", defined({ ...patch, ...(code.length === 6 ? { code } : {}) }) as never);
      setCode("");
    });
  return (
    <div className={card}>
      <h3 className="font-semibold">Публикация замороженных версий (необязательный модуль)</h3>
      <p className={muted}>
        При заморозке окна secure-bb кладёт снимок плагина в git-репозиторий: каталог <code>&lt;id&gt;/</code>, коммит «id@версия frozen хеш», тег <code>id-vверсия</code>. Только наши плагины (снимки через propose). Включение, смена адреса и ветки — с кодом. Токен в настройках не хранится: путь к файлу задаёт переменная окружения сервера <code>BB_SECURE_BB_PUBLISH_TOKEN_FILE</code>.
      </p>
      <p className="mt-1">{PUBLISH_STATE[ov.publish.state]}</p>
      <div className="mt-2 space-y-1">
        <label className="flex items-center justify-between gap-2">Адрес (https)
          <input className={`${input} w-72 tracking-normal`} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/owner/bb-plugins.git" />
        </label>
        <label className="flex items-center justify-between gap-2">Ветка
          <input className={`${input} w-48 tracking-normal`} value={branch} onChange={(e) => setBranch(e.target.value)} />
        </label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={cur.enabled} disabled={act.busy || cur.repoUrl === ""} onChange={(e) => set({ enabled: e.target.checked })} /> Публиковать при заморозке окна</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={cur.onApprove} disabled={act.busy || !cur.enabled} onChange={(e) => set({ onApprove: e.target.checked })} /> Также при одобрении версии кодом</label>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {registered ? <CodeField value={code} onChange={setCode} /> : <span className={muted}>Второй фактор ещё не зарегистрирован.</span>}
        <button className={btn} disabled={act.busy || (url === cur.repoUrl && branch === cur.branch)} onClick={() => set({ repoUrl: url, branch })}>Сохранить адрес и ветку</button>
      </div>
      {ov.publish.recent.length > 0 ? (
        <Fold id="publish-recent" className="mt-1" summary={`Последние публикации (${ov.publish.recent.length})`}>
          <ul className="mt-1 list-disc pl-5">
            {ov.publish.recent.slice(0, 15).map((r) => (
              <li key={r.id} className={r.status === "failed" ? "text-destructive" : undefined}>
                {r.pluginId}@{r.version} · {PUBLISH_STATUS[r.status] ?? r.status} · {when(r.startedAt)}{r.detail ? ` — ${r.detail}` : ""}
              </li>
            ))}
          </ul>
        </Fold>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function ScanButton({ ov, target, rpc, refetch }: { ov: Overview; target: { pluginId: string } | { queueId: number }; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  if (!ov.ai.settings.enabled) return null;
  return (
    <>
      <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("ai.scan", target); return { note: "Скан запущен: он идёт несколько минут." }; })}>
        Сканировать
      </button>
      <Msg error={act.error} ok={act.ok} />
    </>
  );
}

function AiCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const ai = ov.ai;
  const [code, setCode] = useState("");
  const [model, setModel] = useState(ai.settings.secondModel);
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  useEffect(() => setModel(ai.settings.secondModel), [ai.settings.secondModel]);
  const set = (patch: Record<string, unknown>) =>
    void act.run(async () => {
      await rpc.call("ai.settings", defined({ ...patch, ...(code.length === 6 ? { code } : {}) }) as never);
      setCode("");
    });
  const box = (label: string, key: "enabled" | "autoFreeze" | "autoExternal" | "second", dependsOnModule = true) => (
    <label className="flex items-center gap-2">
      <input type="checkbox" checked={ai.settings[key]} disabled={act.busy || (dependsOnModule && !ai.settings.enabled)} onChange={(e) => set({ [key]: e.target.checked })} /> {label}
    </label>
  );
  return (
    <div className={card}>
      <h3 className="font-semibold">ИИ-скан плагинов (необязательный модуль)</h3>
      <p className={muted}>
        Выключен по умолчанию. Включённый, отправляет код плагина (без комментариев) в облако моделей. Модели только добавляют подозрение: одобрить версию они не могут. Включать — только с кодом (код плагина уходит в облако); выключать — без кода.
      </p>
      <div className="mt-2 space-y-1">
        {box("Модуль включён (кнопка «Сканировать»)", "enabled", false)}
        {box("Автоскан при заморозке (все плагины; отдельные — у плагина)", "autoFreeze")}
        {box("Автоскан внешних (каждая версия до решения)", "autoExternal")}
        {box("Вторая модель (cursor-agent, другой вендор, параллельно)", "second")}
        <label className="flex items-center justify-between gap-2">Имя второй модели (не Anthropic)
          <input className={`${input} w-48 tracking-normal`} value={model} onChange={(e) => setModel(e.target.value)} placeholder="например gpt-5" />
        </label>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {registered ? <CodeField value={code} onChange={setCode} /> : <span className={muted}>Код нужен для включения; второй фактор ещё не зарегистрирован.</span>}
        <button className={btn} disabled={act.busy || model === ai.settings.secondModel} onClick={() => set({ secondModel: model })}>Сохранить имя модели</button>
      </div>
      <p className={`mt-2 ${muted}`}>
        Claude: {ai.availability.claude.mode === "unavailable" ? "недоступен — " : ""}{ai.availability.claude.detail}
        {ai.availability.cursor ? ` · cursor-agent: ${ai.availability.cursor.found ? "" : "недоступен — "}${ai.availability.cursor.detail}` : ""}
      </p>
      {ai.recent.length > 0 ? (
        <Fold id="ai-recent" className="mt-1" summary={`Последние сканы (${ai.recent.length})`}>
          {ai.recent.map((r) => <ScanResultView key={r.id} scan={r} other={r.trigger} />)}
        </Fold>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

// ------------------------------------------------------------ sentinel ----
function FeedItem({ row, riskThreshold }: { row: FeedRow; riskThreshold: number }) {
  const fired = firedText(row);
  return (
    <li className="rounded-md border border-border p-2">
      <div className={`text-xs ${muted}`}>{when(row.ts)} · тред {row.threadId} · {row.providerId}{row.windowPlugin ? ` · окно: ${row.windowPlugin}` : ""}</div>
      <div className="font-mono text-xs break-all"><b>{row.tool}</b>{row.args ? ` — ${row.args}` : ""}</div>
      {row.task ? <div className={`text-xs ${muted}`}>задача: {row.task}</div> : <div className={`text-xs ${muted}`}>задача треда не найдена</div>}
      <div className={row.status === "not_scored" ? muted : fired ? "text-destructive" : ""}>{verdictText(row, riskThreshold)}</div>
      <div className={`text-xs ${muted}`}>человек: {OUTCOME_LABEL[row.outcome]}{row.outcomeAt ? ` (${when(row.outcomeAt)})` : ""}</div>
    </li>
  );
}

function QuestionEditor({ q, rpc, refetch }: { q: QuestionView; rpc: Rpc; refetch: () => void }) {
  const [text, setText] = useState(q.instructions);
  const [threshold, setThreshold] = useState(String(q.threshold ?? ""));
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  useEffect(() => setText(q.instructions), [q.instructions]);
  useEffect(() => setThreshold(String(q.threshold ?? "")), [q.threshold]);
  const save = (patch: Record<string, unknown>) => void act.run(async () => { await rpc.call("sentinel.settings", defined({ ...patch, code }) as never); setCode(""); return { note: "Сохранено." }; });
  return (
    <Fold id={`sentinel-q-${q.id}`} className="rounded-md border border-border p-2" summary={`${q.label}${q.threshold !== null ? ` · порог ${q.threshold}` : ""}${q.edited ? " · изменён" : ""}`}>
      <div className="mt-2 space-y-2">
        <textarea className="w-full rounded-md border border-border bg-background p-2 text-xs" rows={4} value={text} onChange={(e) => setText(e.target.value)} />
        {q.threshold !== null ? (
          <label className="flex items-center gap-2">Порог срабатывания (0–1)
            <input className={`${input} w-20 tracking-normal`} value={threshold} onChange={(e) => setThreshold(e.target.value)} />
          </label>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <CodeField value={code} onChange={setCode} />
          <button className={btn} disabled={act.busy || code.length !== 6 || text === q.instructions} onClick={() => save({ instruction: { id: q.id, text } })}>Сохранить вопрос</button>
          {q.edited ? <button className={btn} disabled={act.busy || code.length !== 6} onClick={() => save({ instruction: { id: q.id, text: "" } })}>Вернуть исходный</button> : null}
          {q.threshold !== null ? <button className={btn} disabled={act.busy || code.length !== 6 || Number(threshold) === q.threshold || threshold.trim() === "" || !(Number(threshold) >= 0 && Number(threshold) <= 1)} onClick={() => save({ threshold: { id: q.id, value: Number(threshold) } })}>Сохранить порог</button> : null}
        </div>
        <Msg error={act.error} ok={act.ok} />
      </div>
    </Fold>
  );
}

function SentinelSection({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const v = ov.sentinel;
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const set = (patch: Record<string, unknown>) => void act.run(async () => { await rpc.call("sentinel.settings", defined({ ...patch, code }) as never); setCode(""); });
  return (
    <div className="space-y-2">
      <div className={card}>
        <h3 className="font-semibold">Дозор на Jev — только наблюдение</h3>
        <p className={muted}>
          Выключен по умолчанию. Включённый, на каждую карточку одобрения (все провайдеры) в треде с открытым окном доверия задаёт решателю десять вопросов-категорий и оценку риска и пишет ответ в ленту.
          <b> На карточки он не отвечает</b>: до ступени 5 на карточку может ответить сам агент через API, поэтому решение дозора было бы декорацией. Что попало в запрос, маскируется кодом: секреты скрываются, аргументы сокращаются, но задача треда и действие уходят в облако. Ошибка, таймаут или лимит — запись «не оценено».
          Любое изменение — только с кодом.
        </p>
        <div className="mt-2 space-y-1">
          <label className="flex items-center gap-2">Провайдер Jev (ключ должен быть от него)
            <select className="rounded-md border border-border bg-background px-2 py-1" value={v.settings.provider} disabled={act.busy || code.length !== 6} onChange={(e) => set({ provider: e.target.value })}>
              <option value="typesafe">typesafe (api.typesafe.ai)</option>
              <option value="openrouter">openrouter</option>
            </select>
          </label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={v.settings.enabled} disabled={act.busy || code.length !== 6} onChange={(e) => set({ enabled: e.target.checked })} /> Дозор включён</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={v.settings.allThreads} disabled={act.busy || code.length !== 6} onChange={(e) => set({ allThreads: e.target.checked })} /> Следить во всех тредах, а не только с открытым окном доверия</label>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <CodeField value={code} onChange={setCode} />
          <span className={muted}>Введите код, затем нажмите на переключатель.</span>
        </div>
        <p className={`mt-2 ${muted}`}>
          Решатель: {v.solver}{v.keyConfigured ? " · ключ задан" : " · ключ не задан (BB_SECURE_BB_JEV_KEY_FILE): карточки будут записаны как «не оценено»"} · таймаут {Math.round(v.settings.timeoutMs / 1000)} с · не больше {v.settings.maxPerMinute} запросов в минуту
        </p>
        <Msg error={act.error} ok={act.ok} />
      </div>
      <div className={card}>
        <h3 className="font-semibold">Лента дозора ({v.feed.length})</h3>
        {v.feed.length === 0 ? <p className={muted}>Пока пусто.</p> : <ul className="mt-2 space-y-2">{v.feed.map((r) => <FeedItem key={r.id} row={r} riskThreshold={v.settings.riskThreshold} />)}</ul>}
      </div>
      <Fold id="sentinel-questions" className={card} summaryClassName="cursor-pointer font-semibold" summary={`Вопросы и пороги (${v.questions.length})`}>
        <div className="mt-2 space-y-2">{v.questions.map((q) => <QuestionEditor key={q.id} q={q} rpc={rpc} refetch={refetch} />)}</div>
      </Fold>
    </div>
  );
}

// ------------------------------------------------------------ window bar ---

function windowLine(w: WindowView, remainingSec: number): string {
  const subs = w.scope === "tree" && w.subthreads > 0 ? ` и ${w.subthreads} вложенных чатов` : "";
  const only = w.scope === "thread" ? " (только этот чат)" : "";
  return `Временное доверие: плагин ${w.pluginId} из чата ${w.threadId}${subs}${only} — ещё ${minutes(remainingSec)}`;
}

function cfgWindowLine(w: ConfigWindowView, remainingSec: number): string {
  return `Временное доверие: ${w.scopeLabels.join(", ")} — ещё ${minutes(remainingSec)}`;
}

function WindowRows({ windows, cfgWindows, rpc, refetch }: { windows: WindowView[]; cfgWindows: ConfigWindowView[]; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const now = useNow();
  const ap = useApproval();
  const act = useCodeAction(refetch);
  if (windows.length === 0 && cfgWindows.length === 0) return null;
  return (
    <div className="space-y-2">
      {cfgWindows.map((w) => {
        const remaining = Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000));
        return (
          <div key={`cfg-${w.id}`} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">{cfgWindowLine(w, remaining)}</span>
            <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("watch.window.close", { windowId: w.id }); })}>
              Закрыть
            </button>
          </div>
        );
      })}
      {windows.map((w) => {
        const remaining = Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000));
        return (
          <div key={w.id} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">{windowLine(w, remaining)}</span>
            <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("window.close", { windowId: w.id }); })}>
              Закрыть
            </button>
          </div>
        );
      })}
      <Msg error={act.error} />
    </div>
  );
}

/** A broken journal chain is an alarm: shown on the page and in the strip, never hidden. */
function JournalAlarm({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const act = useCodeAction(refetch);
  if (ov.journal.ok) return null;
  return (
    <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
      <p className="font-semibold">ТРЕВОГА: цепочка журнала решений нарушена</p>
      <ul className="mt-1 list-disc pl-5 text-xs">
        {ov.journal.problems.slice(0, 5).map((p, i) => <li key={i}>{p.detail}</li>)}
        {ov.journal.problems.length > 5 ? <li>и ещё {ov.journal.problems.length - 5}</li> : null}
      </ul>
      <p className="mt-1 text-xs">Журнал или база изменены не гейтом. Всё, что гейт «одобрил» до этого места, нельзя считать надёжным: проверьте плагины и одобрения вручную.</p>
      <button className={`${btn} mt-1`} disabled={act.busy} onClick={() => void act.run(async () => rpc.call("journal.verify"))}>Проверить заново</button>
      <Msg error={act.error} />
    </div>
  );
}

/** Threat model X3: the gate was off for a while, or bb's safe-mode is (or was) on. Shown on the page and in the strip, for a week. */
function AliveAlarm({ ov }: { ov: Overview }) {
  const a = ov.alive;
  if (a.gaps.length === 0 && a.safeMode !== true && !a.safeModeSeen) return null;
  const at = (t: number) => new Date(t).toLocaleString();
  return (
    <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
      <p className="font-semibold">ТРЕВОГА: гейт не всегда работал</p>
      <ul className="mt-1 list-disc pl-5 text-xs">
        {a.gaps.map((g, i) => <li key={i}>Гейт не работал с {at(g.from)} по {at(g.to)} ({Math.round(g.ms / 60_000)} мин){g.stopped ? ": его остановили (выключили)" : ": процесс остановился без предупреждения"}{g.safeMode ? "; safe-mode bb был включён" : ""}.</li>)}
        {a.safeMode === true ? <li>safe-mode bb включён сейчас: сторонние плагины не работают.</li> : null}
        {a.safeMode !== true && a.safeModeSeen ? <li>За последнюю неделю safe-mode bb включался (см. журнал).</li> : null}
      </ul>
      <p className="mt-1 text-xs">Пока гейта нет, ничего не удерживается и не проверяется; за это время могли поменять настройки и вернуть их. Проверьте конфигурацию и плагины вручную.</p>
    </div>
  );
}

/** Always-on-screen strip: open windows are never hidden. */
function WindowOverlay() {
  const { rpc, data, refetch } = useOverview();
  if (!data || (data.windows.length === 0 && data.watch.windows.length === 0 && data.journal.ok && data.alive.gaps.length === 0 && data.alive.safeMode !== true)) return null;
  return (
    <div className="pointer-events-auto fixed bottom-3 left-3 z-50 max-w-[min(32rem,calc(100vw-1.5rem))] space-y-2 rounded-lg border border-border bg-card p-2 shadow-lg" data-secure-bb-banner>
      <JournalAlarm ov={data} rpc={rpc} refetch={refetch} />
      <AliveAlarm ov={data} />
      <WindowRows windows={data.windows} cfgWindows={data.watch.windows} rpc={rpc} refetch={refetch} />
    </div>
  );
}

// ---------------------------------------------------------------- sections --

const dot: Record<string, string> = { ok: "bg-green-500", warn: "bg-yellow-500", bad: "bg-red-500", unknown: "bg-gray-400" };

function StageCard({ ov }: { ov: Overview }) {
  const a = ov.assessment;
  const names = ["Ступень 0 — обычный bb", "Ступень 1 — bb с хуком", "Ступень 2 — гейт обязателен", "Ступень 3 — агенты отдельно", "Ступень 4 — сеть закрыта", "Ступень 5 — аутентификация API"];
  return (
    <div className={card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-lg font-semibold">{names[a.stage]}</h3>
        <span className={muted}>{ov.hookRegistered ? "проверка до загрузки кода" : "режим «после факта»"}</span>
      </div>
      {a.honest.map((h) => (
        <p key={h} className="mt-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 p-2">
          {h}
        </p>
      ))}
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div>
          <h4 className="font-medium">Что защищено</h4>
          <ul className="list-disc pl-5">{a.protects.map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
        <div>
          <h4 className="font-medium">Чего нет</h4>
          {a.missing.length === 0 ? <p className={muted}>—</p> : <ul className="list-disc pl-5">{a.missing.map((p) => <li key={p}>{p}</li>)}</ul>}
        </div>
      </div>
      <p className="mt-3"><span className="font-medium">Следующий шаг: </span>{a.nextStep}</p>
      <Fold id="stage-checks" className="mt-3" summaryClassName="cursor-pointer font-medium" summary="Проверки">
        <ul className="mt-2 space-y-1.5">
          {a.checks.map((c) => (
            <li key={c.id} className="flex gap-2">
              <span className={`mt-1.5 size-2.5 shrink-0 rounded-full ${dot[c.state]}`} aria-label={c.state} />
              <span><span className="font-medium">{c.label}.</span> {c.detail}</span>
            </li>
          ))}
        </ul>
      </Fold>
    </div>
  );
}

function Registration({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [qr, setQr] = useState<{ secret: string; uri: string; matrix: boolean[][] } | null>(null);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const state = ov.totp.state;

  if (ov.guard) {
    return state === "external" ? (
      <div className={card}>✓ Второй фактор у сторожа: секрет лежит в его каталоге, через bb не проходил и нигде не показывается.</div>
    ) : (
      <div className={`${card} border-2 border-destructive`}>
        <h3 className="text-base font-semibold text-destructive">Второй фактор не зарегистрирован у сторожа</h3>
        <p className="mt-1">Регистрация — только на консоли машины, где работает сторож: <span className="font-mono">sudo sbb-guard totp-register</span> (QR выводится в терминал) или passkey: <span className="font-mono">sbb-guard passkey-enroll</span>. Через bb секрет не проходит, поэтому его не может перехватить плагин.</p>
        {ov.guard.connected ? null : <p className="mt-1 text-destructive">Сторож сейчас не отвечает.</p>}
      </div>
    );
  }

  if (state === "locked") return <div className={card}>✓ Второй фактор (TOTP) зарегистрирован. Секрет больше нигде не показывается.</div>;
  if (state === "external") return <div className={card}>✓ Секрет TOTP берётся из внешнего файла (BB_SECURE_BB_TOTP_FILE).</div>;
  if (state === "external-broken") return <div className={`${card} border-destructive`}>Задан BB_SECURE_BB_TOTP_FILE, но файл не читается или в нём нет секрета. Одобрения невозможны.</div>;

  const blockedByPlugins = ov.thirdPartyRunning.length > 0;
  return (
    <div className={`${card} border-2 border-destructive`}>
      <h3 className="text-base font-semibold text-destructive">Зарегистрируйте второй фактор сейчас</h3>
      {ov.totp.pendingUnattended && qr === null ? (
        <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">
          Регистрация была начата не с этой страницы (кто — см. журнал). Её нельзя подтвердить: нажмите «Начать заново» и сканируйте новый код.
        </p>
      ) : null}
      <p className="mt-1">
        Без неё одобрить плагин нельзя. Сделайте это сразу: до регистрации любой процесс на этой машине (в том числе агент) может её начать раньше вас.
      </p>
      <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">{T.totpFile.registerWarning}</p>
      {blockedByPlugins ? (
        <div className="mt-2">
          <p className="text-destructive">Выключите сторонние плагины — их код интерфейса увидел бы QR-код:</p>
          <ul className="list-disc pl-5 font-mono">{ov.thirdPartyRunning.map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
      ) : null}
      {qr === null ? (
        <button
          className={`${btnPrimary} mt-3`}
          disabled={act.busy || blockedByPlugins}
          onClick={() => void act.run(async () => { await rpc.call("page.ping"); setQr(await rpc.call("totp.begin")); })}
        >
          {state === "pending" ? "Начать заново" : "Показать QR-код"}
        </button>
      ) : (
        <div className="mt-3 space-y-3">
          <QrSvg matrix={qr.matrix} />
          <p>Отсканируйте в приложении-аутентификаторе или введите ключ вручную:</p>
          <p className="break-all font-mono text-base">{qr.secret}</p>
          <div className="flex items-center gap-2">
            <CodeField value={code} onChange={setCode} />
            <button
              className={btnPrimary}
              disabled={act.busy || code.length !== 6}
              onClick={() =>
                void act.run(async () => {
                  await rpc.call("totp.confirm", { code });
                  setQr(null);
                  setCode("");
                })
              }
            >
              Подтвердить и запереть
            </button>
          </div>
        </div>
      )}
      <Msg error={act.error} />
    </div>
  );
}

function QrSvg({ matrix }: { matrix: boolean[][] }) {
  const quiet = 4;
  const n = matrix.length + quiet * 2;
  const cells: ReactNode[] = [];
  matrix.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) cells.push(<rect key={`${x}-${y}`} x={x + quiet} y={y + quiet} width={1} height={1} />);
    }),
  );
  return (
    <svg viewBox={`0 0 ${n} ${n}`} className="size-56 max-w-full rounded-md border border-border" role="img" aria-label="QR-код для приложения-аутентификатора" shapeRendering="crispEdges">
      <rect width={n} height={n} fill="#fff" />
      <g fill="#000">{cells}</g>
    </svg>
  );
}

/** What the deterministic checks found in one version (the decision table of spec §5.3 acts on it). */
function ChecksView({ id, result }: { id: string; result: CheckResult | undefined }) {
  if (!result) return <p className={`mt-2 text-xs ${muted}`}>Проверки ещё выполняются или не запускались для этой версии.</p>;
  const sev = (s: string) => (s === "block" ? "блок" : s === "review" ? "на ревью" : "инфо");
  const lines = significantFindings(result.findings);
  return (
    <Fold id={`checks-${id}`} className="mt-2" defaultOpen={lines.some((l) => l.severity === "block")} summary={checksSummary(lines, result.capabilities.length)}>
      {lines.length > 0 ? (
        <ul className="mt-1 list-disc pl-5">
          {lines.map((l, i) => (
            <li key={i}>
              <b>{l.severity === "block" ? "Останавливает" : "Нужен взгляд"}:</b> {l.text}
              {l.count > 1 ? ` (${l.count} мест)` : ""}
              {l.where.length > 0 ? <span className={muted}> · {l.where.join(", ")}{l.count > l.where.length ? ", …" : ""}</span> : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className={`mt-1 ${muted}`}>Ничего, что требовало бы взгляда.</p>
      )}
      <p className="mt-1 font-semibold">Возможности</p>
      {result.capabilities.length === 0 ? (
        <p className={muted}>нет (безопасный класс)</p>
      ) : (
        <ul className="list-disc pl-5">
          {result.capabilities.map((c) => (
            <li key={c.kind}>{capabilityPhrase(attachFlow(result, { kind: c.kind, detail: c.detail }))}</li>
          ))}
        </ul>
      )}
      <DependenciesView result={result} />
      <Fold id={`checks-raw-${id}`} className="mt-2" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Для разработчика: сырые данные проверок">
        <ul className="mt-1 list-disc pl-5 text-xs">
          {result.findings.map((f, i) => (
            <li key={i} className="break-all">
              <b>{sev(f.severity)}</b> {f.rule} · <span className="font-mono">{f.file}{f.line ? `:${f.line}` : ""}</span> · <span className="font-mono">{f.excerpt}</span>
            </li>
          ))}
          {result.capabilities.map((c) => (
            <li key={`cap-${c.kind}`} className="break-all"><span className="font-mono">{c.kind}</span>{c.detail.length ? `: ${c.detail.join(", ")}` : ""}</li>
          ))}
          {(result.flows ?? []).map((f) => (
            <li key={`flow-${f.source}`} className="break-all"><span className="font-mono">flow {f.source}</span>{f.detail.length ? ` (${f.detail.join(", ")})` : ""}: {f.verdict}{f.sinks.length ? ` → ${f.sinks.map((k) => `${k.kind}${k.target ? `:${k.target}` : ""} ${k.file}:${k.line}`).join(", ")}` : ""}{f.why ? ` — ${f.why}` : ""}</li>
          ))}
          {(result.purposes ?? []).map((p, i) => (
            <li key={`purpose-${i}`} className="break-all"><span className="font-mono">purpose</span> {p.on.join("/")}: {p.text} ({p.pair})</li>
          ))}
        </ul>
      </Fold>
    </Fold>
  );
}

const DEP_STATUS: Record<string, string> = {
  ok: "проверена",
  young: "релиз моложе 3 дней",
  unchecked: "не проверена",
  "not-in-registry": "нет в реестре npm",
  "unknown-version": "версии нет в реестре",
  skipped: "не из реестра",
};

/** Dependencies and what the npm registry said about them (stage 2.3). */
function DependenciesView({ result }: { result: CheckResult }) {
  const st = result.dependencyStats;
  const deps = result.dependencies ?? [];
  if (!st || st.total === 0) return null;
  return (
    <>
      <p className="mt-1 font-semibold">Зависимости</p>
      <p className={muted}>
        всего {st.total} (объявлено {st.declared}) ·{" "}
        {st.registry ? `сверено с реестром npm: ${st.verified} · не проверено: ${st.unchecked} · моложе 3 дней: ${st.young}` : "реестр npm не опрашивался"}
        {st.lookalikes > 0 ? ` · похожи на популярные: ${st.lookalikes}` : ""}
      </p>
      {deps.length > 0 ? (
        <ul className="list-disc pl-5">
          {deps.map((d, i) => (
            <li key={i} className="break-all">
              <span className="font-mono">{d.name}@{d.version ?? d.installed ?? d.spec ?? "?"}</span>
              {d.declared ? "" : " (node_modules)"} · {d.status ? (DEP_STATUS[d.status] ?? d.status) : "не опрашивалась"}
              {d.publishedAt ? ` · выпущена ${d.publishedAt.slice(0, 10)}` : ""}
              {d.note ? <span className={muted}> — {d.note}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </>
  );
}

/** A local proposal has a negative id inside; the person reads "предложение 4", not "#-4". */
const queueLabel = (id: number): string => (id < 0 ? `предложение ${-id}` : `#${id}`);
function QueueCard({ q, ov, rpc, refetch }: { q: QueueRow; ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const held = q.status === "held";
  const unsafeDirNow = q.reason?.startsWith("каталог доступен на запись другим") ?? false;
  const ap = useApproval();
  const found = ov.queueChecks[q.id];
  const blocked = isBlockedEntry({ reason: q.reason, findings: found?.findings ?? [] });
  const [ack, setAck] = useState(false);
  // Lifting a block is dangerous: it needs a fresh code even with a session open.
  const liftingBlock = blocked && ack;
  const disabled = act.busy || !ap.ready(code, liftingBlock) || !registered || unsafeDirNow;
  const done = () => setCode("");
  const pk = usePasskey(ov);
  const [touching, setTouching] = useState<string | null>(null);
  /** Approves or opens a window with a touch instead of a code. */
  const touch = (kind: "approve" | "window.open", ack = false) =>
    void act.run(async () => {
      setTouching(null);
      const t = await touchFor(rpc, { kind, queueId: q.id, ...(kind === "approve" ? { acknowledgeBlock: ack } : {}) }, (d) => setTouching(`Подтвердите касанием. Сторож: «${d}»`));
      if (!t) throw new Error("касание не требуется");
      if (kind === "approve") await rpc.call("queue.approve", { id: q.id, passkey: t.passkey, acknowledgeBlock: ack });
      else await rpc.call("window.open", { queueId: q.id, passkey: t.passkey });
      setTouching(null);
      setAck(false);
      return { note: `Одобрено касанием. Сторож описал действие так: «${t.description}» (системное окно Touch ID этого не показывает; точное действие записано в журнале сторожа).` };
    });
  // The directory can be changed by someone other than the server's user: no code approves it; fix the directory, then it is looked at again.
  const unsafeDir = q.reason?.startsWith("каталог доступен на запись другим") ?? false;
  return (
    <div className={blocked && held ? cardBlocked : card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">
          {queueLabel(q.id)} · {q.pluginId} <span className={muted}>{q.version}</span>
        </h3>
        <span className={blocked && held ? "font-semibold text-red-700 dark:text-red-400" : muted}>
          {held ? (blocked ? "заблокировано" : "держится") : q.status === "approved" ? "одобрено" : q.status === "stale" ? "устарело" : "отклонено"} · {when(q.firstSeen)}
        </span>
      </div>
      <p className={`mt-1 break-all ${muted}`}>
        {q.sourceKind}: {q.source}
        {q.threadId ? ` · из чата ${q.threadId}` : ""}
        {q.kind === "afterfact" ? " · выключен после загрузки (его код уже выполнялся)" : ""}
        {q.kind === "proposal" && !q.contentHash ? " · предложен агентом, окно было закрыто" : ""}
      </p>
      {q.contentHash ? <p className={`break-all font-mono text-xs ${muted}`}>{q.contentHash}</p> : null}
      {q.reason ? <p className={`mt-1 ${blocked || unsafeDir ? "font-semibold text-red-700 dark:text-red-400" : muted}`}>{q.reason}</p> : null}
      {unsafeDir && held ? <p className="mt-1 text-red-600">Одобрить нельзя: пока в каталоге или выше может писать кто-то кроме пользователя сервера, его содержимое может измениться после проверки. Исправьте права (владелец — пользователь сервера, без записи для группы и остальных) или предложите плагин через <span className="font-mono">bb secure-bb propose</span>: снимок гейт хранит у себя.</p> : null}
      <ChecksView id={cardFoldId(q, "checks-q")} result={ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined)} />
      <ScanResultView scan={ov.ai.queueScans[q.id]} />
      {held ? (
        <div className="mt-3 space-y-3">
          {blocked ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <button className={btnPrimary} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("queue.dismiss", { id: q.id }); })}>
                  Отклонить
                </button>
                <span className={muted}>Без кода: отклонение только ужесточает.</span>
                <ScanButton ov={ov} target={{ queueId: q.id }} rpc={rpc} refetch={refetch} />
              </div>
              {isMismatch(q.reason) ? <p className={muted}>{MISMATCH_HINT}</p> : <Fold id={cardFoldId(q, "force")} className="rounded-md border border-red-300 p-2 dark:border-red-900" summaryClassName="cursor-pointer text-red-700 dark:text-red-400" summary="Всё равно одобрить (опасно)…">
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {pk.keyOnly ? null : <RoutineCode value={code} onChange={setCode} dangerous />}
                  <label className="flex items-center gap-1 text-xs">
                    <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> понимаю риск: проверки нашли жёсткий признак
                  </label>
                  {pk.has ? (
                    <button className={btnDanger} disabled={act.busy || !ack || pk.problem !== null || !registered || unsafeDirNow} onClick={() => touch("approve", true)}>
                      Снять блок и одобрить касанием
                    </button>
                  ) : null}
                  {pk.keyOnly ? null : (
                    <button className={btnDanger} disabled={disabled || !ack} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("queue.approve", { id: q.id, ...proof, acknowledgeBlock: ack }), true); done(); setAck(false); return r; })}>
                      {pk.has ? "Снять блок и одобрить кодом" : "Снять блок и одобрить"}
                    </button>
                  )}
                </div>
              </Fold>}
            </>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("queue.dismiss", { id: q.id }); })}>
                Отклонить
              </button>
              {pk.has ? (
                <>
                  <button className={btnPrimary} disabled={act.busy || pk.problem !== null || !registered || unsafeDirNow} onClick={() => touch("approve")}>
                    Одобрить касанием
                  </button>
                  {q.threadId && q.id > 0 ? (
                    <button className={btn} disabled={act.busy || pk.problem !== null || !registered} onClick={() => touch("window.open")}>
                      Открыть окно касанием
                    </button>
                  ) : null}
                </>
              ) : null}
              {pk.keyOnly ? null : (
                <>
                  {pk.has ? <span className={muted}>запасной путь — код:</span> : null}
                  <RoutineCode value={code} onChange={setCode} dangerous={false} />
                </>
              )}
              <ScanButton ov={ov} target={{ queueId: q.id }} rpc={rpc} refetch={refetch} />
              {pk.keyOnly ? null : (
                <button className={pk.has ? btn : btnPrimary} disabled={disabled} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("queue.approve", { id: q.id, ...proof, acknowledgeBlock: false }), false); done(); return r; })}>
                  Одобрить версию{pk.has ? " кодом" : ""}
                </button>
              )}
              {q.threadId && !pk.keyOnly ? (
                <button className={btn} disabled={disabled} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("window.open", { queueId: q.id, ...proof })); done(); })}>
                  Открыть окно
                </button>
              ) : null}
            </div>
          )}
        </div>
      ) : null}
      {held && !registered ? <p className={`mt-2 ${muted}`}>Сначала зарегистрируйте второй фактор.</p> : null}
      {held && pk.has && pk.problem ? <p className="mt-2 text-destructive">{pk.problem}</p> : null}
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

/** «Открыть окно на N мин» on the plugin's row, or the reason there is none. */
function PluginWindowOpen({ p, ov, rpc, refetch }: { p: PluginView; ov: Overview; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc);
  if (!p.windowOpen.available) return p.windowOpen.note ? <p className={`text-xs ${muted}`}>{p.windowOpen.note}</p> : null;
  return (
    <div className="mt-1">
      <div className="flex flex-wrap items-center gap-2">
        <ProofField proof={proof} routine />
        <button className={btn} disabled={act.busy || !proof.ready({ routine: true })} onClick={() => void act.run(async () => { await proof.run({ kind: "window.open", pluginId: p.id } as never, (x) => rpc.call("window.open", { pluginId: p.id, ...x } as never), { routine: true }); })}>
          Открыть окно на {ov.policy.windowMin} мин
        </button>
      </div>
      <p className={`text-xs ${muted}`}>Пока окно открыто, новые версии {p.id} из того же треда проходят без вопросов; новое право всё равно спросит.</p>
      <ProofNotes proof={proof} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function PluginRow({ p, ov, rpc, refetch, registered, checks }: { p: PluginView; ov: Overview; checks: Record<string, CheckResult>; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void; registered: boolean }) {
  const now = useNow();
  const ap = useApproval();
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const remaining = p.window ? Math.max(0, Math.ceil((Math.min(p.window.expiresAt, p.window.hardExpiresAt) - now) / 1000)) : 0;
  return (
    <div className={card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{p.id} <span className={muted}>{p.version} · {p.status}</span></h3>
        <span className={muted}>
          {p.pin ? `${p.frozenPin ? "закреплена при заморозке" : "пин"}: ${p.pin.version} (${approvedByText(p.pin, now)})` : p.unreviewedBaseline ? "стоял до secure-bb, не проверялся" : "не одобрен"}
        </span>
      </div>
      {launchProblem(p) && p.pin ? <p className="mt-1 font-semibold text-red-700 dark:text-red-400" role="alert">{launchProblem(p)}</p> : null}
      <p className={muted}>{p.window ? windowLine(p.window, remaining) : "окно закрыто"}</p>
      {!p.window ? <PluginWindowOpen p={p} ov={ov} rpc={rpc} refetch={refetch} /> : null}
      {p.pin ? <ChecksView id={`plugin-${p.id}`} result={checks[p.pin.contentHash]} /> : null}
      <PublicationLine ov={ov} pluginId={p.id} version={p.pin?.version ?? null} rpc={rpc} refetch={refetch} />
      <ScanResultView scan={ov.ai.pluginScans[p.id]} other={ov.ai.pluginScans[p.id] ? (ov.ai.pluginScans[p.id]!.current ? "это закреплённая версия" : "не закреплённая версия") : undefined} />
      {ov.ai.settings.enabled ? (
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <ScanButton ov={ov} target={{ pluginId: p.id }} rpc={rpc} refetch={refetch} />
          <label className="flex items-center gap-1 text-xs">
            <input type="checkbox" checked={ov.ai.settings.freezePlugins.includes(p.id)} disabled={act.busy || (!ov.ai.settings.freezePlugins.includes(p.id) && (!registered || code.length !== 6))} onChange={(e) => void act.run(async () => { await rpc.call("ai.settings", { freezePlugin: { id: p.id, on: e.target.checked }, ...(code.length === 6 ? { code } : {}) }); setCode(""); })} />
            автоскан при заморозке этого плагина{ov.ai.settings.freezePlugins.includes(p.id) ? "" : " (включить — с кодом)"}
          </label>
          {registered && !ov.ai.settings.freezePlugins.includes(p.id) ? <CodeField value={code} onChange={setCode} /> : null}
        </div>
      ) : null}
      {p.history.length > 1 ? (
        <Fold id={`plugin-${p.id}-history`} className="mt-1" summary={`История (${p.history.length})`}>
          <ul className="mt-1 list-disc pl-5">
            {p.history.map((h) => (
              <li key={h.id}>{h.version} · {approvedByText(h, now)}</li>
            ))}
          </ul>
        </Fold>
      ) : null}
      {p.pin ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {p.pin ? (
            <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("approval.revoke", { approvalId: p.pin!.id }); })}>
              Отозвать (без кода)
            </button>
          ) : null}
        </div>
      ) : null}
      <Msg error={act.error} />
    </div>
  );
}

function PolicyCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const p = ov.policy;
  const [windowMin, setWindowMin] = useState(String(p.windowMin));
  const [capMin, setCapMin] = useState(String(p.capMin));
  const [mode, setMode] = useState<"sliding" | "fixed">(p.mode);
  const [scope, setScope] = useState<"tree" | "thread">(p.scope);
  const [cfgWindowMin, setCfgWindowMin] = useState(String(p.cfgWindowMin));
  const [cfgCapMin, setCfgCapMin] = useState(String(p.cfgCapMin));
  const [cfgMode, setCfgMode] = useState<"sliding" | "fixed">(p.cfgMode);
  const [autoSafe, setAutoSafe] = useState(p.autoSafe);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const pk = usePasskey(ov);
  const [touching, setTouching] = useState<string | null>(null);
  useEffect(() => {
    setAutoSafe(p.autoSafe);
    setWindowMin(String(p.windowMin));
    setCapMin(String(p.capMin));
    setMode(p.mode);
    setScope(p.scope);
    setCfgWindowMin(String(p.cfgWindowMin));
    setCfgCapMin(String(p.cfgCapMin));
    setCfgMode(p.cfgMode);
  }, [p.windowMin, p.capMin, p.mode, p.scope, p.cfgWindowMin, p.cfgCapMin, p.cfgMode, p.autoSafe]);
  return (
    <div className={card}>
      <h3 className="font-semibold">Окна доверия: настройки</h3>
      <p className={muted}>Хранятся в базе secure-bb, не в настройках плагина. Расширять (больше размер или потолок, скользящее, дерево) — с кодом; сужать — без.</p>
      <div className="mt-2 grid gap-2 sm:grid-cols-2">
        <label className="flex items-center justify-between gap-2">Размер окна, мин
          <input className={input} inputMode="numeric" value={windowMin} onChange={(e) => setWindowMin(e.target.value.replace(/\D/g, ""))} />
        </label>
        <label className="flex items-center justify-between gap-2">Потолок, мин
          <input className={input} inputMode="numeric" value={capMin} onChange={(e) => setCapMin(e.target.value.replace(/\D/g, ""))} />
        </label>
        <label className="flex items-center justify-between gap-2">Режим
          <select className={input} value={mode} onChange={(e) => setMode(e.target.value as "sliding" | "fixed")}>
            <option value="sliding">скользящее</option>
            <option value="fixed">фиксированное</option>
          </select>
        </label>
        <label className="flex items-center justify-between gap-2">Охват
          <select className={input} value={scope} onChange={(e) => setScope(e.target.value as "tree" | "thread")}>
            <option value="tree">тред и всё дерево</option>
            <option value="thread">только этот тред</option>
          </select>
        </label>
        <label className="flex items-center justify-between gap-2">Окно «конфигурация», мин
          <input className={input} inputMode="numeric" value={cfgWindowMin} onChange={(e) => setCfgWindowMin(e.target.value.replace(/\D/g, ""))} />
        </label>
        <label className="flex items-center justify-between gap-2">Потолок «конфигурации», мин
          <input className={input} inputMode="numeric" value={cfgCapMin} onChange={(e) => setCfgCapMin(e.target.value.replace(/\D/g, ""))} />
        </label>
        <label className="flex items-center justify-between gap-2">Режим «конфигурации»
          <select className={input} value={cfgMode} onChange={(e) => setCfgMode(e.target.value as "sliding" | "fixed")}>
            <option value="sliding">скользящее</option>
            <option value="fixed">фиксированное</option>
          </select>
        </label>
      </div>
      {ov.guard ? (
        <p className={`mt-3 ${muted}`}>Размер, потолок и режим окна хранит сторож (расширять — с кодом, он проверит его сам). Окно доверия нужно для плагинов не из «моих источников». Версия плагина из «моих источников» проходит и без окна, пока не просит новых прав; новое право и всё остальное ждёт вашего касания.</p>
      ) : (
        <>
          <label className="mt-3 flex items-start gap-2">
            <input type="checkbox" className="mt-1" checked={autoSafe} onChange={(e) => setAutoSafe(e.target.checked)} />
            <span>Автопропуск версий без возможностей (без касания)</span>
          </label>
          <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">{T.autoSafeWarning}</p>
        </>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {pk.has ? <span className={muted}>касание или код:</span> : null}
        {pk.keyOnly ? null : <CodeField value={code} onChange={setCode} />}
        <button
          className={btnPrimary}
          disabled={act.busy || (pk.has && pk.problem !== null && pk.keyOnly)}
          onClick={() =>
            void act.run(async () => {
              // Guard mode has no "safe class passes": autoSafe is not sent there (bb rejects undefined fields in an RPC input).
              const change = buildPolicyChange({ autoSafe: ov.guard ? undefined : autoSafe, windowMin, capMin, mode, scope, cfgWindowMin, cfgCapMin, cfgMode });
              // With a key and no code typed: the touch (if the change widens anything; a narrowing needs none).
              const t = pk.has && code.length !== 6 ? await touchFor(rpc, buildPolicyTouchQuery(change), (d) => setTouching(`Подтвердите касанием. Сторож: «${d}»`)) : null;
              await rpc.call("policy.set", buildPolicySetInput(change, t ? { passkey: t.passkey } : code.length === 6 ? { code } : {}) as never);
              setCode("");
              setTouching(null);
              return t ? { note: `Сохранено касанием. Сторож описал действие так: «${t.description}».` } : undefined;
            })
          }
        >
          {pk.has && code.length !== 6 ? "Сохранить (касанием, если расширяет)" : "Сохранить"}
        </button>
      </div>
      {pk.has && pk.problem ? <p className="mt-1 text-destructive">{pk.problem}</p> : null}
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function TrustedRepos({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [pattern, setPattern] = useState("");
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const run = (change: { add: string } | { remove: string }) =>
    void act.run(async () => {
      const r = await rpc.call("trusted.set", { ...change, code });
      setCode("");
      setPattern("");
      return r;
    });
  return (
    <div className={card}>
      <p>
        Свои репозитории (github.com): <span className="font-mono">owner/name</span> или <span className="font-mono">owner/*</span>. <span className="font-mono">git clone/fetch/pull/ls-remote</span> по их адресу и вызовы <span className="font-mono">gh</span> с <span className="font-mono">--repo</span> или адресом такого репозитория не загрязняют тред. <span className="font-mono">gh</span> без явного репозитория загрязняет. Список пуст по умолчанию; менять — только с кодом. Изменение действует на события, прочитанные после него.
      </p>
      {ov.trustedRepos.length === 0 ? <p className={`mt-2 ${muted}`}>Список пуст: любой clone/fetch по адресу загрязняет.</p> : (
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {ov.trustedRepos.map((r) => (
            <li key={r} className="flex items-center gap-2">
              {r}
              <button className={btn} disabled={act.busy || code.length !== 6 || !registered} onClick={() => run({ remove: r })}>Убрать</button>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="rounded border border-border bg-transparent px-2 py-1 font-mono text-xs" placeholder="owner/name или owner/*" value={pattern} onChange={(e) => setPattern(e.target.value)} />
        <CodeField value={code} onChange={setCode} />
        <button className={btnPrimary} disabled={act.busy || code.length !== 6 || pattern.trim() === "" || !registered} onClick={() => run({ add: pattern })}>Добавить</button>
      </div>
      <Msg error={act.error} />
    </div>
  );
}

function TaintCard({ ov }: { ov: Overview }) {
  return (
    <div className={card}>
      <p>
        Тред, который прочитал недоверенное (веб, чужой репозиторий, инструмент MCP, установка скилла, проект с <span className="font-mono">.bb-env-setup.sh</span>), закрывает окно доверия плагина, если он в его дереве, и окно конфигурации. Окно не открыть заново само: нужно новое касание.
      </p>
      {ov.tainted.length === 0 ? (
        <p className={`mt-2 ${muted}`}>Пока ни один просмотренный тред не отмечен.</p>
      ) : (
        <ul className="mt-2 space-y-1 text-xs">
          {ov.tainted.map((t) => (
            <li key={t.threadId} className="break-all">
              <span className="font-mono">{t.threadId}</span> · {t.kinds.map((k) => TAINT_LABEL[k as TaintKind] ?? k).join(", ")} · {when(t.first)}{t.last !== t.first ? ` … ${when(t.last)}` : ""}
            </li>
          ))}
        </ul>
      )}
      <Fold id="taint-not-observed" className="mt-2" summaryClassName={`cursor-pointer ${muted}`} summary="Что не наблюдается (честно)">
        <ul className="mt-1 list-disc pl-5 text-xs">{NOT_OBSERVED.map((n) => <li key={n}>{n}</li>)}</ul>
        <p className={`mt-1 text-xs ${muted}`}>Источник — история событий треда в API bb. Берутся только события после открытия окна; «проект с .bb-env-setup.sh» считается всегда.</p>
      </Fold>
    </div>
  );
}

function logExtra(l: Overview["log"][number]): string {
  const d = (l.detail ?? {}) as Record<string, unknown>;
  if (l.kind === "window.taint" || l.kind === "watch.window.taint")
    return ` · окно закрыто: загрязнение (${((d.kinds as string[] | undefined) ?? []).map((k) => TAINT_LABEL[k as TaintKind] ?? k).join(", ")}); ${((d.lines as string[] | undefined) ?? []).join("; ")}`;
  if (l.kind === "trusted.add" || l.kind === "trusted.remove") return ` · ${(d.pattern as string | undefined) ?? ""}`;
  if (l.kind === "journal.alarm") return ` · цепочка нарушена: ${((d.problems as Array<{ kind: string; id: number | null }> | undefined) ?? []).map((p) => `${p.kind}${p.id ? ` #${p.id}` : ""}`).join(", ")}`;
  return "";
}

function LogCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const j = ov.journal;
  return (
    <div className={card}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className={j.ok ? "text-green-600" : "font-semibold text-destructive"}>
          {j.ok ? `Цепочка хешей цела: ${j.entries} записей, голова ${j.head ?? "—"}` : `Цепочка НАРУШЕНА (${j.problems.length}), записей ${j.entries}`}
        </p>
        <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => rpc.call("journal.verify"))}>Проверить целостность</button>
      </div>
      <p className={`text-xs ${muted}`}>
        Проверено {when(j.checkedAt)}. Каждая запись содержит хеш предыдущей; голова цепочки дополнительно лежит в файле рядом с базой, одобрение без записи в журнале — тоже тревога.
        {j.sealedLegacy > 0 ? ` ${j.sealedLegacy} записей были до цепочки: их целостность до этого момента не доказать.` : ""} Кто может писать и в базу, и в этот файл (тот же пользователь ОС, пока нет ступени 3), перепишет цепочку целиком незаметно.
      </p>
      <Msg error={act.error} />
      {ov.log.length === 0 ? <p className={muted}>Пока пусто.</p> : (
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {ov.log.map((l) => (
            <li key={l.id}>
              {when(l.ts)} · {l.kind}{l.pluginId ? ` · ${l.pluginId}` : ""}
              {l.kind === "window.freeze" ? ` · закреплена версия ${(l.detail as { pinnedVersion?: string | null } | null)?.pinnedVersion ?? "—"}` : ""}
              {l.kind === "totp.begin" ? ` · ${(l.detail as { attended?: boolean; caller?: string } | null)?.attended ? "со страницы" : "НЕ со страницы"} (${(l.detail as { caller?: string } | null)?.caller ?? "?"})` : ""}
              {l.kind === "hold" && (l.detail as { reason?: string } | null)?.reason ? ` · ${(l.detail as { reason: string }).reason}` : ""}
              {logExtra(l)}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ------------------------------------------------------- config watchdog ---

const driftStatus: Record<Drift["status"], string> = {
  open: "открыто",
  "rollback-failed": "откат не удался",
  "rolled-back": "откатано",
  "accepted-window": "принято окном",
  "accepted-touch": "принято вами",
  reverted: "вернулось",
};

function DriftRow({ d, registered, rpc, refetch }: { d: Drift; registered: boolean; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const ap = useApproval();
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const isOpen = d.status === "open" || d.status === "rollback-failed";
  const change = d.kind === "added" ? `новое: ${d.after}` : d.kind === "removed" ? `пропало (было: ${d.before})` : `${d.before} → ${d.after}`;
  return (
    <div className={`${card} ${isOpen ? "border-yellow-500/60" : ""}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{d.label}</h3>
        <span className={muted}>{driftStatus[d.status]} · {when(d.firstSeen)}</span>
      </div>
      <p className="break-all">{CATEGORY_LABEL[d.category]}: {change}</p>
      {d.note ? <p className={muted}>{d.note}</p> : null}
      {isOpen && registered ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} />
          <button className={btn} disabled={act.busy || !ap.ready(code)} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("watch.accept", { id: d.id, ...proof })); setCode(""); })}>
            Принять
          </button>
          {d.rollbackable ? (
            <button className={btn} disabled={act.busy || !ap.ready(code)} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("watch.rollback", { id: d.id, ...proof })); setCode(""); })}>
              Откатить
            </button>
          ) : (
            <span className={`text-xs ${muted}`}>безопасного отката нет</span>
          )}
        </div>
      ) : null}
      <Msg error={act.error} />
    </div>
  );
}

function WatchSection({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const w = ov.watch;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const [code, setCode] = useState("");
  const [scopes, setScopes] = useState<WindowScope[]>([]);
  const act = useCodeAction(refetch);
  const open = w.drifts.filter((d) => d.status === "open" || d.status === "rollback-failed");
  const settled = w.drifts.filter((d) => d.status !== "open" && d.status !== "rollback-failed");
  const toggle = (s: WindowScope) => setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const ap = useApproval();
  const need = code.length !== 6 || act.busy || !registered; // dangerous: a fresh code only
  const needRoutine = !ap.ready(code) || act.busy || !registered; // routine: a code or the session
  return (
    <div className="space-y-3">
      <div className={card}>
        <p>
          {w.baselineAt === null ? (
            <b>Эталон не принят: сторож только показывает, что видит, и ничего не оценивает.</b>
          ) : (
            <>Эталон принят {when(w.baselineAt)}.</>
          )}{" "}
          Проверка раз в минуту и по событиям{w.lastScanAt ? `; последняя — ${when(w.lastScanAt)}, объектов: ${w.observedCount}` : ""}.
        </p>
        <p className={`mt-1 ${muted}`}>
          Пока агенты работают от того же пользователя (ступени 0–2) и API без токенов, агент может вернуть изменение обратно: это сигнализация, не замок.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} />
          <button className={btnPrimary} disabled={needRoutine} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("watch.acceptAll", { ...proof })); setCode(""); return { note: `Эталон принят, объектов: ${r.items}` }; })}>
            {w.baselineAt === null ? "Принять текущую конфигурацию как эталон" : "Принять всё текущее как эталон"}
          </button>
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("watch.scan"); })}>
            Проверить сейчас
          </button>
        </div>
        {!registered ? <p className={`mt-2 ${muted}`}>Сначала зарегистрируйте второй фактор.</p> : null}
        <Msg error={act.error} ok={act.ok} />
      </div>

      <div className={card}>
        <h3 className="font-semibold">Откат: {w.rollbackEnabled ? "включён" : "выключен"}</h3>
        <p className={muted}>
          Откатывает только безопасное и только вне окна: выключает включённый встроенный плагин из списка, удаляет новую переменную окружения, возвращает инструкции. Остальное только показывается.
          Включить можно без кода (это ужесточение), выключить — только кодом.
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {w.rollbackEnabled ? <CodeField value={code} onChange={setCode} /> : null}
          <button className={btn} disabled={act.busy || (w.rollbackEnabled && need)} onClick={() => void act.run(async () => { await rpc.call("watch.rollbackMode", { enabled: !w.rollbackEnabled, ...(w.rollbackEnabled ? { code } : {}) }); setCode(""); })}>
            {w.rollbackEnabled ? "Выключить откат" : "Включить откат"}
          </button>
        </div>
      </div>

      <div className={card}>
        <h3 className="font-semibold">Окно доверия «конфигурация»</h3>
        <p className={muted}>
          Изменения выбранного в окне принимаются в эталон без кода; по умолчанию 10 минут, скользящее. Вход в аккаунт, потолки разрешений, настройки провайдеров, эксперименты и safe-mode окном не принимаются.
        </p>
        <div className="mt-2 flex flex-wrap gap-3">
          {WINDOW_SCOPES.map((s) => (
            <label key={s} className="flex items-center gap-1">
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggle(s)} /> {SCOPE_LABEL[s]}
            </label>
          ))}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} />
          <button className={btnPrimary} disabled={needRoutine || scopes.length === 0 || w.baselineAt === null} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("watch.window.open", { scopes, ...proof })); setCode(""); setScopes([]); })}>
            Открыть окно
          </button>
        </div>
      </div>

      <h3 className="font-semibold">Расхождения ({open.length})</h3>
      {open.length === 0 ? <div className={`${card} ${muted}`}>Открытых расхождений нет.</div> : open.map((d) => <DriftRow key={d.id} d={d} registered={registered} rpc={rpc} refetch={refetch} />)}
      {settled.length > 0 ? (
        <Fold id="watch-settled" summaryClassName={`cursor-pointer ${muted}`} summary={`Лента (${settled.length})`}>
          <div className="mt-2 space-y-2">{settled.map((d) => <DriftRow key={d.id} d={d} registered={registered} rpc={rpc} refetch={refetch} />)}</div>
        </Fold>
      ) : null}

      {w.failed.length > 0 ? (
        <div className={`${card} border-yellow-500/60`}>
          <h4 className="font-medium">Не удалось прочитать сейчас (здесь расхождения не оцениваются)</h4>
          <ul className="list-disc pl-5">{w.failed.map((f) => <li key={f.source} className="break-all"><span className="font-mono">{f.source}</span>: {f.reason}</li>)}</ul>
        </div>
      ) : null}
      {w.notApplicable.length > 0 ? (
        <div className={card}>
          <h4 className="font-medium">Не применимо (читать нечего)</h4>
          <ul className="list-disc pl-5">{w.notApplicable.map((f) => <li key={f.source} className="break-all"><span className="font-mono">{f.source}</span>: {f.reason}</li>)}</ul>
        </div>
      ) : null}
      <Fold id="watch-blind" className={card} summaryClassName="cursor-pointer font-medium" summary={`Что не наблюдается вообще (${w.blind.length})`}>
        <ul className="mt-2 list-disc pl-5">{w.blind.map((b) => <li key={b.source}>{b.reason}</li>)}</ul>
      </Fold>
    </div>
  );
}

// ----------------------------------------------------------------- skills ---

const skillState: Record<SkillQueueView["state"], string> = {
  held: "в очереди",
  alarm: "тревога",
  removed: "удалён",
  approved: "одобрен",
  gone: "исчез",
};

function SkillRow({ q, registered, rpc, refetch }: { q: SkillQueueView; registered: boolean; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const ap = useApproval();
  const [code, setCode] = useState("");
  const [ack, setAck] = useState(false);
  const [shown, setShown] = useState<Array<{ path: string; content: string | null }> | null>(null);
  const act = useCodeAction(refetch);
  const isOpen = q.state === "held" || q.state === "alarm";
  const canApprove = isOpen || q.state === "removed";
  const findings = (q.check?.findings ?? []).filter((f) => f.severity !== "info");
  return (
    <div className={`${card} ${isOpen ? (q.decision === "block" ? "border-destructive" : "border-yellow-500/60") : ""}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{q.name} <span className={`text-xs font-normal ${muted}`}>({q.scope})</span></h3>
        <span className={muted}>{skillState[q.state]} · {when(q.firstSeen)}</span>
      </div>
      <p className="break-all">
        {q.decision === "block" ? "Жёсткий признак. " : ""}{q.reason}
        {q.preexisting ? " Был до модуля скиллов: сам не удаляется." : ""}
      </p>
      {q.note ? <p className={muted}>{q.note}</p> : null}
      {findings.length > 0 ? (
        <ul className="mt-1 list-disc pl-5 text-xs">
          {findings.slice(0, 12).map((f, i) => (
            <li key={i} className="break-all">
              <b>{f.severity}</b> <span className="font-mono">{f.rule}</span> {f.file}{f.line ? `:${f.line}` : ""} — {f.excerpt}
            </li>
          ))}
        </ul>
      ) : null}
      {q.check && q.check.capabilities.length > 0 ? (
        <p className={`mt-1 text-xs ${muted}`}>Возможности скриптов: {q.check.capabilities.map((c) => `${c.kind}${c.detail.length ? ` (${c.detail.slice(0, 3).join(", ")})` : ""}`).join("; ")}</p>
      ) : null}
      {q.source ? <p className={`text-xs ${muted}`}>Источник по метке рядом со скиллом: <span className="font-mono">{q.source}</span> (метка не доказательство)</p> : null}
      {q.removed ? (
        <div className="mt-1">
          <p className={`text-xs ${muted}`}>Что было: {q.removed.map((f) => `${f.path} (${f.size})`).join(", ")}</p>
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { setShown(await rpc.call("skills.removed", { id: q.id })); })}>Показать содержимое</button>
          {shown ? <div className="mt-2 space-y-2">{shown.map((f) => <pre key={f.path} className="max-h-60 overflow-auto rounded border border-border p-2 text-xs"><b>{f.path}</b>{"\n"}{(f.content ?? "(не прочитан)").slice(0, 6000)}</pre>)}</div> : null}
        </div>
      ) : null}
      {canApprove && registered ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} dangerous={q.decision === "block"} />
          {q.decision === "block" ? <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> принимаю, несмотря на жёсткий признак</label> : null}
          <button className={btn} disabled={act.busy || !ap.ready(code, q.decision === "block") || (q.decision === "block" && !ack)} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("skills.approve", { id: q.id, ...proof, acknowledgeBlock: ack }), q.decision === "block"); setCode(""); setAck(false); return r; })}>
            {q.state === "removed" ? "Одобрить хеш (поставить снова)" : "Одобрить"}
          </button>
          {isOpen && q.removable ? <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("skills.remove", { id: q.id }); })}>Удалить скилл</button> : null}
        </div>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function SkillTrusted({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [pattern, setPattern] = useState("");
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const run = (change: { add: string } | { remove: string }) =>
    void act.run(async () => {
      const r = await rpc.call("skills.trusted", { ...change, code });
      setCode("");
      setPattern("");
      return r;
    });
  return (
    <div className={card}>
      <p>
        Доверенные источники: репозитории реестра скиллов (<span className="font-mono">owner/repo</span> или <span className="font-mono">owner/*</span>). Скилл, установленный оттуда, чистый по проверкам и не из очереди, принимается без кода. По умолчанию список пуст; менять — только с кодом. Источник определяется по метке рядом со скиллом, которую агент может подделать: проверки при этом всё равно проходят.
      </p>
      {ov.skills.trusted.length === 0 ? <p className={`mt-2 ${muted}`}>Список пуст: любой новый скилл вне окна «скиллы» ждёт вашего кода.</p> : (
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {ov.skills.trusted.map((r) => (
            <li key={r} className="flex items-center gap-2">
              {r}
              <button className={btn} disabled={act.busy || code.length !== 6 || !registered} onClick={() => run({ remove: r })}>Убрать</button>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="rounded border border-border bg-transparent px-2 py-1 font-mono text-xs" placeholder="owner/repo или owner/*" value={pattern} onChange={(e) => setPattern(e.target.value)} />
        <CodeField value={code} onChange={setCode} />
        <button className={btnPrimary} disabled={act.busy || code.length !== 6 || pattern.trim() === "" || !registered} onClick={() => run({ add: pattern })}>Добавить</button>
      </div>
      <Msg error={act.error} />
    </div>
  );
}

function SkillsSection({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const k = ov.skills;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const act = useCodeAction(refetch);
  return (
    <div className="space-y-3">
      <div className={card}>
        <p>
          {k.baselineAt === null ? <b>Первая проверка ещё не завершена: всё, что есть, будет закреплено как существовавшее до модуля.</b> : <>Закреплено хешей: {k.pinned.total} (встроенные bb: {k.pinned.builtin}, были до модуля: {k.pinned.baseline}, одобрены: {k.pinned.approved}).</>}
          {k.lastScanAt ? ` Последняя проверка — ${when(k.lastScanAt)}.` : ""}
        </p>
        <p className={`mt-1 ${muted}`}>
          Режим «после факта»: у bb нет хука установки скиллов, поэтому скилл уже работал, пока его не проверили. Жёсткий признак — скилл сразу удаляется (если bb позволяет), иначе тревога; сомнительный ждёт здесь, но остаётся установленным. Встроенные скиллы bb только закрепляются.
        </p>
        <div className="mt-2">
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("skills.scan"); })}>Проверить сейчас</button>
        </div>
        <Msg error={act.error} />
      </div>
      {k.unchecked.length > 0 ? (
        <div className={`${card} border-yellow-500/60`}>
          <h4 className="font-medium">Не удалось прочитать (проверка не проводилась, в окне не принимаются)</h4>
          <ul className="list-disc pl-5 font-mono text-xs">{k.unchecked.map((u) => <li key={u} className="break-all">{u}</li>)}</ul>
        </div>
      ) : null}
      <h3 className="font-semibold">Очередь скиллов ({k.open.length})</h3>
      {k.open.length === 0 ? <div className={`${card} ${muted}`}>Ничего не ждёт.</div> : k.open.map((q) => <SkillRow key={q.id} q={q} registered={registered} rpc={rpc} refetch={refetch} />)}
      {k.recent.length > 0 ? (
        <Fold id="skills-recent" summaryClassName={`cursor-pointer ${muted}`} summary={`Недавно рассмотренные (${k.recent.length})`}>
          <div className="mt-2 space-y-2">{k.recent.map((q) => <SkillRow key={q.id} q={q} registered={registered} rpc={rpc} refetch={refetch} />)}</div>
        </Fold>
      ) : null}
      <SkillTrusted ov={ov} rpc={rpc} refetch={refetch} />
      <Fold id="skills-blind" className={card} summaryClassName="cursor-pointer font-medium" summary={`Что не видно в скиллах (${k.blind.length})`}>
        <ul className="mt-2 list-disc pl-5">{k.blind.map((b) => <li key={b}>{b}</li>)}</ul>
      </Fold>
    </div>
  );
}

// ------------------------------------------------------------------- guard --

/** Guard mode: is the guard there, is its journal sound, what it has recorded lately. */
// --------------------------------------------------------- agents: configurations and memory --
// Guard mode. The guard reads the agents' files (settings, rules, memory, MCP) and compares them with the baseline a human accepted;
// this page is its feed. A critical difference has already closed the windows of trust and marked the thread of its working
// directory polluted (v1: a signal, not a block). Accepting is a touch at the guard: a code or a passkey signature over exactly these ids.
const CLASS_LABEL: Record<string, string> = { critical: "критично", instructions: "инструкции", other: "прочее" };
const CLASS_STYLE: Record<string, string> = {
  critical: "border-red-600 bg-red-50 text-red-950 dark:border-red-500 dark:bg-red-950/40 dark:text-red-100",
  instructions: "border-yellow-500/70",
  other: "border-border",
};
/** What an alarm of the watch says: no access, or a link / a swap that led out of what is watched (nothing was read then). */
const alarmText = (x: { kind: string; error: string }): string => (x.kind === "unreadable" ? `нет доступа (${x.error})` : x.kind === "outside" ? `ссылка ведёт за пределы наблюдаемого — ${x.error}` : `подмена во время чтения — ${x.error}`);
const CHANGE_LABEL: Record<string, string> = { added: "новый файл", changed: "изменён", removed: "удалён" };
const SEVERITY_STYLE: Record<string, string> = { block: "font-semibold text-red-700 dark:text-red-400", review: "text-yellow-700 dark:text-yellow-400", info: muted };

/** The alarms of the watch: always on top of the page, not only in its section. */
function AgentsAlarm({ ov, onShow }: { ov: Overview; onShow: () => void }) {
  const a = ov.agents?.state;
  if (!ov.agents) return null;
  const alarms = a?.alarms ?? [];
  const critical = (a?.drifts ?? []).filter((d) => d.class === "critical" && !d.initial);
  if (ov.agents.error && !a)
    return (
      <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
        <p className="font-semibold">Наблюдатель за конфигурациями агентов не отвечает</p>
        <p className="mt-1 text-xs">{ov.agents.error}</p>
      </div>
    );
  if (alarms.length === 0 && critical.length === 0) return null;
  return (
    <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
      {alarms.length > 0 ? (
        <>
          <p className="font-semibold">ТРЕВОГА: защита не может прочитать файлы агентов ({alarms.length})</p>
          <ul className="mt-1 list-disc pl-5 text-xs">{alarms.slice(0, 5).map((x) => <li key={x.path} className="break-all">{x.path} — {alarmText(x)}</li>)}</ul>
          <p className="mt-1 text-xs">Так выглядит снятый ACL на каталоге агентов (его может снять владелец файлов — агент) или сломанные права. Пока доступа нет, наблюдатель слепой: изменения в этих путях никто не видит.</p>
        </>
      ) : null}
      {critical.length > 0 ? (
        <button type="button" className="block w-full text-left" onClick={onShow} data-secure-bb-agents-link>
          <p className="font-semibold underline">Критичные изменения в настройках агентов: {critical.length}</p>
          <p className="mt-1 text-xs">Это файлы с настройками ваших ИИ-агентов: что им разрешено делать без вопросов и какие инструменты подключены. Кто-то (или что-то) их поменял. Пока вы не разобрали, доверие к новым версиям плагинов приостановлено. Нажмите — раздел «Агенты: конфигурации и память» ниже: каждое изменение разбирается отдельно.</p>
        </button>
      ) : null}
    </div>
  );
}

function DriftCard({ d, picked, onPick, threads, marked, accept }: { d: AgentDrift; picked: boolean; onPick: (on: boolean) => void; threads: string[]; marked: boolean; accept: ReactNode }) {
  const critical = isCriticalDrift(d);
  return (
    <div className={`rounded-lg border-2 p-3 text-sm ${CLASS_STYLE[d.class] ?? "border-border"}`} data-agent-drift={d.id}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        {critical ? (
          <span className="min-w-0 break-all font-semibold">{d.rel}</span>
        ) : (
          <label className="flex min-w-0 items-baseline gap-2">
            <input type="checkbox" checked={picked} onChange={(e) => onPick(e.target.checked)} aria-label={`выбрать ${d.rel}`} />
            <span className="break-all font-semibold">{d.rel}</span>
          </label>
        )}
        <span className={critical ? "font-semibold" : muted}>
          {CLASS_LABEL[d.class] ?? d.class} · {CHANGE_LABEL[d.change] ?? d.change}
          {d.initial ? " · первый просмотр" : ""} · {when(d.firstSeen)}
        </span>
      </div>
      <p className={`break-all text-xs ${muted}`}>
        {d.rootKind === "global" ? "домашний каталог агентов" : `рабочий каталог ${d.rootName}`} · {d.path}
        {threads.length > 0 ? ` · ${threads.length > 1 ? "чаты" : "чат"}: ${threads.join(", ")}` : ""}
      </p>
      {marked ? <p className="mt-1 text-xs font-semibold">Чат помечен «под подозрением»: временное доверие в нём и в его вложенных чатах закрыто.</p> : null}
      {d.reasons.length > 0 ? <ul className="mt-1 list-disc pl-5">{criticalMeanings(d.reasons).map((r, i) => <li key={i}><Rich text={r} /></li>)}</ul> : null}
      {d.findings.length > 0 ? (
        <ul className="mt-1 space-y-0.5 text-xs">
          {d.findings.slice(0, 12).map((f, i) => (
            <li key={i} className={SEVERITY_STYLE[f.severity] ?? ""}>
              {f.severity === "block" ? "⛔ " : ""}{f.rule}{f.line > 0 ? `, строка ${f.line}` : ""}: <span className="break-all font-mono">{f.excerpt}</span>
            </li>
          ))}
        </ul>
      ) : null}
      <Fold id={`drift-${d.id}-diff`} className="mt-1" summaryClassName={`cursor-pointer ${muted}`} summary={<><abbr title="diff — построчное сравнение: что было в файле и что в нём стало" className="cursor-help underline decoration-dotted underline-offset-2">Подробнее: что именно изменилось</abbr>{d.size !== null ? ` · ${d.size} байт` : ""}</>}>
        {d.reasons.length > 0 ? <p className={`mt-1 break-all text-xs ${muted}`}>Техническое описание: {d.reasons.join("; ")}</p> : null}
        <pre className="mt-1 max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background p-2 font-mono text-xs">{d.diff}</pre>
      </Fold>
      {accept}
    </div>
  );
}

/** One critical difference: what accepting it lets the agent do, and its own fresh touch (a session does not cover it, and neither does a pack). */
function CriticalAccept({ d, ov, rpc, refetch, canCode, pk }: { d: AgentDrift; ov: Overview; rpc: Rpc; refetch: () => void; canCode: boolean; pk: PasskeyState }) {
  const [code, setCode] = useDraftCode(`drift:${d.id}`);
  const ap = useApproval();
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const title = criticalAcceptTitle(d.reasons);
  const restorable = d.restorable?.ok === true ? d.restorable : null;
  // «Вернуть как было»: the guard writes its own approved copy back through its helper; the touch is for exactly this difference.
  const restore = (by: "passkey" | "code") =>
    void act.run(async () => {
      setTouching(null);
      if (by === "passkey") {
        const t = await touchFor(rpc, { kind: "agents.restore", ids: [d.id] }, setTouching);
        if (!t) throw new Error("касание не требуется");
        const r = await rpc.call("agents.restore", { id: d.id, passkey: t.passkey });
        setTouching(null);
        return r;
      }
      const r = await rpc.call("agents.restore", { id: d.id, code });
      setCode("");
      return r;
    }, "Готово: настройки агента возвращены, тревога снята");
  const accept = (by: "passkey" | "code") =>
    void act.run(async () => {
      setTouching(null);
      if (by === "passkey") {
        const t = await touchFor(rpc, { kind: "agents.accept", ids: [d.id] }, setTouching);
        if (!t) throw new Error("касание не требуется");
        const r = await rpc.call("agents.accept", { ids: [d.id], passkey: t.passkey });
        setTouching(null);
        return { note: `${r.note}. Сторож описал действие так: «${t.description}».` };
      }
      const r = await rpc.call("agents.accept", { ids: [d.id], code });
      setCode("");
      return r;
    }, `принято изменение в ${d.rel}`);
  const reject = () =>
    void act.run(async () => {
      const r = await rpc.call("agents.reject", { ids: [d.id] });
      return { note: r.note };
    }, `отклонено изменение в ${d.rel}: тревога остаётся, пока файл не исправят`);
  const acceptControls = (
    <>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {pk.has ? <button className={btnDanger} disabled={act.busy || pk.problem !== null} onClick={() => accept("passkey")}>Принять только это: касанием</button> : null}
        {canCode ? (
          <>
            {pk.has ? <span className={muted}>запасной путь — код:</span> : null}
            <CodeField value={code} onChange={setCode} />
            <button className={btnDanger} disabled={act.busy || code.length !== 6} onClick={() => accept("code")}>Принять только это{pk.has ? " кодом" : ""}</button>
          </>
        ) : null}
        <CodeHint ov={ov} />
      </div>
      <p className={`mt-1 text-xs ${muted}`}>Нужен свежий {pk.has ? "код или касание" : "код"} именно на это изменение: сессия и «выбрать все» его не принимают.</p>
    </>
  );
  const stop = ov.agents?.stop;
  return (
    <div className="mt-2 rounded-md border border-red-400 p-2 dark:border-red-700" data-agent-critical-accept={d.id}>
      <p className="font-semibold text-red-800 dark:text-red-300"><Rich text={title} /></p>
      {d.rejected ? <p className="mt-1 text-xs">Вы отклонили это изменение{d.rejectedAt ? ` (${clockText(d.rejectedAt, Date.now())}, кнопкой «Это не я»)` : ""}: в одобренные настройки оно не попало. Но в самом файле оно всё ещё есть, поэтому тревога и пометка «под подозрением» остаются.</p> : null}
      {restorable ? (
        <div className="mt-2" data-agent-restore={d.id}>
          <p>Агент работает с этим изменением прямо сейчас. {restorable.action === "delete" ? "Этого файла в одобренных настройках не было — он будет удалён." : restorable.action === "json" ? "В общем файле настроек агента будут возвращены только списки MCP-серверов, как вы их одобряли; всё остальное в файле останется как есть." : "Файл будет записан в том виде, в каком вы его одобряли."} После этого защита сама перечитает файл и снимет тревогу.</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {pk.has ? <button className={btnPrimary} disabled={act.busy || pk.problem !== null} onClick={() => restore("passkey")}>Вернуть как было — касанием</button> : null}
            {canCode ? (
              <>
                {pk.has ? <span className={muted}>запасной путь — код:</span> : null}
                <CodeField value={code} onChange={setCode} />
                <button className={pk.has ? btn : btnPrimary} disabled={act.busy || code.length !== 6} onClick={() => restore("code")}>Вернуть как было{pk.has ? " кодом" : ""}</button>
              </>
            ) : null}
            <CodeHint ov={ov} />
          </div>
          {restoreNote(ap.session !== null) ? <p className="mt-1 text-xs font-semibold" data-agent-restore-fresh={d.id}>{restoreNote(ap.session !== null)}</p> : null}
        </div>
      ) : (
        <p className="mt-2 text-xs" data-agent-no-restore={d.id}>Автоматически вернуть этот файл нельзя{d.restorable && !d.restorable.ok ? `: ${d.restorable.reason}` : ""}</p>
      )}
      <StopAgents rpc={rpc} refetch={refetch} stop={stop} />
      <Fold id={`drift-${d.id}-more`} className="mt-2" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Подробнее">
        <p className="mt-1 text-xs">Вручную: {manualRollback(d.path, d.reasons)}</p>
        {d.rejected ? null : (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button className={btn} disabled={act.busy} onClick={reject} title="Ничего не принимается и не удаляется: изменение помечается как чужое, тревога остаётся, пока файл не исправят. Код не нужен.">Это не я — отклонить</button>
            <span className={`text-xs ${muted}`}>Отклонить — без кода: оно не станет «нормой», тревога останется, файл не изменится.</span>
          </div>
        )}
        <Fold id={`drift-${d.id}-late-accept`} className="mt-2" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Это всё-таки вы? Принять изменение как есть">
          {acceptControls}
        </Fold>
      </Fold>
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} reserve />
    </div>
  );
}

/** «Остановить агентов»: no code (a tightening). Says what was done, and honestly what cannot be held. */
function StopAgents({ rpc, refetch, stop }: { rpc: Rpc; refetch: () => void; stop: NonNullable<Overview["agents"]>["stop"] }) {
  const act = useCodeAction(refetch);
  const stopped = stop?.stoppedAt != null;
  return (
    <div className="mt-2" data-agents-stop>
      <div className="flex flex-wrap items-center gap-2">
        <button className={btnDanger} disabled={act.busy} onClick={() => void act.run(async () => rpc.call("agents.stop", null))} title="Останавливает все работающие чаты. Код не нужен.">Остановить агентов</button>
        <span className={`text-xs ${muted}`}>сразу, без кода</span>
      </div>
      {stopped ? (
        <p className="mt-1 text-xs font-semibold">
          Агенты остановлены{stop?.stoppedAt ? ` (${clockText(stop.stoppedAt, Date.now())})` : ""}. Пока настройки не исправлены, лучше не запускать их снова.
          {stop?.holdAvailable ? " Новые сообщения агентам держатся, пока тревога не снята." : " Но удержать новые сообщения этот bb не позволяет: агенты могут быть запущены снова."}
        </p>
      ) : stop && !stop.holdAvailable ? (
        <p className={`mt-1 text-xs ${muted}`}>Этот bb не умеет удерживать новые сообщения: после остановки агентов их можно запустить снова.</p>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function AgentsSection({ ov, rpc, refetch, showDone }: { ov: Overview; rpc: Rpc; refetch: () => void; showDone: boolean }) {
  const ag = ov.agents;
  const [pickedIds, setPickedIds] = useSticky<number[]>("agents-picked", []);
  const [code, setCode] = useState("");
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const pk = usePasskey(ov);
  if (!ag) return <div className={`${card} ${muted}`}>Наблюдатель работает внутри сторожа решений; здесь его нет (режим сторожа выключен).</div>;
  const st = ag.state;
  if (!st) return <div className={card}><Msg error={ag.error ?? "сторож не ответил"} /></div>;
  if (!st.enabled) return <div className={`${card} ${muted}`}>Сторож запущен без наблюдателя (нет каталога агентов в его настройках).</div>;
  const drifts = st.drifts ?? [];
  const pending = st.initial?.pending ?? 0;
  const firstBaseline = pending > 0 && pending === drifts.length && (st.baselineFiles ?? 0) === 0;
  // The selection keeps what is still there and is not critical; a refresh itself neither adds nor removes anything.
  const chosen = reconcileSelection(pickedIds, drifts);
  const toggle = (id: number, on: boolean) => setPickedIds((p) => toggleId(reconcileSelection(p, drifts), id, on));
  const criticalCount = drifts.filter(isCriticalDrift).length;
  const plain = selectableDriftIds(drifts);
  const accept = (ids: number[], by: "passkey" | "code") =>
    void act.run(async () => {
      const problem = agentAcceptProblem(ids, drifts);
      if (problem) throw new Error(problem);
      setTouching(null);
      if (by === "passkey") {
        const t = await touchFor(rpc, { kind: "agents.accept", ids }, setTouching);
        if (!t) throw new Error("касание не требуется");
        const r = await rpc.call("agents.accept", { ids, passkey: t.passkey });
        setTouching(null);
        setPickedIds([]);
        return { note: `${r.note}. Сторож описал действие так: «${t.description}» (точное действие записано в его журнале).` };
      }
      const r = await rpc.call("agents.accept", { ids, code });
      setCode("");
      setPickedIds([]);
      return r;
    }, ids.length === 1 ? "принято одно изменение" : `приняты изменения: ${ids.length}`);
  const canCode = !pk.keyOnly;
  const buttons = (ids: number[], label: string) =>
    ids.length === 0 ? null : (
      <div className="flex flex-wrap items-center gap-2">
        {pk.has ? (
          <button className={btnPrimary} disabled={act.busy || pk.problem !== null} onClick={() => accept(ids, "passkey")}>
            {label} касанием
          </button>
        ) : null}
        {canCode ? (
          <>
            {pk.has ? <span className={muted}>запасной путь — код:</span> : null}
            <CodeField value={code} onChange={setCode} />
            <button className={pk.has ? btn : btnPrimary} disabled={act.busy || code.length !== 6} onClick={() => accept(ids, "code")}>
              {label}{pk.has ? " кодом" : ""}
            </button>
          </>
        ) : null}
        <CodeHint ov={ov} />
      </div>
    );
  return (
    <div className="space-y-3">
      <div className={`${card} space-y-1`}>
        <p>
          Защита следит за настройками, правилами и памятью агентов и сравнивает их с теми, что вы одобрили. Просмотрено файлов: {st.scannedFiles ?? 0}
          {st.lastScanAt ? `, последний просмотр ${when(st.lastScanAt)}` : ""}.
        </p>
        <Fold id="agents-more" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Подробнее">
          <p className={`mt-1 text-xs ${muted}`}>
            Одобренных файлов: {st.baselineFiles ?? 0}; каталогов-корней: {st.roots ?? 0}. Рабочие каталоги чатов защита находит сама; каталоги проектов в домашней папке в v1 не просматриваются. Критичное изменение закрывает временное доверие и помечает чат «под подозрением»; в его карточке есть кнопки «Вернуть как было» и «Остановить агентов».
          </p>
        </Fold>
        <div className="flex flex-wrap items-center gap-2">
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("agents.scan", null); })}>Просмотреть сейчас</button>
          <span className={`text-xs ${muted}`}>не чаще раза в 10 с</span>
        </div>
      </div>
      {ag.error ? <Msg error={`Защита не ответила на последний запрос: ${humanError(ag.error)}`} /> : null}
      {(st.alarms ?? []).length > 0 ? (
        <div className={cardBlocked} role="alert">
          <p className="font-semibold">Файлы агентов не читаются ({st.alarms!.length})</p>
          <ul className="mt-1 list-disc pl-5 text-xs">{st.alarms!.map((x) => <li key={x.path} className="break-all">{x.path} — {alarmText(x)}</li>)}</ul>
          <p className="mt-1 text-xs">Либо ACL чтения для пользователя сторожа снят или права сломаны, либо агент подсунул ссылку или подменил файл (сторож по ссылкам за пределы наблюдаемого не ходит и ничего оттуда не читает) (установщик выдаёт его, `--undo` снимает). Без него наблюдатель слепой.</p>
        </div>
      ) : null}
      {(st.notes ?? []).length > 0 ? (
        <ul className={`list-disc pl-5 text-xs ${muted}`}>{st.notes!.map((n, i) => <li key={i} className="break-all">{n.text}</li>)}</ul>
      ) : null}
      {firstBaseline ? (
        <div className={`${card} space-y-2 border-yellow-500/70`}>
          <h3 className="font-semibold">Первые одобренные настройки</h3>
          <p>Первый просмотр нашёл {pending} файлов. Если всё это — как должно быть, примите их как есть одним касанием; дальше каждое расхождение будет ждать решения.{criticalCount > 0 ? ` Критичных среди них ${criticalCount}: каждое принимается отдельно, ниже, со своим касанием и своим объяснением, что именно вы разрешаете.` : ""}</p>
          {buttons(plain, "Принять всё как есть")}
        </div>
      ) : null}
      {drifts.length === 0 ? <div className={`${card} ${muted}`}>Расхождений с одобренными настройками нет.</div> : null}
      {drifts.map((d) => (
        <DriftCard key={d.id} d={d} picked={chosen.includes(d.id)} onPick={(on) => toggle(d.id, on)} threads={ag.threads[d.root] ?? []} marked={(ag.threads[d.root] ?? []).some((t) => ag.marked[t]?.includes(d.id))} accept={isCriticalDrift(d) ? <CriticalAccept d={d} ov={ov} rpc={rpc} refetch={refetch} canCode={canCode} pk={pk} /> : null} />
      ))}
      {plain.length > 0 && !firstBaseline ? (
        <div className={`${card} space-y-2`}>
          <div className="flex flex-wrap items-center gap-2">
            <button className={btn} onClick={() => setPickedIds(plain)}>Выбрать все ({plain.length}){criticalCount > 0 ? ", кроме критичных" : ""}</button>
            <button className={btn} onClick={() => setPickedIds([])}>Снять выбор</button>
            <span className={muted}>выбрано: {chosen.length}{(st.openTotal ?? 0) > drifts.length ? ` (показаны первые ${drifts.length} из ${st.openTotal})` : ""}</span>
          </div>
          {buttons(chosen, "Принять выбранные")}
          <p className={`text-xs ${muted}`}>Критичные изменения ({criticalCount}) в «выбрать все» не входят: у каждого свой блок с кнопкой выше. «Оставить» — ничего не нажимать: расхождение видно, пока его не примут или пока файл не вернут как был.</p>
        </div>
      ) : null}
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} reserve />
      {(st.recent ?? []).length > 0 ? (
        <Fold id="agents-recent" summaryClassName={`cursor-pointer ${muted}`} summary={`Недавно закрытые (${st.recent!.length})`}>
          <ul className="mt-1 space-y-1 text-xs">
            {st.recent!.map((d) => (
              <li key={d.id} className="break-all">
                <span className="font-mono">{d.rel}</span> · {CLASS_LABEL[d.class] ?? d.class} · {d.status === "accepted" ? "принято вами" : d.status === "reverted" ? "файл вернули как был" : "заменено более новым изменением"}{d.resolvedAt ? ` ${clockText(d.resolvedAt, Date.now())}` : ""}
              </li>
            ))}
          </ul>
        </Fold>
      ) : null}
    </div>
  );
}

function GuardAlarm({ ov }: { ov: Overview }) {
  const g = ov.guard;
  if (!g) return null;
  if (!g.connected)
    return (
      <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
        <p className="font-semibold">Защита решений не отвечает</p>
        <p className="mt-1 text-xs">Ядро держит всё не встроенное: новые плагины не загрузятся, уже загруженные работают. Одобрить сейчас ничего нельзя. Проверьте службу защиты (<span className="font-mono">sbb-guard status</span> на машине). {g.error}</p>
      </div>
    );
  if (g.journal && !g.journal.valid)
    return (
      <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
        <p className="font-semibold">ТРЕВОГА: журнал защиты повреждён</p>
        <ul className="mt-1 list-disc pl-5 text-xs">{g.journal.problems.slice(0, 5).map((p, i) => <li key={i}>{p.detail}</li>)}</ul>
        <p className="mt-1 text-xs">Файлы защиты изменены не ею. Всё, что она «одобрила» до этого места, нельзя считать надёжным.</p>
      </div>
    );
  return null;
}

/** Registering a key: the token comes from the console of the machine where the guard runs; the key is not active until it is confirmed there. */
function PasskeyCard({ ov, rpc, refetch, enrollToken }: { ov: Overview; rpc: Rpc; refetch: () => void; enrollToken: string | null }) {
  const pk = ov.guard?.passkey ?? null;
  // The token from the link `sbb-guard setup` printed (#enroll=…) is already in the field; it is sent to the guard (passkey.register) and nowhere else.
  const [token, setToken] = useState(enrollToken ?? "");
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const state = usePasskey(ov);
  if (!pk) return null;
  // «Проверить касание»: the touch `sbb-guard setup` waits for. The guard describes it, the key signs it, the guard writes it into its journal. Nothing is approved.
  const check = () =>
    void act.run(async () => {
      const t = await touchFor(rpc, { kind: "touch", purpose: "setup-check" }, setTouching);
      if (!t) throw new Error("сторож не попросил касания");
      await rpc.call("setup-check", { passkey: t.passkey } as never);
      setTouching(null);
      return { note: "Касание сработало. Ничего не одобрено и не изменено: сторож только записал проверку в журнал." };
    });
  const add = () =>
    void act.run(async () => {
      const first = await rpc.call("passkey.register", { token });
      const options = first.options as CreationOptions | undefined;
      if (!options) throw new Error("сторож не выдал параметры регистрации");
      const made = await createCredential(options, navigator.credentials as never, window.location.origin, pk.origin);
      const done = await rpc.call("passkey.register", { token, ...made });
      setToken("");
      return { note: typeof done.note === "string" ? done.note : "Ключ зарегистрирован; подтвердите его на консоли (y)." };
    });
  return (
    <div className={card}>
      <h3 className="font-semibold">Passkey (касание вместо кода)</h3>
      <p className={`mt-1 ${muted}`}>
        Подпись привязана к действию, которое описал сторож, и годится один раз: код, который прошёл через процесс bb, мог перехватить плагин, подпись — нет.
        Ключи: {pk.keys.length === 0 ? "нет" : pk.keys.map((k) => `${k.label} — хранится: ${aaguidName(k.aaguid)}${k.lastUsedAt ? ` (последний раз ${when(k.lastUsedAt)})` : ""}`).join("; ")}.
        {pk.totpOff ? " Коды (TOTP) у сторожа выключены: подтверждает только ключ." : " Код остаётся запасным путём."}
      </p>
      {pk.keys.some((k) => isPasswordManager(aaguidName(k.aaguid))) ? <p className="mt-2 text-yellow-700 dark:text-yellow-400">Ключ сохранён в менеджере паролей, а не в системе. Его расширение в браузере может перехватить запрос на касание: если «ничего не происходит», посмотрите его окно.</p> : null}
      {state.problem ? <p className="mt-2 text-destructive">{state.problem}</p> : null}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="w-52 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm" placeholder="XXXX-XXXX-XXXX" aria-label="Токен с консоли сторожа" value={token} onChange={(e) => setToken(e.target.value.slice(0, 40))} />
        <button className={btn} disabled={act.busy || token.trim() === "" || state.problem !== null || !pk.enrollmentOpen} onClick={add}>
          Добавить passkey
        </button>
        {pk.enrollmentOpen ? null : <span className={muted}>Окно регистрации закрыто: на консоли сторожа выполните <span className="font-mono">sbb-guard setup</span> (или <span className="font-mono">passkey-enroll</span>): 5 минут, одноразовый токен.</span>}
      </div>
      {enrollToken !== null && token === enrollToken ? <p className={`mt-1 ${muted}`}>Токен подставлен из ссылки консоли. Нажмите «Добавить passkey» и приложите палец.</p> : null}
      {pk.keys.length > 0 ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button className={btn} disabled={act.busy || state.problem !== null} onClick={check}>Проверить касание</button>
          <span className={muted}>Проверка ничего не одобряет: в журнал сторожа ложится только запись «касание сработало».</span>
        </div>
      ) : null}
      <TouchNote text={touching} />
      <p className={`mt-1 ${muted}`}>Ключ заработает только после подтверждения <span className="font-mono">y</span> на консоли: так вредный плагин не сможет зарегистрировать свой ключ раньше вас. Список и удаление ключей — только консоль (<span className="font-mono">passkey-list</span>, <span className="font-mono">passkey-remove</span>).</p>
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

/** The guard's own words for why a version passed by itself (journal record `approved.source`). */
const whyOf = (detail: unknown): string | null => {
  const why = (detail as { why?: unknown } | null)?.why;
  return typeof why === "string" ? why : null;
};

const MODE_RANK_UI = { simple: 0, detailed: 1, strict: 2 } as const;

/** Trust by source and rights: the mode and "my sources". Both are the guard's; the guard checks every touch itself. */
function TrustCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const t = ov.guard?.trust ?? null;
  const [entry, setEntry] = useState("");
  const [code, setCode] = useState("");
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const pk = usePasskey(ov);
  if (!t) return <div className={card}><p className={muted}>Этот сторож не знает «доверия по источнику» (старая версия): версии проходят только по одобрению или окну.</p></div>;
  /** Runs one action that may take a touch: a key if there is one and no code was typed, else the code. A narrowing needs none (the guard says so). */
  const touch = (query: Record<string, unknown>, send: (proof: { code?: string; passkey?: PasskeyAssertion }) => Promise<unknown>) =>
    void act.run(async () => {
      const k = pk.has && code.length !== 6 ? await touchFor(rpc, query, setTouching) : null;
      await send(k ? { passkey: k.passkey } : code.length === 6 ? { code } : {});
      setCode("");
      setTouching(null);
      if (k) return { note: `Сохранено касанием. Сторож описал действие так: «${k.description}».` };
      return code.length === 6 ? undefined : { note: SAVED_NARROWING };
    });
  const mine = t.mySources;
  const oldRepos = ov.trustedRepos.map((r) => `github:${r}`).filter((r) => !mine.includes(r));
  return (
    <div className={card}>
      <h3 className="font-semibold">Доверие по источнику и правам</h3>
      <p className={muted}>
        Новая версия плагина проходит сама, только если её источник «свой» (список ниже) или «известный» (официальный каталог, который назвал владелец сторожу), у плагина есть одобренная версия из того же источника, <b>права не выросли</b> и жёстких флагов нет. Права сторож считает сам, по каталогу плагина; слова плагина о себе не учитываются. Остальное идёт в очередь.
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <span>Режим:</span>
        {(["simple", "detailed", "strict"] as const).map((m) => (
          <button key={m} className={m === t.mode ? btnPrimary : btn} disabled={act.busy || m === t.mode || (MODE_RANK_UI[m] < MODE_RANK_UI[t.mode] && pk.has && pk.keyOnly && pk.problem !== null)} onClick={() => touch({ kind: "trust.mode", trustMode: m }, (proof) => rpc.call("trust.mode", { mode: m, ...proof } as never))}>
            {MODE_NAMES[m]}
          </button>
        ))}
        <span className={muted}>{MODE_DESCRIPTIONS[t.mode]}</span>
      </div>
      <p className={`mt-1 ${muted}`}>Усилить режим — без касания; ослабить — касанием или кодом.</p>
      <h4 className="mt-3 font-medium">Мои источники ({mine.length})</h4>
      {mine.length === 0 ? <p className={muted}>Список пуст: ничего не проходит само (кроме окон доверия и одобренных версий).</p> : (
        <ul className="mt-1 space-y-1 font-mono text-xs">
          {mine.map((e) => (
            <li key={e} className="flex items-center gap-2">
              {e}
              <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("trust.remove", { entry: e } as never); return { note: SAVED_NARROWING }; })}>Убрать</button>
            </li>
          ))}
        </ul>
      )}
      <p className={`mt-1 ${muted}`}>Убрать — без касания. Уже одобренные версии остаются одобренными; следующие версии из этого источника сторож спросит.</p>
      {t.known.length > 0 ? <p className={`mt-2 ${muted}`}>Известные источники (названы при запуске сторожа): <span className="font-mono">{t.known.join(", ")}</span></p> : null}
      {t.pluginsRoots === 0 ? <p className="mt-2 text-destructive">У сторожа не задан каталог плагинов ядра (<span className="font-mono">--plugins-root</span>): плагины из git сами не пройдут. Плагины с диска (<span className="font-mono">path:</span>) читаются по своему пути.</p> : null}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="rounded border border-border bg-transparent px-2 py-1 font-mono text-xs" placeholder="owner/name, owner/* или path:/каталог" value={entry} onChange={(e) => setEntry(e.target.value)} />
        {pk.has ? <span className={muted}>касание или код:</span> : null}
        {pk.keyOnly ? null : <CodeField value={code} onChange={setCode} />}
        <button className={btnPrimary} disabled={act.busy || entry.trim() === "" || (!pk.has && code.length !== 6)} onClick={() => touch({ kind: "trust.add", entries: [entry.trim()] }, (proof) => rpc.call("trust.add", { entries: [entry.trim()], ...proof } as never).then(() => setEntry("")))}>
          Добавить (касание)
        </button>
        {oldRepos.length > 0 ? (
          <button className={btn} disabled={act.busy || (!pk.has && code.length !== 6)} onClick={() => touch({ kind: "trust.migrate" }, (proof) => rpc.call("trust.migrate", proof as never))}>
            Перенести из «доверенных репозиториев» ({oldRepos.length})
          </button>
        ) : null}
      </div>
      {pk.has && pk.problem ? <p className="mt-1 text-destructive">{pk.problem}</p> : null}
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function GuardCard({ ov, rpc, refetch, enrollToken }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void; enrollToken: string | null }) {
  const g = ov.guard;
  const act = useCodeAction(refetch);
  if (!g) return null;
  return (
    <div className="space-y-3">
      <PasskeyCard ov={ov} rpc={rpc} refetch={refetch} enrollToken={enrollToken} />
      <div className={card}>
        <p>
          Одобрения, окна доверия и секрет второго фактора — у <b>сторожа</b> (отдельный процесс и пользователь ОС). Здесь только интерфейс, проверки и «стоп по новой возможности»: этот плагин может лишь <b>добавить</b> удержание, разрешает только сторож.
        </p>
        <p className={`mt-1 ${muted}`}>
          {g.connected ? "Сторож отвечает." : "Сторож не отвечает."}
          {g.journal ? ` Журнал сторожа: ${g.journal.valid ? "цепочка цела" : "НАРУШЕН"}, записей ${g.journal.entries}, голова ${g.journal.head ?? "—"}.` : ""}
          {" "}Код, введённый здесь, проходит через процесс bb, поэтому вредный плагин мог бы его перехватить (с passkey подпись привязана к действию); после действия в журнале видно, что именно одобрено и чем.
        </p>
        <div className="mt-2">
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("guard.verify"); })}>Проверить журнал сторожа</button>
        </div>
        <Msg error={act.error} />
      </div>
      <Fold id="guard-journal" className={card} summaryClassName="cursor-pointer font-medium" summary={`Последние записи журнала сторожа (${g.recent.length})`}>
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {g.recent.map((r) => (
            <li key={r.id} className="break-all">
              #{r.id} {when(r.ts)} {r.kind}{r.pluginId ? ` ${r.pluginId}` : ""}{whyOf(r.detail) ? ` — ${whyOf(r.detail)}` : ""}{r.detail ? ` ${JSON.stringify(r.detail).slice(0, 200)}` : ""}
            </li>
          ))}
        </ul>
      </Fold>
    </div>
  );
}

/** Migration: the approvals this plugin holds, to a file that `sbb-guard import` reads on the console. Works with or without a guard. */
function MigrationCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [code, setCode] = useState("");
  const [out, setOut] = useState<{ path: string; digest: string; count: number } | null>(null);
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  return (
    <div className={card}>
      <p>Перенос одобрений этого плагина в сторож: выгрузка в файл (с кодом), затем на консоли <span className="font-mono">sudo sbb-guard import &lt;файл&gt;</span> — он покажет каждую строку и спросит подтверждение. Файл делает код внутри bb, поэтому сторож не верит ему без вашего подтверждения; сверьте контрольную сумму.</p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <CodeField value={code} onChange={setCode} />
        <button className={btn} disabled={act.busy || code.length !== 6 || !registered} onClick={() => void act.run(async () => { setOut(await rpc.call("approvals.export", { code })); setCode(""); })}>
          Выгрузить одобрения
        </button>
      </div>
      {out ? (
        <div className="mt-2 text-xs">
          <p>Выгружено одобрений: {out.count}.</p>
          <p className="break-all font-mono">{out.path}</p>
          <p className="break-all font-mono">sha256 {out.digest}</p>
          <p className="break-all font-mono">sudo sbb-guard import {out.path} --digest {out.digest}</p>
        </div>
      ) : null}
      {!registered ? <p className={`mt-1 ${muted}`}>Нужен зарегистрированный второй фактор.</p> : null}
      <Msg error={act.error} />
    </div>
  );
}

// ------------------------------------------------- UX v1 (PR 2): status, cards, quarantine ---
// What the page SHOWS and which button leads where. The decisions are the guard's: every approval here goes through the same RPC and
// the same touch as before; nothing on this part of the page can approve anything the old page could not.

const lsGet = (k: string): string | null => {
  try {
    return window.localStorage.getItem(k);
  } catch {
    return null;
  }
};
/** localStorage holds only conveniences (when "while you were away" starts, which cards were put aside): not security data. */
const lsSet = (k: string, v: string): void => {
  try {
    window.localStorage.setItem(k, v);
  } catch {
    /* a private window: the page just forgets */
  }
};

type AnyProof = { code?: string; session?: string; passkey?: PasskeyAssertion };
interface ProofHook {
  code: string;
  setCode: (v: string) => void;
  pk: PasskeyState;
  touching: string | null;
  registered: boolean;
  /** Can the action start with what is typed now? */
  ready: (o?: { routine?: boolean; dangerous?: boolean }) => boolean;
  /** Runs an action with a touch (a key, if there is one and no code typed) or a code (or a session, for a routine action). */
  run: <T>(query: TouchQuery, call: (proof: AnyProof) => Promise<T>, o?: { routine?: boolean; dangerous?: boolean }) => Promise<T>;
}
function useProof(ov: Overview, rpc: Rpc, draftKey?: string): ProofHook {
  const ap = useApproval();
  const pk = usePasskey(ov);
  const ownKey = useId();
  const [code, setCode] = useDraftCode(draftKey ?? ownKey);
  const [touching, setTouching] = useState<string | null>(null);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  // An open session covers a routine action: no touch and no code (with a key too). The dangerous kind of an action never uses it.
  const viaSession = (o: { routine?: boolean; dangerous?: boolean }): boolean => o.routine === true && o.dangerous !== true && ap.session !== null && code.length !== 6;
  const ready: ProofHook["ready"] = (o = {}) => registered && (viaSession(o) ? true : pk.has ? pk.problem === null || code.length === 6 : o.routine ? ap.ready(code, o.dangerous) : code.length === 6);
  const run: ProofHook["run"] = async (query, call, o = {}) => {
    try {
      if (viaSession(o)) return await ap.routine(code, (p) => call(p as AnyProof), o.dangerous);
      if (pk.has && code.length !== 6) {
        setTouching(null);
        const t = await touchFor(rpc, query, setTouching);
        return await call(t ? { passkey: t.passkey } : {});
      }
      if (o.routine) return await ap.routine(code, (p) => call(p as AnyProof), o.dangerous);
      return await call({ code });
    } finally {
      setCode("");
      setTouching(null);
    }
  };
  return { code, setCode, pk, touching, registered, ready, run };
}
/** The code field (when codes work), the note about what is being touched, and why a touch is impossible. */
function ProofField({ proof, routine, dangerous }: { proof: ProofHook; routine?: boolean; dangerous?: boolean }) {
  const ap = useApproval();
  return (
    <>
      {ap.session && routine && !dangerous ? <span className={`text-xs ${muted}`}>сессия открыта: {proof.pk.has ? "касание и код" : "код"} не нужен</span> : null}
      {ap.session && routine && !dangerous ? null : proof.pk.has ? <span className={muted}>касание или код:</span> : null}
      {ap.session && routine && !dangerous ? null : proof.pk.keyOnly ? null : routine && !proof.pk.has ? <RoutineCode value={proof.code} onChange={proof.setCode} dangerous={dangerous} /> : <CodeField value={proof.code} onChange={proof.setCode} />}
      {!proof.registered ? <span className={muted}>сначала зарегистрируйте второй фактор</span> : null}
      {proof.registered && !(ap.session && routine && !dangerous) ? <span className={`basis-full text-xs ${muted}`}>{proofHint({ hasKey: proof.pk.has, keyOnly: proof.pk.keyOnly })}</span> : null}
    </>
  );
}
/** Plain words next to a bare code field (outside ProofField). */
function CodeHint({ ov }: { ov: Overview }) {
  const pk = usePasskey(ov);
  return <span className={`basis-full text-xs ${muted}`}>{proofHint({ hasKey: pk.has, keyOnly: pk.keyOnly })}</span>;
}
/** What a card says a plugin can do; the word «все» (of all variables) is red. */
function Emph({ text }: { text: string }) {
  return <>{glossSegments(emphasize(text)).map((x, i) => (x.red ? <b key={i} className="text-red-700 dark:text-red-400">{x.text}</b> : x.hint ? <abbr key={i} title={x.hint} className="cursor-help underline decoration-dotted underline-offset-2">{x.text}</abbr> : <span key={i}>{x.text}</span>))}</>;
}
/** `a command in backticks` is shown as code; the words around it go through the glossary. */
function Rich({ text }: { text: string }) {
  return <>{text.split("`").map((part, i) => (i % 2 === 1 ? <code key={i} className="break-all rounded bg-muted px-1 font-mono text-xs">{part}</code> : <Emph key={i} text={part} />))}</>;
}
function ProofNotes({ proof }: { proof: ProofHook }) {
  return (
    <>
      {proof.pk.has && proof.pk.problem ? <p className="mt-1 text-destructive">{proof.pk.problem}</p> : null}
      <TouchNote text={proof.touching} />
    </>
  );
}

const statusStyle = {
  ok: "border-green-600 bg-green-50 text-green-950 dark:border-green-500 dark:bg-green-950/40 dark:text-green-100",
  attention: "border-yellow-500 bg-yellow-50 text-yellow-950 dark:border-yellow-500 dark:bg-yellow-950/40 dark:text-yellow-100",
  stopped: "border-red-600 bg-red-50 text-red-950 dark:border-red-500 dark:bg-red-950/40 dark:text-red-100",
  down: "border-red-600 bg-red-50 text-red-950 dark:border-red-500 dark:bg-red-950/40 dark:text-red-100",
} as const;
const cardYellow = "rounded-lg border-2 border-yellow-500 bg-yellow-50 p-4 text-sm text-yellow-950 dark:border-yellow-500 dark:bg-yellow-950/30 dark:text-yellow-50";

/** Troubleshooting mode of the guard (switched on at its console): everything passes, every decision is written down; red, with the time left. */
function TroubleshootBar({ until }: { until: number }) {
  const now = useNow();
  if (until <= 0 || until <= now) return null;
  const left = Math.max(0, Math.ceil((until - now) / 1000));
  const mmss = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  return (
    <div className="rounded-lg border-2 border-red-600 bg-red-600 p-4 text-white" role="alert" data-secure-bb-troubleshoot>
      <p className="text-lg font-semibold">Режим отладки: защита снята, осталось {mmss}</p>
      <p className="text-sm">Защита пропускает всё и пишет каждое решение в журнал. Она вернётся сама; раньше — командой «sbb-guard troubleshoot off» на этой машине. Не ставьте и не обновляйте ничего лишнего, пока плашка видна.</p>
    </div>
  );
}

function StatusBar({ level, label, text, onShow }: { level: keyof typeof statusStyle; label: string; text: string | null; onShow: (() => void) | null }) {
  return (
    <div className={`flex flex-wrap items-center gap-3 rounded-lg border-2 p-4 ${statusStyle[level]}`} role="status" data-secure-bb-status={level}>
      <span aria-hidden className={`size-4 shrink-0 rounded-full ${level === "ok" ? "bg-green-600" : level === "attention" ? "bg-yellow-500" : "bg-red-600"}`} />
      <div className="min-w-0 flex-1">
        <p className="text-lg font-semibold">{label}</p>
        {text ? <p className="text-sm">{text}</p> : null}
      </div>
      {onShow ? <button className={btnPrimary} onClick={onShow}>Показать</button> : null}
    </div>
  );
}

/** «откуда»: thread → subthread (links), then the source in words. */
function Origin({ ux, q }: { ux: QueueUx | undefined; q: QueueRow }) {
  const nav = useBbNavigate();
  const chain = ux?.chain ?? [];
  return (
    <p className={`mt-1 break-words ${muted}`}>
      Откуда:{" "}
      {chain.map((t, i) => (
        <span key={t.id}>
          {i > 0 ? " → " : ""}
          <button type="button" className="underline hover:no-underline" onClick={() => nav.toThread(t.id)}>{t.title ?? `чат ${t.id}`}</button>
        </span>
      ))}
      {chain.length > 0 ? " · " : ""}
      {ux?.sourceLabel ?? q.source}
      {ux ? ` (${ux.level === "own" ? "ваш источник" : ux.level === "known" ? "известный источник" : "неизвестный источник"})` : ""}
    </p>
  );
}

/** What the author says of the plugin's purpose (`secureBb.why`): shown in italics and marked as unchecked. */
function AuthorWhy({ why }: { why: string | null | undefined }) {
  if (!why) return null;
  return (
    <p className="mt-1">
      <em>«{why}»</em> <span className={`text-xs ${muted}`}>— со слов автора, не проверено</span>
    </p>
  );
}

interface ReviewProps {
  q: QueueRow;
  /** The card is the one of its plugin in the list (a resolved one leaves a stub of the same height); the older versions folded under it are not. */
  slotted?: boolean;
  /** Came after the page was opened. */
  fresh?: boolean;
  ov: Overview;
  rpc: Rpc;
  refetch: () => void;
  deferred: boolean;
  onDefer: (q: QueueRow, on: boolean) => void;
  /** «Оставить в карантине»: a decision. */
  onKeep: (q: QueueRow) => void;
  /** The version was let in but the source was not added yet (a code works once; the second touch waits for a fresh one). */
  onTrustPending: (entry: string, label: string) => void;
}

/** Yellow «Проверьте» (a new right or an unknown source) and red «Остановлено» (a hard flag). Every action on it is about THIS version, and says so. */
function ReviewCard({ q, ov, rpc, refetch, deferred, onDefer, onKeep, onTrustPending, slotted = true, fresh = false }: ReviewProps) {
  const act = useCodeAction(refetch, { pin: true, ...(slotted ? { slot: { key: q.pluginId, elId: `sbb-card-${q.id}` } } : {}) });
  const proof = useProof(ov, rpc, `card:${cardKey(q)}`);
  const [typed, setTyped] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const found = ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined);
  const ux = ov.ux[q.id];
  const detail = detailLevel(ov.guard?.trust?.mode ?? null);
  const color = cardColor({ reason: q.reason, findings: found?.findings ?? [] });
  const unsafeDir = q.reason?.startsWith("каталог доступен на запись другим") ?? false;
  const caps = capsWithPaths(found);
  const red = color === "red";
  const text = isMismatch(q.reason)
    ? mismatchText(q.pluginId, q.version)
    : red
    ? (() => {
        const r = redText((found?.findings ?? []).filter((f) => f.severity === "block").map((f) => f.rule));
        return { title: `Остановлено: ${r.title}`, line: `Плагин «${q.pluginId}» ${q.version}. ${r.line}${redWhere(caps) ? ` ${redWhere(caps)}` : ""} Плагин не запущен.` };
      })()
    : yellowText({ pluginId: q.pluginId, version: q.version, level: ux?.level ?? "unknown", sourceLabel: ux?.sourceLabel ?? q.source, reason: q.reason, caps });
  const approve = (acknowledgeBlock: boolean) =>
    proof.run({ kind: "approve", queueId: q.id, acknowledgeBlock }, (p) => rpc.call("queue.approve", { id: q.id, ...p, acknowledgeBlock } as never), { routine: true, dangerous: acknowledgeBlock });
  // A version the guard has no record of (it loaded without the guard's check): nothing here can approve it, and a green «можно включить» would be a lie.
  const noRecord = hasNoGuardRecord(q);
  const risk = noRecord ? { level: "caution" as const, text: NO_RECORD_HEADLINE } : riskHeadline(caps, (found?.findings ?? []).filter((f) => f.severity === "review").map((f) => f.rule));
  const allowedWhat = enabledWhat(q.pluginId, q.version);
  const verb = approveVerb(risk);
  const configNote = agentConfigNote(found?.findings ?? []);
  const riskClass = risk.level === "safe" ? "text-green-800 dark:text-green-300" : risk.level === "danger" ? "text-red-700 dark:text-red-400" : "text-yellow-900 dark:text-yellow-200";
  const trustEntry = ux?.entry ?? null;
  const blockedApprove = unsafeDir || !proof.ready({ routine: true });
  const win = windowAvailability({ threadId: q.threadId, queueId: q.id, sourceKind: q.sourceKind, level: ux?.level ?? "unknown" });
  const trust = trustButton({ entry: trustEntry, level: ux?.level ?? "unknown", queueId: q.id });
  const del = () =>
    void act.run(async () => {
      await rpc.call("queue.dismiss", { id: q.id });
      setConfirmDelete(false);
      return { note: deletedNote(q.pluginId, q.version) };
    }, `удалён плагин ${q.pluginId} ${q.version}`);
  return (
    <div className={red ? cardBlocked : cardYellow} id={`sbb-card-${q.id}`} data-secure-bb-card={color} data-secure-bb-version={q.version}>
      {red ? (
        <h3 className="text-base font-semibold">{text.title}{fresh ? <span className="ml-2 rounded bg-blue-600 px-1.5 py-0.5 text-xs font-medium text-white">новое</span> : null}</h3>
      ) : (
        <>
          <h3 className={`text-base font-semibold ${riskClass}`} data-secure-bb-risk={risk.level}>{risk.text}{fresh ? <span className="ml-2 rounded bg-blue-600 px-1.5 py-0.5 text-xs font-medium text-white">новое</span> : null}</h3>
          <p className={`text-xs ${muted}`}>«{q.pluginId}» {q.version}{risk.level === "safe" ? ": можно включить" : ""}</p>
        </>
      )}
      <p className="mt-1">{noRecord ? <>{NO_RECORD_LINE}{q.reason ? <> <span className={muted}>({q.reason.replace(/\.$/, "")}.)</span></> : null}</> : <Emph text={text.line} />}</p>
      {configNote && !red ? <p className="mt-1 text-xs">{configNote}</p> : null}
      <AuthorWhy why={ux?.why} />
      <Origin ux={ux} q={q} />
      {unsafeDir ? <p className="mt-1 font-semibold text-red-700 dark:text-red-400">Разрешить нельзя: в папке плагина или выше может писать кто-то кроме пользователя сервера, и после проверки файлы можно подменить. Исправьте права или предложите плагин через <span className="font-mono">bb secure-bb propose</span>.</p> : null}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {red || noRecord ? null : (
          <>
            <ProofField proof={proof} routine />
            <button className={btnPrimary} disabled={act.busy || blockedApprove} onClick={() => void act.run(async () => { await approve(false); return { note: approvedNote(q.pluginId, q.version) }; }, allowedWhat)}>
              {actionLabel(verb, q.pluginId, q.version)}
            </button>
          </>
        )}
        {confirmDelete ? (
          // The question on its own line, the two buttons under it on one line, always in the same order: «Да, удалить» does not move from card to card.
          <div className="basis-full">
            <p className="font-semibold">{deleteConfirmText(q.pluginId, q.version)}</p>
            <div className="mt-2 flex flex-nowrap items-center gap-2">
              <button className={`${btnDanger} whitespace-nowrap`} disabled={act.busy} onClick={del}>{DELETE_CONFIRM_BUTTONS[0]}</button>
              <button className={`${btn} whitespace-nowrap`} disabled={act.busy} onClick={() => setConfirmDelete(false)}>{DELETE_CONFIRM_BUTTONS[1]}</button>
            </div>
          </div>
        ) : (
          <>
            <button className={red || noRecord ? btnPrimary : btn} disabled={act.busy} onClick={() => setConfirmDelete(true)}>{noRecord ? `${NO_RECORD_FIX}: ${q.pluginId} ${q.version}` : actionLabel("Удалить", q.pluginId, q.version)}</button>
            {red ? (
              <button className={btn} disabled={act.busy} onClick={() => onKeep(q)} title="Плагин остаётся в карантине, не запущен; карточка уходит из «Ждут решения», красный статус снимается">Оставить в карантине</button>
            ) : (
              <button className={btn} disabled={act.busy} onClick={() => onDefer(q, !deferred)}>{deferred ? "Вернуть в список" : "Решить позже"}</button>
            )}
          </>
        )}
      </div>
      {red && deferred ? <p className="mt-1"><button className={btn} onClick={() => onDefer(q, false)}>Вернуть в список</button></p> : null}
      {!red ? (
        <Fold id={cardFoldId(q, "scope")} className="mt-2" summary="Подробнее: на какой срок">
          <div className="mt-2 space-y-2">
            <p className={muted}>{scopeText(q.version)} «{actionLabel(verb, q.pluginId, q.version)}» действует только на эту версию.</p>
            <div className="flex flex-wrap items-center gap-2">
              {win.available ? (
                <button className={btn} disabled={act.busy || !proof.ready({ routine: true })} onClick={() => void act.run(async () => { await proof.run({ kind: "window.open", queueId: q.id }, (p) => rpc.call("window.open", { queueId: q.id, ...p } as never), { routine: true }); })}>
                  Доверять новым версиям {ov.policy.windowMin} мин
                </button>
              ) : null}
              {trust.enabled ? <button
                className={btn}
                disabled={act.busy || blockedApprove}
                title="Одна операция: разрешить версию и добавить источник. Одно касание."
                onClick={() =>
                  void act.run(async () => {
                    const r = (await proof.run({ kind: "approve.trust", queueId: q.id }, (p) => rpc.call("queue.approveTrust", { id: q.id, ...p } as never))) as { note: string };
                    return { note: `${r.note}. Новые версии из этого источника идут без вопросов, пока плагин не попросит новых прав.` };
                  }, `${allowedWhat}, источник доверенный`)
                }
              >
                Разрешить и доверять источнику
              </button> : null}
            </div>
            <p className={muted}>{uniqueSentences([win.note ?? "Временное доверие: новые версии этого плагина из этого чата проходят без вопросов на время.", trust.note]).join(" ")}</p>
          </div>
        </Fold>
      ) : null}
      <Fold id={cardFoldId(q, "tech")} className="mt-2" defaultOpen={detail.expanded || risk.look === true} summary={red ? "Подробности" : "Технические подробности"}>
        <div className="mt-2 space-y-1">
          {red ? <p className={`text-xs ${muted}`}>{scopeText(q.version)}</p> : null}
          <p className="break-all text-xs">{q.sourceKind}: {q.source} · версия {q.version}{q.trigger ? ` · ${q.trigger}` : ""}</p>
          {q.reason ? <p className="text-xs">Причина: {q.reason}</p> : null}
          {detail.hashes && q.contentHash ? <p className="break-all font-mono text-xs">{q.contentHash}</p> : null}
          {caps.length > 0 ? <p className="text-xs">Возможности: <Emph text={caps.map((c) => capabilitySegments(c).map((x) => x.text).join("")).join("; ")} />.</p> : null}
          <ChecksView id={cardFoldId(q, "checks")} result={found} />
          <ScanResultView scan={ov.ai.queueScans[q.id]} />
          <ScanButton ov={ov} target={{ queueId: q.id }} rpc={rpc} refetch={refetch} />
          {red && bypassAllowed(ov.guard?.trust?.mode ?? null, q.reason) ? (
            <Fold id={cardFoldId(q, "bypass")} className="mt-2 rounded-md border border-red-300 p-2 dark:border-red-900" summaryClassName="cursor-pointer text-red-700 dark:text-red-400" summary="Всё равно разрешить…">
              <p className="mt-2">Так ведут себя вредоносные плагины. Разрешайте, только если вы сами написали этот плагин и знаете, почему проверки сработали. Для этого нужны касание и имя плагина.</p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <input className="w-56 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm" placeholder={q.pluginId} aria-label="Введите имя плагина" value={typed} onChange={(e) => setTyped(e.target.value)} />
                <ProofField proof={proof} routine dangerous />
                <button className={btnDanger} disabled={act.busy || typed !== q.pluginId || unsafeDir || !proof.ready({ routine: true, dangerous: true })} onClick={() => void act.run(async () => { await approve(true); setTyped(""); return { note: approvedNote(q.pluginId, q.version) }; }, allowedWhat)}>
                  Всё равно разрешить
                </button>
              </div>
            </Fold>
          ) : null}
          {red && isMismatch(q.reason) ? <p className={`mt-2 ${muted}`}>{MISMATCH_HINT}</p> : null}
          {red && !isMismatch(q.reason) && !detail.bypass ? <p className={`mt-2 ${muted}`}>В режиме «Строгий» обойти остановку нельзя. Чтобы разрешить, сначала ослабьте режим (касанием) на вкладке «Исключения и доверие».</p> : null}
        </div>
      </Fold>
      <ProofNotes proof={proof} />
    </div>
  );
}

/** A trust in a source that was asked for but not finished (the first touch let the version in; a code works once). */
function PendingTrust({ entries, ov, rpc, refetch, onDone }: { entries: Array<{ entry: string; label: string }>; ov: Overview; rpc: Rpc; refetch: () => void; onDone: (entry: string) => void }) {
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc);
  if (entries.length === 0) return null;
  return (
    <div className={card}>
      <p className="font-semibold">Осталось добавить источник</p>
      <ul className="mt-1 list-disc pl-5">
        {entries.map((e) => <li key={e.entry}>{e.label} <span className="font-mono text-xs">{e.entry}</span></li>)}
      </ul>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <ProofField proof={proof} />
        <button className={btnPrimary} disabled={act.busy || !proof.ready()} onClick={() => void act.run(async () => { await proof.run({ kind: "trust.add", entries: entries.map((e) => e.entry) }, (p) => rpc.call("trust.add", { entries: entries.map((e) => e.entry), ...p } as never)); entries.forEach((e) => onDone(e.entry)); return { note: "Источник добавлен: новые версии из него идут без вопросов, пока плагин не попросит новых прав." }; })}>
          Доверять источнику (касание)
        </button>
        <button className={btn} onClick={() => entries.forEach((e) => onDone(e.entry))}>Не нужно</button>
      </div>
      <ProofNotes proof={proof} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

/** The journal records of both journals as the summary reads them. */
function awayEventsOf(ov: Overview): AwayEvent[] {
  const threadOf = new Map<string, string>();
  for (const q of ov.queue) if (q.threadId && !threadOf.has(q.pluginId)) threadOf.set(q.pluginId, q.threadId);
  return [
    ...(ov.guard?.recent ?? []).map((r) => ({ ts: r.ts, kind: r.kind, pluginId: r.pluginId, threadId: r.pluginId ? (threadOf.get(r.pluginId) ?? null) : null, detail: r.detail, from: "guard" as const })),
    ...ov.log.map((l) => {
      const d = (l.detail ?? {}) as { thread?: unknown };
      return { ts: l.ts, kind: l.kind, pluginId: l.pluginId, threadId: typeof d.thread === "string" ? d.thread : l.pluginId ? (threadOf.get(l.pluginId) ?? null) : null, detail: l.detail, from: "plugin" as const };
    }),
  ];
}

/** The skills that wait are ONE line on the status, with a link to the list (not a card each): the list itself is in «Подробно». */
function SkillsLine({ ov, onOpen }: { ov: Overview; onOpen: () => void }) {
  const sum = skillsSummary(ov.skills.open);
  if (!sum) return null;
  return (
    <div className={`${card} flex flex-wrap items-center justify-between gap-2 ${sum.hard > 0 ? "border-yellow-500/60" : ""}`} data-secure-bb-skills-line>
      <span className={sum.hard > 0 ? "font-semibold" : ""}>{sum.text}</span>
      <button type="button" className={btn} onClick={onOpen}>Открыть список</button>
    </div>
  );
}

/** «Пока вас не было»: what the journals say happened since the last «Всё в порядке», grouped by plugin and thread. */
function AwayCard({ ov, since, onSeen, onReview, canReview, kept, alarms, onShowAlarm }: { ov: Overview; since: number; onSeen: (mark: number) => void; onReview: () => void; canReview: boolean; kept: Set<number>; alarms: ProblemRef[]; onShowAlarm: (p: ProblemRef) => void }) {
  const nav = useBbNavigate();
  const guardMode = ov.guard?.connected === true;
  const events = awayEventsOf(ov);
  const heldNow: Record<string, HeldNow> = {};
  for (const q of ov.queue) {
    // What the person has already answered (kept in quarantine) is not waiting any more.
    if (q.status !== "held" || kept.has(q.id)) continue;
    const h = (heldNow[q.pluginId] ??= { yellow: 0, red: 0 });
    if (cardColor({ reason: q.reason, findings: ov.queueChecks[q.id]?.findings ?? [] }) === "red") h.red++;
    else h.yellow++;
  }
  const groups = groupAway(awayInfoEvents(events, guardMode), since, guardMode, heldNow);
  const alarmBlock = awayAlarms(alarms);
  if (groups.length === 0 && !alarmBlock) return null;
  return (
    <div className={card} data-secure-bb-away>
      <h2 className="text-base font-semibold">Пока вас не было</h2>
      {alarmBlock ? (
        <div className="mt-2 rounded-md border border-red-400 p-2 text-red-700 dark:border-red-700 dark:text-red-400" data-secure-bb-away-alarms>
          <p className="font-semibold">{alarmBlock.title}: они остаются, пока вы не разберёте их на месте</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5">
            {alarmBlock.items.map((a, i) => (
              <li key={`${a.anchor}-${i}`}>
                {a.text} · <button type="button" className="underline hover:no-underline" onClick={() => onShowAlarm(a)}>Показать</button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <ul className="mt-2 space-y-1">
        {groups.slice(0, 12).map((g) => (
          <li key={g.key} className={g.counts.stopped + g.counts.alarm > 0 ? "font-semibold text-red-700 dark:text-red-400" : ""}>
            {g.text}
            {g.threadId ? <> · <button type="button" className="underline hover:no-underline" onClick={() => nav.toThread(g.threadId!)}>из чата</button></> : null}
          </li>
        ))}
      </ul>
      <p className={`mt-1 text-xs ${muted}`}>С {when(since)}. Показаны последние записи; более старые могли не поместиться.</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <button className={btnPrimary} title={alarmBlock ? "Скрывает только строки выше, без тревог. Тревоги остаются, пока их не разберут." : undefined} onClick={() => onSeen(awaySeenMark(events, Date.now()))}>{alarmBlock ? "Скрыть эти строки (тревоги останутся)" : AWAY_HIDE_LABEL}</button>
        {canReview ? <button className={btn} onClick={onReview}>Разобрать</button> : null}
      </div>
    </div>
  );
}

// ---- quarantine -----------------------------------------------------------------------------------------------------------

function rejectedOf(queue: QueueRow[]): QueueRow[] {
  const seen = new Set<string>();
  const out: QueueRow[] = [];
  for (const q of [...queue].sort((a, b) => b.id - a.id)) {
    const k = `${q.pluginId}:${q.contentHash}`;
    if (!q.contentHash || seen.has(k)) continue;
    seen.add(k);
    if (q.status === "dismissed") out.push(q);
  }
  return out;
}

function QuarantineRow({ q, ov, rpc, refetch, onTrustPending, onShowCard, kept, onUnkeep }: { q: QueueRow; ov: Overview; rpc: Rpc; refetch: () => void; onTrustPending: (entry: string, label: string) => void; onShowCard: (id: number) => void; kept: boolean; onUnkeep: (q: QueueRow) => void }) {
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc);
  const found = ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined);
  const ux = ov.ux[q.id];
  const red = cardColor({ reason: q.reason, findings: found?.findings ?? [] }) === "red";
  const unsafeDir = q.reason?.startsWith("каталог доступен на запись другим") ?? false;
  const approve = () => proof.run({ kind: "approve", queueId: q.id, acknowledgeBlock: false }, (p) => rpc.call("queue.approve", { id: q.id, ...p, acknowledgeBlock: false } as never), { routine: true });
  const entry = ux?.entry ?? null;
  // «Вернуть и доверять»: ONE operation at the guard (the version and its source), so ONE touch — never a session (adding a source is always a fresh touch).
  const approveAndTrust = async () => {
    const r = (await proof.run({ kind: "approve.trust", queueId: q.id }, (p) => rpc.call("queue.approveTrust", { id: q.id, ...p } as never))) as { note: string };
    return { note: r.note };
  };
  return (
    <div className={red ? cardBlocked : card} id={`sbb-quarantine-${q.id}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{q.pluginId} <span className={muted}>{q.version}</span></h3>
        <span className={red && !kept ? "font-semibold text-red-700 dark:text-red-400" : muted}>{kept ? "оставлен вами в карантине" : red ? "остановлен" : "ждёт решения"} · {when(q.firstSeen)}</span>
      </div>
      {kept ? <p className="mt-1">Вы решили оставить его здесь: он не запущен и больше не отмечен как нерешённый. <button className={btn} onClick={() => onUnkeep(q)}>Вернуть в «Ждут решения»</button></p> : null}
      <AuthorWhy why={ux?.why} />
      <Origin ux={ux} q={q} />
      {red ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span>Остановлен проверками: вернуть его можно только из карточки, через «Подробности».</span>
          <button className={btn} onClick={() => onShowCard(q.id)}>К карточке</button>
        </div>
      ) : (
        <>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <ProofField proof={proof} routine />
            <button className={btnPrimary} disabled={act.busy || unsafeDir || !proof.ready({ routine: true })} onClick={() => void act.run(approve, `вернули ${q.pluginId} ${q.version}`)}>
              Вернуть только эту версию
            </button>
            {entry ? (
              <button
                className={btn}
                disabled={act.busy || unsafeDir || !proof.ready()}
                title="Одна операция сторожа: одобрить версию и добавить источник. Одно касание."
                onClick={() => void act.run(() => approveAndTrust(), `вернули ${q.pluginId} ${q.version}, источник доверенный`)}
              >
                Вернуть и доверять этому источнику
              </button>
            ) : null}
          </div>
          <p className={`mt-1 text-xs ${muted}`}>{entry ? "«Вернуть и доверять этому источнику»: версия возвращается и источник попадает в «мои источники» одним касанием; новые версии — без вопросов, пока плагин не попросит новых прав." : "Источник нельзя занести в «мои источники» (не github и не папка на диске), поэтому вернуть можно только эту версию."}</p>
        </>
      )}
      <ProofNotes proof={proof} />
      <Msg error={act.error} ok={act.ok} reserve />
    </div>
  );
}

function RemovedSkillRow({ q, ov, rpc, refetch }: { q: SkillQueueView; ov: Overview; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const ap = useApproval();
  const [code, setCode] = useState("");
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const block = q.decision === "block";
  return (
    <div className={card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">Скилл {q.name} <span className={`text-xs font-normal ${muted}`}>({q.scope})</span></h3>
        <span className={muted}>удалён · {when(q.firstSeen)}</span>
      </div>
      <p className="mt-1">{block ? "Остановлен проверками. " : ""}{q.reason}</p>
      {block ? <p className={muted}>Вернуть такой скилл можно только в разделе «Скиллы» вкладки «Подробно».</p> : (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} />
          <button className={btnPrimary} disabled={act.busy || !registered || !ap.ready(code)} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("skills.approve", { id: q.id, ...proof, acknowledgeBlock: false } as never)); setCode(""); return r; })}>
            Вернуть только эту версию
          </button>
        </div>
      )}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

/** Removed skills, once each: the list of the «Карантин» tab and the number on it. */
const removedSkillsOf = (ov: Overview): SkillQueueView[] => [...ov.skills.open, ...ov.skills.recent].filter((s, i, all) => s.state === "removed" && all.findIndex((x) => x.id === s.id) === i);

/** The versions the person rejected and has not brought back: one row per (plugin, hash), the newest; none if the same version is held or approved since. */
function RejectedRow({ q, ov, rpc, refetch }: { q: QueueRow; ov: Overview; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc);
  // The files on disk are no longer the ones that were rejected: the guard says so only when asked, and from then on the button is not offered.
  const [gone, setGone] = useState(false);
  const back = () =>
    proof.run({ kind: "approve", queueId: q.id, acknowledgeBlock: false }, (p) => rpc.call("queue.approve", { id: q.id, ...p, acknowledgeBlock: false } as never), { routine: true }).catch((e: unknown) => {
      if (e instanceof Error && /hash did not match|never approved/i.test(e.message)) setGone(true);
      throw e;
    });
  const restorable = canRestore(q) && !gone;
  return (
    <div className={card} id={`sbb-rejected-${q.id}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{q.pluginId} <span className={muted}>{q.version}</span></h3>
        <span className={muted}>{rejectedByText(rejectedAtOf(q, awayEventsOf(ov)), Date.now())}</span>
      </div>
      {restorable ? (
        <>
          <p className="mt-1">Эта версия не запущена. Отклонение остаётся, пока вы сами его не отмените.</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <ProofField proof={proof} routine />
            <button className={btn} disabled={act.busy || !proof.ready({ routine: true })} onClick={() => void act.run(back, `вернули ${q.pluginId} ${q.version}`)}>Вернуть</button>
          </div>
          <ProofNotes proof={proof} />
        </>
      ) : (
        <p className="mt-1">Эта версия не запущена, и вернуть её нельзя: {isMismatch(q.reason) ? "её файлы изменились после проверки" : "нет данных, по которым её можно узнать"}. Чтобы пользоваться плагином, установите его заново из источника.</p>
      )}
      <Msg error={act.error} ok={act.ok} reserve />
    </div>
  );
}

function QuarantineTab({ ov, rpc, refetch, onTrustPending, onShowCard, isKept, onUnkeep }: { ov: Overview; rpc: Rpc; refetch: () => void; onTrustPending: (entry: string, label: string) => void; onShowCard: (id: number) => void; isKept: (q: QueueRow) => boolean; onUnkeep: (q: QueueRow) => void }) {
  const held = ov.queue.filter((q) => q.status === "held");
  const rejected = rejectedOf(ov.queue);
  const skills = removedSkillsOf(ov);
  return (
    <div className="space-y-3">
      <p className={muted}>Здесь то, что стоит на паузе: плагины, которые не запущены, пока вы не решите, и удалённые скиллы. Ничего не потеряно: любую вещь можно вернуть.</p>
      <Section title={`Плагины (${held.length})`} id="sbb-quarantine-plugins">
        {held.length === 0 ? <div className={`${card} ${muted}`}>В карантине ничего нет.</div> : held.map((q) => <QuarantineRow key={q.id} q={q} ov={ov} rpc={rpc} refetch={refetch} onTrustPending={onTrustPending} onShowCard={onShowCard} kept={isKept(q)} onUnkeep={onUnkeep} />)}
      </Section>
      {rejected.length > 0 ? (
        <Section title={`Отклонено вами (${rejected.length})`} id="sbb-quarantine-rejected">
          <p className={muted}>Эти версии вы отклонили: они не запущены, и страница о них больше не спрашивает. Передумали — «Вернуть» (одно касание).</p>
          {rejected.map((q) => <RejectedRow key={q.id} q={q} ov={ov} rpc={rpc} refetch={refetch} />)}
        </Section>
      ) : null}
      <Section title={`Удалённые скиллы (${skills.length})`} id="sbb-quarantine-skills">
        {skills.length === 0 ? <div className={`${card} ${muted}`}>Удалённых скиллов нет.</div> : skills.map((s) => <RemovedSkillRow key={s.id} q={s} ov={ov} rpc={rpc} refetch={refetch} />)}
      </Section>
    </div>
  );
}

// ---- exceptions and trust ---------------------------------------------------------------------------------------------------


function ExceptionsTab({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const now = useNow();
  const act = useCodeAction(refetch);
  const [day, setDay] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const approvals = ov.plugins.flatMap((p) => p.history.map((a) => ({ ...a, pluginId: p.id }))).filter((a) => a.revokedAt === null && (!day || now - a.approvedAt < 24 * 3600_000)).sort((a, b) => b.approvedAt - a.approvedAt);
  const mine = ov.guard?.trust?.mySources ?? [];
  const windows = ov.windows;
  const cfg = ov.watch.windows;
  const reset = () =>
    void act.run(async () => {
      // All three only tighten: no touch. The mode stays (weakening it takes a touch, so a reset must not do it either).
      for (const w of windows) await rpc.call("window.close", { windowId: w.id });
      for (const w of cfg) await rpc.call("watch.window.close", { windowId: w.id });
      for (const a of ov.plugins.flatMap((p) => p.history)) if (a.revokedAt === null) await rpc.call("approval.revoke", { approvalId: a.id });
      for (const e of mine) await rpc.call("trust.remove", { entry: e } as never);
      setConfirm(false);
      return { note: "Сброшено: окна закрыты, одобрения отозваны, «мои источники» очищены. Режим не менялся." };
    });
  return (
    <div className="space-y-4">
      {ov.guard ? <TrustCard ov={ov} rpc={rpc} refetch={refetch} /> : <div className={`${card} ${muted}`}>Режимы и «мои источники» есть только у сторожа решений.</div>}
      <Section title={`Окна (${windows.length + cfg.length})`}>
        {windows.length + cfg.length === 0 ? <div className={`${card} ${muted}`}>Открытых окон нет.</div> : <WindowRows windows={windows} cfgWindows={cfg} rpc={rpc} refetch={refetch} />}
      </Section>
      <Section title={`Одобрения (${approvals.length})`}>
        <label className="flex items-center gap-2"><input type="checkbox" checked={day} onChange={(e) => setDay(e.target.checked)} /> только за последние 24 часа</label>
        {approvals.length === 0 ? <div className={`${card} ${muted}`}>Одобрений нет.</div> : (
          <ul className="space-y-1">
            {approvals.map((a) => (
              <li key={a.id} className={`${card} flex flex-wrap items-center justify-between gap-2`}>
                <span>{a.pluginId} <span className={muted}>{a.version} · {approvedByText(a, now)}</span></span>
                <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("approval.revoke", { approvalId: a.id }); return { note: "Отозвано: следующая версия снова спросит." }; })}>Отозвать</button>
              </li>
            ))}
          </ul>
        )}
        <p className={`text-xs ${muted}`}>Показаны последние версии каждого плагина. Отзыв выключает плагин и кода не требует.</p>
      </Section>
      <Section title="Сбросить к умолчаниям">
        <div className={card}>
          <p>Закрывает все окна, отзывает одобрения и очищает «мои источники». Это только ужесточение, касание не нужно. Плагины, у которых отозвано одобрение, перестанут загружаться, пока вы не решите заново. Режим не меняется.</p>
          {confirm ? (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="font-semibold">Точно? Отзовётся одобрений: {approvals.length}, источников: {mine.length}.</span>
              <button className={btnDanger} disabled={act.busy} onClick={reset}>Да, сбросить</button>
              <button className={btn} onClick={() => setConfirm(false)}>Нет</button>
            </div>
          ) : <button className={`${btn} mt-2`} onClick={() => setConfirm(true)}>Сбросить к умолчаниям…</button>}
          <Msg error={act.error} ok={act.ok} />
        </div>
      </Section>
    </div>
  );
}

// ---- first run --------------------------------------------------------------------------------------------------------------

/** Three screens: the mode, "my sources", the second factor. Shown once (the page remembers that it was closed: a convenience, not a security fact). */
function Wizard({ ov, rpc, refetch, onClose }: { ov: Overview; rpc: Rpc; refetch: () => void; onClose: () => void }) {
  const t = ov.guard?.trust ?? null;
  const [step, setStep] = useState(0);
  const [mode, setMode] = useState<TrustMode>(t?.mode ?? "simple");
  const [picked, setPicked] = useState<string[]>([]);
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc);
  if (!t) return null;
  const suggestions = ov.sourceSuggestions.filter((s) => !t.mySources.includes(s));
  const keys = ov.guard?.passkey?.keys ?? [];
  const second = ov.totp.state === "locked" || ov.totp.state === "external" || keys.length > 0;
  return (
    <div className={card} data-secure-bb-wizard={step}>
      <div className="flex items-baseline justify-between gap-2">
        <h2 className="text-base font-semibold">Первый запуск · шаг {step + 1} из 3</h2>
        <button className={btn} onClick={onClose}>Пропустить</button>
      </div>
      {step === 0 ? (
        <div className="mt-2 space-y-2">
          <p>Как строго проверять плагины? Это можно поменять потом.</p>
          {(["simple", "detailed", "strict"] as const).map((m) => (
            <label key={m} className="flex items-start gap-2">
              <input type="radio" name="sbb-mode" className="mt-1" checked={mode === m} onChange={() => setMode(m)} />
              <span><b>{MODE_NAMES[m]}</b>{m === "simple" ? " (рекомендуется)" : ""}<br /><span className={muted}>{MODE_DESCRIPTIONS[m]}</span></span>
            </label>
          ))}
          <div className="flex flex-wrap items-center gap-2">
            {mode !== t.mode ? <ProofField proof={proof} /> : null}
            <button className={btnPrimary} disabled={act.busy || (mode !== t.mode && !proof.ready())} onClick={() => void act.run(async () => { if (mode !== t.mode) await proof.run({ kind: "trust.mode", trustMode: mode }, (p) => rpc.call("trust.mode", { mode, ...p } as never)); setStep(1); })}>Дальше</button>
          </div>
        </div>
      ) : null}
      {step === 1 ? (
        <div className="mt-2 space-y-2">
          <p>{WIZARD_SOURCES_TEXT}</p>
          {suggestions.length === 0 ? <p className={muted}>Подходящих источников у установленных плагинов не нашлось. Свои можно добавить позже на вкладке «Исключения и доверие».</p> : suggestions.map((s) => (
            <label key={s} className="flex items-center gap-2"><input type="checkbox" checked={picked.includes(s)} onChange={(e) => setPicked(e.target.checked ? [...picked, s] : picked.filter((x) => x !== s))} /><span className="text-sm">{friendlySource(s)}</span></label>
          ))}
          <div className="flex flex-wrap items-center gap-2">
            {picked.length > 0 ? <ProofField proof={proof} /> : null}
            <button className={btnPrimary} disabled={act.busy || (picked.length > 0 && !proof.ready())} onClick={() => void act.run(async () => { if (picked.length > 0) await proof.run({ kind: "trust.add", entries: picked }, (p) => rpc.call("trust.add", { entries: picked, ...p } as never)); setStep(2); })}>{picked.length > 0 ? "Добавить и дальше" : "Пропустить"}</button>
            <button className={btn} onClick={() => setStep(0)}>Назад</button>
          </div>
        </div>
      ) : null}
      {step === 2 ? (
        <div className="mt-2 space-y-2">
          <p>Второй фактор подтверждает ваши решения: без него одобрить нельзя.</p>
          <p className={second ? "text-green-700 dark:text-green-400" : "font-semibold text-red-700 dark:text-red-400"}>{secondFactorText({ codes: ov.totp.state === "locked" || ov.totp.state === "external", keys: keys.length })}</p>
          {second ? null : <p>На машине со сторожем выполните <span className="font-mono">sbb-guard setup</span>: мастер сам подключит коды или ключ, напечатает ссылку для этой страницы и проверит касание. Если такой команды в вашей сборке ещё нет, используйте <span className="font-mono">sudo sbb-guard passkey-enroll</span>, а затем вернитесь сюда.</p>}
          <div className="flex flex-wrap gap-2">
            <button className={btnPrimary} onClick={onClose}>Готово</button>
            <button className={btn} onClick={() => setStep(1)}>Назад</button>
          </div>
        </div>
      ) : null}
      <ProofNotes proof={proof} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

// -------------------------------------------------------------------- page --

/** Tells the server this page is open, so a registration started now counts as attended. */
function usePagePing(rpc: ReturnType<typeof useRpc<SecureBbRpc>>) {
  useEffect(() => {
    const ping = () => void rpc.call("page.ping").catch(() => undefined);
    ping();
    const t = setInterval(ping, 15_000);
    return () => clearInterval(t);
  }, [rpc]);
}

const TAB_LABEL: Record<TabId, string> = { status: "Статус", quarantine: "Карантин", trust: "Исключения и доверие", more: "Подробно" };

function GatePage() {
  const { rpc, data: ov, error, refetch } = useOverview();
  usePagePing(rpc);
  const { approval, open, lock, closed: sessionClosed } = useApprovalSession(rpc, refetch);
  // The link from `sbb-guard setup` (#enroll=TOKEN): taken once, from the fragment (it never went to a server), and the address bar is cleaned at once.
  const [enrollToken] = useState<string | null>(enrollTokenOnce);
  const [tab, setTab] = useState<TabId>(enrollToken !== null ? "more" : "status");
  // Marks carry the time the person made them: a mark older than the entry belongs to an earlier data set (ids start again after a reset) and does not count.
  // Marks of an older page, with no time on them, cannot be told from such ones: they are dropped once.
  const [deferredKeys, setDeferredKeys] = useState<string[]>(() => dropUnstamped(parseDeferred(lsGet(DEFERRED_KEY))));
  const [keptKeys, setKeptKeys] = useState<string[]>(() => dropUnstamped(parseDeferred(lsGet(KEPT_KEY))));
  const [seenAt, setSeenAt] = useState<string | null>(() => lsGet(AWAY_KEY));
  const [wizardDone, setWizardDone] = useState<boolean>(() => lsGet(WIZARD_KEY) !== null);
  const [pending, setPending] = useState<Array<{ entry: string; label: string }>>([]);
  const [focus, setFocus] = useState<string | null>(null);
  const [doneNotes, setDoneNotes] = useState<Note[]>([]);
  const doneSeq = useRef(0);
  // A resolved card leaves a stub of its height where it stood; it stays until the person closes it. The list keeps its order while the page is open.
  const [stubs, setStubs] = useState<Stub[]>([]);
  const orderRef = useRef<string[] | null>(null);
  const laterOrderRef = useRef<string[] | null>(null);
  const freshRef = useRef<Set<string>>(new Set());
  const pageStart = useRef(Date.now());
  const dismissNote = useCallback((id: number) => setDoneNotes((l) => l.filter((n) => n.id !== id)), []);
  const announce = useCallback((text: string, opts: AnnounceOpts = {}) => {
    const id = ++doneSeq.current;
    const kind = opts.kind ?? "done";
    setDoneNotes((l) => [...l, { id, text, kind }].slice(-4));
    if (kind !== "error") window.setTimeout(() => setDoneNotes((l) => l.filter((n) => n.id !== id)), DONE_MS);
    if (opts.slot && kind === "done") {
      const { key, height } = opts.slot;
      setStubs((l) => [...l.filter((x) => x.key !== key), makeStub(key, text, height)]);
    }
  }, []);
  const doneCtx = useMemo(() => ({ notes: doneNotes, announce, dismiss: dismissNote }), [doneNotes, announce, dismissNote]);
  // «Показать» and the banners: switch to the tab that holds the element, open the list of put-aside cards if it is there, scroll to it and
  // flash it, so that a press is always seen to do something (also when the element is already on the screen).
  useEffect(() => {
    if (!focus) return;
    const el = document.getElementById(focus);
    if (el) {
      el.scrollIntoView({ block: "start" });
      el.classList.add("sbb-flash");
      window.setTimeout(() => el.classList.remove("sbb-flash"), 1800);
      setFocus(null);
    }
  }, [focus, tab, ov]);
  if (error && !ov) return <div className="p-6 text-destructive">Не удалось загрузить: {error}</div>;
  if (!ov)
    return (
      <div className="mx-auto max-w-3xl space-y-3 p-6" role="status" aria-busy="true" data-secure-bb-loading>
        <h1 className="text-xl font-semibold">secure-bb</h1>
        <p className={`text-base ${muted}`}>Загрузка…</p>
      </div>
    );
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const heldAll = ov.queue.filter((q) => q.status === "held");
  const settled = ov.queue.filter((q) => q.status !== "held").slice(0, 10);
  const colorOf = (q: QueueRow) => cardColor({ reason: q.reason, findings: ov.queueChecks[q.id]?.findings ?? [] });
  const decisions = { deferred: deferredKeys, kept: keptKeys };
  const isDeferred = (q: QueueRow) => decisionOf(q, decisions) === "deferred";
  const isKept = (q: QueueRow) => decisionOf(q, decisions) === "kept";
  const store = (key: string, list: string[]) => lsSet(key, JSON.stringify(list.slice(-500)));
  const onDefer = (q: QueueRow, on: boolean) => {
    const k = deferKey(q.pluginId, q.contentHash, q.id);
    const next = on ? [...withoutMark(deferredKeys, k), stampMark(k, Date.now())] : withoutMark(deferredKeys, k);
    // «Решить позже»: a stub of the card's height stays where the card was («Отложено: X · Вернуть»), so that the next card does not slide under the cursor.
    if (on) {
      const height = document.getElementById(`sbb-card-${q.id}`)?.offsetHeight ?? 0;
      setStubs((l) => [...l.filter((x) => x.key !== q.pluginId), makeDeferStub(q, height)]);
    } else setStubs((l) => l.filter((x) => !(x.restore && x.key === q.pluginId)));
    setDeferredKeys(next);
    store(DEFERRED_KEY, next);
  };
  // «Оставить в карантине» is an answer: the entry is held at the guard as before, but it leaves «Ждут решения» and the status.
  const onKeep = (q: QueueRow) => {
    const k = deferKey(q.pluginId, q.contentHash, q.id);
    const next = [...withoutMark(keptKeys, k), stampMark(k, Date.now())];
    setKeptKeys(next);
    store(KEPT_KEY, next);
    onDefer(q, false);
  };
  const onUnkeep = (q: QueueRow) => {
    const next = withoutMark(keptKeys, deferKey(q.pluginId, q.contentHash, q.id));
    setKeptKeys(next);
    store(KEPT_KEY, next);
  };
  // ONE card per plugin: its latest version; the other versions that wait are folded under it. The status counts the cards that are not decided.
  const plan = planCards(heldAll, decisions);
  const cardColorOf = (c: { all: QueueRow[] }): "red" | "yellow" => (c.all.some((q) => colorOf(q) === "red") ? "red" : "yellow");
  const refOf = (c: { shown: QueueRow; all: QueueRow[]; pluginId: string }): ProblemRef => ({ anchor: `sbb-card-${c.shown.id}`, tab: "status", text: `${c.pluginId} ${c.shown.version}` });
  const stubKeys = stubs.map((x) => x.key);
  const activeOrder = stableOrder(orderRef.current, plan.active.map((c) => c.pluginId), stubKeys);
  orderRef.current = activeOrder.order;
  const laterOrder = stableOrder(laterOrderRef.current, plan.later.map((c) => c.pluginId));
  laterOrderRef.current = laterOrder.order;
  for (const k of [...activeOrder.fresh, ...laterOrder.fresh]) freshRef.current.add(k);
  const activeItems = layoutItems(activeOrder.order, new Set(plan.active.map((c) => c.pluginId)), stubs);
  const planned = [...plan.active, ...plan.later];
  const reds = planned.filter((c) => cardColorOf(c) === "red");
  const yellows = planned.filter((c) => cardColorOf(c) === "yellow");
  const alarms: ProblemRef[] = [];
  if (!ov.journal.ok) alarms.push({ anchor: "sbb-alarms", tab: "status", text: "Журнал решений нарушен" });
  if (ov.alive.gaps.length > 0 || ov.alive.safeMode === true) alarms.push({ anchor: "sbb-alarms", tab: "status", text: "Гейт не всегда работал" });
  if (ov.guard?.connected && ov.guard.journal && !ov.guard.journal.valid) alarms.push({ anchor: "sbb-guard-alarm", tab: "status", text: "Журнал сторожа нарушен" });
  const agentsCritical = (ov.agents?.state?.drifts ?? []).filter((d) => d.class === "critical" && !d.initial).length;
  const agentsAlarms = (ov.agents?.state?.alarms ?? []).length;
  // While something critical or an alarm waits, the section is on «Статус» (the banner leads to it); otherwise it stays in «Подробно».
  const agentsTab = agentsSectionTab({ critical: agentsCritical, alarms: agentsAlarms });
  if (ov.agents && (agentsAlarms > 0 || agentsCritical > 0)) alarms.push({ anchor: "sbb-agents", tab: agentsTab, text: `Настройки агентов: ${[agentsCritical > 0 ? `критичных изменений — ${agentsCritical}` : "", agentsAlarms > 0 ? `файлов не прочитать — ${agentsAlarms}` : ""].filter(Boolean).join(", ")}`, weight: agentsCritical + agentsAlarms });
  if (ov.watch.drifts.some((d) => d.status === "open" || d.status === "rollback-failed")) alarms.push({ anchor: "sbb-watch", tab: "more", text: "Настройки bb изменились" });
  if (!registered) alarms.push({ anchor: "sbb-registration", tab: "more", text: "Второй фактор не настроен" });
  if ((ov.guard?.troubleshootUntil ?? 0) > ov.now) alarms.push({ anchor: "sbb-guard-alarm", tab: "status", text: "Включён режим отладки сторожа: он пропускает всё" });
  const guardDown = ov.guard !== undefined && !ov.guard.connected;
  const status = pageStatus({ guardDown, red: reds.map(refOf), yellow: yellows.map(refOf), alarms });
  // Every number on the page comes from the one plan of cards.
  const counts = pageCounts(plan, alarmCount(alarms), removedSkillsOf(ov).length);
  const showProblem = (p: ProblemRef) => {
    setTab(p.tab);
    const id = Number(p.anchor.replace("sbb-card-", ""));
    if (p.anchor.startsWith("sbb-card-") && heldAll.some((q) => q.id === id && isDeferred(q))) openFold("deferred", true);
    setFocus(p.anchor);
  };
  // Fixed for as long as the page is open: «С …» must not change under the eyes.
  const since = awaySince(seenAt, Math.max(pageStart.current, Number(seenAt ?? 0) || 0));
  const seen = (mark: number) => {
    lsSet(AWAY_KEY, String(mark));
    setSeenAt(String(mark));
  };
  const closeWizard = () => {
    lsSet(WIZARD_KEY, String(ov.now));
    setWizardDone(true);
  };
  const addPending = (entry: string, label: string) => setPending((p) => (p.some((x) => x.entry === entry) ? p : [...p, { entry, label }]));
  const level = detailLevel(ov.guard?.trust?.mode ?? null);
  const cardProps = { ov, rpc, refetch, onDefer, onKeep, onTrustPending: addPending };
  const launchFailed = ov.plugins.filter((p) => p.pin !== null && launchProblem(p) !== null);
  /** A card of a plugin: its latest version, the other waiting versions folded under it. */
  const renderCard = (c: { shown: QueueRow; others: QueueRow[] }, deferred: boolean) => (
    <div key={c.shown.pluginId} className="space-y-2">
      <ReviewCard key={cardKey(c.shown)} q={c.shown} {...cardProps} deferred={deferred} fresh={freshRef.current.has(c.shown.pluginId)} />
      {c.others.length > 0 ? (
        <Fold id={`more-${c.shown.pluginId}`} className="ml-3" summary={`${moreVersionsText(c.others.length)} (${c.others.map((o) => o.version).join(", ")})`}>
          <div className="mt-2 space-y-2">{c.others.map((o) => <ReviewCard key={cardKey(o)} q={o} {...cardProps} deferred={isDeferred(o)} slotted={false} />)}</div>
        </Fold>
      ) : null}
    </div>
  );
  const agentsSection = ov.agents ? <Section id="sbb-agents" title={`Агенты: конфигурации и память${agentsAlarms > 0 || agentsCritical > 0 ? " (!)" : (ov.agents.state?.openTotal ?? 0) > 0 ? ` (${ov.agents.state?.openTotal})` : ""}`}><AgentsSection ov={ov} rpc={rpc} refetch={refetch} showDone={agentsTab !== "status"} /></Section> : null;
  const tabCount: Record<TabId, string> = { status: status.count > 0 ? ` (${status.count})` : "", quarantine: counts.quarantine > 0 ? ` (${counts.quarantine})` : "", trust: "", more: "" };
  // What the person has answered or put aside is not «waiting» any more: «Пока вас не было» does not repeat it.
  const keptIds = new Set([...plan.kept.map((q) => q.id), ...plan.later.flatMap((c) => c.all.map((q) => q.id))]);
  return (
    <DoneContext.Provider value={doneCtx}>
    <ApprovalContext.Provider value={approval}>
    <div className="h-full overflow-y-auto">
      <style>{".sbb-flash{outline:3px solid #eab308;outline-offset:3px;border-radius:0.5rem}"}</style>
      <div className="mx-auto max-w-3xl space-y-6 p-4 sm:p-6">
        <h1 className="text-xl font-semibold">secure-bb</h1>
        <PinnedNotes />
        <TroubleshootBar until={ov.guard?.troubleshootUntil ?? 0} />
        <StatusBar level={status.level} label={status.label} text={guardDown ? GUARD_DOWN_TEXT : status.first ? `Сначала: ${status.first.text}.` : "Всё, что нужно решить, решено."} onShow={status.first ? () => showProblem(status.first!) : null} />
        {countsLine(counts) ? <p className={`-mt-4 text-xs ${muted}`} data-secure-bb-counts>{countsLine(counts)}</p> : null}
        <div role="tablist" className="flex flex-wrap gap-1 border-b border-border">
          {(["status", "quarantine", "trust", "more"] as const).map((t) => (
            <button key={t} role="tab" aria-selected={tab === t} className={`rounded-t-md px-3 py-1.5 text-sm font-medium ${tab === t ? "border border-b-0 border-border bg-card" : "text-muted-foreground hover:bg-muted"}`} onClick={() => setTab(t)}>
              {TAB_LABEL[t]}{tabCount[t]}
            </button>
          ))}
        </div>
        {tab === "status" ? (
          <div className="space-y-4">
            {!wizardDone && wizardNeeded({ hasTrust: ov.guard?.trust != null, mySources: ov.guard?.trust?.mySources.length ?? 0, done: false }) ? <Wizard ov={ov} rpc={rpc} refetch={refetch} onClose={closeWizard} /> : null}
            <PendingTrust entries={pending} ov={ov} rpc={rpc} refetch={refetch} onDone={(e) => setPending((p) => p.filter((x) => x.entry !== e))} />
            <AwayCard ov={ov} since={since} onSeen={seen} canReview={status.first !== null} onReview={() => status.first && showProblem(status.first)} kept={keptIds} alarms={alarms} onShowAlarm={showProblem} />
            <SkillsLine ov={ov} onOpen={() => showProblem({ anchor: "sbb-skills", tab: "more", text: "" })} />
            <SessionBar ov={ov} rpc={rpc} session={approval.session} open={open} lock={lock} closed={sessionClosed} />
            {ov.totp.blockedUntil > 0 ? (
              <p className="rounded-md border border-destructive p-2 text-destructive">Слишком много неверных кодов: коды заблокированы до {when(ov.totp.blockedUntil)}.{(ov.guard?.passkey?.keys.length ?? 0) > 0 ? " Касание ключом работает: подпись не подобрать, поэтому её это не касается." : ""}</p>
            ) : null}
            <div id="sbb-alarms" className="space-y-2">
              <JournalAlarm ov={ov} rpc={rpc} refetch={refetch} />
              <AliveAlarm ov={ov} />
            </div>
            <div id="sbb-guard-alarm"><GuardAlarm ov={ov} /></div>
            <AgentsAlarm ov={ov} onShow={() => showProblem({ anchor: "sbb-agents", tab: agentsTab, text: "" })} />
            <WindowRows windows={ov.windows} cfgWindows={ov.watch.windows} rpc={rpc} refetch={refetch} />
            <Section title={`Ждут решения вас${counts.waiting > 0 ? ` (${counts.waiting})` : ""}`}>
              {activeItems.length === 0 ? <div className={`${card} ${muted}`}>Сейчас решать нечего.</div> : activeItems.map((it) => {
                if (it.stub) {
                  const st = it.stub;
                  return (
                    <div key={`stub:${st.key}`} className="flex items-center justify-between gap-2 rounded-lg border-2 border-green-600/50 bg-green-50 p-4 text-sm font-semibold text-green-900 dark:bg-green-950/40 dark:text-green-100" style={{ minHeight: st.height }} data-secure-bb-stub>
                      <span>{st.text}</span>
                      {st.restore ? (
                        <button type="button" className={btn} onClick={() => { const r = st.restore!; const e = heldAll.find((x) => x.id === r.id); if (e) onDefer(e, false); else setStubs((l) => l.filter((x) => x.key !== st.key)); }}>{DEFER_STUB_RESTORE}</button>
                      ) : (
                        <button type="button" className={btn} onClick={() => setStubs((l) => l.filter((x) => x.key !== st.key))}>Скрыть</button>
                      )}
                    </div>
                  );
                }
                const c = plan.active.find((x) => x.pluginId === it.key)!;
                return renderCard(c, false);
              })}
            </Section>
            {plan.later.length > 0 ? (
              <Fold id="deferred" summaryClassName="cursor-pointer font-semibold" summary={`Отложено (${counts.deferred})`}>
                <p className={`mt-1 text-xs ${muted}`}>Вы отложили эти карточки кнопкой «Решить позже». Плагины остаются в карантине и не запущены.</p>
                <div className="mt-2 space-y-2">{laterOrder.order.map((k) => plan.later.find((c) => c.pluginId === k)).filter((c): c is NonNullable<typeof c> => c !== undefined).map((c) => renderCard(c, true))}</div>
              </Fold>
            ) : null}
            {plan.kept.length > 0 ? <p className={`text-xs ${muted}`}>Оставлено вами в карантине: {plan.kept.map((q) => `${q.pluginId} ${q.version}`).join(", ")}. Они не запущены; вернуть решение можно на вкладке «Карантин».</p> : null}
            {launchFailed.length > 0 ? (
              <Section title="Разрешены, но не запустились">
                {launchFailed.map((p) => <div key={p.id} className={cardBlocked} role="alert"><p className="font-semibold">{p.id} {p.version}</p><p>{launchProblem(p)}</p></div>)}
              </Section>
            ) : null}
            {agentsTab === "status" ? agentsSection : null}
            {level.expanded ? <p className={`text-xs ${muted}`}>Режим «{MODE_NAMES[ov.guard!.trust!.mode]}»: технические подробности на карточках открыты.</p> : null}
          </div>
        ) : null}
        {tab === "quarantine" ? <QuarantineTab ov={ov} rpc={rpc} refetch={refetch} onTrustPending={addPending} onShowCard={(id) => { setTab("status"); setFocus(`sbb-card-${id}`); }} isKept={isKept} onUnkeep={onUnkeep} /> : null}
        {tab === "trust" ? <ExceptionsTab ov={ov} rpc={rpc} refetch={refetch} /> : null}
        {tab === "more" ? (
          <div className="space-y-6">
            <Section title="Защита этого bb"><StageCard ov={ov} /></Section>
            <Section title="Второй фактор" id="sbb-registration"><Registration ov={ov} rpc={rpc} refetch={refetch} /></Section>
            {ov.guard ? <Section title={`Сторож решений${ov.guard.connected ? "" : " (не отвечает!)"}`}><GuardCard ov={ov} rpc={rpc} refetch={refetch} enrollToken={enrollToken} /></Section> : null}
            <Section title={`Гейт плагинов — очередь, расширенный вид (${heldAll.length})`}>
              {heldAll.length === 0 ? <div className={`${card} ${muted}`}>Ничего не держится.</div> : heldAll.map((q) => <QueueCard key={q.id} q={q} ov={ov} rpc={rpc} refetch={refetch} />)}
              {settled.length > 0 ? (
                <Fold id="queue-settled" summaryClassName={`cursor-pointer ${muted}`} summary={`Недавно рассмотренные (${settled.length})`}>
                  <div className="mt-2 space-y-2">{settled.map((q) => <QueueCard key={q.id} q={q} ov={ov} rpc={rpc} refetch={refetch} />)}</div>
                </Fold>
              ) : null}
            </Section>
            <BatchCard ov={ov} rpc={rpc} refetch={refetch} />
            <Section title="Гейт плагинов — сторонние плагины">
              {ov.plugins.length === 0 ? <div className={`${card} ${muted}`}>Сторонних плагинов нет.</div> : ov.plugins.map((p) => <PluginRow key={p.id} p={p} ov={ov} rpc={rpc} refetch={refetch} registered={registered} checks={ov.checks} />)}
            </Section>
            <Section title="Гейт плагинов — окна доверия"><PolicyCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
            <Section title="Гейт плагинов — ИИ-скан"><AiCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
            <Section title="Гейт плагинов — публикация"><PublishCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
            <Section id="sbb-watch" title={`Сторож конфигурации${ov.watch.drifts.some((d) => d.status === "open" || d.status === "rollback-failed") ? " (!)" : ""}`}><WatchSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
            {agentsTab === "more" ? agentsSection : ov.agents ? <p className={`text-xs ${muted}`}>Раздел «Агенты: конфигурации и память» сейчас на вкладке «Статус»: там критичное.</p> : null}
            <Section title={`Дозор${ov.sentinel.settings.enabled ? "" : " (выключен)"}`}><SentinelSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
            <Section id="sbb-skills" title={`Скиллы${ov.skills.open.length > 0 ? ` — очередь (${ov.skills.open.length})` : ""}`}><SkillsSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
            <Section title={`Загрязнение тредов${ov.tainted.length > 0 ? ` (${ov.tainted.length})` : ""}`}><TaintCard ov={ov} /></Section>
            <Section title={`Доверенные репозитории (${ov.trustedRepos.length})`}><TrustedRepos ov={ov} rpc={rpc} refetch={refetch} /></Section>
            <Section title="Перенос одобрений в сторож"><MigrationCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
            <Section title={`Журнал${ov.journal.ok ? "" : " (!)"}`}><LogCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
          </div>
        ) : null}
      </div>
    </div>
    </ApprovalContext.Provider>
    </DoneContext.Provider>
  );
}

export default definePluginApp((app) => {
  app.slots.navPanel({
    id: "gate",
    title: "secure-bb",
    icon: "Shield",
    path: "gate",
    component: GatePage,
  });
  app.slots.experimental_appOverlay({ id: "windows", component: WindowOverlay });
});
