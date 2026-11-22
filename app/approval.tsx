import { createContext, useContext, useEffect, useRef, useState } from "react";
import type { Overview } from "../src/overview";
import { T } from "../src/text";
import type { PasskeyAssertion } from "../src/guardlink";
import { sessionClosedText, sessionEndReason, slideIdle, type SessionCloseReason, sessionBlockText, sessionText } from "../src/ux";
import { useCodeAction, CodeField, type Rpc } from "./code";
import { useProof, ProofField, ProofNotes } from "./confirm";
import { card, btn, btnPrimary, muted, when, Fold, useNow, Msg } from "./ui";

// The session token lives ONLY in this component's memory (state): not localStorage, not a cookie, not the URL. Reloading the page
// forgets it, and so does leaving it. The server keeps only a hash. Routine actions use it instead of a code; dangerous ones never do.
export type Proof = { code: string } | { session: string };

export interface SessionLocal {
  token: string;
  /** When this page stops using the token (a little before the server does: the server's clock decides, this only avoids a wasted call). */
  idleUntil: number;
  hardUntil: number;
}

export interface Approval {
  session: SessionLocal | null;
  /** Can an action run with what is typed now? `dangerous`: it needs a fresh code whatever the session says. */
  ready: (code: string, dangerous?: boolean) => boolean;
  /** Runs a routine action: with the code when six digits are typed, else with the session; slides the local clock on success. */
  routine: <T>(code: string, fn: (proof: Proof) => Promise<T>, dangerous?: boolean) => Promise<T>;
}

export const MARGIN_MS = 5_000;

export const noApproval: Approval = {
  session: null,
  ready: (code) => code.length === 6,
  routine: (code, fn) => fn({ code }),
};

export const ApprovalContext = createContext<Approval>(noApproval);

export const useApproval = () => useContext(ApprovalContext);

/** A code field that gives way to the session note while a session covers the action. */
export function RoutineCode({ value, onChange, dangerous }: { value: string; onChange: (v: string) => void; dangerous?: boolean }) {
  const ap = useApproval();
  if (ap.session && !dangerous) return <span className={`text-xs ${muted}`}>сессия открыта: код не нужен</span>;
  return <CodeField value={value} onChange={onChange} />;
}

export function useApprovalSession(rpc: Rpc, refetch: () => void): { approval: Approval; open: (proof: { code?: string; passkey?: PasskeyAssertion }, hour?: boolean) => Promise<void>; lock: () => Promise<void>; closed: SessionCloseReason | null } {
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
export function SessionBar({ ov, rpc, session, open, lock, closed }: { ov: Overview; rpc: Rpc; session: SessionLocal | null; open: (proof: { code?: string; passkey?: PasskeyAssertion }, hour?: boolean) => Promise<void>; lock: () => Promise<void>; closed: SessionCloseReason | null }) {
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
    <div className={card} id="sbb-session">
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
