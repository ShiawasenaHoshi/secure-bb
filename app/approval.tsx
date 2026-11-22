import { createContext, useContext, useEffect, useRef, useState } from "react";
import type { Overview } from "../src/overview";
import { T } from "../src/text";
import type { PasskeyAssertion } from "../src/guardlink";
import { sessionClosedText, sessionEndReason, slideIdle, type SessionCloseReason, sessionBlockText, sessionText } from "../src/ux";
import { useCodeAction, CodeField, type Rpc } from "./code";
import { useProof } from "./confirm";
import { muted, when, useNow, Msg, Tip } from "./ui";
import { Button } from "../components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../components/ui/dialog";

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

/**
 * The session of confirmation, small, at the right of the header: «Сессия: закрыта · Открыть» / «открыта ещё 12 мин · Закрыть». «Открыть» goes to the same
 * confirmation dialog as every other action. When it cannot be opened, the reason is in the hint and in a muted line.
 */
export function SessionBar({ ov, rpc, session, open, lock, closed }: { ov: Overview; rpc: Rpc; session: SessionLocal | null; open: (proof: { code?: string; passkey?: PasskeyAssertion }, hour?: boolean) => Promise<void>; lock: () => Promise<void>; closed: SessionCloseReason | null }) {
  const now = useNow();
  const proof = useProof(ov, rpc, "session");
  const act = useCodeAction(() => undefined);
  const [whyOpen, setWhyOpen] = useState(false);
  if (!proof.registered) return null;
  if (session) {
    const left = Math.max(0, Math.ceil((Math.min(session.idleUntil, session.hardUntil) - now) / 60_000));
    const ceiling = Math.max(0, Math.ceil((session.hardUntil - now) / 60_000));
    return (
      <div className="flex flex-wrap items-center justify-end gap-x-2 text-sm" role="status" id="sbb-session" data-secure-bb-session="open">
        <Tip tip={`Потолок — через ${ceiling} мин; 15-минутная продлевается от каждого действия. Опасное всё равно требует свежего ${ov.guard ? "касания" : "кода"}.`}>
          <span className={muted}>Сессия: открыта ещё {left} мин</span>
        </Tip>
        <span aria-hidden className={muted}>·</span>
        <Button size="sm" variant="ghost" disabled={act.busy} onClick={() => void act.run(() => lock())}>Закрыть</Button>
      </div>
    );
  }
  const blockers = ov.sessionBlockers.map((b) => b.id);
  const st = sessionText(ov.guard?.trust?.mode ?? null, ov.guard !== undefined);
  const blocked = ov.guard && proof.pk.has ? false : ov.totp.blockedUntil > 0;
  const blockReason = blockers.length > 0 ? sessionBlockText(ov.sessionBlockers) : blocked ? `Слишком много неверных кодов: коды заблокированы до ${when(ov.totp.blockedUntil)}.` : null;
  const closedNote = closed ? sessionClosedText(closed) : null;
  const detail = [st.line, st.details].filter(Boolean).join(" ");
  const openWith = (hour: boolean) =>
    void act.run(async () => {
      await proof.run({ kind: "session.open", ...(hour ? { hour: true } : {}) }, (p) => open(p as { code?: string; passkey?: PasskeyAssertion }, hour), { what: hour ? "Открыть сессию подтверждения на 1 час" : "Открыть сессию подтверждения на 15 минут", detail });
    });
  // One short state in the header; the reason is in the hint and, by «почему?», in a dialog: a long sentence would break the header.
  const why = [blockReason, closedNote].filter(Boolean).join(" ");
  return (
    <div className="flex flex-wrap items-center justify-end gap-x-2 text-sm" id="sbb-session" data-secure-bb-session={blockReason ? "unavailable" : "closed"}>
      {blockReason ? (
        <>
          <Tip tip={blockReason}>
            <span className={muted} data-secure-bb-session-block>Сессия: недоступна</span>
          </Tip>
        </>
      ) : (
        <>
          <span className={muted}>Сессия: закрыта</span>
          <span aria-hidden className={muted}>·</span>
          <Button size="sm" variant="ghost" disabled={act.busy} onClick={() => openWith(false)}>Открыть</Button>
          <Tip tip="Один час подряд, без продления. Дольше потолка политики сессия не живёт.">
            <Button size="sm" variant="ghost" disabled={act.busy} onClick={() => openWith(true)}>на 1 час</Button>
          </Tip>
        </>
      )}
      {why ? <Button size="sm" variant="link" className="px-1" onClick={() => setWhyOpen(true)} data-secure-bb-session-closed={closedNote ? "" : undefined}>почему?</Button> : null}
      <Dialog open={whyOpen} onOpenChange={setWhyOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Сессия подтверждения</DialogTitle>
            <DialogDescription>{why || st.line}</DialogDescription>
          </DialogHeader>
          <p className={`text-sm ${muted}`}>{detail}</p>
        </DialogContent>
      </Dialog>
      <Msg error={act.error} />
    </div>
  );
}
