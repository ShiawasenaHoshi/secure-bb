import { useState } from "react";
import type { Overview } from "../src/overview";
import type { PasskeyAssertion } from "../src/guardlink";
import { sessionClosedText, type SessionCloseReason, sessionBlockText, sessionText } from "../src/ux";
import type { SessionLocal } from "./approval";
import { useCodeAction } from "./code";
import { useProof } from "./proof";
import type { Rpc } from "./touch";
import { muted, when, useNow, Msg, Tip } from "./ui";
import { Button } from "../components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../components/ui/dialog";

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
