import { useState } from "react";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";
import { cardFoldId, isBlockedEntry, MISMATCH_HINT } from "../src/ux";
import { queueFacts, queueLabel, queueSourceLine, queueStatusWord, type QueueFacts } from "../src/cardview";
import { isMismatchEntry } from "../src/ux";
import { useApproval, RoutineCode } from "./approval";
import { ChecksView } from "./checks";
import { useCodeAction, TouchNote } from "./code";
import { usePasskey, touchFor, type Rpc } from "./touch";
import { ScanResultView, ScanButton } from "./scan";
import { card, btn, btnPrimary, input, muted, cardBlocked, btnDanger, when, Fold, Msg } from "./ui";

export { queueLabel };

interface Ctl {
  q: QueueRow;
  ov: Overview;
  rpc: Rpc;
  refetch: () => void;
  facts: QueueFacts;
  registered: boolean;
  pk: ReturnType<typeof usePasskey>;
  act: ReturnType<typeof useCodeAction>;
  code: string;
  setCode: (v: string) => void;
  ack: boolean;
  setAck: (v: boolean) => void;
  touching: string | null;
  /** The buttons that take a code are off while it is not possible: the action runs, the second factor is missing, the directory is unsafe, or a block is being lifted with no fresh code. */
  disabled: boolean;
  touch: (kind: "approve" | "window.open", ack?: boolean) => void;
  dismiss: () => void;
  approveByCode: (acknowledgeBlock: boolean) => void;
  openWindowByCode: () => void;
}

/** The state and the actions of the extended card (what a press does); the pieces below only draw. */
function useQueueCtl(q: QueueRow, ov: Overview, rpc: Rpc, refetch: () => void): Ctl {
  const [code, setCode] = useState("");
  const [ack, setAck] = useState(false);
  const [touching, setTouching] = useState<string | null>(null);
  const act = useCodeAction(refetch);
  const ap = useApproval();
  const pk = usePasskey(ov);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const blocked = isBlockedEntry({ reason: q.reason, reasonKind: q.reasonKind, blocks: q.blocks, findings: ov.queueChecks[q.id]?.findings ?? [] });
  const facts = queueFacts(q, blocked);
  // Lifting a block is dangerous: it needs a fresh code even with a session open.
  const disabled = act.busy || !ap.ready(code, blocked && ack) || !registered || facts.unsafeDir;
  /** Approves or opens a window with a touch instead of a code. */
  const touch = (kind: "approve" | "window.open", acknowledge = false) =>
    void act.run(async () => {
      setTouching(null);
      const t = await touchFor(rpc, { kind, queueId: q.id, ...(kind === "approve" ? { acknowledgeBlock: acknowledge } : {}) }, (d) => setTouching(`Подтвердите касанием. Сторож: «${d}»`));
      if (!t) throw new Error("касание не требуется");
      if (kind === "approve") await rpc.call("queue.approve", { id: q.id, passkey: t.passkey, acknowledgeBlock: acknowledge });
      else await rpc.call("window.open", { queueId: q.id, passkey: t.passkey });
      setTouching(null);
      setAck(false);
      return { note: `Одобрено касанием. Сторож описал действие так: «${t.description}» (системное окно Touch ID этого не показывает; точное действие записано в журнале сторожа).` };
    });
  const dismiss = () => void act.run(async () => { await rpc.call("queue.dismiss", { id: q.id }); });
  const approveByCode = (acknowledgeBlock: boolean) =>
    void act.run(async () => {
      const r = await ap.routine(code, (proof) => rpc.call("queue.approve", { id: q.id, ...proof, acknowledgeBlock }), acknowledgeBlock);
      setCode("");
      if (acknowledgeBlock) setAck(false);
      return r;
    });
  const openWindowByCode = () =>
    void act.run(async () => {
      await ap.routine(code, (proof) => rpc.call("window.open", { queueId: q.id, ...proof }));
      setCode("");
    });
  return { q, ov, rpc, refetch, facts, registered, pk, act, code, setCode, ack, setAck, touching, disabled, touch, dismiss, approveByCode, openWindowByCode };
}

function QueueHeader({ c }: { c: Ctl }) {
  const { q, facts } = c;
  const red = facts.blocked && facts.held;
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h3 className="font-semibold">
        {queueLabel(q.id)} · {q.pluginId} <span className={muted}>{q.version}</span>
      </h3>
      <span className={red ? "font-semibold text-destructive" : muted}>{queueStatusWord(q.status, facts.blocked)} · {when(q.firstSeen)}</span>
    </div>
  );
}

function QueueDetails({ c }: { c: Ctl }) {
  const { q, ov, facts } = c;
  return (
    <>
      <p className={`mt-1 break-all ${muted}`}>{queueSourceLine(q)}</p>
      {q.contentHash ? <p className={`break-all font-mono text-xs ${muted}`}>{q.contentHash}</p> : null}
      {q.reason ? <p className={`mt-1 ${facts.blocked || facts.unsafeDir ? "font-semibold text-destructive" : muted}`}>{q.reason}</p> : null}
      {facts.unsafeDir && facts.held ? <p className="mt-1 text-destructive">Одобрить нельзя: пока в каталоге или выше может писать кто-то кроме пользователя сервера, его содержимое может измениться после проверки. Исправьте права (владелец — пользователь сервера, без записи для группы и остальных) или предложите плагин через <span className="font-mono">bb secure-bb propose</span>: снимок гейт хранит у себя.</p> : null}
      <ChecksView id={cardFoldId(q, "checks-q")} result={ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined)} />
      <ScanResultView scan={ov.ai.queueScans[q.id]} enabled={ov.ai.settings.enabled} />
    </>
  );
}

/** A blocked entry: «Отклонить» only tightens; lifting the block is under a fold, with a fresh code or a touch. */
function BlockedActions({ c }: { c: Ctl }) {
  const { q, ov, rpc, refetch, act, pk } = c;
  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <button className={btnPrimary} disabled={act.busy} onClick={c.dismiss}>Отклонить</button>
        <span className={muted}>Без кода: отклонение только ужесточает.</span>
        <ScanButton ov={ov} target={{ queueId: q.id }} rpc={rpc} refetch={refetch} />
      </div>
      {isMismatchEntry(q) ? <p className={muted}>{MISMATCH_HINT}</p> : <LiftBlock c={c} />}
    </>
  );
}

function LiftBlock({ c }: { c: Ctl }) {
  const { q, act, pk, ack, registered, facts } = c;
  return (
    <Fold id={cardFoldId(q, "force")} className="rounded-md border border-destructive p-2" summaryClassName="cursor-pointer text-destructive" summary="Всё равно одобрить (опасно)…">
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {pk.keyOnly ? null : <RoutineCode value={c.code} onChange={c.setCode} dangerous />}
        <label className="flex items-center gap-1 text-xs">
          <input type="checkbox" checked={ack} onChange={(e) => c.setAck(e.target.checked)} /> понимаю риск: проверки нашли жёсткий признак
        </label>
        {pk.has ? <button className={btnDanger} disabled={act.busy || !ack || pk.problem !== null || !registered || facts.unsafeDir} onClick={() => c.touch("approve", true)}>Снять блок и одобрить касанием</button> : null}
        {pk.keyOnly ? null : <button className={btnDanger} disabled={c.disabled || !ack} onClick={() => c.approveByCode(ack)}>{pk.has ? "Снять блок и одобрить кодом" : "Снять блок и одобрить"}</button>}
      </div>
    </Fold>
  );
}

function TouchButtons({ c }: { c: Ctl }) {
  const { q, act, pk, registered, facts } = c;
  if (!pk.has) return null;
  return (
    <>
      <button className={btnPrimary} disabled={act.busy || pk.problem !== null || !registered || facts.unsafeDir} onClick={() => c.touch("approve")}>Одобрить касанием</button>
      {q.threadId && q.id > 0 ? <button className={btn} disabled={act.busy || pk.problem !== null || !registered} onClick={() => c.touch("window.open")}>Открыть окно касанием</button> : null}
    </>
  );
}

function CodeButtons({ c }: { c: Ctl }) {
  const { q, pk } = c;
  if (pk.keyOnly) return null;
  return (
    <>
      {pk.has ? <span className={muted}>запасной путь — код:</span> : null}
      <RoutineCode value={c.code} onChange={c.setCode} dangerous={false} />
      <ScanButton ov={c.ov} target={{ queueId: q.id }} rpc={c.rpc} refetch={c.refetch} />
      <button className={pk.has ? btn : btnPrimary} disabled={c.disabled} onClick={() => c.approveByCode(false)}>Одобрить версию{pk.has ? " кодом" : ""}</button>
      {q.threadId ? <button className={btn} disabled={c.disabled} onClick={c.openWindowByCode}>Открыть окно</button> : null}
    </>
  );
}

/** A held entry that is not blocked: dismiss, approve by a touch or a code, open a window. */
function PlainActions({ c }: { c: Ctl }) {
  const { q, ov, rpc, refetch, act, pk } = c;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <button className={btn} disabled={act.busy} onClick={c.dismiss}>Отклонить</button>
      <TouchButtons c={c} />
      <CodeButtons c={c} />
      {pk.keyOnly ? <ScanButton ov={ov} target={{ queueId: q.id }} rpc={rpc} refetch={refetch} /> : null}
    </div>
  );
}

export function QueueCard({ q, ov, rpc, refetch }: { q: QueueRow; ov: Overview; rpc: Rpc; refetch: () => void }) {
  const c = useQueueCtl(q, ov, rpc, refetch);
  const { facts, pk } = c;
  return (
    <div className={facts.blocked && facts.held ? cardBlocked : card}>
      <QueueHeader c={c} />
      <QueueDetails c={c} />
      {facts.held ? <div className="mt-3 space-y-3">{facts.blocked ? <BlockedActions c={c} /> : <PlainActions c={c} />}</div> : null}
      {facts.held && !c.registered ? <p className={`mt-2 ${muted}`}>Сначала зарегистрируйте второй фактор.</p> : null}
      {facts.held && pk.has && pk.problem ? <p className="mt-2 text-destructive">{pk.problem}</p> : null}
      <TouchNote text={c.touching} />
      <Msg error={c.act.error} ok={c.act.ok} />
    </div>
  );
}
