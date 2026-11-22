import { useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";
import { cardFoldId, isBlockedEntry, MISMATCH_HINT } from "../src/ux";
import { isMismatchEntry } from "../src/ux";
import { useApproval, RoutineCode } from "./approval";
import { ChecksView } from "./checks";
import { useCodeAction, TouchNote } from "./code";
import { usePasskey, touchFor } from "./touch";
import { ScanResultView, ScanButton } from "./scan";
import { card, btn, btnPrimary, input, muted, cardBlocked, btnDanger, when, Fold, Msg } from "./ui";

/** A local proposal has a negative id inside; the person reads "предложение 4", not "#-4". */
export const queueLabel = (id: number): string => (id < 0 ? `предложение ${-id}` : `#${id}`);

export function QueueCard({ q, ov, rpc, refetch }: { q: QueueRow; ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const held = q.status === "held";
  const unsafeDirNow = q.reason?.startsWith("каталог доступен на запись другим") ?? false;
  const ap = useApproval();
  const found = ov.queueChecks[q.id];
  const blocked = isBlockedEntry({ reason: q.reason, reasonKind: q.reasonKind, blocks: q.blocks, findings: found?.findings ?? [] });
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
        <span className={blocked && held ? "font-semibold text-destructive" : muted}>
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
      {q.reason ? <p className={`mt-1 ${blocked || unsafeDir ? "font-semibold text-destructive" : muted}`}>{q.reason}</p> : null}
      {unsafeDir && held ? <p className="mt-1 text-destructive">Одобрить нельзя: пока в каталоге или выше может писать кто-то кроме пользователя сервера, его содержимое может измениться после проверки. Исправьте права (владелец — пользователь сервера, без записи для группы и остальных) или предложите плагин через <span className="font-mono">bb secure-bb propose</span>: снимок гейт хранит у себя.</p> : null}
      <ChecksView id={cardFoldId(q, "checks-q")} result={ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined)} />
      <ScanResultView scan={ov.ai.queueScans[q.id]} enabled={ov.ai.settings.enabled} />
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
              {isMismatchEntry(q) ? <p className={muted}>{MISMATCH_HINT}</p> : <Fold id={cardFoldId(q, "force")} className="rounded-md border border-destructive p-2" summaryClassName="cursor-pointer text-destructive" summary="Всё равно одобрить (опасно)…">
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
