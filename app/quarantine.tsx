import { useState } from "react";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";
import type { SkillQueueView } from "../src/skills/guard";
import { canRestore, rejectedAtOf, rejectedByText, cardColor } from "../src/ux";
import { isMismatch } from "../src/ux";
import { useApproval, RoutineCode } from "./approval";
import { awayEventsOf } from "./away";
import { useCodeAction, type Rpc } from "./code";
import { useProof, ProofField, ProofNotes } from "./confirm";
import { Origin, AuthorWhy } from "./review-card";
import { card, btn, btnPrimary, muted, cardBlocked, when, Msg, Section } from "./ui";

export function rejectedOf(queue: QueueRow[]): QueueRow[] {
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

export function QuarantineRow({ q, ov, rpc, refetch, onTrustPending, onShowCard, kept, onUnkeep }: { q: QueueRow; ov: Overview; rpc: Rpc; refetch: () => void; onTrustPending: (entry: string, label: string) => void; onShowCard: (id: number) => void; kept: boolean; onUnkeep: (q: QueueRow) => void }) {
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
        <span className={red && !kept ? "font-semibold text-destructive" : muted}>{kept ? "оставлен вами в карантине" : red ? "остановлен" : "ждёт решения"} · {when(q.firstSeen)}</span>
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

export function RemovedSkillRow({ q, ov, rpc, refetch }: { q: SkillQueueView; ov: Overview; rpc: Rpc; refetch: () => void }) {
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
export const removedSkillsOf = (ov: Overview): SkillQueueView[] => [...ov.skills.open, ...ov.skills.recent].filter((s, i, all) => s.state === "removed" && all.findIndex((x) => x.id === s.id) === i);

/** The versions the person rejected and has not brought back: one row per (plugin, hash), the newest; none if the same version is held or approved since. */
export function RejectedRow({ q, ov, rpc, refetch }: { q: QueueRow; ov: Overview; rpc: Rpc; refetch: () => void }) {
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

export function QuarantineTab({ ov, rpc, refetch, onTrustPending, onShowCard, isKept, onUnkeep }: { ov: Overview; rpc: Rpc; refetch: () => void; onTrustPending: (entry: string, label: string) => void; onShowCard: (id: number) => void; isKept: (q: QueueRow) => boolean; onUnkeep: (q: QueueRow) => void }) {
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
