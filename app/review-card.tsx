import { useState } from "react";
import { useBbNavigate } from "@get-bb/plugin-sdk/app";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";
import type { QueueUx } from "../src/uxview";
import { approvedNote, uniqueSentences, capsWithPaths, redWhere, cardFoldId, cardKey, capabilitySegments, cardColor, detailLevel, MISMATCH_HINT, cardRisk, FREQ_BUTTON, FREQ_NOT_NOW, type FreqHint, bypassAllowed, mismatchText, redText, yellowText, actionLabel, deleteConfirmText, deletedNote, trustButton, windowAvailability } from "../src/ux";
import { isMismatch, approveVerb, enabledWhat, agentConfigNote, scopeText } from "../src/ux";
import { DELETE_CONFIRM_BUTTONS, hasNoGuardRecord, NO_RECORD_FIX, NO_RECORD_HEADLINE, NO_RECORD_LINE } from "../src/ux";
import { ChecksView } from "./checks";
import { useCodeAction, type Rpc } from "./code";
import { useProof, ProofField, Emph, ProofNotes } from "./confirm";
import { cardYellow } from "./header";
import { ScanResultView, ScanButton } from "./scan";
import { card, btn, btnPrimary, input, muted, cardBlocked, btnDanger, Fold, Msg } from "./ui";

/** «откуда»: thread → subthread (links), then the source in words. */
export function Origin({ ux, q }: { ux: QueueUx | undefined; q: QueueRow }) {
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
export function AuthorWhy({ why }: { why: string | null | undefined }) {
  if (!why) return null;
  return (
    <p className="mt-1">
      <em>«{why}»</em> <span className={`text-xs ${muted}`}>— со слов автора, не проверено</span>
    </p>
  );
}

export interface ReviewProps {
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
  /** The person approves this plugin or its source often: a question with ready buttons (on one card at a time). */
  freq?: FreqHint | null;
  /** The hint was used or put away. */
  onFreqDone?: () => void;
}

/** Yellow «Проверьте» (a new right or an unknown source) and red «Остановлено» (a hard flag). Every action on it is about THIS version, and says so. */
export function ReviewCard({ q, ov, rpc, refetch, deferred, onDefer, onKeep, onTrustPending, slotted = true, fresh = false, freq = null, onFreqDone }: ReviewProps) {
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
  const risk = noRecord ? { level: "caution" as const, text: NO_RECORD_HEADLINE } : cardRisk(q, found, ov.policy.flowDowngrade);
  const allowedWhat = enabledWhat(q.pluginId, q.version);
  const verb = approveVerb(risk);
  const configNote = agentConfigNote(found?.findings ?? []);
  const riskClass = risk.level === "safe" ? "text-green-800 dark:text-green-300" : risk.level === "danger" ? "text-red-700 dark:text-red-400" : "text-yellow-900 dark:text-yellow-200";
  const trustEntry = ux?.entry ?? null;
  const blockedApprove = unsafeDir || !proof.ready({ routine: true });
  const win = windowAvailability({ threadId: q.threadId, queueId: q.id, sourceKind: q.sourceKind, level: ux?.level ?? "unknown" });
  const trust = trustButton({ entry: trustEntry, level: ux?.level ?? "unknown", queueId: q.id });
  const openWindowNow = () => void act.run(async () => { await proof.run({ kind: "window.open", queueId: q.id }, (p) => rpc.call("window.open", { queueId: q.id, ...p } as never), { routine: true }); onFreqDone?.(); });
  const approveTrustNow = () =>
    void act.run(async () => {
      const r = (await proof.run({ kind: "approve.trust", queueId: q.id }, (p) => rpc.call("queue.approveTrust", { id: q.id, ...p } as never))) as { note: string };
      onFreqDone?.();
      return { note: `${r.note}. Новые версии из этого источника идут без вопросов, пока плагин не попросит новых прав.` };
    }, `${allowedWhat}, источник доверенный`);
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
      {freq && !red ? (
        <div className="mt-2 rounded-md border border-blue-400 p-2 text-sm dark:border-blue-700" data-secure-bb-freq={freq.scope}>
          <p>{freq.text}</p>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            {freq.offer.map((o, i) => (
              <button key={o} className={i === 0 ? btnPrimary : btn} disabled={act.busy || blockedApprove || (o === "window" && !proof.ready({ routine: true }))} onClick={o === "trust" ? approveTrustNow : openWindowNow}>{FREQ_BUTTON[o](ov.policy.windowMin)}</button>
            ))}
            <button className={btn} onClick={onFreqDone}>{FREQ_NOT_NOW}</button>
          </div>
        </div>
      ) : null}
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
                <button className={btn} disabled={act.busy || !proof.ready({ routine: true })} onClick={openWindowNow}>
                  Доверять новым версиям {ov.policy.windowMin} мин
                </button>
              ) : null}
              {trust.enabled ? <button
                className={btn}
                disabled={act.busy || blockedApprove}
                title="Одна операция: разрешить версию и добавить источник. Одно касание."
                onClick={approveTrustNow}
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
          <ScanResultView scan={ov.ai.queueScans[q.id]} enabled={ov.ai.settings.enabled} />
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
export function PendingTrust({ entries, ov, rpc, refetch, onDone }: { entries: Array<{ entry: string; label: string }>; ov: Overview; rpc: Rpc; refetch: () => void; onDone: (entry: string) => void }) {
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
