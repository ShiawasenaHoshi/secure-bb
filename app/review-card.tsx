import { useState } from "react";
import { useBbNavigate } from "@get-bb/plugin-sdk/app";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";
import type { QueueUx } from "../src/uxview";
import { approvedNote, uniqueSentences, capsWithPaths, redWhere, cardFoldId, cardKey, capabilitySegments, cardColor, detailLevel, MISMATCH_HINT, cardRisk, FREQ_BUTTON, FREQ_NOT_NOW, type FreqHint, bypassAllowed, mismatchText, redText, yellowText, actionLabel, deleteConfirmText, deletedNote, trustButton, windowAvailability } from "../src/ux";
import { isMismatchEntry, approveVerb, enabledWhat, agentConfigNote, scopeText, meaningfulCaps } from "../src/ux";
import { Card } from "../components/ui/card";
import { DELETE_CONFIRM_BUTTONS, hasNoGuardRecord, NO_RECORD_FIX, NO_RECORD_HEADLINE, NO_RECORD_LINE } from "../src/ux";
import { ChecksView } from "./checks";
import { useCodeAction } from "./code";
import { type Rpc } from "./touch";
import { ProofField, Emph, ProofNotes } from "./confirm";
import { useProof } from "./proof";
import { ScanResultView, ScanButton } from "./scan";
import { card, btn, btnPrimary, input, muted, btnDanger, Fold, FoldAccordion, Msg, Tip } from "./ui";
import { cardLevel, LEVEL_LABEL, permissionList, whyLine, type CardLevel } from "../src/cardview";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Icon } from "../components/ui/icon";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "../components/ui/alert-dialog";
import { cn } from "../lib/utils";

/** The badge of the level: «Опасно» is the only red thing on a card. */
export function LevelBadge({ level }: { level: CardLevel }) {
  return level === "danger" ? (
    <Badge variant="destructive" data-secure-bb-level="danger">{LEVEL_LABEL.danger}</Badge>
  ) : level === "check" ? (
    <Badge variant="outline" className="gap-1" data-secure-bb-level="check">
      <Icon name="AlertTriangle" aria-hidden="true" className="size-3" />
      {LEVEL_LABEL.check}
    </Badge>
  ) : (
    <Badge variant="secondary" data-secure-bb-level="calm">{LEVEL_LABEL.calm}</Badge>
  );
}

const STRIPE: Record<CardLevel, string> = { danger: "border-l-destructive", check: "border-l-muted-foreground", calm: "border-l-border" };

/** «откуда»: thread → subthread (links), when the plugin came from a chat. */
export function Origin({ ux }: { ux: QueueUx | undefined }) {
  const nav = useBbNavigate();
  const chain = ux?.chain ?? [];
  if (chain.length === 0) return null;
  return (
    <p className={`break-words text-xs ${muted}`}>
      Из чата:{" "}
      {chain.map((t, i) => (
        <span key={t.id}>
          {i > 0 ? " → " : ""}
          <button type="button" className="underline hover:no-underline" onClick={() => nav.toThread(t.id)}>{t.title ?? `чат ${t.id}`}</button>
        </span>
      ))}
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

/** The source as a chip: the address in words as the page knows it; «неизвестный источник» as a badge when it is one. */
export function SourceChip({ ux, q }: { ux: QueueUx | undefined; q: QueueRow }) {
  const label = ux?.sourceLabel ?? q.source;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {/* One line: a long address is cut with an ellipsis and stands in full in the hint (on a phone it must not wrap inside its frame). */}
      <Tip tip={label} className="min-w-0 max-w-full">
        <Badge variant="outline" className="inline-block max-w-full truncate font-mono text-xs font-normal" data-secure-bb-source>{label}</Badge>
      </Tip>
      {ux ? (
        ux.level === "unknown" ? <Badge variant="secondary">неизвестный источник</Badge> : <Badge variant="secondary">{ux.level === "own" ? "ваш источник" : "известный источник"}</Badge>
      ) : null}
    </div>
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

type DetailTab = "code" | "term" | "tech";

/**
 * The card of a version that waits: the name, the source, one line of why, the rights as rows, three buttons. «Опасно» / «Нужна проверка» / «Только оформление»
 * is the badge and the thin stripe on the left; the card itself is neutral. Every action on it is about THIS version, and says so.
 * A decision is made with a touch or a code in the one confirmation dialog (an open session covers a routine one: then it just runs).
 */
export function ReviewCard({ q, ov, rpc, refetch, deferred, onDefer, onKeep, onTrustPending, slotted = true, fresh = false, freq = null, onFreqDone }: ReviewProps) {
  const act = useCodeAction(refetch, { pin: true, ...(slotted ? { slot: { key: q.pluginId, elId: `sbb-card-${q.id}` } } : {}) });
  const proof = useProof(ov, rpc, `card:${cardKey(q)}`);
  const [typed, setTyped] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [tab, setTab] = useState<DetailTab>("code");
  const [allRows, setAllRows] = useState(false);
  const found = ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined);
  const ux = ov.ux[q.id];
  const detail = detailLevel(ov.guard?.trust?.mode ?? null);
  const color = cardColor({ reason: q.reason, reasonKind: q.reasonKind, blocks: q.blocks, findings: found?.findings ?? [] });
  const unsafeDir = q.reason?.startsWith("каталог доступен на запись другим") ?? false;
  const caps = capsWithPaths(found);
  const red = color === "red";
  const text = isMismatchEntry(q)
    ? mismatchText(q.pluginId, q.version)
    : red
    ? (() => {
        const r = redText((found?.findings ?? []).filter((f) => f.severity === "block").map((f) => f.rule));
        return { title: `Остановлено: ${r.title}`, line: `Плагин «${q.pluginId}» ${q.version}. ${r.line}${redWhere(caps) ? ` ${redWhere(caps)}` : ""} Плагин не запущен.` };
      })()
    : yellowText({ pluginId: q.pluginId, version: q.version, level: ux?.level ?? "unknown", sourceLabel: ux?.sourceLabel ?? q.source, reason: q.reason, reasonKind: q.reasonKind, caps });
  // A version the guard has no record of (it loaded without the guard's check): nothing here can approve it, and a green «можно включить» would be a lie.
  const noRecord = hasNoGuardRecord(q);
  const risk = noRecord ? { level: "caution" as const, text: NO_RECORD_HEADLINE } : cardRisk(q, found, ov.policy.flowDowngrade);
  // What the line that takes the card's place says (after «Готово: »).
  const allowedWhat = `${q.pluginId} ${q.version} разрешён и включён`;
  const verb = approveVerb(risk);
  const approveWhat = actionLabel(verb, q.pluginId, q.version);
  const level = cardLevel({ red, risk });
  const configNote = agentConfigNote(found?.findings ?? []);
  const trustEntry = ux?.entry ?? null;
  const blockedApprove = unsafeDir || !proof.ready({ routine: true });
  const win = windowAvailability({ threadId: q.threadId, queueId: q.id, sourceKind: q.sourceKind, level: ux?.level ?? "unknown" });
  const trust = trustButton({ entry: trustEntry, level: ux?.level ?? "unknown", queueId: q.id });
  const rights = permissionList(red ? caps : meaningfulCaps(caps), ov.policy.flowDowngrade);
  const why = whyLine({ authorWhy: ux?.why, caps, reasonLine: noRecord ? NO_RECORD_LINE : text.line });
  const approve = (acknowledgeBlock: boolean) =>
    proof.run({ kind: "approve", queueId: q.id, acknowledgeBlock }, (p) => rpc.call("queue.approve", { id: q.id, ...p, acknowledgeBlock } as never), { routine: true, dangerous: acknowledgeBlock, what: acknowledgeBlock ? `Всё равно разрешить ${q.pluginId} ${q.version}` : approveWhat, detail: acknowledgeBlock ? "Так ведут себя вредоносные плагины. Разрешайте, только если вы сами написали этот плагин." : risk.text });
  const openWindowNow = () => void act.run(async () => { await proof.run({ kind: "window.open", queueId: q.id }, (p) => rpc.call("window.open", { queueId: q.id, ...p } as never), { routine: true, what: `Доверять новым версиям ${q.pluginId} ${ov.policy.windowMin} мин`, ...(win.note ? { detail: win.note } : {}) }); onFreqDone?.(); });
  const approveTrustNow = () =>
    void act.run(async () => {
      const r = (await proof.run({ kind: "approve.trust", queueId: q.id }, (p) => rpc.call("queue.approveTrust", { id: q.id, ...p } as never), { what: `${approveWhat} и доверять источнику`, ...(trust.note ? { detail: trust.note } : {}) })) as { note: string };
      onFreqDone?.();
      return { note: `${r.note}. Новые версии из этого источника идут без вопросов, пока плагин не попросит новых прав.` };
    }, `${allowedWhat}, источник добавлен в «мои источники»`);
  const del = () =>
    void act.run(async () => {
      await rpc.call("queue.dismiss", { id: q.id });
      setConfirmDelete(false);
      return { note: deletedNote(q.pluginId, q.version) };
    }, `удалён плагин ${q.pluginId} ${q.version}`);
  const canApprove = !(red || noRecord);
  return (
    <Card className={cn("border-l-4 p-4 text-sm", STRIPE[level])} id={`sbb-card-${q.id}`} data-secure-bb-card={color} data-secure-bb-version={q.version} data-secure-bb-level-of={level}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="flex flex-wrap items-baseline gap-x-2 text-lg font-semibold leading-tight" data-secure-bb-risk={risk.level}>
            <span className="break-all">{q.pluginId}</span>
            <span className={`text-xs font-normal ${muted}`}>{q.version}</span>
            {fresh ? <Badge variant="secondary">новое</Badge> : null}
          </h3>
        </div>
        <LevelBadge level={level} />
      </div>
      <div className="mt-2 space-y-1">
        <SourceChip ux={ux} q={q} />
        <Origin ux={ux} />
      </div>
      {red || isMismatchEntry(q) ? <p className="mt-3 font-medium text-destructive">{text.title}</p> : null}
      <p className="mt-3" data-secure-bb-why>
        {why.byAuthor ? <><em>«{why.text}»</em> <span className={`text-xs ${muted}`}>— со слов автора, не проверено</span></> : red || noRecord ? <Emph text={noRecord ? NO_RECORD_LINE : text.line} /> : <Emph text={why.text} />}
      </p>
      {noRecord && q.reason ? <p className={`text-xs ${muted}`}>({q.reason.replace(/\.$/, "")}.)</p> : null}
      {configNote && !red ? <p className="mt-1 text-xs">{configNote}</p> : null}
      {rights.rows.length > 0 ? (
        <ul className="mt-3 space-y-1.5" data-secure-bb-rights>
          {(allRows ? rights.rows : rights.visible).map((r) => (
            <li key={r.kind} className="flex items-start gap-2" data-secure-bb-right={r.kind} data-danger={r.danger ? "true" : undefined}>
              <Icon name={r.icon} aria-hidden="true" className={cn("mt-0.5 size-4 shrink-0", r.danger ? "text-destructive" : muted)} />
              <span className="min-w-0">
                <span className={r.danger ? "font-medium text-destructive" : "font-medium"}>{r.label}</span>
                {r.detail ? <span className={muted}> · {r.detail}</span> : null}
              </span>
            </li>
          ))}
          {rights.more.length > 0 && !allRows ? (
            <li><button type="button" className={`text-xs underline hover:no-underline ${muted}`} onClick={() => setAllRows(true)}>ещё {rights.more.length}</button></li>
          ) : null}
        </ul>
      ) : null}
      {rights.networkNote ? <p className={`mt-1.5 text-xs ${muted}`}>{rights.networkNote}</p> : null}
      {freq && !red ? (
        <div className="mt-3 rounded-md border border-border bg-muted p-2" data-secure-bb-freq={freq.scope}>
          <p>{freq.text}</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {freq.offer.map((o, i) => (
              <Button key={o} size="sm" variant={i === 0 ? "default" : "outline"} disabled={act.busy || blockedApprove || (o === "window" && !proof.ready({ routine: true }))} onClick={o === "trust" ? approveTrustNow : openWindowNow}>{FREQ_BUTTON[o](ov.policy.windowMin)}</Button>
            ))}
            <Button size="sm" variant="ghost" onClick={onFreqDone}>{FREQ_NOT_NOW}</Button>
          </div>
        </div>
      ) : null}
      {unsafeDir ? <p className="mt-3 font-medium text-destructive">Разрешить нельзя: в папке плагина или выше может писать кто-то кроме пользователя сервера, и после проверки файлы можно подменить. Исправьте права или предложите плагин через <span className="font-mono">bb secure-bb propose</span>.</p> : null}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        {canApprove ? (
          <Button size="sm" disabled={act.busy || blockedApprove} onClick={() => void act.run(async () => { await approve(false); return { note: approvedNote(q.pluginId, q.version) }; }, allowedWhat)}>
            {approveWhat}
          </Button>
        ) : null}
        <Button size="sm" variant={canApprove ? "outline" : "default"} disabled={act.busy} onClick={() => setConfirmDelete(true)}>
          {noRecord ? `${NO_RECORD_FIX}: ${q.pluginId} ${q.version}` : actionLabel("Удалить", q.pluginId, q.version)}
        </Button>
        {red ? (
          <Tip tip="Плагин остаётся в карантине, не запущен; карточка уходит из «Ждут решения», красный статус снимается"><Button size="sm" variant="ghost" disabled={act.busy} onClick={() => onKeep(q)}>Оставить в карантине</Button></Tip>
        ) : (
          <Button size="sm" variant="ghost" disabled={act.busy} onClick={() => onDefer(q, !deferred)}>{deferred ? "Вернуть в список" : "Решить позже"}</Button>
        )}
        {canApprove ? <ProofField proof={proof} routine /> : null}
      </div>
      {red && deferred ? <p className="mt-1"><Button size="sm" variant="ghost" onClick={() => onDefer(q, false)}>Вернуть в список</Button></p> : null}
      <AlertDialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{deleteConfirmText(q.pluginId, q.version)}</AlertDialogTitle>
            <AlertDialogDescription>Плагин будет удалён из карантина.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction disabled={act.busy} onClick={del}>{DELETE_CONFIRM_BUTTONS[0]}</AlertDialogAction>
            <AlertDialogCancel disabled={act.busy}>{DELETE_CONFIRM_BUTTONS[1]}</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <FoldAccordion id={cardFoldId(q, "more")} className="mt-4" defaultOpen={detail.expanded || risk.look === true} title="Подробнее">
        <Tabs value={tab} onValueChange={(v) => setTab(v as DetailTab)}>
          <TabsList>
            <TabsTrigger value="code">Где это в коде</TabsTrigger>
            {!red ? <TabsTrigger value="term">На какой срок</TabsTrigger> : null}
            <TabsTrigger value="tech">Технические подробности</TabsTrigger>
          </TabsList>
          <TabsContent value="code" className="space-y-2 pt-3">
            {caps.length > 0 ? <p className="text-xs">Возможности: <Emph text={caps.map((c) => capabilitySegments(c).map((x) => x.text).join("")).join("; ")} />.</p> : <p className={`text-xs ${muted}`}>Особых возможностей в коде не найдено.</p>}
            <ChecksView id={cardFoldId(q, "checks")} result={found} />
            <ScanResultView scan={ov.ai.queueScans[q.id]} enabled={ov.ai.settings.enabled} />
            <ScanButton ov={ov} target={{ queueId: q.id }} rpc={rpc} refetch={refetch} />
          </TabsContent>
          {!red ? (
            <TabsContent value="term" className="space-y-2 pt-3">
              <p className={muted}>{scopeText(q.version)} «{approveWhat}» действует только на эту версию.</p>
              <div className="flex flex-wrap items-center gap-2">
                {win.available ? (
                  <Button size="sm" variant="outline" disabled={act.busy || !proof.ready({ routine: true })} onClick={openWindowNow}>
                    Доверять новым версиям {ov.policy.windowMin} мин
                  </Button>
                ) : null}
                {trust.enabled ? (
                  <Tip tip="Одна операция: разрешить версию и добавить источник. Одно касание.">
                    <Button size="sm" variant="outline" disabled={act.busy || blockedApprove} onClick={approveTrustNow}>
                      Разрешить и доверять источнику
                    </Button>
                  </Tip>
                ) : null}
              </div>
              <p className={muted}>{uniqueSentences([win.note ?? "Временное доверие: новые версии этого плагина из этого чата проходят без вопросов на время.", trust.note]).join(" ")}</p>
            </TabsContent>
          ) : null}
          <TabsContent value="tech" className="space-y-1 pt-3">
            {red ? <p className={`text-xs ${muted}`}>{scopeText(q.version)}</p> : null}
            <p className="break-all text-xs">{q.sourceKind}: {q.source} · версия {q.version}{q.trigger ? ` · ${q.trigger}` : ""}</p>
            {q.reason ? <p className="text-xs">Причина: {q.reason}</p> : null}
            {detail.hashes && q.contentHash ? <p className="break-all font-mono text-xs">{q.contentHash}</p> : null}
            {red && bypassAllowed(ov.guard?.trust?.mode ?? null, q) ? (
              <Fold id={cardFoldId(q, "bypass")} className="mt-2 rounded-md border border-destructive p-2" summaryClassName="cursor-pointer text-destructive" summary="Всё равно разрешить…">
                <p className="mt-2">Так ведут себя вредоносные плагины. Разрешайте, только если вы сами написали этот плагин и знаете, почему проверки сработали. Для этого нужны касание и имя плагина.</p>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <input className="w-56 rounded-md border border-input bg-background px-2 py-1.5 font-mono text-sm" placeholder={q.pluginId} aria-label="Введите имя плагина" value={typed} onChange={(e) => setTyped(e.target.value)} />
                  <ProofField proof={proof} routine dangerous />
                  <Button size="sm" variant="destructive" disabled={act.busy || typed !== q.pluginId || unsafeDir || !proof.ready({ routine: true, dangerous: true })} onClick={() => void act.run(async () => { await approve(true); setTyped(""); return { note: approvedNote(q.pluginId, q.version) }; }, allowedWhat)}>
                    Всё равно разрешить
                  </Button>
                </div>
              </Fold>
            ) : null}
            {red && isMismatchEntry(q) ? <p className={`mt-2 ${muted}`}>{MISMATCH_HINT}</p> : null}
            {red && !isMismatchEntry(q) && !detail.bypass ? <p className={`mt-2 ${muted}`}>В режиме «Строгий» обойти остановку нельзя. Чтобы разрешить, сначала ослабьте режим (касанием) на вкладке «Доверие и исключения».</p> : null}
          </TabsContent>
        </Tabs>
      </FoldAccordion>
    </Card>
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
