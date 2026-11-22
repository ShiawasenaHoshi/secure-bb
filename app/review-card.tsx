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
import { useProof, type ProofHook } from "./proof";
import { ScanResultView, ScanButton } from "./scan";
import { card, btn, btnPrimary, input, muted, btnDanger, Fold, FoldAccordion, Msg, Tip } from "./ui";
import { LEVEL_LABEL, reviewView, type CardLevel, type ReviewView } from "../src/cardview";
import type { CheckResult } from "../src/checks/types";
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

/** The state and the actions of one card (what a press does); the pieces below only draw. */
interface Ctl extends ReviewProps {
  v: ReviewView;
  found: CheckResult | undefined;
  ux: QueueUx | undefined;
  act: ReturnType<typeof useCodeAction>;
  proof: ProofHook;
  mode: ReturnType<typeof detailLevel>;
  /** The button of an approval is off while the directory is unsafe or no second factor is set up. */
  blockedApprove: boolean;
  approve: (acknowledgeBlock: boolean) => Promise<unknown>;
  approveNow: () => void;
  openWindowNow: () => void;
  approveTrustNow: () => void;
  del: () => void;
  confirmDelete: boolean;
  setConfirmDelete: (on: boolean) => void;
  /** The name of the plugin typed under «Всё равно разрешить…». */
  typed: string;
  setTyped: (v: string) => void;
}

function useReviewCtl(p: ReviewProps): Ctl {
  const { q, ov, rpc, onFreqDone } = p;
  const act = useCodeAction(p.refetch, { pin: true, ...(p.slotted !== false ? { slot: { key: q.pluginId, elId: `sbb-card-${q.id}` } } : {}) });
  const proof = useProof(ov, rpc, `card:${cardKey(q)}`);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [typed, setTyped] = useState("");
  const found = ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined);
  const ux = ov.ux[q.id];
  const v = reviewView({ q, found, ux, flowDowngrade: ov.policy.flowDowngrade });
  const approve = (acknowledgeBlock: boolean) =>
    proof.run({ kind: "approve", queueId: q.id, acknowledgeBlock }, (x) => rpc.call("queue.approve", { id: q.id, ...x, acknowledgeBlock } as never), { routine: true, dangerous: acknowledgeBlock, what: acknowledgeBlock ? `Всё равно разрешить ${q.pluginId} ${q.version}` : v.approveWhat, detail: acknowledgeBlock ? "Так ведут себя вредоносные плагины. Разрешайте, только если вы сами написали этот плагин." : v.risk.text });
  const approveNow = () => void act.run(async () => { await approve(false); return { note: approvedNote(q.pluginId, q.version) }; }, v.allowedWhat);
  const openWindowNow = () => void act.run(async () => { await proof.run({ kind: "window.open", queueId: q.id }, (x) => rpc.call("window.open", { queueId: q.id, ...x } as never), { routine: true, what: `Доверять новым версиям ${q.pluginId} ${ov.policy.windowMin} мин`, ...(v.win.note ? { detail: v.win.note } : {}) }); onFreqDone?.(); });
  const approveTrustNow = () =>
    void act.run(async () => {
      const r = (await proof.run({ kind: "approve.trust", queueId: q.id }, (x) => rpc.call("queue.approveTrust", { id: q.id, ...x } as never), { what: `${v.approveWhat} и доверять источнику`, ...(v.trust.note ? { detail: v.trust.note } : {}) })) as { note: string };
      onFreqDone?.();
      return { note: `${r.note}. Новые версии из этого источника идут без вопросов, пока плагин не попросит новых прав.` };
    }, `${v.allowedWhat}, источник добавлен в «мои источники»`);
  const del = () =>
    void act.run(async () => {
      await rpc.call("queue.dismiss", { id: q.id });
      setConfirmDelete(false);
      return { note: deletedNote(q.pluginId, q.version) };
    }, `удалён плагин ${q.pluginId} ${q.version}`);
  return { ...p, v, found, ux, act, proof, mode: detailLevel(ov.guard?.trust?.mode ?? null), blockedApprove: v.unsafeDir || !proof.ready({ routine: true }), approve, approveNow, openWindowNow, approveTrustNow, del, confirmDelete, setConfirmDelete, typed, setTyped };
}

function CardHead({ c }: { c: Ctl }) {
  const { q, v, ux, fresh } = c;
  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="flex flex-wrap items-baseline gap-x-2 text-lg font-semibold leading-tight" data-secure-bb-risk={v.risk.level}>
            <span className="break-all">{q.pluginId}</span>
            <span className={`text-xs font-normal ${muted}`}>{q.version}</span>
            {fresh ? <Badge variant="secondary">новое</Badge> : null}
          </h3>
        </div>
        <LevelBadge level={v.level} />
      </div>
      <div className="mt-2 space-y-1">
        <SourceChip ux={ux} q={q} />
        <Origin ux={ux} />
      </div>
    </>
  );
}

function WhyLine({ c }: { c: Ctl }) {
  const { v } = c;
  if (v.why.byAuthor) return <p className="mt-3" data-secure-bb-why><em>«{v.why.text}»</em> <span className={`text-xs ${muted}`}>— со слов автора, не проверено</span></p>;
  const sentence = v.red || v.noRecord ? (v.noRecord ? NO_RECORD_LINE : v.text.line) : v.why.text;
  return <p className="mt-3" data-secure-bb-why><Emph text={sentence} /></p>;
}

function RightRows({ rights }: { rights: ReviewView["rights"] }) {
  const [all, setAll] = useState(false);
  if (rights.rows.length === 0) return null;
  return (
    <ul className="mt-3 space-y-1.5" data-secure-bb-rights>
      {(all ? rights.rows : rights.visible).map((r) => (
        <li key={r.kind} className="flex items-start gap-2" data-secure-bb-right={r.kind} data-danger={r.danger ? "true" : undefined}>
          <Icon name={r.icon} aria-hidden="true" className={cn("mt-0.5 size-4 shrink-0", r.danger ? "text-destructive" : muted)} />
          <span className="min-w-0">
            <span className={r.danger ? "font-medium text-destructive" : "font-medium"}>{r.label}</span>
            {r.detail ? <span className={muted}> · {r.detail}</span> : null}
          </span>
        </li>
      ))}
      {rights.more.length > 0 && !all ? <li><button type="button" className={`text-xs underline hover:no-underline ${muted}`} onClick={() => setAll(true)}>ещё {rights.more.length}</button></li> : null}
    </ul>
  );
}

function CardBody({ c }: { c: Ctl }) {
  const { q, v } = c;
  return (
    <>
      {v.red || v.mismatch ? <p className="mt-3 font-medium text-destructive">{v.text.title}</p> : null}
      <WhyLine c={c} />
      {v.noRecord && q.reason ? <p className={`text-xs ${muted}`}>({q.reason.replace(/\.$/, "")}.)</p> : null}
      {v.configNote && !v.red ? <p className="mt-1 text-xs">{v.configNote}</p> : null}
      <RightRows rights={v.rights} />
      {v.rights.networkNote ? <p className={`mt-1.5 text-xs ${muted}`}>{v.rights.networkNote}</p> : null}
    </>
  );
}

/** «Вы часто одобряете…»: ready buttons for this plugin or its source (on one card at a time). */
function FreqHintBox({ c }: { c: Ctl }) {
  const { freq, v, act, proof, ov, blockedApprove, onFreqDone } = c;
  if (!freq || v.red) return null;
  return (
    <div className="mt-3 rounded-md border border-border bg-muted p-2" data-secure-bb-freq={freq.scope}>
      <p>{freq.text}</p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {freq.offer.map((o, i) => (
          <Button key={o} size="sm" variant={i === 0 ? "default" : "outline"} disabled={act.busy || blockedApprove || (o === "window" && !proof.ready({ routine: true }))} onClick={o === "trust" ? c.approveTrustNow : c.openWindowNow}>{FREQ_BUTTON[o](ov.policy.windowMin)}</Button>
        ))}
        <Button size="sm" variant="ghost" onClick={onFreqDone}>{FREQ_NOT_NOW}</Button>
      </div>
    </div>
  );
}

function LaterButton({ c }: { c: Ctl }) {
  const { q, v, act, deferred } = c;
  if (v.red) return <Tip tip="Плагин остаётся в карантине, не запущен; карточка уходит из «Ждут решения», красный статус снимается"><Button size="sm" variant="ghost" disabled={act.busy} onClick={() => c.onKeep(q)}>Оставить в карантине</Button></Tip>;
  return <Button size="sm" variant="ghost" disabled={act.busy} onClick={() => c.onDefer(q, !deferred)}>{deferred ? "Вернуть в список" : "Решить позже"}</Button>;
}

function CardButtons({ c }: { c: Ctl }) {
  const { q, v, act, proof, blockedApprove } = c;
  return (
    <div className="mt-4 flex flex-wrap items-center gap-2">
      {v.canApprove ? <Button size="sm" disabled={act.busy || blockedApprove} onClick={c.approveNow}>{v.approveWhat}</Button> : null}
      <Button size="sm" variant={v.canApprove ? "outline" : "default"} disabled={act.busy} onClick={() => c.setConfirmDelete(true)}>
        {v.noRecord ? `${NO_RECORD_FIX}: ${q.pluginId} ${q.version}` : actionLabel("Удалить", q.pluginId, q.version)}
      </Button>
      <LaterButton c={c} />
      {v.canApprove ? <ProofField proof={proof} routine /> : null}
    </div>
  );
}

function DeleteDialog({ c }: { c: Ctl }) {
  const { q, act } = c;
  return (
    <AlertDialog open={c.confirmDelete} onOpenChange={c.setConfirmDelete}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{deleteConfirmText(q.pluginId, q.version)}</AlertDialogTitle>
          <AlertDialogDescription>Плагин будет удалён из карантина.</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogAction disabled={act.busy} onClick={c.del}>{DELETE_CONFIRM_BUTTONS[0]}</AlertDialogAction>
          <AlertDialogCancel disabled={act.busy}>{DELETE_CONFIRM_BUTTONS[1]}</AlertDialogCancel>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function CodePanel({ c }: { c: Ctl }) {
  const { q, ov, rpc, refetch, v, found } = c;
  const caps = v.caps.map((x) => capabilitySegments(x).map((y) => y.text).join("")).join("; ");
  return (
    <TabsContent value="code" className="space-y-2 pt-3">
      {v.caps.length > 0 ? <p className="text-xs">Возможности: <Emph text={caps} />.</p> : <p className={`text-xs ${muted}`}>Особых возможностей в коде не найдено.</p>}
      <ChecksView id={cardFoldId(q, "checks")} result={found} />
      <ScanResultView scan={ov.ai.queueScans[q.id]} enabled={ov.ai.settings.enabled} />
      <ScanButton ov={ov} target={{ queueId: q.id }} rpc={rpc} refetch={refetch} />
    </TabsContent>
  );
}

function TermPanel({ c }: { c: Ctl }) {
  const { q, ov, v, act, proof, blockedApprove } = c;
  return (
    <TabsContent value="term" className="space-y-2 pt-3">
      <p className={muted}>{scopeText(q.version)} «{v.approveWhat}» действует только на эту версию.</p>
      <div className="flex flex-wrap items-center gap-2">
        {v.win.available ? <Button size="sm" variant="outline" disabled={act.busy || !proof.ready({ routine: true })} onClick={c.openWindowNow}>Доверять новым версиям {ov.policy.windowMin} мин</Button> : null}
        {v.trust.enabled ? (
          <Tip tip="Одна операция: разрешить версию и добавить источник. Одно касание.">
            <Button size="sm" variant="outline" disabled={act.busy || blockedApprove} onClick={c.approveTrustNow}>Разрешить и доверять источнику</Button>
          </Tip>
        ) : null}
      </div>
      <p className={muted}>{uniqueSentences([v.win.note ?? "Временное доверие: новые версии этого плагина из этого чата проходят без вопросов на время.", v.trust.note]).join(" ")}</p>
    </TabsContent>
  );
}

/** «Всё равно разрешить…» on a red card: the name of the plugin typed and a fresh touch. */
function BypassFold({ c }: { c: Ctl }) {
  const { q, v, act, proof, typed } = c;
  const go = () => void act.run(async () => { await c.approve(true); c.setTyped(""); return { note: approvedNote(q.pluginId, q.version) }; }, v.allowedWhat);
  return (
    <Fold id={cardFoldId(q, "bypass")} className="mt-2 rounded-md border border-destructive p-2" summaryClassName="cursor-pointer text-destructive" summary="Всё равно разрешить…">
      <p className="mt-2">Так ведут себя вредоносные плагины. Разрешайте, только если вы сами написали этот плагин и знаете, почему проверки сработали. Для этого нужны касание и имя плагина.</p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="w-56 rounded-md border border-input bg-background px-2 py-1.5 font-mono text-sm" placeholder={q.pluginId} aria-label="Введите имя плагина" value={typed} onChange={(e) => c.setTyped(e.target.value)} />
        <ProofField proof={proof} routine dangerous />
        <Button size="sm" variant="destructive" disabled={act.busy || typed !== q.pluginId || v.unsafeDir || !proof.ready({ routine: true, dangerous: true })} onClick={go}>Всё равно разрешить</Button>
      </div>
    </Fold>
  );
}

function RedTail({ c }: { c: Ctl }) {
  const { q, ov, v, mode } = c;
  if (!v.red) return null;
  return (
    <>
      {bypassAllowed(ov.guard?.trust?.mode ?? null, q) ? <BypassFold c={c} /> : null}
      {v.mismatch ? <p className={`mt-2 ${muted}`}>{MISMATCH_HINT}</p> : null}
      {!v.mismatch && !mode.bypass ? <p className={`mt-2 ${muted}`}>В режиме «Строгий» обойти остановку нельзя. Чтобы разрешить, сначала ослабьте режим (касанием) на вкладке «Доверие и исключения».</p> : null}
    </>
  );
}

function TechPanel({ c }: { c: Ctl }) {
  const { q, v, mode } = c;
  return (
    <TabsContent value="tech" className="space-y-1 pt-3">
      {v.red ? <p className={`text-xs ${muted}`}>{scopeText(q.version)}</p> : null}
      <p className="break-all text-xs">{q.sourceKind}: {q.source} · версия {q.version}{q.trigger ? ` · ${q.trigger}` : ""}</p>
      {q.reason ? <p className="text-xs">Причина: {q.reason}</p> : null}
      {mode.hashes && q.contentHash ? <p className="break-all font-mono text-xs">{q.contentHash}</p> : null}
      <RedTail c={c} />
    </TabsContent>
  );
}

function Details({ c }: { c: Ctl }) {
  const { q, v, mode } = c;
  const [tab, setTab] = useState<DetailTab>("code");
  return (
    <FoldAccordion id={cardFoldId(q, "more")} className="mt-4" defaultOpen={mode.expanded || v.risk.look === true} title="Подробнее">
      <Tabs value={tab} onValueChange={(x) => setTab(x as DetailTab)}>
        <TabsList>
          <TabsTrigger value="code">Где это в коде</TabsTrigger>
          {!v.red ? <TabsTrigger value="term">На какой срок</TabsTrigger> : null}
          <TabsTrigger value="tech">Технические подробности</TabsTrigger>
        </TabsList>
        <CodePanel c={c} />
        {!v.red ? <TermPanel c={c} /> : null}
        <TechPanel c={c} />
      </Tabs>
    </FoldAccordion>
  );
}

/**
 * The card of a version that waits: the name, the source, one line of why, the rights as rows, three buttons. «Опасно» / «Нужна проверка» / «Только оформление»
 * is the badge and the thin stripe on the left; the card itself is neutral. Every action on it is about THIS version, and says so.
 * A decision is made with a touch or a code in the one confirmation dialog (an open session covers a routine one: then it just runs).
 * What the card shows is decided in `reviewView` (src/cardview.ts); here it is drawn.
 */
export function ReviewCard(p: ReviewProps) {
  const c = useReviewCtl(p);
  const { q, v } = c;
  return (
    <Card className={cn("border-l-4 p-4 text-sm", STRIPE[v.level])} id={`sbb-card-${q.id}`} data-secure-bb-card={v.red ? "red" : "yellow"} data-secure-bb-version={q.version} data-secure-bb-level-of={v.level}>
      <CardHead c={c} />
      <CardBody c={c} />
      <FreqHintBox c={c} />
      {v.unsafeDir ? <p className="mt-3 font-medium text-destructive">Разрешить нельзя: в папке плагина или выше может писать кто-то кроме пользователя сервера, и после проверки файлы можно подменить. Исправьте права или предложите плагин через <span className="font-mono">bb secure-bb propose</span>.</p> : null}
      <CardButtons c={c} />
      {v.red && c.deferred ? <p className="mt-1"><Button size="sm" variant="ghost" onClick={() => c.onDefer(q, false)}>Вернуть в список</Button></p> : null}
      <DeleteDialog c={c} />
      <Details c={c} />
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
