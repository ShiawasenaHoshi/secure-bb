import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { QueueRow } from "../src/store";
import { AWAY_KEY, DEFERRED_KEY, cardKey, KEPT_KEY, MODE_NAMES, WIZARD_KEY, awaySince, cardColor, deferKey, detailLevel, pageStatus, STOPPED_EXPLAIN, FREQ_KEY, FREQ_OFF_KEY, approvalEventsOf, parseFreqAt, pickFrequent, alarmCount, parseDeferred, wizardNeeded, GUARD_DOWN_TEXT, agentsSectionTab, decisionOf, launchProblem, moreVersionsText, planCards, trustButton, windowAvailability } from "../src/ux";
import { makeStub, stableOrder, layoutItems, type Stub } from "../src/ux";
import { DEFER_STUB_RESTORE, dropUnstamped, makeDeferStub, pageCounts, stampMark, withoutMark } from "../src/ux";
import { emptySnapshot, makeNote, restoreView, snapshotView, type ViewSnapshot } from "../src/stable-view";
import { openFold } from "../src/fold";
import type { ProblemRef, TabId } from "../src/ux";
import { AgentsAlarm, AgentsSection } from "./agents";
import { ApprovalContext, useApprovalSession, SessionBar } from "./approval";
import { SkillsLine, AwayCard } from "./away";
import { BatchCard } from "./batch";
import { press, enrollTokenOnce } from "./code";
import { lsGet, lsSet } from "./confirm";
import { GuardAlarm, GuardCard, MigrationCard } from "./guard";
import { TroubleshootBar, StatusHeader } from "./header";
import { ConfirmHost } from "./confirm-dialog";
import { TaintCard, LogCard } from "./journal";
import { PluginRow } from "./plugins";
import { PolicyCard, TrustedRepos } from "./policy";
import { ProtectedSection } from "./protected";
import { removedSkillsOf, QuarantineTab } from "./quarantine";
import { QueueCard } from "./queue-card";
import { StageCard, Registration } from "./registration";
import { ReviewCard, PendingTrust } from "./review-card";
import { PublishCard, AiCard } from "./scan";
import { SentinelSection } from "./sentinel";
import { SkillsSection } from "./skills";
import { ExceptionsTab } from "./trust";
import { card, muted, cardBlocked, when, useOverview, Fold, FoldAccordion, Section, type Note, type AnnounceOpts, DoneContext, AnchoredNotes, PinnedNotes, DONE_MS } from "./ui";
import { headerLine, splitAlarms } from "../src/pageview";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { EmptyState } from "../components/ui/empty-state";
import { TooltipProvider } from "../components/ui/tooltip";
import { Tabs, TabsList, TabsTrigger } from "../components/ui/tabs";
import { WatchSection } from "./watch";
import { WindowRows, JournalAlarm, gapsBySeverity, AliveAlarm } from "./windows";
import { Wizard } from "./wizard";

/** Tells the server this page is open, so a registration started now counts as attended. */
export function usePagePing(rpc: ReturnType<typeof useRpc<SecureBbRpc>>) {
  useEffect(() => {
    const ping = () => void rpc.call("page.ping").catch(() => undefined);
    ping();
    const t = setInterval(ping, 15_000);
    return () => clearInterval(t);
  }, [rpc]);
}

/** What a place gets for a moment when «Показать» takes the person to it: the theme's ring. */
const FLASH = ["ring-2", "ring-ring", "ring-offset-2", "ring-offset-background", "rounded-lg"];

export const TAB_LABEL: Record<TabId, string> = { status: "Обзор", quarantine: "Карантин", trust: "Доверие и исключения", more: "Журнал" };

export function GatePage() {
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
  // «Вы часто одобряете…»: when the hint was last used or put away, and whether the person switched it off (a convenience of this page, not a security fact).
  const [freqAt, setFreqAt] = useState<number | null>(() => parseFreqAt(lsGet(FREQ_KEY)));
  const [freqOff, setFreqOff] = useState<boolean>(() => lsGet(FREQ_OFF_KEY) === "1");
  const [wizardDone, setWizardDone] = useState<boolean>(() => lsGet(WIZARD_KEY) !== null);
  const [pending, setPending] = useState<Array<{ entry: string; label: string }>>([]);
  const [focus, setFocus] = useState<string | null>(null);
  // Scroll and focus survive a redraw: what the person did is remembered as it happens, and put back when a draw moved or dropped it.
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<ViewSnapshot>(emptySnapshot());
  const rememberView = useCallback(() => {
    if (scrollRef.current) viewRef.current = snapshotView(scrollRef.current, document);
  }, []);
  useLayoutEffect(() => {
    if (scrollRef.current) restoreView(scrollRef.current, document, viewRef.current);
  });
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
    setDoneNotes((l) => [...l, makeNote(id, text, { kind, anchor: opts.anchor })].slice(-4));
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
      // The jump is the person's own («Показать»): remembered at once, so that it is not taken for a draw's.
      rememberView();
      el.classList.add(...FLASH);
      window.setTimeout(() => el.classList.remove(...FLASH), 1800);
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
  // The count is by the journal: the guard's in guard mode, the plugin's own otherwise (the guard's record would count the same approval twice).
  const approvalEvents = approvalEventsOf(ov.guard?.connected ? (ov.guard.recent ?? []) : ov.log);
  const freqPick = pickFrequent(
    plan.active.map((c) => {
      const u = ov.ux[c.shown.id];
      return { pluginId: c.pluginId, source: c.shown.source, canTrust: trustButton({ entry: u?.entry ?? null, level: u?.level ?? "unknown", queueId: c.shown.id }).enabled, canWindow: windowAvailability({ threadId: c.shown.threadId, queueId: c.shown.id, sourceKind: c.shown.sourceKind, level: u?.level ?? "unknown" }).available };
    }),
    approvalEvents,
    ov.now,
    { off: freqOff, lastAt: freqAt },
    ov.policy.windowMin,
  );
  const onFreqDone = () => {
    lsSet(FREQ_KEY, String(Date.now()));
    setFreqAt(Date.now());
  };
  const setFreqSwitch = (off: boolean) => {
    lsSet(FREQ_OFF_KEY, off ? "1" : "0");
    setFreqOff(off);
  };
  const reds = planned.filter((c) => cardColorOf(c) === "red");
  const yellows = planned.filter((c) => cardColorOf(c) === "yellow");
  const alarms: ProblemRef[] = [];
  if (!ov.journal.ok) alarms.push({ anchor: "sbb-alarms", tab: "status", text: "Журнал решений нарушен" });
  if (gapsBySeverity(ov).critical.length > 0 || ov.alive.safeMode === true) alarms.push({ anchor: "sbb-alarms", tab: "status", text: gapsBySeverity(ov).critical.every((g) => g.text.mode === "guard") ? "Плагин secure-bb не работал" : "Гейт не всегда работал" });
  if (ov.guard?.connected && ov.guard.journal && !ov.guard.journal.valid) alarms.push({ anchor: "sbb-guard-alarm", tab: "status", text: "Журнал сторожа нарушен" });
  const agentsCritical = (ov.agents?.state?.drifts ?? []).filter((d) => d.class === "critical" && !d.initial).length;
  const agentsAlarms = (ov.agents?.state?.alarms ?? []).length;
  // While something critical or an alarm waits, the section is on «Статус» (the banner leads to it); otherwise it stays in «Журнал».
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
      <ReviewCard key={cardKey(c.shown)} q={c.shown} {...cardProps} deferred={deferred} fresh={freshRef.current.has(c.shown.pluginId)} freq={!deferred && freqPick?.pluginId === c.shown.pluginId ? freqPick.hint : null} onFreqDone={onFreqDone} />
      {c.others.length > 0 ? (
        <Fold id={`more-${c.shown.pluginId}`} className="ml-3" summary={`${moreVersionsText(c.others.length)} (${c.others.map((o) => o.version).join(", ")})`}>
          <div className="mt-2 space-y-2">{c.others.map((o) => <ReviewCard key={cardKey(o)} q={o} {...cardProps} deferred={isDeferred(o)} slotted={false} />)}</div>
        </Fold>
      ) : null}
    </div>
  );
  const agentsSection = ov.agents ? <Section id="sbb-agents" title={`Агенты: конфигурации и память${agentsAlarms > 0 || agentsCritical > 0 ? " (!)" : (ov.agents.state?.openTotal ?? 0) > 0 ? ` (${ov.agents.state?.openTotal})` : ""}`}><AgentsSection ov={ov} rpc={rpc} refetch={refetch} showDone={agentsTab !== "status"} /></Section> : null;
  const tabCount: Record<TabId, number> = { status: status.count, quarantine: counts.quarantine, trust: 0, more: 0 };
  // What the person has answered or put aside is not «waiting» any more: «Пока вас не было» does not repeat it.
  const keptIds = new Set([...plan.kept.map((q) => q.id), ...plan.later.flatMap((c) => c.all.map((q) => q.id))]);
  const header = headerLine({ status, waiting: counts.waiting, deferred: counts.deferred, alarms });
  const { calm: calmAlarms } = splitAlarms(alarms);
  const headerMore = guardDown ? GUARD_DOWN_TEXT : status.level === "stopped" ? STOPPED_EXPLAIN : null;
  return (
    <DoneContext.Provider value={doneCtx}>
    <ApprovalContext.Provider value={approval}>
    <TooltipProvider delayDuration={200}>
    <ConfirmHost ov={ov} rpc={rpc}>
    <div className="h-full overflow-y-auto" ref={scrollRef} onScroll={rememberView} onFocusCapture={rememberView} onKeyUp={rememberView} onPointerUp={rememberView}>
      <AnchoredNotes />
      <div className="mx-auto max-w-3xl space-y-6 p-4 sm:p-6">
        <h1 className="text-xl font-semibold">secure-bb</h1>
        <PinnedNotes />
        <TroubleshootBar until={ov.guard?.troubleshootUntil ?? 0} />
        <Tabs value={tab} onValueChange={(v) => setTab(v as TabId)}>
          <TabsList aria-label="Разделы secure-bb">
            {(["status", "quarantine", "trust", "more"] as const).map((t) => (
              <TabsTrigger key={t} value={t}>
                {TAB_LABEL[t]}
                {tabCount[t] > 0 ? <Badge variant="secondary" className="px-1.5 py-0">{tabCount[t]}</Badge> : null}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        {tab === "status" ? (
          <div className="space-y-6">
            {!wizardDone && wizardNeeded({ hasTrust: ov.guard?.trust != null, mySources: ov.guard?.trust?.mySources.length ?? 0, done: false }) ? <Wizard ov={ov} rpc={rpc} refetch={refetch} onClose={closeWizard} /> : null}
            <StatusHeader line={header} more={headerMore} onAction={header.target ? () => showProblem(header.target!) : null} session={<SessionBar ov={ov} rpc={rpc} session={approval.session} open={open} lock={lock} closed={sessionClosed} />} />
            {ov.totp.blockedUntil > 0 ? (
              <p className="rounded-md border border-destructive p-2 text-sm text-destructive">Слишком много неверных кодов: коды заблокированы до {when(ov.totp.blockedUntil)}.{(ov.guard?.passkey?.keys.length ?? 0) > 0 ? " Касание ключом работает: подпись не подобрать, поэтому её это не касается." : ""}</p>
            ) : null}
            <PendingTrust entries={pending} ov={ov} rpc={rpc} refetch={refetch} onDone={(e) => setPending((p) => p.filter((x) => x.entry !== e))} />
            <div id="sbb-alarms" className="space-y-2 empty:hidden">
              <JournalAlarm ov={ov} rpc={rpc} refetch={refetch} />
              <AliveAlarm ov={ov} />
            </div>
            <div id="sbb-guard-alarm" className="empty:hidden"><GuardAlarm ov={ov} /></div>
            <AgentsAlarm ov={ov} onShow={() => showProblem({ anchor: "sbb-agents", tab: agentsTab, text: "" })} />
            <WindowRows windows={ov.windows} cfgWindows={ov.watch.windows} rpc={rpc} refetch={refetch} />
            <Section title={`Ждут решения вас${counts.waiting > 0 ? ` (${counts.waiting})` : ""}`}>
              {activeItems.length === 0 ? <EmptyState message="Сейчас решать нечего — всё под защитой" className="py-2" /> : activeItems.map((it) => {
                if (it.stub) {
                  const st = it.stub;
                  return (
                    <Card key={`stub:${st.key}`} className="flex items-center justify-between gap-2 border-dashed p-4 text-sm font-medium" style={{ minHeight: st.height }} data-secure-bb-stub>
                      <span>{st.text}</span>
                      {st.restore ? (
                        <Button size="sm" variant="outline" onClick={() => { const r = st.restore!; const e = heldAll.find((x) => x.id === r.id); if (e) onDefer(e, false); else setStubs((l) => l.filter((x) => x.key !== st.key)); }}>{DEFER_STUB_RESTORE}</Button>
                      ) : (
                        <Button size="sm" variant="outline" onClick={() => setStubs((l) => l.filter((x) => x.key !== st.key))}>Скрыть</Button>
                      )}
                    </Card>
                  );
                }
                const c = plan.active.find((x) => x.pluginId === it.key)!;
                return renderCard(c, false);
              })}
            </Section>
            {plan.later.length > 0 ? (
              <FoldAccordion id="deferred" title={`Отложено (${counts.deferred})`}>
                <p className={`text-xs ${muted}`}>Вы отложили эти карточки кнопкой «Решить позже». Плагины остаются в карантине и не запущены.</p>
                <div className="mt-2 space-y-3">{laterOrder.order.map((k) => plan.later.find((c) => c.pluginId === k)).filter((c): c is NonNullable<typeof c> => c !== undefined).map((c) => renderCard(c, true))}</div>
              </FoldAccordion>
            ) : null}
            <AwayCard ov={ov} since={since} onSeen={seen} kept={keptIds} calmAlarms={calmAlarms} onShowAlarm={showProblem} />
            <SkillsLine ov={ov} onOpen={() => showProblem({ anchor: "sbb-skills", tab: "more", text: "" })} />
            <ProtectedSection ov={ov} waiting={new Set(plan.active.map((c) => c.pluginId))} />
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
        {tab === "trust" ? <ExceptionsTab ov={ov} rpc={rpc} refetch={refetch} freqOff={freqOff} onFreqOff={setFreqSwitch} /> : null}
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
    </ConfirmHost>
    </TooltipProvider>
    </ApprovalContext.Provider>
    </DoneContext.Provider>
  );
}
