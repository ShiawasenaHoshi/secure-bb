// «Обзор»: the header, what waits, what passed by itself, what is under protection. The decisions (what is shown, in what order, what counts) are made in
// `src/pageview.ts` and `page-plan.ts`; these components draw what those say.
import type { ReactNode } from "react";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";
import { SECOND_FACTOR_ANCHOR, startedBadly, type PageSummary } from "../src/pageview";
import { DEFER_STUB_RESTORE, MODE_NAMES, cardKey, detailLevel, humanError, launchProblem, moreVersionsText, wizardNeeded, type ProblemRef, type Stub } from "../src/ux";
import { AgentsAlarm } from "./agents";
import type { SessionLocal } from "./approval";
import { SkillsLine, AwayCard } from "./away";
import type { Rpc } from "./touch";
import { when } from "./ui";
import { GuardAlarm } from "./guard";
import { StatusHeader } from "./header";
import { DoneRow } from "./done-row";
import type { CardPlanView } from "./page-plan";
import type { useMarks, useNotes } from "./page-state";
import { ProtectedSection } from "./protected";
import { ReviewCard, PendingTrust } from "./review-card";
import { SessionBar } from "./session-bar";
import { Wizard } from "./wizard";
import { WindowRows, JournalAlarm, AliveAlarm } from "./windows";
import { cardBlocked, muted, Fold, FoldAccordion, Section } from "./ui";
import { EmptyState } from "../components/ui/empty-state";

type Marks = ReturnType<typeof useMarks>;
type Notes = ReturnType<typeof useNotes>;

export interface SessionProps {
  session: SessionLocal | null;
  open: Parameters<typeof SessionBar>[0]["open"];
  lock: () => Promise<void>;
  closed: Parameters<typeof SessionBar>[0]["closed"];
}

export interface OverviewProps {
  ov: Overview;
  rpc: Rpc;
  refetch: () => void;
  view: CardPlanView;
  summary: PageSummary;
  marks: Marks;
  notes: Notes;
  session: SessionProps;
  /** «С …» of the summary: fixed for as long as the page is open. */
  since: number;
  pending: Array<{ entry: string; label: string }>;
  setPending: (f: (p: Array<{ entry: string; label: string }>) => Array<{ entry: string; label: string }>) => void;
  addPending: (entry: string, label: string) => void;
  forceWizard: boolean;
  setForceWizard: (on: boolean) => void;
  showProblem: (p: ProblemRef) => void;
  agentsSection: ReactNode;
}

function WizardSlot({ p }: { p: OverviewProps }) {
  const { ov, marks } = p;
  const wanted = wizardNeeded({ hasTrust: ov.guard?.trust != null, mySources: ov.guard?.trust?.mySources.length ?? 0, done: false });
  if (!(p.forceWizard || (!marks.wizardDone && wanted))) return null;
  return <Wizard ov={ov} rpc={p.rpc} refetch={p.refetch} onClose={() => { p.setForceWizard(false); marks.closeWizard(ov.now); }} startStep={p.forceWizard ? 2 : 0} />;
}

/** The main button of the header: the missing second factor opens the wizard when there is one; the rest go to the place of the problem. */
function headerAction(p: OverviewProps): (() => void) | null {
  const target = p.summary.header.target;
  if (!target) return null;
  return () => (target.anchor === SECOND_FACTOR_ANCHOR && p.ov.guard?.trust != null ? p.setForceWizard(true) : p.showProblem(target));
}

function BlockedCodes({ ov }: { ov: Overview }) {
  if (ov.totp.blockedUntil <= 0) return null;
  const keyNote = (ov.guard?.passkey?.keys.length ?? 0) > 0 ? " Касание ключом работает: подпись не подобрать, поэтому её это не касается." : "";
  return <p className="rounded-md border border-destructive p-2 text-sm text-destructive">Слишком много неверных кодов: коды заблокированы до {when(ov.totp.blockedUntil)}.{keyNote}</p>;
}

function OverviewHead({ p }: { p: OverviewProps }) {
  const { ov, rpc, refetch, summary } = p;
  const s = p.session;
  return (
    <>
      <WizardSlot p={p} />
      <StatusHeader line={summary.header} more={summary.headerMore} onAction={headerAction(p)} session={<SessionBar ov={ov} rpc={rpc} session={s.session} open={s.open} lock={s.lock} closed={s.closed} />} />
      <BlockedCodes ov={ov} />
      <PendingTrust entries={p.pending} ov={ov} rpc={rpc} refetch={refetch} onDone={(e) => p.setPending((l) => l.filter((x) => x.entry !== e))} />
      <div id="sbb-alarms" className="space-y-2 empty:hidden">
        <JournalAlarm ov={ov} rpc={rpc} refetch={refetch} />
        <AliveAlarm ov={ov} />
      </div>
      <div id="sbb-guard-alarm" className="empty:hidden"><GuardAlarm ov={ov} /></div>
      <AgentsAlarm ov={ov} onShow={() => p.showProblem({ anchor: "sbb-agents", tab: summary.agents.tab, text: "" })} />
      <WindowRows windows={ov.windows} cfgWindows={ov.watch.windows} rpc={rpc} refetch={refetch} />
    </>
  );
}

/** A card of a plugin: its latest version, the other waiting versions folded under it. */
function PluginCardBlock({ c, deferred, p }: { c: { shown: QueueRow; others: QueueRow[] }; deferred: boolean; p: OverviewProps }) {
  const { view, marks } = p;
  const props = { ov: p.ov, rpc: p.rpc, refetch: p.refetch, onDefer: marks.onDefer, onKeep: marks.onKeep, onTrustPending: p.addPending };
  const freq = !deferred && view.freqPick?.pluginId === c.shown.pluginId ? view.freqPick.hint : null;
  return (
    <div className="space-y-2">
      <ReviewCard key={cardKey(c.shown)} q={c.shown} {...props} deferred={deferred} fresh={view.fresh.has(c.shown.pluginId)} freq={freq} onFreqDone={marks.onFreqDone} />
      {c.others.length > 0 ? (
        <Fold id={`more-${c.shown.pluginId}`} className="ml-3" summary={`${moreVersionsText(c.others.length)} (${c.others.map((o) => o.version).join(", ")})`}>
          <div className="mt-2 space-y-2">{c.others.map((o) => <ReviewCard key={cardKey(o)} q={o} {...props} deferred={view.isDeferred(o)} slotted={false} />)}</div>
        </Fold>
      ) : null}
    </div>
  );
}

/** What undoing the line that stands where a card was does: bring the put-aside card back, or take the approval back (a tightening, no code). */
function undoOf(st: Stub, p: OverviewProps, hide: () => void): (() => void) | null {
  if (st.restore) {
    const r = st.restore;
    return () => {
      const e = p.view.held.find((x) => x.id === r.id);
      if (e) p.marks.onDefer(e, false);
      else hide();
    };
  }
  const approvalId = p.ov.plugins.find((x) => x.id === st.key)?.pin?.id ?? null;
  if (approvalId === null || !/разрешён/.test(st.text)) return null;
  const { announce } = p.notes;
  return () =>
    void p.rpc.call("approval.revoke", { approvalId }).then(
      () => {
        hide();
        announce("Отозвано: плагину снова нужно ваше решение.", { kind: "info" });
        p.refetch();
      },
      (e: unknown) => announce(humanError(e instanceof Error ? e.message : String(e)), { kind: "error" }),
    );
}

function StubLine({ st, p }: { st: Stub; p: OverviewProps }) {
  const hide = () => p.notes.setStubs((l) => l.filter((x) => x.key !== st.key));
  return <DoneRow text={st.text} undoLabel={DEFER_STUB_RESTORE} busy={p.notes.settling} onHide={hide} onUndo={undoOf(st, p, hide)} />;
}

function WaitingList({ p }: { p: OverviewProps }) {
  const { view, summary, notes } = p;
  return (
    <Section title={`Ждут решения вас${summary.counts.waiting > 0 ? ` (${summary.counts.waiting})` : ""}`}>
      <div className={notes.settling ? "pointer-events-none space-y-2" : "space-y-2"} data-secure-bb-settling={notes.settling ? "" : undefined}>
        {view.activeItems.length === 0 ? <EmptyState message="Сейчас решать нечего — всё под защитой" className="py-2" /> : null}
        {view.activeItems.map((it) => {
          if (it.stub) return <StubLine key={`stub:${it.stub.key}`} st={it.stub} p={p} />;
          const c = view.plan.active.find((x) => x.pluginId === it.key)!;
          return <PluginCardBlock key={c.shown.pluginId} c={c} deferred={false} p={p} />;
        })}
      </div>
    </Section>
  );
}

function DeferredList({ p }: { p: OverviewProps }) {
  const { view } = p;
  if (view.plan.later.length === 0) return null;
  const cards = view.laterOrder.map((k) => view.plan.later.find((c) => c.pluginId === k)).filter((c): c is NonNullable<typeof c> => c !== undefined);
  return (
    <FoldAccordion id="deferred" title={`Отложено (${p.summary.counts.deferred})`}>
      <p className={`text-xs ${muted}`}>Вы отложили эти карточки кнопкой «Решить позже». Плагины остаются в карантине и не запущены.</p>
      <div className="mt-2 space-y-3">{cards.map((c) => <PluginCardBlock key={c.shown.pluginId} c={c} deferred p={p} />)}</div>
    </FoldAccordion>
  );
}

function PlainNotes({ p }: { p: OverviewProps }) {
  const { ov, view } = p;
  const failed = startedBadly(ov.plugins, launchProblem);
  const level = detailLevel(ov.guard?.trust?.mode ?? null);
  return (
    <>
      {view.plan.kept.length > 0 ? <p className={`text-xs ${muted}`}>Оставлено вами в карантине: {view.plan.kept.map((q) => `${q.pluginId} ${q.version}`).join(", ")}. Они не запущены; вернуть решение можно на вкладке «Карантин».</p> : null}
      {failed.length > 0 ? (
        <Section title="Разрешены, но не запустились">
          {failed.map((x) => <div key={x.id} className={cardBlocked} role="alert"><p className="font-semibold">{x.id} {x.version}</p><p>{launchProblem(x)}</p></div>)}
        </Section>
      ) : null}
      {p.summary.agents.tab === "status" ? p.agentsSection : null}
      {level.expanded ? <p className={`text-xs ${muted}`}>Режим «{MODE_NAMES[ov.guard!.trust!.mode]}»: технические подробности на карточках открыты.</p> : null}
    </>
  );
}

function OverviewFoot({ p }: { p: OverviewProps }) {
  const { ov, view } = p;
  // What the person has answered or put aside is not «waiting» any more: «Пока вас не было» does not repeat it.
  const kept = new Set([...view.plan.kept.map((q) => q.id), ...view.plan.later.flatMap((c) => c.all.map((q) => q.id))]);
  const showWaiting = (pluginId: string) => {
    const c = view.plan.active.find((x) => x.pluginId === pluginId);
    if (c) p.showProblem({ anchor: `sbb-card-${c.shown.id}`, tab: "status", text: `${c.pluginId} ${c.shown.version}` });
  };
  return (
    <>
      <AwayCard ov={ov} since={p.since} onSeen={p.marks.seen} kept={kept} />
      <SkillsLine ov={ov} onOpen={() => p.showProblem({ anchor: "sbb-skills", tab: "more", text: "" })} />
      <ProtectedSection ov={ov} waiting={new Set(view.plan.active.map((c) => c.pluginId))} onShowCard={showWaiting} />
      <PlainNotes p={p} />
    </>
  );
}

export function OverviewTab({ p }: { p: OverviewProps }) {
  return (
    <div className="space-y-6">
      <OverviewHead p={p} />
      <WaitingList p={p} />
      <DeferredList p={p} />
      <OverviewFoot p={p} />
    </div>
  );
}
