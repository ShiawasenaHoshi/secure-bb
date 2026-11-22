import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { awaySince, TAB_LABEL, TAB_ORDER, type ProblemRef, type TabId } from "../src/ux";
import { openFold } from "../src/fold";
import { registeredOf, summarize, type PageSummary } from "../src/pageview";
import { AgentsSection } from "./agents";
import { ApprovalContext, useApprovalSession } from "./approval";
import { enrollTokenOnce } from "./code";
import { ConfirmHost } from "./confirm-dialog";
import { TroubleshootBar } from "./header";
import { PAGE_TITLE } from "./page-title";
import { ExceptionsTab } from "./trust";
import { JournalTab } from "./journal-tab";
import { SettingsTab } from "./settings-tab";
import { OverviewTab, type OverviewProps, type SessionProps } from "./overview-tab";
import { useCardPlan } from "./page-plan";
import { useFocusJump, useMarks, useNotes, useSavedTab, useStableView } from "./page-state";
import { QuarantineTab } from "./quarantine";
import type { Rpc } from "./touch";
import { muted, useOverview, Section, DoneContext, AnchoredNotes, PinnedNotes } from "./ui";
import { Badge } from "../components/ui/badge";
import { TooltipProvider } from "../components/ui/tooltip";
import { Tabs, TabsList, TabsTrigger } from "../components/ui/tabs";

/** Tells the server this page is open, so a registration started now counts as attended. */
export function usePagePing(rpc: ReturnType<typeof useRpc<SecureBbRpc>>) {
  useEffect(() => {
    const ping = () => void rpc.call("page.ping").catch(() => undefined);
    ping();
    const t = setInterval(ping, 15_000);
    return () => clearInterval(t);
  }, [rpc]);
}


/** The section of the agents' configurations and memory, drawn on the tab the facts say (a critical change or an alarm brings it to «Обзор»). */
function agentsSectionOf(ov: Overview, rpc: Rpc, refetch: () => void, agents: PageSummary["agents"]): ReactNode {
  if (!ov.agents) return null;
  const open = ov.agents.state?.openTotal ?? 0;
  const mark = agents.alarms > 0 || agents.critical > 0 ? " (!)" : open > 0 ? ` (${open})` : "";
  return (
    <Section id="sbb-agents" sub={agents.tab !== "status"} title={`Агенты: конфигурации и память${mark}`}>
      <AgentsSection ov={ov} rpc={rpc} refetch={refetch} showDone={agents.tab !== "status"} />
    </Section>
  );
}

function PageTabs({ tab, setTab, counts }: { tab: TabId; setTab: (t: TabId) => void; counts: Record<TabId, number> }) {
  return (
    <Tabs value={tab} onValueChange={(v) => setTab(v as TabId)}>
      <TabsList aria-label={`Разделы ${PAGE_TITLE}`}>
        {TAB_ORDER.map((t) => (
          <TabsTrigger key={t} value={t}>
            {TAB_LABEL[t]}
            {counts[t] > 0 ? <Badge variant="secondary" className="px-1.5 py-0">{counts[t]}</Badge> : null}
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  );
}

interface ContentProps {
  ov: Overview;
  rpc: Rpc;
  refetch: () => void;
  notes: ReturnType<typeof useNotes>;
  marks: ReturnType<typeof useMarks>;
  session: SessionProps;
  enrollToken: string | null;
  tab: TabId;
  setTab: (t: TabId) => void;
  setFocus: (id: string | null) => void;
  /** The moment the page was opened: «С …» of the summary does not move under the eyes. */
  pageStart: number;
}

/** The page once the overview is there: the plan of the cards, the summary, the tabs. */
function GateContent(c: ContentProps) {
  const { ov, rpc, refetch, notes, marks, tab, setTab } = c;
  const [pending, setPending] = useState<Array<{ entry: string; label: string }>>([]);
  // «Настроить» in the header when the second factor is missing: the first-run wizard, on its screen about the second factor.
  const [forceWizard, setForceWizard] = useState(false);
  const view = useCardPlan(ov, marks.decisions, { off: marks.freqOff, lastAt: marks.freqAt }, notes.stubs);
  const registered = registeredOf(ov);
  const summary = summarize(ov, view.plan, registered);
  const showProblem = (p: ProblemRef) => {
    setTab(p.tab);
    const id = Number(p.anchor.replace("sbb-card-", ""));
    if (p.anchor.startsWith("sbb-card-") && view.held.some((q) => q.id === id && view.isDeferred(q))) openFold("deferred", true);
    c.setFocus(p.anchor);
  };
  const addPending = (entry: string, label: string) => setPending((p) => (p.some((x) => x.entry === entry) ? p : [...p, { entry, label }]));
  const agentsSection = agentsSectionOf(ov, rpc, refetch, summary.agents);
  const tabCount: Record<TabId, number> = { status: summary.status.count, quarantine: summary.counts.quarantine, trust: 0, journal: 0, settings: 0 };
  const overview: OverviewProps = { ov, rpc, refetch, view, summary, marks, notes, session: c.session, since: awaySince(marks.seenAt, Math.max(c.pageStart, Number(marks.seenAt ?? 0) || 0)), pending, setPending, addPending, forceWizard, setForceWizard, showProblem, agentsSection };
  return (
    <>
      <TroubleshootBar until={ov.guard?.troubleshootUntil ?? 0} />
      <PageTabs tab={tab} setTab={setTab} counts={tabCount} />
      {tab === "status" ? <OverviewTab p={overview} /> : null}
      {tab === "quarantine" ? <QuarantineTab ov={ov} rpc={rpc} refetch={refetch} onTrustPending={addPending} onShowCard={(id) => { setTab("status"); c.setFocus(`sbb-card-${id}`); }} isKept={view.isKept} onUnkeep={marks.onUnkeep} /> : null}
      {tab === "trust" ? <ExceptionsTab ov={ov} rpc={rpc} refetch={refetch} freqOff={marks.freqOff} onFreqOff={marks.setFreqSwitch} /> : null}
      {tab === "journal" ? <JournalTab ov={ov} rpc={rpc} refetch={refetch} /> : null}
      {tab === "settings" ? <SettingsTab ov={ov} rpc={rpc} refetch={refetch} held={view.held} registered={registered} enrollToken={c.enrollToken} agentsSection={agentsSection} agentsHere={summary.agents.tab === "settings"} /> : null}
    </>
  );
}

function Loading() {
  return (
    <div className="mx-auto max-w-3xl space-y-3 p-6" role="status" aria-busy="true" data-secure-bb-loading>
      <h1 className="text-xl font-semibold">{PAGE_TITLE}</h1>
      <p className={`text-base ${muted}`}>Загрузка…</p>
    </div>
  );
}

export function GatePage() {
  const { rpc, data: ov, error, refetch } = useOverview();
  usePagePing(rpc);
  const { approval, open, lock, closed } = useApprovalSession(rpc, refetch);
  // The link from `sbb-guard setup` (#enroll=TOKEN): taken once, from the fragment (it never went to a server), and the address bar is cleaned at once.
  const [enrollToken] = useState<string | null>(enrollTokenOnce);
  // The link from `sbb-guard setup` leads to the guard card (on «Настройки»); otherwise the tab the page was left on, or «Обзор».
  const [tab, setTab] = useSavedTab(enrollToken !== null ? "settings" : null);
  const [focus, setFocus] = useState<string | null>(null);
  const pageStart = useRef(Date.now());
  const { scrollRef, rememberView } = useStableView();
  const notes = useNotes();
  const marks = useMarks(notes);
  useFocusJump(focus, setFocus, rememberView, [tab, ov]);
  if (error && !ov) return <div className="p-6 text-destructive">Не удалось загрузить: {error}</div>;
  if (!ov) return <Loading />;
  return (
    <DoneContext.Provider value={notes.ctx}>
      <ApprovalContext.Provider value={approval}>
        <TooltipProvider delayDuration={200}>
          <ConfirmHost ov={ov} rpc={rpc}>
            <div className="h-full overflow-y-auto" ref={scrollRef} onScroll={rememberView} onFocusCapture={rememberView} onKeyUp={rememberView} onPointerUp={rememberView}>
              <AnchoredNotes />
              <div className="mx-auto max-w-3xl space-y-6 p-4 sm:p-6">
                <h1 className="text-xl font-semibold">{PAGE_TITLE}</h1>
                <PinnedNotes />
                <GateContent ov={ov} rpc={rpc} refetch={refetch} notes={notes} marks={marks} session={{ session: approval.session, open, lock, closed }} enrollToken={enrollToken} tab={tab} setTab={setTab} setFocus={setFocus} pageStart={pageStart.current} />
              </div>
            </div>
          </ConfirmHost>
        </TooltipProvider>
      </ApprovalContext.Provider>
    </DoneContext.Provider>
  );
}
