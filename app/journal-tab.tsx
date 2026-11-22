// «Журнал»: events only — what the system did and saw (the decisions, the guard's journal, the sentinel's feed, which threads were marked). Nothing here changes how the
// protection behaves: every switch, mode, policy and scan on demand is on «Настройки» (settings-tab.tsx). A control that is not a setting (the check of a chain) may stand here.
import type { Overview } from "../src/overview";
import type { Rpc } from "./touch";
import { GuardJournal } from "./guard";
import { TaintCard, LogCard } from "./journal";
import { SentinelFeed } from "./sentinel";
import { Section } from "./ui";

interface Props {
  ov: Overview;
  rpc: Rpc;
  refetch: () => void;
}

export function JournalTab({ ov, rpc, refetch }: Props) {
  return (
    <div className="space-y-6" data-secure-bb-tabpanel="journal">
      <Section title={`Журнал решений${ov.journal.ok ? "" : " (!)"}`}><LogCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
      {ov.guard ? <Section title={`Журнал сторожа${ov.guard.connected ? "" : " (не отвечает!)"}`}><GuardJournal ov={ov} rpc={rpc} refetch={refetch} /></Section> : null}
      <Section title={`Лента дозора (${ov.sentinel.feed.length})`}><SentinelFeed ov={ov} /></Section>
      <Section title={`Загрязнение тредов${ov.tainted.length > 0 ? ` (${ov.tainted.length})` : ""}`}><TaintCard ov={ov} /></Section>
    </div>
  );
}
