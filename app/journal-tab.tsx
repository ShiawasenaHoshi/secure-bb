// «Журнал»: the technical sections (the old extended view): the gate's queue, plugins, windows, the AI scan, the watch, the sentinel, skills, the journal itself.
import type { Overview } from "../src/overview";
import type { Rpc } from "./touch";
import { BatchCard } from "./batch";
import { GuardCard, MigrationCard } from "./guard";
import { TaintCard, LogCard } from "./journal";
import { PluginRow } from "./plugins";
import { PolicyCard, UntaintingRepos } from "./policy";
import { QueueCard } from "./queue-card";
import { StageCard, Registration } from "./registration";
import { PublishCard, AiCard } from "./scan";
import { SentinelSection } from "./sentinel";
import { SkillsSection } from "./skills";
import { WatchSection } from "./watch";
import { card, muted, Fold, Section } from "./ui";

interface Props {
  ov: Overview;
  rpc: Rpc;
  refetch: () => void;
}

const watchOpen = (ov: Overview): boolean => ov.watch.drifts.some((d) => d.status === "open" || d.status === "rollback-failed");

function QueueSection({ ov, rpc, refetch, held }: Props & { held: Overview["queue"] }) {
  const settled = ov.queue.filter((q) => q.status !== "held").slice(0, 10);
  const one = (q: Overview["queue"][number]) => <QueueCard key={q.id} q={q} ov={ov} rpc={rpc} refetch={refetch} />;
  return (
    <Section title={`Гейт плагинов — очередь, расширенный вид (${held.length})`}>
      {held.length === 0 ? <div className={`${card} ${muted}`}>Ничего не держится.</div> : held.map(one)}
      {settled.length > 0 ? (
        <Fold id="queue-settled" summaryClassName={`cursor-pointer ${muted}`} summary={`Недавно рассмотренные (${settled.length})`}>
          <div className="mt-2 space-y-2">{settled.map(one)}</div>
        </Fold>
      ) : null}
    </Section>
  );
}

function GateSections({ ov, rpc, refetch, registered }: Props & { registered: boolean }) {
  return (
    <>
      <Section title="Гейт плагинов — сторонние плагины">
        {ov.plugins.length === 0 ? <div className={`${card} ${muted}`}>Сторонних плагинов нет.</div> : ov.plugins.map((p) => <PluginRow key={p.id} p={p} ov={ov} rpc={rpc} refetch={refetch} registered={registered} checks={ov.checks} />)}
      </Section>
      <Section title="Гейт плагинов — окна доверия"><PolicyCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
      <Section title="Гейт плагинов — ИИ-скан"><AiCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
      <Section title="Гейт плагинов — публикация"><PublishCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
    </>
  );
}

function WatchersSections({ ov, rpc, refetch, agentsSection, agentsHere }: Props & { agentsSection: React.ReactNode; agentsHere: boolean }) {
  return (
    <>
      <Section id="sbb-watch" title={`Сторож конфигурации${watchOpen(ov) ? " (!)" : ""}`}><WatchSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
      {agentsHere ? agentsSection : null}
      {!agentsHere && ov.agents ? <p className={`text-xs ${muted}`}>Раздел «Агенты: конфигурации и память» сейчас на вкладке «Статус»: там критичное.</p> : null}
      <Section title={`Дозор${ov.sentinel.settings.enabled ? "" : " (выключен)"}`}><SentinelSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
    </>
  );
}

function MemorySections({ ov, rpc, refetch }: Props) {
  return (
    <>
      <Section id="sbb-skills" title={`Скиллы${ov.skills.open.length > 0 ? ` — очередь (${ov.skills.open.length})` : ""}`}><SkillsSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
      <Section title={`Загрязнение тредов${ov.tainted.length > 0 ? ` (${ov.tainted.length})` : ""}`}><TaintCard ov={ov} /></Section>
      <Section title={`Репозитории, которые не загрязняют тред (${ov.trustedRepos.length})`}><UntaintingRepos ov={ov} rpc={rpc} refetch={refetch} /></Section>
      <Section title="Перенос одобрений в сторож"><MigrationCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
      <Section title={`Журнал${ov.journal.ok ? "" : " (!)"}`}><LogCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
    </>
  );
}

export function JournalTab({ ov, rpc, refetch, held, registered, enrollToken, agentsSection, agentsHere }: Props & { held: Overview["queue"]; registered: boolean; enrollToken: string | null; agentsSection: React.ReactNode; agentsHere: boolean }) {
  return (
    <div className="space-y-6">
      <Section title="Защита этого bb"><StageCard ov={ov} /></Section>
      <Section title="Второй фактор" id="sbb-registration"><Registration ov={ov} rpc={rpc} refetch={refetch} /></Section>
      {ov.guard ? <Section title={`Сторож решений${ov.guard.connected ? "" : " (не отвечает!)"}`}><GuardCard ov={ov} rpc={rpc} refetch={refetch} enrollToken={enrollToken} /></Section> : null}
      <QueueSection ov={ov} rpc={rpc} refetch={refetch} held={held} />
      <BatchCard ov={ov} rpc={rpc} refetch={refetch} />
      <GateSections ov={ov} rpc={rpc} refetch={refetch} registered={registered} />
      <WatchersSections ov={ov} rpc={rpc} refetch={refetch} agentsSection={agentsSection} agentsHere={agentsHere} />
      <MemorySections ov={ov} rpc={rpc} refetch={refetch} />
    </div>
  );
}
