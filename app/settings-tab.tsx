// «Настройки»: everything that changes how the protection behaves, in groups with headings — the second factor and the guard, the plugin gate (its queue, its plugins, the
// windows, the repositories), the AI scans and the publication, the watchers (configuration, agents, sentinel), the skills. The events are on «Журнал».
import type { ReactNode } from "react";
import type { Overview } from "../src/overview";
import type { Rpc } from "./touch";
import { BatchCard } from "./batch";
import { GuardCard, MigrationCard } from "./guard";
import { PluginRow } from "./plugins";
import { PolicyCard, UntaintingRepos } from "./policy";
import { QueueCard } from "./queue-card";
import { StageCard, Registration } from "./registration";
import { PublishCard, AiCard } from "./scan";
import { SentinelSection } from "./sentinel";
import { SkillsSection } from "./skills";
import { WatchSection } from "./watch";
import { card, muted, Fold, Group, Section } from "./ui";

interface Props {
  ov: Overview;
  rpc: Rpc;
  refetch: () => void;
}

const watchOpen = (ov: Overview): boolean => ov.watch.drifts.some((d) => d.status === "open" || d.status === "rollback-failed");

function ProtectionGroup({ ov, rpc, refetch, enrollToken }: Props & { enrollToken: string | null }) {
  return (
    <Group title="Защита и второй фактор" hint="Какая ступень защиты у этого bb, чем подтверждаются решения и кто их принимает.">
      <Section sub title="Защита этого bb"><StageCard ov={ov} /></Section>
      <Section sub title="Второй фактор" id="sbb-registration"><Registration ov={ov} rpc={rpc} refetch={refetch} /></Section>
      {ov.guard ? <Section sub title={`Сторож решений${ov.guard.connected ? "" : " (не отвечает!)"}`}><GuardCard ov={ov} rpc={rpc} refetch={refetch} enrollToken={enrollToken} /></Section> : null}
      <Section sub title="Перенос одобрений в сторож"><MigrationCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
    </Group>
  );
}

function QueueSection({ ov, rpc, refetch, held }: Props & { held: Overview["queue"] }) {
  const settled = ov.queue.filter((q) => q.status !== "held").slice(0, 10);
  const one = (q: Overview["queue"][number]) => <QueueCard key={q.id} q={q} ov={ov} rpc={rpc} refetch={refetch} />;
  return (
    <Section sub title={`Очередь, расширенный вид (${held.length})`}>
      {held.length === 0 ? <div className={`${card} ${muted}`}>Ничего не держится.</div> : held.map(one)}
      {settled.length > 0 ? (
        <Fold id="queue-settled" summaryClassName={`cursor-pointer ${muted}`} summary={`Недавно рассмотренные (${settled.length})`}>
          <div className="mt-2 space-y-2">{settled.map(one)}</div>
        </Fold>
      ) : null}
    </Section>
  );
}

function GateGroup({ ov, rpc, refetch, held, registered }: Props & { held: Overview["queue"]; registered: boolean }) {
  return (
    <Group title="Гейт плагинов" hint="Сторонние плагины: что держится, окна доверия, политика окон.">
      <QueueSection ov={ov} rpc={rpc} refetch={refetch} held={held} />
      <BatchCard ov={ov} rpc={rpc} refetch={refetch} />
      <Section sub title="Сторонние плагины">
        {ov.plugins.length === 0 ? <div className={`${card} ${muted}`}>Сторонних плагинов нет.</div> : ov.plugins.map((p) => <PluginRow key={p.id} p={p} ov={ov} rpc={rpc} refetch={refetch} registered={registered} checks={ov.checks} />)}
      </Section>
      <Section sub title="Окна доверия"><PolicyCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
      <Section sub title={`Репозитории, которые не загрязняют тред (${ov.trustedRepos.length})`}><UntaintingRepos ov={ov} rpc={rpc} refetch={refetch} /></Section>
    </Group>
  );
}

function ScansGroup({ ov, rpc, refetch }: Props) {
  return (
    <Group title="ИИ-модели и публикация" hint="Сканы по запросу и автоматические, какие модели читают код, куда уходят замороженные версии.">
      <Section sub title="ИИ-скан плагинов"><AiCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
      <Section sub title="Публикация замороженных версий"><PublishCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
    </Group>
  );
}

function WatchGroup({ ov, rpc, refetch, agentsSection, agentsHere }: Props & { agentsSection: ReactNode; agentsHere: boolean }) {
  return (
    <Group title="Наблюдение за конфигурацией и агентами" hint="Эталон настроек bb, откат, окно «конфигурация», конфигурации и память агентов, дозор.">
      <Section sub id="sbb-watch" title={`Сторож конфигурации${watchOpen(ov) ? " (!)" : ""}`}><WatchSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
      {agentsHere ? agentsSection : null}
      {!agentsHere && ov.agents ? <p className={`text-xs ${muted}`}>Раздел «Агенты: конфигурации и память» сейчас на вкладке «Обзор»: там критичное.</p> : null}
      <Section sub title={`Дозор${ov.sentinel.settings.enabled ? "" : " (выключен)"}`}><SentinelSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
    </Group>
  );
}

function SkillsGroup({ ov, rpc, refetch }: Props) {
  return (
    <Group title="Скиллы" hint="Очередь скиллов, источники, которым верят, проверка по запросу.">
      <Section sub id="sbb-skills" title={`Скиллы${ov.skills.open.length > 0 ? ` — очередь (${ov.skills.open.length})` : ""}`}><SkillsSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
    </Group>
  );
}

export function SettingsTab({ ov, rpc, refetch, held, registered, enrollToken, agentsSection, agentsHere }: Props & { held: Overview["queue"]; registered: boolean; enrollToken: string | null; agentsSection: ReactNode; agentsHere: boolean }) {
  return (
    <div className="space-y-8" data-secure-bb-tabpanel="settings">
      <ProtectionGroup ov={ov} rpc={rpc} refetch={refetch} enrollToken={enrollToken} />
      <GateGroup ov={ov} rpc={rpc} refetch={refetch} held={held} registered={registered} />
      <ScansGroup ov={ov} rpc={rpc} refetch={refetch} />
      <WatchGroup ov={ov} rpc={rpc} refetch={refetch} agentsSection={agentsSection} agentsHere={agentsHere} />
      <SkillsGroup ov={ov} rpc={rpc} refetch={refetch} />
    </div>
  );
}
