import { useBbNavigate } from "@get-bb/plugin-sdk/app";
import type { Overview } from "../src/overview";
import { skillsSummary, awayInfoEvents, cardColor, groupAway, awaySeenMark } from "../src/ux";
import { AWAY_HIDE_LABEL } from "../src/ux";
import type { AwayEvent, HeldNow, ProblemRef } from "../src/ux";
import { muted, when, useOverview, FoldAccordion } from "./ui";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { quietAwayGroups } from "../src/pageview";
import { gapsBySeverity } from "../src/pageview";

/** The journal records of both journals as the summary reads them. */
export function awayEventsOf(ov: Overview): AwayEvent[] {
  const threadOf = new Map<string, string>();
  for (const q of ov.queue) if (q.threadId && !threadOf.has(q.pluginId)) threadOf.set(q.pluginId, q.threadId);
  return [
    ...(ov.guard?.recent ?? []).map((r) => ({ ts: r.ts, kind: r.kind, pluginId: r.pluginId, threadId: r.pluginId ? (threadOf.get(r.pluginId) ?? null) : null, detail: r.detail, from: "guard" as const })),
    ...ov.log.map((l) => {
      const d = (l.detail ?? {}) as { thread?: unknown };
      return { ts: l.ts, kind: l.kind, pluginId: l.pluginId, threadId: typeof d.thread === "string" ? d.thread : l.pluginId ? (threadOf.get(l.pluginId) ?? null) : null, detail: l.detail, from: "plugin" as const };
    }),
  ];
}

/** The skills that wait are ONE line on the overview, with a link to the list (not a card each): the list itself is in «Журнал». */
export function SkillsLine({ ov, onOpen }: { ov: Overview; onOpen: () => void }) {
  const sum = skillsSummary(ov.skills.open);
  if (!sum) return null;
  return (
    <Card className="flex flex-wrap items-center justify-between gap-2 p-3 text-sm" data-secure-bb-skills-line>
      <span className={sum.hard > 0 ? "font-semibold" : ""}>{sum.text}</span>
      <Button size="sm" variant="outline" onClick={onOpen}>Открыть список</Button>
    </Card>
  );
}

/**
 * «Пока вас не было»: what the journals say happened since the last «Всё в порядке» and needs NO decision: what passed by itself, what was rejected
 * or deleted, what the system did. What waits for the person is not repeated here (the cards are on the page). One folded line, «Подробнее» opens it.
 */
export function AwayCard({ ov, since, onSeen, kept }: { ov: Overview; since: number; onSeen: (mark: number) => void; kept: Set<number> }) {
  const nav = useBbNavigate();
  const { rpc, refetch } = useOverview();
  const guardMode = ov.guard?.connected === true;
  const events = awayEventsOf(ov);
  const heldNow: Record<string, HeldNow> = {};
  for (const q of ov.queue) {
    if (q.status !== "held" || kept.has(q.id)) continue;
    const h = (heldNow[q.pluginId] ??= { yellow: 0, red: 0 });
    if (cardColor({ reason: q.reason, reasonKind: q.reasonKind, blocks: q.blocks, findings: ov.queueChecks[q.id]?.findings ?? [] }) === "red") h.red++;
    else h.yellow++;
  }
  const groups = quietAwayGroups(groupAway(awayInfoEvents(events, guardMode), since, guardMode, heldNow));
  const calm = gapsBySeverity(ov).calm;
  if (groups.length === 0 && calm.length === 0) return null;
  const lines = groups.slice(0, 12);
  const brief = [...lines.slice(0, 2).map((g) => g.text)].join("; ");
  const more = lines.length + calm.length > 2;
  return (
    <div data-secure-bb-away>
      <FoldAccordion
        id="away"
        title={
          <span className="flex min-w-0 flex-wrap items-baseline gap-x-2">
            <span className="font-semibold">Пока вас не было</span>
            <span className={`min-w-0 font-normal ${muted}`}>{brief || "ничего особенного"}{more ? "…" : ""}</span>
            <span className="text-xs font-normal underline">Подробнее</span>
          </span>
        }
      >
        {calm.length > 0 ? (
          <div className={`mb-2 space-y-1 text-xs ${muted}`} data-secure-bb-gap-calm>
            {calm.map(({ gap: g, text }) => (
              <p key={g.at}>{text.headline}. {text.works} {text.notWorking}</p>
            ))}
            <Button size="sm" variant="outline" onClick={() => void rpc.call("alive.ack", null).then(refetch)}>Понятно</Button>
          </div>
        ) : null}
        <ul className="space-y-1">
          {lines.map((g) => (
            <li key={g.key}>
              {g.text}
              {g.threadId ? <> · <button type="button" className="underline hover:no-underline" onClick={() => nav.toThread(g.threadId!)}>из чата</button></> : null}
            </li>
          ))}
        </ul>
        <p className={`mt-2 text-xs ${muted}`}>С {when(since)}. Показаны последние записи; более старые могли не поместиться.</p>
        <div className="mt-2">
          <Button size="sm" onClick={() => onSeen(awaySeenMark(events, Date.now()))}>{AWAY_HIDE_LABEL}</Button>
        </div>
      </FoldAccordion>
    </div>
  );
}
