import { useBbNavigate } from "@get-bb/plugin-sdk/app";
import type { Overview } from "../src/overview";
import { skillsSummary, awayAlarms, awayInfoEvents, cardColor, groupAway, awaySeenMark } from "../src/ux";
import { AWAY_HIDE_LABEL } from "../src/ux";
import type { AwayEvent, HeldNow, ProblemRef } from "../src/ux";
import { card, btn, btnPrimary, muted, when, useOverview } from "./ui";
import { gapsBySeverity } from "./windows";

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

/** The skills that wait are ONE line on the status, with a link to the list (not a card each): the list itself is in «Подробно». */
export function SkillsLine({ ov, onOpen }: { ov: Overview; onOpen: () => void }) {
  const sum = skillsSummary(ov.skills.open);
  if (!sum) return null;
  return (
    <div className={`${card} flex flex-wrap items-center justify-between gap-2 ${sum.hard > 0 ? "border-yellow-500/60" : ""}`} data-secure-bb-skills-line>
      <span className={sum.hard > 0 ? "font-semibold" : ""}>{sum.text}</span>
      <button type="button" className={btn} onClick={onOpen}>Открыть список</button>
    </div>
  );
}

/** «Пока вас не было»: what the journals say happened since the last «Всё в порядке», grouped by plugin and thread. */
export function AwayCard({ ov, since, onSeen, onReview, canReview, kept, alarms, onShowAlarm }: { ov: Overview; since: number; onSeen: (mark: number) => void; onReview: () => void; canReview: boolean; kept: Set<number>; alarms: ProblemRef[]; onShowAlarm: (p: ProblemRef) => void }) {
  const nav = useBbNavigate();
  const { rpc, refetch } = useOverview();
  const guardMode = ov.guard?.connected === true;
  const events = awayEventsOf(ov);
  const heldNow: Record<string, HeldNow> = {};
  for (const q of ov.queue) {
    // What the person has already answered (kept in quarantine) is not waiting any more.
    if (q.status !== "held" || kept.has(q.id)) continue;
    const h = (heldNow[q.pluginId] ??= { yellow: 0, red: 0 });
    if (cardColor({ reason: q.reason, findings: ov.queueChecks[q.id]?.findings ?? [] }) === "red") h.red++;
    else h.yellow++;
  }
  const groups = groupAway(awayInfoEvents(events, guardMode), since, guardMode, heldNow);
  const alarmBlock = awayAlarms(alarms);
  const calm = gapsBySeverity(ov).calm;
  if (groups.length === 0 && !alarmBlock && calm.length === 0) return null;
  return (
    <div className={card} data-secure-bb-away>
      <h2 className="text-base font-semibold">Пока вас не было</h2>
      {calm.length > 0 ? (
        <div className={`mt-2 rounded-md border border-border p-2 text-xs ${muted}`} data-secure-bb-gap-calm>
          {calm.map(({ gap: g, text }) => (
            <p key={g.at}>{text.headline}. {text.works} {text.notWorking}</p>
          ))}
          <button type="button" className={`${btn} mt-1`} onClick={() => void rpc.call("alive.ack", null).then(refetch)}>Понятно</button>
        </div>
      ) : null}
      {alarmBlock ? (
        <div className="mt-2 rounded-md border border-red-400 p-2 text-red-700 dark:border-red-700 dark:text-red-400" data-secure-bb-away-alarms>
          <p className="font-semibold">{alarmBlock.title}: они остаются, пока вы не разберёте их на месте</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5">
            {alarmBlock.items.map((a, i) => (
              <li key={`${a.anchor}-${i}`}>
                {a.text} · <button type="button" className="underline hover:no-underline" onClick={() => onShowAlarm(a)}>Показать</button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <ul className="mt-2 space-y-1">
        {groups.slice(0, 12).map((g) => (
          <li key={g.key} className={g.counts.stopped + g.counts.alarm > 0 ? "font-semibold text-red-700 dark:text-red-400" : ""}>
            {g.text}
            {g.threadId ? <> · <button type="button" className="underline hover:no-underline" onClick={() => nav.toThread(g.threadId!)}>из чата</button></> : null}
          </li>
        ))}
      </ul>
      <p className={`mt-1 text-xs ${muted}`}>С {when(since)}. Показаны последние записи; более старые могли не поместиться.</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <button className={btnPrimary} title={alarmBlock ? "Скрывает только строки выше, без тревог. Тревоги остаются, пока их не разберут." : undefined} onClick={() => onSeen(awaySeenMark(events, Date.now()))}>{alarmBlock ? "Скрыть эти строки (тревоги останутся)" : AWAY_HIDE_LABEL}</button>
        {canReview ? <button className={btn} onClick={onReview}>Разобрать</button> : null}
      </div>
    </div>
  );
}

// ---- quarantine -----------------------------------------------------------------------------------------------------------
