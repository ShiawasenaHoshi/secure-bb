// What the first screen says, as data: the one line of the header, which alarms are real alarms, what «Пока вас не было» may repeat.
// The verdicts themselves (what is red, what waits, what is an alarm) are ux.ts's; this arranges them for the page.
import { awayText, type AwayGroup, type ProblemRef, type Status } from "./ux";

/** The anchor of the alarm «Второй фактор не настроен»: without a second factor nothing can be approved, so it is the first thing to do, not a calm line. */
export const SECOND_FACTOR_ANCHOR = "sbb-registration";

export type HeaderTone = "ok" | "waiting" | "alarm";

export interface HeaderLine {
  tone: HeaderTone;
  /** One sentence: «Всё под защитой» / «Ждут вашего решения: 3» / «Тревога: …». */
  text: string;
  /** The place the one main button goes to; null: nothing to do. */
  target: ProblemRef | null;
  /** The button's words. */
  action: string | null;
}

/** The one state of the header. Waiting cards never make a red alarm; stopped plugins, a guard that is down, a missing second factor and the other alarms do. */
export function headerLine(i: { status: { level: Status["level"]; first: ProblemRef | null }; waiting: number; deferred: number; alarms: ProblemRef[] }): HeaderLine {
  const critical = i.alarms;
  const first = i.status.first;
  if (i.status.level === "down") return { tone: "alarm", text: "Тревога: защита не отвечает", target: first, action: first ? "Показать" : null };
  if (i.status.level === "stopped") {
    const target = first;
    return { tone: "alarm", text: `Тревога: ${target ? `остановлен плагин — ${target.text}` : "плагин остановлен"}`, target, action: "Показать" };
  }
  // The second factor first: until it is set up the person cannot approve anything, so this is what the header asks for.
  const noFactor = critical.find((a) => a.anchor === SECOND_FACTOR_ANCHOR);
  if (noFactor) return { tone: "alarm", text: "Настройте второй фактор: без него ничего нельзя подтвердить", target: noFactor, action: "Настроить" };
  if (critical.length > 0) {
    const t = critical[0]!;
    return { tone: "alarm", text: `Тревога: ${t.text}${critical.length > 1 ? ` (и ещё ${critical.length - 1})` : ""}`, target: t, action: "Показать" };
  }
  if (i.waiting > 0) return { tone: "waiting", text: `Ждут вашего решения: ${i.waiting}`, target: first, action: "К решению" };
  if (i.deferred > 0) return { tone: "waiting", text: `Отложено вами: ${i.deferred}`, target: first, action: "Показать" };
  if (first) return { tone: "waiting", text: `Требует внимания: ${first.text}`, target: first, action: "Показать" };
  return { tone: "ok", text: "Всё под защитой", target: null, action: null };
}

/**
 * «Пока вас не было» shows what needs no decision: what passed by itself, was rejected or deleted, what the system did. What waits for the person is on the
 * page already (the cards), and what was stopped is a card too: neither is repeated here.
 */
export function quietAwayGroups(groups: AwayGroup[]): AwayGroup[] {
  return groups
    .map((g) => {
      const counts = { ...g.counts, held: 0, stopped: 0 };
      return { ...g, counts, text: awayText({ pluginId: g.pluginId, counts }) };
    })
    .filter((g) => g.text !== "");
}
