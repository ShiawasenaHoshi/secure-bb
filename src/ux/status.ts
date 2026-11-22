// The header's verdict (which problem first), the counts of the page, and why the session cannot be opened.


export type StatusLevel = "ok" | "attention" | "stopped" | "down";

export type ProblemKind = "guard" | "red" | "yellow" | "alarm";

/** The page's tabs; a problem says which one holds its element. */
export type TabId = "status" | "quarantine" | "trust" | "more";

export interface ProblemRef {
  /** The element the button scrolls to. */
  anchor: string;
  tab: TabId;
  text: string;
  /** How many alarms this one line stands for (one per changed file / change, not one per line); 1 when absent. Every count on the page sums these. */
  weight?: number;
}

/** The number of alarms a list of problems stands for: one per change, whichever line they are told in. */
export const alarmCount = (list: Array<{ weight?: number }>): number => list.reduce((n, p) => n + (p.weight ?? 1), 0);

export interface Problem extends ProblemRef {
  kind: ProblemKind;
}

export interface StatusInput {
  /** Guard mode is on and the guard does not answer. */
  guardDown: boolean;
  /** Anchors and short names of cards that wait (deferred ones too: they are still unresolved). */
  red: ProblemRef[];
  yellow: ProblemRef[];
  /** The watchers' alarms (journal chain, gaps of the gate, agents, configuration). */
  alarms: ProblemRef[];
}

export interface Status {
  level: StatusLevel;
  label: string;
  count: number;
  /** All problems in the order the page walks them: guard, red, yellow, alarms. */
  problems: Problem[];
  first: Problem | null;
}

/** One indicator. Down: the guard does not answer. Attention: something waits or alarms. The first problem is the one the button leads to. */
export function pageStatus(i: StatusInput): Status {
  const problems: Problem[] = [
    ...(i.guardDown ? [{ kind: "guard" as const, anchor: "sbb-guard-alarm", tab: "status" as const, text: "Защита не отвечает" }] : []),
    ...i.red.map((r) => ({ kind: "red" as const, ...r })),
    ...i.yellow.map((r) => ({ kind: "yellow" as const, ...r })),
    ...i.alarms.map((r) => ({ kind: "alarm" as const, ...r })),
  ];
  const first = problems[0] ?? null;
  const count = alarmCount(problems);
  if (i.guardDown) return { level: "down", label: "Защита не работает", count, problems, first };
  if (i.red.length > 0) return { level: "stopped", label: `Остановлено (${i.red.length})`, count, problems, first };
  if (problems.length > 0) return { level: "attention", label: `Требует внимания (${count})`, count, problems, first };
  return { level: "ok", label: "Защищено", count: 0, problems, first: null };
}

/** Under the red «Остановлено»: what it means for the person (nothing of the found has run). */
export const STOPPED_EXPLAIN = "Эти плагины не запущены: то, что в них нашли, не выполнялось. Решите, что с ними делать.";

/** The text under the status when the guard is down (the page must say what actually happens: everything unbuilt-in is held). */
export const GUARD_DOWN_TEXT = "Защита не работает: она не отвечает. Новые плагины не загрузятся, а одобрить сейчас ничего нельзя. Что делать: на этой машине выполните «sbb-guard status».";

/** Why a running plugin keeps the approval session closed (its code could take the session's token). */
export interface SessionBlocker {
  id: string;
  /** Its source is not one of «мои источники»: code that is not yours. */
  foreign: boolean;
  /** It has an interface (an app part): its code runs in this very page. */
  ui: boolean;
}

/** The calm sentence for the page: who keeps the session closed and why, and what to do instead. */
export function sessionBlockText(blockers: SessionBlocker[]): string {
  const names = (list: SessionBlocker[]): string => list.map((b) => b.id).join(", ");
  const foreign = blockers.filter((b) => b.foreign);
  const uiOnly = blockers.filter((b) => !b.foreign);
  const parts: string[] = [];
  if (foreign.length > 0) parts.push(`Сессия недоступна, пока ${foreign.length > 1 ? "работают плагины" : "работает плагин"} ${names(foreign)} не из ваших источников: ${foreign.length > 1 ? "их код мог бы её перехватить" : "его код мог бы её перехватить"}.`);
  if (uiOnly.length > 0) parts.push(`${foreign.length > 0 ? "Ещё" : "Сессия недоступна, пока"} ${uiOnly.length > 1 ? "работают плагины" : "работает плагин"} ${names(uiOnly)} с интерфейсом: ${uiOnly.length > 1 ? "их интерфейс открыт" : "его интерфейс открыт"} на этой же странице и мог бы её перехватить.`);
  parts.push("Подтверждайте каждое действие касанием.");
  return parts.join(" ");
}

export interface PageCounts {
  /** Cards that wait for the person (open ones). Titles: «Ждут решения вас (N)». */
  waiting: number;
  /** Cards the person put aside themselves. «Отложено (N)». */
  deferred: number;
  /** The watchers' alarms (an alarm counts once per change). */
  alarms: number;
  /** What «Требует внимания (N)» and the tab «Статус (N)» say: waiting + deferred + alarms. */
  attention: number;
  /** Plugins held in quarantine (one per plugin, not per version): the tab «Карантин (N)». Kept, deferred and open ones, and removed skills. */
  quarantine: number;
  /** Kept in quarantine by the person: decided, not in the status. */
  kept: number;
}

/** Every number on the page from ONE plan of cards, so that they cannot disagree. */
export function pageCounts(plan: { active: unknown[]; later: unknown[]; kept: unknown[] }, alarms: number, removedSkills: number): PageCounts {
  const waiting = plan.active.length;
  const deferred = plan.later.length;
  const kept = plan.kept.length;
  return { waiting, deferred, alarms, attention: waiting + deferred + alarms, quarantine: waiting + deferred + kept + removedSkills, kept };
}

/** «Ждут вас: 14 · отложено: 1 · тревог: 2»: where the number of the status comes from. Empty when there is nothing to add up. */
export function countsLine(c: PageCounts): string {
  const parts = [c.waiting > 0 ? `ждут вас: ${c.waiting}` : "", c.deferred > 0 ? `отложено вами: ${c.deferred}` : "", c.alarms > 0 ? `тревог: ${c.alarms}` : ""].filter(Boolean);
  return parts.length > 1 ? `Из чего число: ${parts.join(" · ")}.` : "";
}
