// What the first screen says, as data: the one line of the header, which alarms are real alarms, what «Пока вас не было» may repeat.
// The verdicts themselves (what is red, what waits, what is an alarm) are ux.ts's; this arranges them for the page.
import type { Overview } from "./overview";
import type { QueueRow } from "./store";
import type { SkillQueueView } from "./skills/guard";
import { agentsSectionTab, alarmCount, awayText, cardColor, GUARD_DOWN_TEXT, STOPPED_EXPLAIN, gapView, pageCounts, plural, pageStatus, unackedGaps, type AwayGroup, type CardPlan, type GapContext, type GapView, type PageCounts, type PluginCard, type ProblemRef, type Status, type TabId } from "./ux";

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

// ---- the gaps of the gate and the page's alarms ----------------------------------------------------------------------------------
/** What a gap says, built from the facts of its mode (`gapAlarmText`). */
export function gapContext(ov: Overview): GapContext {
  return { guardModeNow: ov.guard !== undefined, coreHoldsNow: ov.alive.coreHolds, configWatch: ov.watch.baselineAt !== null };
}

export type GapLine = { gap: Overview["alive"]["gaps"][number]; text: GapView };

const defaultTime = (t: number): string => new Date(t).toLocaleString();

/**
 * The pauses of the plugin, sorted by what they are:
 *  - `critical`: a red alarm — a pause that opened something, outside the owner's declared maintenance (or past its window), and not yet confirmed with «Я проверил»;
 *  - `calm`: a line in «Пока вас не было» — a pause that opened nothing, or the owner's own planned update (begun and ended inside a window declared at the guard's console).
 * Whatever is an alarm without a declared window stays an alarm: only a window the guard recorded can make one calm, and only a code or a touch can hide one.
 */
export function gapsBySeverity(ov: Overview, fmt: (t: number) => string = defaultTime): { critical: GapLine[]; calm: GapLine[] } {
  const ctx = gapContext(ov);
  const windows = ov.guard?.maintenance ?? [];
  const reviewed = new Set(ov.alive.reviewedAts ?? []);
  const all = ov.alive.gaps.map((gap) => ({ gap, text: gapView(gap, ctx, windows, fmt) }));
  const calm = unackedGaps(all.filter((g) => g.text.severity === "calm").map((g) => ({ ...g, at: g.gap.at })), ov.alive.gapsAckedAt);
  return { critical: all.filter((g) => g.text.severity === "critical" && !reviewed.has(g.gap.at)), calm };
}

// ---- the floating strip over the whole of bb --------------------------------------------------------------------------------------
/**
 * What the strip that floats over EVERY screen of bb shows. It must stay small: the alarm about a pause is ONE line (the words, the paragraphs and the lists are on the plugin's
 * own page), and it can be folded to a dot. Folding hides nothing from the page and confirms nothing; it is remembered only until a NEW alarm comes (the key is the set of the
 * pauses' `at`). An open trust window is never folded away: its row is shown whatever the alarm does.
 */
export interface OverlayView {
  /** The one line of the alarm about the gate not working, or null when there is none. */
  alarmLine: string | null;
  /** What the folded state is remembered against: the set of the pauses (`at`) and the safe-mode flag. A new alarm is a new key. */
  alarmKey: string;
  /** The alarm is folded to a dot (the remembered key is this alarm's). */
  collapsed: boolean;
  windows: boolean;
  journalAlarm: boolean;
  /** Anything at all to draw. */
  show: boolean;
}
export const OVERLAY_COLLAPSE_KEY = "sbb-overlay-collapsed";
const minutesOfGap = (ms: number): number => Math.max(1, Math.round(ms / 60_000));
const listAnd = (xs: string[]): string => (xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} и ${xs[xs.length - 1]}`);
export function overlayView(ov: Overview, collapsedKey: string | null): OverlayView {
  const gaps = gapsBySeverity(ov).critical.map((g) => g.gap).sort((a, b) => a.from - b.from);
  const safe = ov.alive.safeMode === true;
  const parts: string[] = [];
  if (gaps.length === 1) parts.push(`защита не работала ${minutesOfGap(gaps[0]!.ms)} мин`);
  if (gaps.length > 1) parts.push(`защита не работала ${gaps.length} ${plural(gaps.length, "раз", "раза", "раз")} (${listAnd(gaps.map((g) => String(minutesOfGap(g.ms))))} мин)`);
  if (safe) parts.push("включён safe-mode bb");
  const alarmLine = parts.length > 0 ? `Тревога: ${parts.join("; ")}` : null;
  const alarmKey = `${[...gaps.map((g) => g.at)].sort((a, b) => a - b).join(",")}${safe ? "|safe" : ""}`;
  const windows = ov.windows.length > 0 || ov.watch.windows.length > 0;
  const journalAlarm = !ov.journal.ok;
  return { alarmLine, alarmKey, collapsed: alarmLine !== null && collapsedKey === alarmKey, windows, journalAlarm, show: alarmLine !== null || windows || journalAlarm };
}

/** What the guard found in the agents' settings, as the numbers that make an alarm, and the tab the section stands on while one is open. */
export function agentsFacts(ov: Overview): { critical: number; alarms: number; tab: TabId } {
  const critical = (ov.agents?.state?.drifts ?? []).filter((d) => d.class === "critical" && !d.initial).length;
  const alarms = (ov.agents?.state?.alarms ?? []).length;
  // While something critical or an alarm waits, the section is on «Обзор» (the banner leads to it); otherwise it stays in «Журнал».
  return { critical, alarms, tab: agentsSectionTab({ critical, alarms }) };
}

const agentsAlarmText = (critical: number, alarms: number): string =>
  `Настройки агентов: ${[critical > 0 ? `критичных изменений — ${critical}` : "", alarms > 0 ? `файлов не прочитать — ${alarms}` : ""].filter(Boolean).join(", ")}`;

/** The alarms of the system, in the order the header and the counts read them. Every one is a real alarm; none is turned down. */
export function pageAlarms(ov: Overview, registered: boolean): ProblemRef[] {
  const alarms: ProblemRef[] = [];
  const gaps = gapsBySeverity(ov).critical;
  const agents = agentsFacts(ov);
  if (!ov.journal.ok) alarms.push({ anchor: "sbb-alarms", tab: "status", text: "Журнал решений нарушен" });
  if (gaps.length > 0 || ov.alive.safeMode === true) alarms.push({ anchor: "sbb-alarms", tab: "status", text: gaps.every((g) => g.text.mode === "guard") ? "Плагин secure-bb не работал" : "Гейт не всегда работал" });
  if (ov.guard?.connected && ov.guard.journal && !ov.guard.journal.valid) alarms.push({ anchor: "sbb-guard-alarm", tab: "status", text: "Журнал сторожа нарушен" });
  if (ov.agents && (agents.alarms > 0 || agents.critical > 0)) alarms.push({ anchor: "sbb-agents", tab: agents.tab, text: agentsAlarmText(agents.critical, agents.alarms), weight: agents.critical + agents.alarms });
  if (ov.watch.drifts.some((d) => d.status === "open" || d.status === "rollback-failed")) alarms.push({ anchor: "sbb-watch", tab: "more", text: "Настройки bb изменились" });
  if (!registered) alarms.push({ anchor: SECOND_FACTOR_ANCHOR, tab: "more", text: "Второй фактор не настроен" });
  if ((ov.guard?.troubleshootUntil ?? 0) > ov.now) alarms.push({ anchor: "sbb-guard-alarm", tab: "status", text: "Включён режим отладки сторожа: он пропускает всё" });
  return alarms;
}

/** The skills that were removed, once each: the list of «Карантин» and the number on it. */
export const removedSkillsOf = (ov: Overview): SkillQueueView[] => [...ov.skills.open, ...ov.skills.recent].filter((s, i, all) => s.state === "removed" && all.findIndex((x) => x.id === s.id) === i);

/** The versions that wait for the person (the guard holds them). */
export const heldOf = (ov: Overview): QueueRow[] => ov.queue.filter((q) => q.status === "held");

/** Plugins with a version that was let in but did not start, and the reason. */
export const startedBadly = <P extends { pin: unknown }>(plugins: P[], problem: (p: P) => string | null): P[] => plugins.filter((p) => p.pin !== null && problem(p) !== null);

const isRed = (ov: Overview, q: QueueRow): boolean => cardColor({ reason: q.reason, reasonKind: q.reasonKind, blocks: q.blocks, findings: ov.queueChecks[q.id]?.findings ?? [] }) === "red";

/** The place a plugin's card is: «Показать» goes to it. */
export const cardRef = (c: { shown: QueueRow; pluginId: string }): ProblemRef => ({ anchor: `sbb-card-${c.shown.id}`, tab: "status", text: `${c.pluginId} ${c.shown.version}` });

export interface PageSummary {
  alarms: ProblemRef[];
  status: Status;
  counts: PageCounts;
  header: HeaderLine;
  /** The longer words behind an alarm header, or null. */
  headerMore: string | null;
  guardDown: boolean;
  agents: ReturnType<typeof agentsFacts>;
}

/** Everything the first screen says, from the overview and the plan of cards: one place, so every number on the page comes from the same plan. */
export function summarize(ov: Overview, plan: CardPlan<QueueRow>, registered: boolean): PageSummary {
  const planned: Array<PluginCard<QueueRow>> = [...plan.active, ...plan.later];
  const redOf = (c: PluginCard<QueueRow>): boolean => c.all.some((q) => isRed(ov, q));
  const alarms = pageAlarms(ov, registered);
  const guardDown = ov.guard !== undefined && !ov.guard.connected;
  const status = pageStatus({ guardDown, red: planned.filter(redOf).map(cardRef), yellow: planned.filter((c) => !redOf(c)).map(cardRef), alarms });
  // Every number on the page comes from the one plan of cards.
  const counts = pageCounts(plan, alarmCount(alarms), removedSkillsOf(ov).length);
  const header = headerLine({ status, waiting: counts.waiting, deferred: counts.deferred, alarms });
  const headerMore = guardDown ? GUARD_DOWN_TEXT : status.level === "stopped" ? STOPPED_EXPLAIN : null;
  return { alarms, status, counts, header, headerMore, guardDown, agents: agentsFacts(ov) };
}
