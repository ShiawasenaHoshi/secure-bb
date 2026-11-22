// «Пока вас не было» and the alarms of the page: journal records grouped for the summary, the guard's and the gate's gaps, what a stopped plugin leaves open.
import { type ProblemRef, alarmCount } from "./status.js";
import { plural } from "./words.js";

export interface AwayEvent {
  ts: number;
  kind: string;
  pluginId: string | null;
  /** The thread a version came from, when the journal knows it. */
  threadId?: string | null;
  detail?: unknown;
  /** Which journal wrote it. In guard mode the guard's journal is the truth for decisions and the plugin's only adds alarms. */
  from: "guard" | "plugin";
}

export type AwayClass = "auto" | "window" | "approved" | "held" | "stopped" | "rejected" | "deleted" | "alarm";

const ALARM_KINDS = new Set(["window.taint", "watch.window.taint", "journal.alarm", "skills.alarm", "gate.gap", "hook.dead", "watch.rollback.failed", "agents.critical", "agents.taint"]);

const detailOf = (e: AwayEvent): Record<string, unknown> => (e.detail !== null && typeof e.detail === "object" ? (e.detail as Record<string, unknown>) : {});

/** One journal record → what it was, for the summary. Null: not something to report (reads, sessions, scans). */
export function classifyAway(e: AwayEvent, guardMode: boolean): AwayClass | null {
  if (ALARM_KINDS.has(e.kind)) return "alarm";
  // With a guard, its journal tells the decisions; the plugin's copies of the same decisions would count them twice.
  if (guardMode && e.from === "plugin") return null;
  if (!guardMode && e.from === "guard") return null;
  const d = detailOf(e);
  switch (e.kind) {
    case "approved.source":
      return "auto";
    case "approved.window":
      return "window";
    case "approved.touch":
    case "approved.trust":
    case "approved.guard":
      return "approved";
    case "hold": {
      const reason = typeof d.reason === "string" ? d.reason : typeof d.note === "string" ? d.note : "";
      return d.stop === true || /жёсткий флаг|заблокирован/.test(reason) ? "stopped" : "held";
    }
    case "dismissed":
      // The person pressed «Удалить»: the summary says «удалён», not «отклонена».
      return "deleted";
    case "reject":
      return "rejected";
    default:
      return null;
  }
}

export interface AwayGroup {
  key: string;
  pluginId: string | null;
  threadId: string | null;
  counts: Record<AwayClass, number>;
  last: number;
  text: string;
}

const emptyCounts = (): Record<AwayClass, number> => ({ auto: 0, window: 0, approved: 0, held: 0, stopped: 0, rejected: 0, deleted: 0, alarm: 0 });

const versions = (n: number): string => `${n} ${plural(n, "версия", "версии", "версий")}`;

/** «4 версии figma-sync прошли сами, 1 остановлена». */
export function awayText(g: Pick<AwayGroup, "pluginId" | "counts">): string {
  const c = g.counts;
  const name = g.pluginId ?? "системы";
  const parts: string[] = [];
  if (c.auto > 0) parts.push(`${versions(c.auto)} ${name} ${c.auto % 10 === 1 && c.auto % 100 !== 11 ? "прошла сама" : "прошли сами"}`);
  if (c.window > 0) parts.push(`${versions(c.window)} ${name} ${c.window % 10 === 1 && c.window % 100 !== 11 ? "прошла" : "прошли"} во временном доверии`);
  // Neutral: the journal does not always know who touched (a window, a source, a session), so it does not say «вы».
  if (c.approved > 0) parts.push(`${versions(c.approved)} ${name} ${plural(c.approved, "одобрена", "одобрены", "одобрено")}`);
  if (c.held > 0) parts.push(`${c.held} ${plural(c.held, "версия ждёт", "версии ждут", "версий ждут")} вашего решения`);
  if (c.stopped > 0) parts.push(`${c.stopped} ${plural(c.stopped, "остановлена", "остановлены", "остановлено")}`);
  if (c.rejected > 0) parts.push(`${c.rejected} ${plural(c.rejected, "отклонена", "отклонены", "отклонено")}`);
  if (c.deleted > 0) parts.push(`${versions(c.deleted)} ${name} ${plural(c.deleted, "удалена", "удалены", "удалено")}`);
  if (c.alarm > 0) parts.push(`${c.alarm} ${plural(c.alarm, "тревога", "тревоги", "тревог")}`);
  // "4 версии figma-sync прошли сами, 1 остановлена": the name stands once, with the first part; for the lone alarm of the system it stands alone.
  if (parts.length === 0) return "";
  const head = parts[0]!;
  if (c.alarm > 0 && g.pluginId === null && parts.length === 1) return `${c.alarm} ${plural(c.alarm, "тревога", "тревоги", "тревог")} системы`;
  const tail = parts.slice(1).map((p) => p.replace(` ${name} `, " "));
  // A line always says WHOSE versions it counts: «2 остановлены» with no name next to «1 остановлена» of another plugin reads as a contradiction.
  const joined = [head, ...tail].join(", ");
  return head.includes(name) ? joined : `${name}: ${joined}`;
}

/** Events since `since`, grouped by plugin and thread, the busiest (stopped, waiting, alarm) first. Journal order does not matter. */
export interface HeldNow {
  /** Cards waiting (yellow) and stopped (red) right now: the lists the person sees. */
  yellow: number;
  red: number;
}

export function groupAway(events: AwayEvent[], since: number, guardMode: boolean, heldNow?: Record<string, HeldNow>): AwayGroup[] {
  const groups = new Map<string, AwayGroup>();
  const seen = new Set<string>();
  for (const e of events) {
    if (e.ts <= since) continue;
    const cls = classifyAway(e, guardMode);
    if (cls === null) continue;
    // A decision about a plugin version always names the plugin. A record without one is the system's own: only an alarm is told of it ("1 остановлена"
    // with no subject next to the line of the plugin itself said the same thing twice).
    if (e.pluginId === null && cls !== "alarm") continue;
    // The same record can come twice (both journals list recent entries, the page re-reads them): one line per record.
    const id = `${e.from}|${e.ts}|${e.kind}|${e.pluginId ?? ""}|${JSON.stringify(e.detail ?? null)}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const threadId = e.threadId ?? null;
    const key = `${e.pluginId ?? "-"}|${threadId ?? "-"}`;
    let g = groups.get(key);
    if (!g) {
      g = { key, pluginId: e.pluginId, threadId, counts: emptyCounts(), last: 0, text: "" };
      groups.set(key, g);
    }
    g.counts[cls]++;
    g.last = Math.max(g.last, e.ts);
  }
  if (heldNow) {
    // What waits is what the lists say now, once per plugin (on its latest group), and only where a hold happened in the period.
    const byPlugin = new Map<string, AwayGroup[]>();
    for (const g of groups.values()) if (g.pluginId !== null) byPlugin.set(g.pluginId, [...(byPlugin.get(g.pluginId) ?? []), g]);
    for (const [plugin, list] of byPlugin) {
      const sawHold = list.some((g) => g.counts.held + g.counts.stopped > 0);
      const now = heldNow[plugin];
      for (const g of list) {
        g.counts.held = 0;
        g.counts.stopped = 0;
      }
      if (sawHold && now) {
        const latest = list.reduce((x, y) => (y.last > x.last ? y : x));
        latest.counts.held = now.yellow;
        latest.counts.stopped = now.red;
      }
    }
  }
  // A plugin's «остановлена» and «ждёт решения» are said once, on its latest line, however many threads the plugin's records came from.
  const byPlugin = new Map<string, AwayGroup[]>();
  for (const g of groups.values()) if (g.pluginId !== null) byPlugin.set(g.pluginId, [...(byPlugin.get(g.pluginId) ?? []), g]);
  for (const list of byPlugin.values()) {
    if (list.length < 2) continue;
    const latest = list.reduce((x, y) => (y.last > x.last ? y : x));
    for (const g of list) {
      if (g === latest) continue;
      latest.counts.stopped = Math.max(latest.counts.stopped, g.counts.stopped);
      latest.counts.held = Math.max(latest.counts.held, g.counts.held);
      g.counts.stopped = 0;
      g.counts.held = 0;
    }
  }
  const weight = (g: AwayGroup): number => (g.counts.stopped + g.counts.alarm > 0 ? 2 : g.counts.held > 0 ? 1 : 0);
  return [...groups.values()]
    .map((g) => ({ ...g, text: awayText(g) }))
    .filter((g) => g.text !== "")
    .sort((a, b) => weight(b) - weight(a) || b.last - a.last);
}

/**
 * The summary's information lines: the alarms are not among them. An alarm is told from what is wrong NOW (see `awayAlarms`), so that
 * «Всё в порядке» (which only hides the information lines) cannot close one: it goes when it is dealt with where it is.
 */
export const awayInfoEvents = (events: AwayEvent[], guardMode: boolean): AwayEvent[] => events.filter((e) => classifyAway(e, guardMode) !== "alarm");

export interface AwayAlarms {
  /** «3 тревоги системы»: the count, with the decoding below. */
  title: string;
  items: ProblemRef[];
}

/** The alarms of the summary: each current alarm by name, with the place to deal with it. Null when none. */
export function awayAlarms(alarms: ProblemRef[]): AwayAlarms | null {
  if (alarms.length === 0) return null;
  const n = alarmCount(alarms);
  return { title: `${n} ${plural(n, "тревога", "тревоги", "тревог")} системы`, items: alarms };
}

/** One line for the skills that wait: «Скиллы: 38 ждут проверки, из них 12 с жёсткими признаками». Null: nothing waits. */
export function skillsSummary(open: Array<{ decision?: string }>): { text: string; hard: number; total: number } | null {
  if (open.length === 0) return null;
  const hard = open.filter((q) => q.decision === "block").length;
  const waits = `${open.length} ${plural(open.length, "ждёт проверки", "ждут проверки", "ждут проверки")}`;
  return { total: open.length, hard, text: `Скиллы: ${waits}${hard > 0 ? `, из них ${hard} с жёсткими признаками` : ""}` };
}

/** The number on the «Карантин» tab: what its two lists show. */
export const quarantineCount = (heldPlugins: number, removedSkills: number): number => heldPlugins + removedSkills;

/** From when "while you were away" counts: the moment of the last «Всё в порядке» the page saved, else a day back. Not a security value. */
export function awaySince(stored: string | null, now: number): number {
  const day = 24 * 60 * 60 * 1000;
  const t = stored === null ? NaN : Number(stored);
  if (!Number.isFinite(t) || t <= 0 || t > now) return now - day;
  return t;
}

/**
 * The time to remember at «Всё в порядке»: not before the newest event the person was shown. A journal's clock can run a little ahead of
 * the page's, and an event stamped after «now» would come back at once as if it were new.
 */
export function awaySeenMark(events: AwayEvent[], now: number): number {
  let t = now;
  for (const e of events) if (Number.isFinite(e.ts) && e.ts > t) t = e.ts;
  return t;
}

export const AWAY_HIDE_LABEL = "Понятно, скрыть";

/**
 * What an open CRITICAL difference in the agents' settings does at this moment. Each flag is a fact about the code, and test/guard/critical-effects.test.ts
 * measures every one of them against a real guard: if the behaviour changes, that test fails and the text below is not allowed to stay as it is.
 */
export interface CriticalEffects {
  /** The windows of trust that were open when the change was seen are closed (and a thread whose directory it is, with its sub-threads, is marked). */
  closesEarlierWindows: boolean;
  /** A new version from an own or known source whose rights did not grow still passes by itself. */
  sourcesStillPass: boolean;
  /** Versions already approved keep running. */
  approvedStillRun: boolean;
  /** A window can be opened after the change only with a fresh code or touch (a session does not cover it), and the touch says why it is risky. */
  newWindowsNeedFreshTouch: boolean;
  /** New messages to the agents are held only after «Остановить агентов» was pressed. */
  holdsAgentsOnlyAfterStop: boolean;
}

export const CRITICAL_EFFECTS: CriticalEffects = { closesEarlierWindows: true, sourcesStillPass: false, approvedStillRun: true, newWindowsNeedFreshTouch: true, holdsAgentsOnlyAfterStop: true };

export interface AgentAlarmText {
  /** What is blocked while it is open. */
  blocked: string;
  /** What keeps working. */
  works: string;
}

export function agentAlarmText(e: CriticalEffects = CRITICAL_EFFECTS): AgentAlarmText {
  const blocked: string[] = [];
  const works: string[] = [];
  if (e.closesEarlierWindows) blocked.push("окна доверия, открытые до этого изменения, закрыты, а в чатах, где оно случилось, временное доверие не действует");
  if (!e.sourcesStillPass) blocked.push("новые версии плагинов сами не проходят (ни по источнику, ни по окнам): только вашим решением");
  else works.push("версии из ваших источников без новых прав проходят сами");
  if (e.newWindowsNeedFreshTouch) blocked.push("новое окно доверия открывается только со свежим кодом или касанием, с предупреждением");
  else works.push("новое окно доверия открыть можно");
  if (!e.approvedStillRun) blocked.push("одобренные плагины не запускаются");
  else works.push("уже одобренные плагины работают");
  works.push(e.holdsAgentsOnlyAfterStop ? "агенты сами не остановлены: это делает кнопка «Остановить агентов» в карточке" : "новые сообщения агентам удерживаются");
  const cap = (t: string): string => t.charAt(0).toUpperCase() + t.slice(1);
  return { blocked: blocked.length > 0 ? `${cap(blocked.join("; "))}.` : "Ничего не заблокировано: это только сигнал.", works: `${cap(works.join("; "))}.` };
}

/**
 * What happens while the secure-bb PLUGIN is not running and the guard daemon (sbb-guard) is. Each flag is a fact about the code;
 * test/guard/plugin-down-effects.test.ts measures the first five against a real guard, so the alarm text cannot stay as it is when they change.
 * The rest is by construction (what lives in the plugin: the page, the codes' form, the config watch, the hook's extra checks) and the test pins them too.
 */
export interface PluginDownEffects {
  /** The core asks the guard, not the plugin: a version nobody approved is held. */
  guardHoldsUnknown: boolean;
  /** Versions approved before keep loading. */
  guardApprovedStillRun: boolean;
  /** The guard reads the agents' files by itself and closes the windows on a critical change. */
  guardWatchesAgents: boolean;
  /** An open window keeps its time (the guard expires it). */
  guardExpiresWindows: boolean;
  /** A window bound to a thread (tree / thread) lets nothing in while the plugin does not call the guard: only the plugin knows the threads. */
  windowPausedWithoutPlugin: boolean;
  /** Any window lets a version in only after the guard's own checks, pulse or no pulse (a pulse can be faked): no hard sign, no right the approved version did not have. */
  windowChecked: boolean;
  /** The page, the form for codes and touches, `bb secure-bb propose` and the config watch (account, instructions, skills, env, built-in plugins) are the plugin's own. */
  pageAndConfigWatchAreThePlugins: boolean;
}

export const PLUGIN_DOWN_EFFECTS: PluginDownEffects = {
  guardHoldsUnknown: true,
  guardApprovedStillRun: true,
  guardWatchesAgents: true,
  guardExpiresWindows: true,
  windowPausedWithoutPlugin: true,
  windowChecked: true,
  pageAndConfigWatchAreThePlugins: true,
};

export interface GapLike {
  from: number;
  to: number;
  ms: number;
  stopped?: boolean;
  safeMode?: boolean | null;
  mode?: "guard" | "hook";
  cause?: "server" | "unknown";
  coreHolds?: boolean;
  errorText?: string | null;
}

export interface GapContext {
  /** How the plugin runs now: used for a record written before the record carried its own mode. */
  guardModeNow: boolean;
  coreHoldsNow: boolean;
  /** The config watch has an accepted first snapshot (nothing is watched without one). */
  configWatch: boolean;
  /** What the host said about why the plugin was down, when something can say it (a status or an error text). Overrides the guess in the record. */
  reason?: { kind: "disabled" } | { kind: "error"; text?: string | null };
}

export interface GapText {
  /** `critical`: a red alarm that stays; `calm`: a line in «Пока вас не было» with «Понятно». */
  severity: "critical" | "calm";
  mode: "guard" | "hook";
  headline: string;
  /** What kept working (guard mode only). */
  works: string;
  /** What did not work. */
  notWorking: string;
  /** What the downtime really opened, by name; empty for a calm line. */
  opens: string[];
}

const minutesOf = (ms: number): string => `${Math.max(1, Math.round(ms / 60_000))} мин`;

/** Why it was down, in words; null when it cannot be told (then the text does not say «выключили»). */
export function gapCauseText(gap: Pick<GapLike, "cause">, reason?: GapContext["reason"]): string | null {
  if (reason?.kind === "disabled") return "плагин был выключен";
  if (reason?.kind === "error") return reason.text ? `ошибка запуска плагина: ${reason.text}` : "ошибка запуска плагина";
  if (gap.cause === "server") return "сервер bb был остановлен";
  return null;
}

export function gapAlarmText(gap: GapLike, ctx: GapContext, e: PluginDownEffects = PLUGIN_DOWN_EFFECTS): GapText {
  const mode = gap.mode ?? (ctx.guardModeNow ? "guard" : "hook");
  const cause = gapCauseText(gap, ctx.reason);
  const because = cause ? ` (${cause})` : "";
  const dur = minutesOf(gap.ms);
  if (mode !== "guard") {
    const coreHolds = gap.coreHolds ?? ctx.coreHoldsNow;
    return {
      severity: "critical",
      mode,
      headline: `Гейт не работал ${dur}${because}`,
      works: "",
      notWorking: coreHolds
        ? "Ядро bb не загружало новые плагины и версии (ждали гейт), но ничего не проверялось и не одобрялось; настройки bb и агентов не отслеживались, за это время их могли поменять и вернуть."
        : "Пока гейта нет, ничего не удерживается и не проверяется; за это время могли поменять настройки и вернуть их.",
      opens: ["всё"],
    };
  }
  const works: string[] = [];
  if (e.guardHoldsUnknown) works.push("версии плагинов удерживались и проверялись сторожем");
  if (e.guardApprovedStillRun) works.push("одобренные версии работали");
  if (e.guardWatchesAgents) works.push("настройки агентов отслеживались");
  if (e.windowPausedWithoutPlugin) works.push("окна доверия по треду стояли (версии по ним не проходили)");
  if (e.windowChecked) works.push("окна доверия пропускали версию только после проверок сторожа (жёсткие признаки, новые права)");
  const notWorking: string[] = [];
  const opens: string[] = [];
  if (e.pageAndConfigWatchAreThePlugins) notWorking.push("страница, коды и касания (одобрить версию и открыть окно было нельзя), команда `bb secure-bb propose`");
  if (e.pageAndConfigWatchAreThePlugins && ctx.configWatch) {
    const t = "наблюдение за настройками bb (аккаунт, инструкции, скиллы, окружение, встроенные плагины): что изменили и вернули за это время, не видно";
    notWorking.push(t);
    opens.push(t);
  }
  return {
    severity: opens.length > 0 ? "critical" : "calm",
    mode,
    headline: `Страница защиты не работала ${dur}${because}`,
    works: `Сторож в это время работал: ${works.join(", ")}.`,
    notWorking: `Не работало: ${notWorking.join("; ")}.`,
    opens,
  };
}

/** The gaps that are still to be shown: not set aside with «Понятно». */
export const unackedGaps = <G extends { at: number }>(gaps: G[], ackedAt: number | null): G[] => gaps.filter((g) => ackedAt === null || g.at > ackedAt);

// ---- a pause of the plugin during an update the owner declared ----------------------------------------------------------------------
/**
 * A window of planned maintenance, as the guard keeps it (declared at its console, never over the socket): from `beganAt` to `endedAt` if the owner closed it,
 * else to `until` (20 minutes by default, 60 at most).
 */
export interface MaintenanceWindow {
  beganAt: number;
  until: number;
  endedAt: number | null;
  reason?: string;
}
/** The plugin writes its mark of life every 15 s, so the last mark of a pause can come this much before the moment the owner declared the window. */
export const GAP_START_SLACK_MS = 15_000;

/**
 * Was the pause the owner's planned update?
 *  - `planned`: it began and ended inside one declared window: a calm line;
 *  - `overrun`: it began inside a window and ended after the window did («во время обновления, но дольше окна»): still an alarm, with that note;
 *  - `outside`: no window, or it began before the window, or after it: an alarm, as it always was.
 * Pure: the windows and the pause are the only inputs, and nothing but a window the guard recorded can make an alarm calm.
 */
export function gapPlan(gap: { from: number; to: number }, windows: MaintenanceWindow[]): "planned" | "overrun" | "outside" {
  let overrun = false;
  for (const w of windows) {
    const end = Math.min(w.endedAt ?? w.until, w.until);
    const beganInside = gap.from >= w.beganAt - GAP_START_SLACK_MS && gap.from <= end;
    if (!beganInside) continue;
    if (gap.to <= end) return "planned";
    overrun = true;
  }
  return overrun ? "overrun" : "outside";
}

export type GapPlan = ReturnType<typeof gapPlan>;
export interface GapView extends GapText {
  plan: GapPlan;
}
/**
 * The text of one pause, with the owner's declared maintenance taken into account. A planned pause is a calm line («Обновление secure-bb: страница не работала 3 мин
 * (с … по …), сторож работал»; what did not work is for «Подробнее»); one that ran past the window is an alarm with a note; the rest is `gapAlarmText` as before.
 */
export function gapView(gap: GapLike, ctx: GapContext, windows: MaintenanceWindow[], fmt: (t: number) => string): GapView {
  const base = gapAlarmText(gap, ctx);
  const plan = base.mode === "guard" ? gapPlan(gap, windows) : "outside";
  if (plan === "planned") return { ...base, severity: "calm", plan, opens: [], headline: `Обновление secure-bb: страница не работала ${minutesOf(gap.ms)} (с ${fmt(gap.from)} по ${fmt(gap.to)}), сторож работал` };
  if (plan === "overrun") return { ...base, plan, headline: `${base.headline} — во время обновления, но дольше окна` };
  return { ...base, plan };
}

export interface GapGroup {
  mode: "guard" | "hook";
  /** One line: «Страница защиты не работала 2 раза: 3 мин и 13 мин». */
  summary: string;
  /** One line per pause, for «Подробнее». */
  items: string[];
  /** What worked and what did not: the same for every pause of the mode, said once. */
  works: string;
  notWorking: string;
  count: number;
}
const listAnd = (xs: string[]): string => (xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} и ${xs[xs.length - 1]}`);
/** Pauses of one kind are told together: a line of the point and the list under «Подробнее» (one paragraph for «что работало / что нет», not one per pause). */
export function groupGaps(lines: Array<{ gap: GapLike; text: GapView }>, fmt: (t: number) => string): GapGroup[] {
  const out: GapGroup[] = [];
  for (const mode of ["guard", "hook"] as const) {
    const mine = lines.filter((l) => l.text.mode === mode);
    if (mine.length === 0) continue;
    const first = mine[0]!;
    const noun = mode === "guard" ? "Страница защиты не работала" : "Гейт не работал";
    const over = mine.some((l) => l.text.plan === "overrun");
    const summary =
      mine.length === 1
        ? `${first.text.headline} (с ${fmt(first.gap.from)} по ${fmt(first.gap.to)})`
        : `${noun} ${mine.length} ${plural(mine.length, "раз", "раза", "раз")}: ${listAnd(mine.map((l) => minutesOf(l.gap.ms)))}${over ? " (в том числе во время обновления, но дольше окна)" : ""}`;
    const items = mine.map((l) => {
      const cause = gapCauseText(l.gap);
      return `${fmt(l.gap.from)} — ${fmt(l.gap.to)}: ${minutesOf(l.gap.ms)}${cause ? ` (${cause})` : ""}${l.text.plan === "overrun" ? " — во время обновления, но дольше окна" : ""}`;
    });
    out.push({ mode, summary, items, works: first.text.works, notWorking: first.text.notWorking, count: mine.length });
  }
  return out;
}
