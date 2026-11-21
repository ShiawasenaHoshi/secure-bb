// UX v1, PR 2: the page's decisions as pure functions (no React, no I/O, no clock): which status, which problem first, which colour a
// card has, what its plain words are, what "while you were away" says, what a key's AAGUID means. The page only draws what these say.
//
// Nothing here decides anything about plugins: approving and holding stay with the guard. These functions choose what to SHOW.
import type { TrustMode } from "./guardlink.js";

// ---- modes ------------------------------------------------------------------------------------------------------------------
export interface DetailLevel {
  /** Technical fields are open when the card is drawn. */
  expanded: boolean;
  /** Hashes and exact versions are shown (Strict). */
  hashes: boolean;
  /** "Всё равно разрешить…" exists on a red card. */
  bypass: boolean;
}
/** What a mode changes on the page: Simple folds the technical fields, Detailed opens them, Strict opens them with hashes and has no bypass. */
export function detailLevel(mode: TrustMode | null): DetailLevel {
  switch (mode) {
    case "detailed":
      return { expanded: true, hashes: false, bypass: true };
    case "strict":
      return { expanded: true, hashes: true, bypass: false };
    default:
      return { expanded: false, hashes: false, bypass: true };
  }
}

// ---- plain words ------------------------------------------------------------------------------------------------------------
/** Words the MAIN text of a card must not use (the technical fields below the fold may). */
export const TECHNICAL_WORDS = /хеш|хэш|hash|\bast\b|манифест|manifest|sha-?\d|sha256/i;

/** Russian plural: `plural(4, "версия", "версии", "версий")`. */
export function plural(n: number, one: string, few: string, many: string): string {
  const a = Math.abs(n) % 100;
  const b = a % 10;
  if (a > 10 && a < 20) return many;
  if (b === 1) return one;
  if (b >= 2 && b <= 4) return few;
  return many;
}

// Control, bidi and zero-width characters, built from code points so this file itself carries none of them.
const NOT_TEXT = new RegExp(`[${[[0x00, 0x1f], [0x7f, 0x9f], [0x200b, 0x200f], [0x202a, 0x202e], [0x2066, 0x2069], [0xfeff, 0xfeff]].map(([a, b]) => `\\u{${a!.toString(16)}}-\\u{${b!.toString(16)}}`).join("")}]`, "gu");

/** The author's words (`secureBb.why`), made safe to show: text only, no control characters, one line, short. Null: nothing usable. */
export function cleanWhy(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  // eslint-disable-next-line no-control-regex
  const t = raw.replace(NOT_TEXT, " ").replace(/\s+/g, " ").trim();
  if (t === "") return null;
  return t.length > 240 ? `${t.slice(0, 239)}…` : t;
}

/** A readable name of where a version came from, from the core's own `source` (never from the plugin). */
export function sourceLabel(sourceKind: string, source: string): string {
  if (sourceKind === "git") {
    const m = /github\.com[/:]([^/\s]+)\/([^/@#\s]+?)(?:\.git)?(?:[@#\s]|$)/i.exec(source);
    return m ? `github.com/${m[1]}/${m[2]}` : source.replace(/^git:/, "").slice(0, 80);
  }
  if (sourceKind === "path") return `из папки ${source.replace(/^path:/, "").slice(0, 80)}`;
  if (sourceKind === "npm") return `npm: ${source.replace(/^npm:/, "").slice(0, 60)}`;
  return source.slice(0, 80);
}

export interface CapLike {
  kind: string;
  detail: string[];
}
/** A piece of a phrase; `red` marks the word that must catch the eye («все»). */
export interface Segment {
  text: string;
  red?: boolean;
}
const ENV_PLAIN: Record<string, string> = {
  HOME: "узнать путь к вашей домашней папке",
  USER: "узнать имя вашего пользователя",
  LOGNAME: "узнать имя вашего пользователя",
  PATH: "узнать, в каких папках компьютер ищет программы",
  SHELL: "узнать, какая у вас оболочка терминала",
  LANG: "узнать язык системы",
  TZ: "узнать часовой пояс",
  PWD: "узнать, в какой папке он запущен",
  TMPDIR: "узнать, где лежат временные файлы",
  NODE_ENV: "узнать режим запуска (рабочий или отладочный)",
};
const SECRETISH = /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH/i;
/** One variable name → what reading it means. Secret-looking names say so; unknown ones are named. */
export function envNamePhrase(name: string): string {
  const known = ENV_PLAIN[name.toUpperCase()];
  if (known) return known;
  if (SECRETISH.test(name)) return `прочитать «${name}» (там обычно пароль или ключ)`;
  return `прочитать переменную окружения «${name}»`;
}
/** Reading the environment, concretely: the names it asks for, or ALL of it (the word «все» is red). */
function envSegments(detail: string[]): Segment[] {
  const names = [...new Set(detail.filter((d) => !d.includes(":") || !/^[a-z_]+:/.test(d)).map((d) => d.replace(/^env:/, "")))];
  if (names.length === 0 || names.includes("*")) return [{ text: "прочитать " }, { text: "все", red: true }, { text: " переменные окружения (там бывают пароли и токены)" }];
  const parts = names.slice(0, 4).map(envNamePhrase);
  return [{ text: parts.join("; ") + (names.length > 4 ? `; и ещё ${names.length - 4}` : "") }];
}
/** The network right, concretely: the hosts named in the code are named; with none named it says it can go anywhere. */
function networkText(detail: string[]): string {
  const hosts = detail.filter((d) => d.startsWith("host:")).map((d) => d.slice(5));
  if (hosts.length === 0) return "выходить в интернет на любые адреса (какие именно, из кода не видно)";
  return `обращаться по сети только к ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ", …" : ""} (других адресов в коде не найдено)`;
}
/** What a right means for a person, in pieces (so that «все» can be red). */
export function capabilitySegments(c: CapLike): Segment[] {
  switch (c.kind) {
    case "env":
      return envSegments(c.detail);
    case "network":
      return [{ text: networkText(c.detail) }];
    default:
      return [{ text: capabilityPhrase(c) }];
  }
}
/** What a right means for a person. Hosts of the network right are named; the environment is named variable by variable, or «все»; the rest is one phrase. */
export function capabilityPhrase(c: CapLike): string {
  switch (c.kind) {
    case "network":
      return networkText(c.detail);
    case "env":
      return envSegments(c.detail).map((x) => x.text).join("");
    case "child_process":
      return "запускать программы на компьютере";
    case "fs":
      return "читать и писать файлы";
    case "dynamic_code":
      return "выполнять код, собранный на лету";
    case "ui":
      return "менять внешний вид bb";
    case "http_routes":
      return "открывать свои адреса на сервере bb";
    case "contribute_env":
      return "менять окружение запускаемых программ";
    case "host_artifact":
      return "класть свои файлы на компьютер";
    case "builtin_rpc":
      return "управлять встроенными частями bb (аккаунт, инструкции, подключения)";
    case "server_access":
      return "получать расширенный доступ к серверу bb";
    case "database":
      return "работать с базами данных";
    default:
      return "использовать возможность «" + c.kind + "»";
  }
}
export const capabilityPhrases = (caps: CapLike[]): string[] => caps.map(capabilityPhrase);

/** A hard flag, in one plain sentence about what the plugin does. `title` fits "Остановлено: …"; `line` says what it means. Unknown rules fall back to a general text. */
const RED: Record<string, { title: string; line: string }> = {
  "secret-read-network": { title: "плагин читает ваши ключи и выходит в сеть", line: "Он читает файлы, где хранятся пароли и ключи, и может отправить их наружу." },
  "env-dump": { title: "плагин пытается забрать все ваши секреты из окружения", line: "Он собирает переменные окружения целиком (там бывают пароли и токены)." },
  "decode-eval": { title: "плагин прячет и запускает чужой код", line: "Он расшифровывает спрятанный текст и сразу выполняет его. Так ведут себя вредоносные плагины." },
  "download-exec": { title: "плагин скачивает и запускает программу", line: "Он берёт файл из сети и запускает его. Что именно будет запущено, заранее не видно." },
  "rc-or-agent-config-write": { title: "плагин правит настройки оболочки или агентов", line: "Он может дописать себя в файлы, которые запускаются при каждом открытии терминала или работе агента." },
  "contribute-env-dangerous": { title: "плагин подменяет окружение запускаемых программ", line: "Через это можно подсунуть чужой код любой программе, которую запустит bb." },
  "install-script": { title: "плагин хочет выполнить команды при установке", line: "Команды при установке запускаются до того, как вы что-то увидите." },
  "url-dependency": { title: "плагин тянет код по ссылке", line: "Часть его кода берётся из места, которое никто не проверяет и которое может измениться." },
  "url-import": { title: "плагин подгружает код по ссылке", line: "Часть его кода берётся из сети во время работы." },
  "invisible-chars": { title: "в коде плагина спрятаны невидимые символы", line: "Так прячут команды, которые не видно при чтении кода." },
  minified: { title: "код плагина нарочно нечитаем", line: "Он сжат так, что человек не может его проверить." },
  binary: { title: "в плагине лежит готовая программа", line: "Это не текст, прочитать и проверить её нельзя." },
  "native-module": { title: "плагин содержит собираемую программу", line: "Её нельзя проверить так же, как обычный код." },
  "agent-config": { title: "плагин приносит настройки для агентов", line: "Так можно изменить, что агенты вам разрешают и чего не спрашивают." },
  npmrc: { title: "плагин приносит файл с настройками загрузки пакетов", line: "Через него можно подменить место, откуда берутся пакеты." },
  "writable-by-others": { title: "файлы плагина может менять кто угодно", line: "После проверки их можно подменить, поэтому проверка ничего не значит." },
  "escaping-symlink": { title: "плагин ссылается на файлы вне своей папки", line: "Он может прочитать или подменить то, что ему не принадлежит." },
  "special-file": { title: "в плагине лежит необычный файл", line: "Проверить такой файл нельзя." },
  "sqlite-extension": { title: "плагин подгружает расширение базы данных", line: "Это чужая программа внутри базы secure-bb." },
};
const RED_FALLBACK = { title: "плагин ведёт себя как вредоносный", line: "Проверки нашли в нём признак, который бывает только у вредного кода." };

export interface RedText {
  title: string;
  line: string;
  /** The rule, for the folded technical part. */
  rule: string | null;
}
export function redText(rules: string[]): RedText {
  for (const r of rules) {
    const t = RED[r];
    if (t) return { ...t, rule: r };
  }
  return { ...RED_FALLBACK, rule: rules[0] ?? null };
}

export type CardColor = "red" | "yellow";
export interface ReviewEntry {
  id: number;
  status: string;
  reason: string | null;
  /** Checks of this version: severities of the findings. */
  findings: Array<{ rule: string; severity: string }>;
}
/** A hard flag, as the core says it (the reason of the held entry) or as the checks found it. */
/** The guard read the directory itself and its count did not match the request's: files changed between the check and the load. */
export const isMismatch = (reason: string | null): boolean => /не совпал с хешем/.test(reason ?? "");
export const isBlockedEntry = (e: Pick<ReviewEntry, "reason" | "findings">): boolean => isMismatch(e.reason) || /заблокирован(о)? проверками/.test(e.reason ?? "") || /жёсткий флаг/.test(e.reason ?? "") || e.findings.some((f) => f.severity === "block");

/** Why the guard held a version, as its own note says (the card's words follow this, not a default). */
export type ReasonKind = "mismatch" | "unknown-source" | "new-right" | "strict" | "first-version" | "other";
export function reasonKind(reason: string | null): ReasonKind {
  const r = reason ?? "";
  if (isMismatch(r)) return "mismatch";
  if (/новое право|новое замечание/.test(r)) return "new-right";
  if (/неизвестный источник|нельзя назвать своим/.test(r)) return "unknown-source";
  if (/Строгий/.test(r)) return "strict";
  if (/нет одобренной версии/.test(r)) return "first-version";
  return "other";
}

/** «Всё равно разрешить…» exists on a red card only if the mode allows it AND the stop is not a mismatch (an approval would be written for the hash of a suspect request). */
export const bypassAllowed = (mode: TrustMode | null, reason: string | null): boolean => detailLevel(mode).bypass && !isMismatch(reason);
export const MISMATCH_HINT = "Переустановите плагин из его источника. Если код снова не совпадёт, сообщите об этом в разделе журнала.";

/** A version whose code is not what the guard checked: red, with its own words. */
export function mismatchText(pluginId: string, version: string): RedText {
  return {
    title: "Остановлено: код плагина не совпал с тем, что проверил сторож",
    line: `Плагин «${pluginId}» ${version}: код не совпал с тем, что проверил сторож. Так бывает при подмене файлов. Не разрешайте, если не знаете причину. Плагин не запущен. ${MISMATCH_HINT}`,
    rule: null,
  };
}
/** Red: a hard flag. Yellow: everything else that waits for a person (a new right, an unknown source). */
export const cardColor = (e: Pick<ReviewEntry, "reason" | "findings">): CardColor => (isBlockedEntry(e) ? "red" : "yellow");

export type Level = "own" | "known" | "unknown";
export interface YellowInput {
  pluginId: string;
  version: string;
  level: Level;
  sourceLabel: string;
  /** The guard's reason in its words (it may mention a new right). */
  reason: string | null;
  caps: CapLike[];
}
export interface YellowText {
  title: string;
  line: string;
}
/** The yellow card: «figma-sync» ждёт вашего решения + what it can do + that it does not run meanwhile. */
export function yellowText(y: YellowInput): YellowText {
  const phrases = capabilityPhrases(y.caps);
  const list = phrases.slice(0, 5).join("; ") + (phrases.length > 5 ? "; …" : "");
  const can = phrases.length > 0 ? ` Он сможет: ${list}.` : "";
  const who = y.level === "own" ? "вашего" : "известного";
  const tail = " Пока вы не решите, он не запускается.";
  let line: string;
  switch (reasonKind(y.reason)) {
    case "new-right":
      line = `Плагин из ${who} источника (${y.sourceLabel}) просит новое, чего раньше не просил.${can || " Что именно, видно в подробностях."}`;
      break;
    case "unknown-source":
      line = `Плагин из места, которое вы раньше не отмечали (${y.sourceLabel}).${can || " Особых прав он не просит."}`;
      break;
    case "strict":
      line = `Режим «Строгий»: каждый плагин ждёт вас, даже из ${y.level === "unknown" ? "источника" : who + " источника"} (${y.sourceLabel}).${can}`;
      break;
    case "first-version":
      line = `Плагин из ${y.level === "unknown" ? "источника" : who + " источника"} (${y.sourceLabel}), который вы ещё не разрешали.${can || " Особых прав он не просит."}`;
      break;
    default:
      line = `Сторож не пропустил плагин сам (${y.sourceLabel}).${can}`;
  }
  return { title: `«${y.pluginId}» ${y.version} ждёт вашего решения`, line: `${line}${tail}` };
}

// ---- status ----------------------------------------------------------------------------------------------------------------
export type StatusLevel = "ok" | "attention" | "stopped" | "down";
export type ProblemKind = "guard" | "red" | "yellow" | "alarm";
/** The page's tabs; a problem says which one holds its element. */
export type TabId = "status" | "quarantine" | "trust" | "more";
export interface ProblemRef {
  /** The element the button scrolls to. */
  anchor: string;
  tab: TabId;
  text: string;
}
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
    ...(i.guardDown ? [{ kind: "guard" as const, anchor: "sbb-guard-alarm", tab: "status" as const, text: "Сторож не отвечает" }] : []),
    ...i.red.map((r) => ({ kind: "red" as const, ...r })),
    ...i.yellow.map((r) => ({ kind: "yellow" as const, ...r })),
    ...i.alarms.map((r) => ({ kind: "alarm" as const, ...r })),
  ];
  const first = problems[0] ?? null;
  if (i.guardDown) return { level: "down", label: "Защита не работает", count: problems.length, problems, first };
  if (i.red.length > 0) return { level: "stopped", label: `Остановлено (${i.red.length})`, count: problems.length, problems, first };
  if (problems.length > 0) return { level: "attention", label: `Требует внимания (${problems.length})`, count: problems.length, problems, first };
  return { level: "ok", label: "Защищено", count: 0, problems, first: null };
}

/** The text under the status when the guard is down (the page must say what actually happens: everything unbuilt-in is held). */
export const GUARD_DOWN_TEXT = "Защита не работает: сторож не отвечает. Новые плагины не загрузятся, а одобрить сейчас ничего нельзя. Что делать: на этой машине выполните «sbb-guard status».";

// ---- while you were away ----------------------------------------------------------------------------------------------------
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
  if (c.window > 0) parts.push(`${versions(c.window)} ${name} ${c.window % 10 === 1 && c.window % 100 !== 11 ? "прошла" : "прошли"} в окне доверия`);
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
export const AWAY_KEY = "secure-bb.away.seenAt";
export const DEFERRED_KEY = "secure-bb.deferred";
export const KEPT_KEY = "secure-bb.kept";
export const WIZARD_KEY = "secure-bb.wizard.done";

/** Cards the person put aside («Решить позже») or kept in quarantine: remembered by the page only. The key has the id of the queue entry: the same code held again later is a NEW entry and comes back as a new question (a stale mark of an earlier session must not show «Вы отложили» on a card nobody put aside). */
export const deferKey = (pluginId: string, contentHash: string | null, id: number): string => `${pluginId}:${contentHash ?? "-"}:#${id}`;
export function parseDeferred(raw: string | null): string[] {
  if (raw === null) return [];
  try {
    const j = JSON.parse(raw) as unknown;
    return Array.isArray(j) ? j.filter((x): x is string => typeof x === "string").slice(0, 500) : [];
  } catch {
    return [];
  }
}

// ---- keys: where is the passkey stored --------------------------------------------------------------------------------------
const AAGUIDS: Record<string, string> = {
  "fbfc3007154e4ecc8c0b6e020557d7bd": "iCloud-связка",
  adce000235bcc60a648b0b25f1f05503: "Chrome (Touch ID)",
  "50726f746f6e5061737350726f746f6e": "Proton Pass",
  bada5566a7aa401fbd9645619a55120d: "1Password",
  "531126d6e717415c93203d9aa6981239": "Dashlane",
  d548826e79b4db40a3d811116f7e8349: "Bitwarden",
  "6028b017b1d44c02b4b3afcdafc96bb2": "Windows Hello",
  "08987058cadc4b81b6e130de50dcbe96": "Windows Hello",
  "9ddd1817af5a4672a2b93e3dd95000a9": "Windows Hello",
};
/** Where the key is kept, by the AAGUID the guard recorded (hex, with or without dashes). Unknown or empty: «другое». */
export function aaguidName(aaguid: string | null | undefined): string {
  const h = (aaguid ?? "").toLowerCase().replace(/[^0-9a-f]/g, "");
  return AAGUIDS[h] || "другое";
}
/** For a name that is not one of the safe stores a warning goes with it: a password manager's extension may answer the request instead of the system. */
export const isPasswordManager = (name: string): boolean => name === "Proton Pass" || name === "1Password" || name === "Dashlane" || name === "Bitwarden";

// ---- touch hints ------------------------------------------------------------------------------------------------------------
export const TOUCH_SLOW_MS = 15_000;
export const TOUCH_SLOW_HINT = "Проверьте окно менеджера паролей (1Password, Proton Pass…) или выберите другое устройство.";
export const SAVED_NARROWING = "Сохранено: это сужение, касание не требуется.";
export const touchWithHint = (description: string, slow: boolean): string => `Подтвердите касанием. Сторож: «${description}»${slow ? `. ${TOUCH_SLOW_HINT}` : ""}`;

// ---- first run ---------------------------------------------------------------------------------------------------------------
export const MODE_NAMES: Record<TrustMode, string> = { simple: "Простой", detailed: "Подробный", strict: "Строгий" };
export const MODE_DESCRIPTIONS: Record<TrustMode, string> = {
  simple: "Свои и известные источники проходят сами, пока не просят нового. Технические подробности свёрнуты. Для большинства.",
  detailed: "Так же, но подробности на карточках сразу открыты: что именно просит плагин и где это в коде.",
  strict: "Каждая версия ждёт вас. Подробности открыты, обойти красную карточку нельзя.",
};
/** Whether to show the wizard: the guard knows the modes, nothing is set up yet, and the person has not closed it. */
export function wizardNeeded(i: { hasTrust: boolean; mySources: number; done: boolean }): boolean {
  return i.hasTrust && i.mySources === 0 && !i.done;
}
/** Suggestions for «мои источники»: git repositories and folders of the installed plugins, from the core's `source`, once each. */
export function suggestSources(plugins: Array<{ sourceKind?: string; source: string }>, identity: (kind: string, source: string) => string | null): string[] {
  const out = new Set<string>();
  for (const p of plugins) {
    const kind = p.sourceKind ?? (p.source.startsWith("git:") ? "git" : p.source.startsWith("path:") ? "path" : "");
    const id = identity(kind, p.source);
    if (id) out.add(id);
  }
  return [...out].slice(0, 20);
}

// ---- one card per plugin; the person's decisions on cards --------------------------------------------------------------------
/** What the page keeps about a card the person has acted on without the guard being asked. */
export interface Decisions {
  /** «Решить позже»: still unresolved (the status counts it), only folded away. */
  deferred: string[];
  /** «Оставить в карантине»: DECIDED. The plugin stays held at the guard, but the person has answered: it is not a question and not a red status. */
  kept: string[];
}
export interface HeldLike {
  id: number;
  pluginId: string;
  version: string;
  contentHash: string | null;
}
export type CardDecision = "open" | "deferred" | "kept";
export const decisionOf = (e: HeldLike, d: Decisions): CardDecision => {
  const k = deferKey(e.pluginId, e.contentHash, e.id);
  return d.kept.includes(k) ? "kept" : d.deferred.includes(k) ? "deferred" : "open";
};
/** Dotted versions compared by number («0.0.10» after «0.0.9»); what is not a number compares as text. Negative: a before b. */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/i, "").split(/[.+-]/);
  const pb = b.replace(/^v/i, "").split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      if (Number(x) !== Number(y)) return Number(x) - Number(y);
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
/** One plugin's card: the latest version is shown; the others wait folded away under it. */
export interface PluginCard<E extends HeldLike> {
  pluginId: string;
  shown: E;
  others: E[];
  /** All of its versions that are unresolved (shown first). */
  all: E[];
}
export interface CardPlan<E extends HeldLike> {
  /** Cards to decide now (at least one open version). */
  active: Array<PluginCard<E>>;
  /** Cards folded away with «Решить позже» (every unresolved version of the plugin is deferred). */
  later: Array<PluginCard<E>>;
  /** Kept in quarantine: decided, not in the list and not in the status. */
  kept: E[];
  /** What the status counts: everything not decided (open and deferred). */
  unresolved: E[];
}
/** From the held entries to the cards: ONE per plugin (the latest version; «ещё N версий ждут» for the rest). Kept entries leave the list and the status. */
export function planCards<E extends HeldLike>(held: E[], d: Decisions): CardPlan<E> {
  const kept: E[] = [];
  const byPlugin = new Map<string, E[]>();
  for (const e of held) {
    if (decisionOf(e, d) === "kept") {
      kept.push(e);
      continue;
    }
    byPlugin.set(e.pluginId, [...(byPlugin.get(e.pluginId) ?? []), e]);
  }
  const latestFirst = (a: E, b: E): number => compareVersions(b.version, a.version) || b.id - a.id;
  const active: Array<PluginCard<E>> = [];
  const later: Array<PluginCard<E>> = [];
  const unresolved: E[] = [];
  for (const [pluginId, list] of byPlugin) {
    const open = list.filter((e) => decisionOf(e, d) === "open").sort(latestFirst);
    const deferred = list.filter((e) => decisionOf(e, d) === "deferred").sort(latestFirst);
    const all = [...open, ...deferred];
    unresolved.push(...all);
    const card = { pluginId, shown: all[0]!, others: all.slice(1), all };
    (open.length > 0 ? active : later).push(card);
  }
  return { active, later, kept, unresolved };
}
/** «ещё 1 версия ждёт» / «ещё 2 версии ждут» / «ещё 5 версий ждут». */
export const moreVersionsText = (n: number): string => `ещё ${n} ${plural(n, "версия ждёт", "версии ждут", "версий ждут")}`;

/** The action on a card names the version it is about. */
export const actionLabel = (verb: string, pluginId: string, version: string): string => `${verb} ${pluginId} ${version}`;
export const deleteConfirmText = (pluginId: string, version: string): string => `Удалить плагин ${pluginId} ${version}? Чтобы вернуть, установите плагин снова`;
export const deletedNote = (pluginId: string, version: string): string => `Удалён: плагин ${pluginId} ${version}.`;

// ---- trust window and «доверять источнику» on a card ----------------------------------------------------------------------------
export interface WindowAvailInput {
  /** The thread the version came from (a window covers a thread and its tree). */
  threadId: string | null;
  /** Negative: a proposal not yet installed. */
  queueId: number;
  sourceKind: string;
  level: Level;
}
export interface WindowAvail {
  available: boolean;
  /** Why not, and what to do instead (shown on the card). */
  note: string | null;
}
/** A trust window belongs to a plugin that an agent installs from a thread. A plugin from a folder has no such thread: say so, and say what to use instead. */
export function windowAvailability(i: WindowAvailInput): WindowAvail {
  if (i.threadId && i.queueId > 0) return { available: true, note: null };
  if (i.sourceKind === "path") {
    return {
      available: false,
      note: `Окно доверия для плагина из папки недоступно: оно открывается для плагина, который агент ставит из треда. ${i.level === "own" ? "Ваш источник уже в доверенных: версии без новых прав проходят сами." : "Вместо окна доверьте источник кнопкой «Разрешить и доверять источнику»: тогда версии без новых прав будут проходить сами."}`,
    };
  }
  return { available: false, note: "Окно доверия недоступно: плагин пришёл не из треда. Одобряйте версию или доверьте источник." };
}
export interface TrustButtonInput {
  entry: string | null;
  level: Level;
  queueId: number;
}
export interface TrustButton {
  enabled: boolean;
  /** Under the button: why it does nothing, or what it does. */
  note: string | null;
}
/** «Разрешить и доверять источнику» is active only when it changes something: the source is not yet trusted and can be named. */
export function trustButton(i: TrustButtonInput): TrustButton {
  if (i.entry === null) return { enabled: false, note: "Этот источник нельзя занести в «мои источники» (не github и не папка на диске)." };
  if (i.queueId < 0) return { enabled: false, note: "Плагин ещё не установлен: сначала разрешите версию." };
  if (i.level === "own") return { enabled: false, note: "Ваш источник уже в доверенных: версии без новых прав проходят сами. Эта кнопка ничего бы не добавила." };
  return { enabled: true, note: null };
}

// ---- after the approval: did it start? ------------------------------------------------------------------------------------------
/** The core's `error` after an approval: the plugin is allowed but did not start. Null: nothing to add. */
export function launchProblem(p: { status: string; statusDetail?: string | null }): string | null {
  if (p.status !== "error") return null;
  const why = (p.statusDetail ?? "").replace(/\s+/g, " ").trim();
  return `Разрешён, но упал при запуске: ${why !== "" ? (why.length > 300 ? `${why.slice(0, 299)}…` : why) : "ядро не назвало причину"}`;
}

// ---- touches: what to enter, and the session paragraph -------------------------------------------------------------------------
export const CODE_HINT = "6 цифр из приложения на телефоне (Google Authenticator и т. п.)";
export const KEY_HINT = "приложите палец";
/** The line next to the code field: a key if there is one (the code is the fallback), else the code's own words. */
export function proofHint(i: { hasKey: boolean; keyOnly: boolean }): string {
  if (i.hasKey) return i.keyOnly ? `${KEY_HINT[0]!.toUpperCase()}${KEY_HINT.slice(1)}.` : `${KEY_HINT[0]!.toUpperCase()}${KEY_HINT.slice(1)} или введите ${CODE_HINT}.`;
  return `${CODE_HINT[0]!.toUpperCase()}${CODE_HINT.slice(1)}.`;
}
export const SESSION_LINE = "Открыть на 15 минут, чтобы не вводить код каждый раз";
export interface SessionText {
  /** The one line (always). */
  line: string;
  /** The rest, folded in «Простой» and open in the others; null: none. */
  details: string;
  foldDetails: boolean;
}
/** The session paragraph without «токен» and «хеш»: one line in «Простой», the details folded. */
export function sessionText(mode: TrustMode | null, guard: boolean): SessionText {
  const touch = guard ? "касанием" : "кодом";
  const details = `Действует на этой странице: 15 минут после последнего действия, не дольше часа. Рутину (одобрить версию, пакет, открыть окно, принять расхождение, одобрить скилл) она покрывает без ${guard ? "касания" : "кода"}. Опасное — снятие блока, ослабление режима, добавление источника, расширение политики, критичные настройки агентов — всегда ${touch} заново. ${guard ? "Ключ сессии хранится только в памяти этой страницы. " : ""}Перезагрузка страницы закрывает сессию.`;
  return { line: SESSION_LINE, details, foldDetails: mode === null || mode === "simple" };
}

// ---- agents: critical changes are accepted one by one --------------------------------------------------------------------------
export interface DriftLike {
  id: number;
  class: string;
  reasons: string[];
}
export const isCriticalDrift = (d: Pick<DriftLike, "class">): boolean => d.class === "critical";
/** «Выбрать все» and the pack: never a critical difference. */
export const selectableDriftIds = (drifts: Array<Pick<DriftLike, "id" | "class">>): number[] => drifts.filter((d) => !isCriticalDrift(d)).map((d) => d.id);
/** The selection kept across a refresh: what is still there and not critical; nothing is added and nothing is lost by a refresh itself. */
export function reconcileSelection(selected: number[], drifts: Array<Pick<DriftLike, "id" | "class">>): number[] {
  const ok = new Set(selectableDriftIds(drifts));
  return selected.filter((id) => ok.has(id));
}
/** The same check as the guard's, before a code is spent: null when the call may go. */
export function agentAcceptProblem(ids: number[], drifts: Array<Pick<DriftLike, "id" | "class">>): string | null {
  if (ids.length > 1 && ids.some((id) => drifts.find((d) => d.id === id)?.class === "critical")) return "критичное изменение принимается отдельно, не вместе с другими: у каждого своё касание";
  return null;
}
const MEANINGS: Array<[RegExp, (m: RegExpExecArray) => string]> = [
  [/permissions\.defaultMode: bypassPermissions/, () => "агент будет делать всё без вопросов к вам (режим bypassPermissions)"],
  [/permissions\.defaultMode: acceptEdits/, () => "агент будет сам менять файлы, не спрашивая вас"],
  [/permissions\.allow «Bash(?:\(\s*(?:\*|:\*|\*:\*)?\s*\))?»/, () => "агент сможет выполнять любые команды без спроса"],
  [/permissions\.allow «[^»]*»: сеть/, () => "агент сможет ходить в сеть без спроса"],
  [/permissions\.allow «[^»]*»: путь вне/, () => "агент сможет читать и менять файлы вне рабочей папки без спроса"],
  [/permissions\.allow/, () => "агент сможет выполнять часть действий без спроса"],
  [/permissions\.additionalDirectories/, () => "агент получит доступ к папке вне рабочей"],
  [/^hooks/, () => "агент будет сам запускать команды при своих действиях (хуки)"],
  [/^MCP-сервер ([^:]+): новый/, (m) => `агент получит новый внешний инструмент «${m[1]}» (MCP-сервер): он сможет выполнять действия, о которых bb не знает`],
  [/^MCP-сервер ([^:]+): изменён/, (m) => `у внешнего инструмента «${m[1]}» (MCP-сервер) изменили запуск или адрес`],
  [/^env [A-Z0-9_]*_BASE_URL/i, () => "запросы агента к модели пойдут на другой адрес: всё, что он отправляет, увидит владелец адреса"],
  [/^env [A-Z0-9_]*_PROXY/i, () => "сеть агента пойдёт через прокси: всё, что он отправляет, увидит владелец прокси"],
  [/^env NODE_OPTIONS/i, () => "в каждую запущенную агентом программу на Node подмешается чужой код"],
  [/apiKeyHelper/, () => "ключ доступа агенту будет выдавать команда, которую запустят при каждом обращении"],
  [/песочница отключена/, () => "агент будет работать без песочницы: ничто не ограничит его команды"],
  [/скрипт хука/, () => "агент будет запускать этот скрипт сам"],
  [/код расширения агента/, () => "агент будет выполнять этот код как своё расширение"],
  [/адрес сервера модели/, () => "запросы агента к модели пойдут на другой адрес"],
  [/approval_policy = "never"/, () => "агент будет делать всё без вопросов к вам"],
  [/sandbox_mode = "danger-full-access"/, () => "агент получит полный доступ к компьютеру, без песочницы"],
  [/network_access = true/, () => "агенту откроют доступ в сеть"],
  [/MCP-сервер/, () => "агент получит внешний инструмент (MCP-сервер)"],
  [/файл не разобран как JSON/, () => "файл нельзя прочитать как настройки: агент может понять его иначе, чем сторож"],
];
/** What each critical reason lets the agent do, in plain words; a reason with no text of its own is passed through. */
export function criticalMeanings(reasons: string[]): string[] {
  const out: string[] = [];
  for (const r of reasons) {
    let text: string | null = null;
    for (const [re, f] of MEANINGS) {
      const m = re.exec(r);
      if (m) {
        text = f(m);
        break;
      }
    }
    const t = text ?? r;
    if (!out.includes(t)) out.push(t);
  }
  return out;
}
/** The title of one critical acceptance: exactly what is being accepted. «Принимая это, вы разрешаете: …». */
export const criticalAcceptTitle = (reasons: string[]): string => {
  const m = criticalMeanings(reasons);
  return m.length === 0 ? "Принимая это, вы разрешаете агенту работать с новой настройкой" : `Принимая это, вы разрешаете: ${m.join("; ")}`;
};

/** Where the card of the agents' differences is shown: on the «Статус» tab while something critical or an alarm waits there, else in «Подробно». */
export function agentsSectionTab(i: { critical: number; alarms: number }): TabId {
  return i.critical > 0 || i.alarms > 0 ? "status" : "more";
}

// ---- stable state of folds and selections --------------------------------------------------------------------------------------
/** A fold's state is kept by the element's id, so that a refresh (even one that rebuilds the list) leaves it as the person left it. */
export function setFold(state: Record<string, boolean>, id: string, open: boolean): Record<string, boolean> {
  return state[id] === open ? state : { ...state, [id]: open };
}
/** One checkbox changed: the others are not touched. */
export function toggleId(ids: number[], id: number, on: boolean): number[] {
  const has = ids.includes(id);
  return on ? (has ? ids : [...ids, id]) : ids.filter((x) => x !== id);
}
/** Two overviews that differ only by the server's clock say the same: the page keeps the old object and draws nothing again. */
export function sameData(a: unknown, b: unknown): boolean {
  // Only the TOP-level clock is ignored: everything else, the guard's data about the agents included, counts.
  const strip = (x: unknown): string => {
    if (typeof x === "object" && x !== null && !Array.isArray(x)) {
      const { now: _now, ...rest } = x as Record<string, unknown>;
      return JSON.stringify(rest);
    }
    return JSON.stringify(x);
  };
  return strip(a) === strip(b);
}

/** A card's line, in pieces: the word «все» of «прочитать все переменные окружения» is red wherever the line says it. */
export function emphasize(text: string): Segment[] {
  const out: Segment[] = [];
  const re = /(прочитать )(все)( переменные)/g;
  let last = 0;
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    out.push({ text: text.slice(last, m.index) + m[1]! }, { text: m[2]!, red: true });
    last = m.index + m[1]!.length + m[2]!.length;
  }
  out.push({ text: text.slice(last) });
  return out.filter((x) => x.text !== "");
}
