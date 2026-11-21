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
  if (sourceKind === "path") return `папки ${source.replace(/^path:/, "").slice(0, 80)}`;
  if (sourceKind === "npm") return `npm: ${source.replace(/^npm:/, "").slice(0, 60)}`;
  return source.slice(0, 80);
}

interface CapLike {
  kind: string;
  detail: string[];
}
/** What a right means for a person. Hosts of the network right are named; the rest is one phrase. */
export function capabilityPhrase(c: CapLike): string {
  const hosts = c.detail.filter((d) => d.startsWith("host:")).map((d) => d.slice(5));
  switch (c.kind) {
    case "network":
      return hosts.length > 0 ? `ходить в сеть (${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ", …" : ""})` : "ходить в сеть";
    case "child_process":
      return "запускать программы на компьютере";
    case "env":
      return "читать переменные окружения (там бывают пароли и токены)";
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
  return { title: `«${y.pluginId}» ждёт вашего решения`, line: `${line}${tail}` };
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
export type AwayClass = "auto" | "window" | "approved" | "held" | "stopped" | "rejected" | "alarm";
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
const emptyCounts = (): Record<AwayClass, number> => ({ auto: 0, window: 0, approved: 0, held: 0, stopped: 0, rejected: 0, alarm: 0 });

const versions = (n: number): string => `${n} ${plural(n, "версия", "версии", "версий")}`;
/** «4 версии figma-sync прошли сами, 1 остановлена». */
export function awayText(g: Pick<AwayGroup, "pluginId" | "counts">): string {
  const c = g.counts;
  const name = g.pluginId ?? "системы";
  const parts: string[] = [];
  if (c.auto > 0) parts.push(`${versions(c.auto)} ${name} ${c.auto % 10 === 1 && c.auto % 100 !== 11 ? "прошла сама" : "прошли сами"}`);
  if (c.window > 0) parts.push(`${versions(c.window)} ${name} ${c.window % 10 === 1 && c.window % 100 !== 11 ? "прошла" : "прошли"} в окне доверия`);
  if (c.approved > 0) parts.push(`${c.approved} ${plural(c.approved, "версию", "версии", "версий")} ${name} одобрили вы`);
  if (c.held > 0) parts.push(`${c.held} ${plural(c.held, "версия ждёт", "версии ждут", "версий ждут")} вашего решения`);
  if (c.stopped > 0) parts.push(`${c.stopped} ${plural(c.stopped, "остановлена", "остановлены", "остановлено")}`);
  if (c.rejected > 0) parts.push(`${c.rejected} ${plural(c.rejected, "отклонена", "отклонены", "отклонено")}`);
  if (c.alarm > 0) parts.push(`${c.alarm} ${plural(c.alarm, "тревога", "тревоги", "тревог")}`);
  // "4 версии figma-sync прошли сами, 1 остановлена": the name stands once, with the first part; for the lone alarm of the system it stands alone.
  if (parts.length === 0) return "";
  const head = parts[0]!;
  if (c.alarm > 0 && g.pluginId === null && parts.length === 1) return `${c.alarm} ${plural(c.alarm, "тревога", "тревоги", "тревог")} системы`;
  const tail = parts.slice(1).map((p) => p.replace(` ${name} `, " "));
  return [head, ...tail].join(", ");
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
export const AWAY_KEY = "secure-bb.away.seenAt";
export const DEFERRED_KEY = "secure-bb.deferred";
export const WIZARD_KEY = "secure-bb.wizard.done";

/** Cards the person put aside («Решить позже»): remembered by the page only, so a card comes back if it is a different version. */
export const deferKey = (pluginId: string, contentHash: string | null, id: number): string => `${pluginId}:${contentHash ?? `#${id}`}`;
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
