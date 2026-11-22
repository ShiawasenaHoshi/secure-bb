// What a card says first: its colour, the red and yellow texts, the headline of the rights, the verbs of the buttons. The verdicts (blocked, mismatch) come from `entry-facts.ts`.
import { FS_HOME } from "../checks/sdk-rights.js";
import { type CardColor, type ReviewEntry, isBlockedEntry, reasonKind, entryReasonKind, hasNoGuardRecord } from "./entry-facts.js";
import { type CapLike, type FlowLike, UNRESOLVED_HOST, capsWithPaths, READS_PLAIN, flowSuffix, leakHeadline, programName, riskyProgram, SECRETISH, capabilityPhrases, hostsOf, uiClickLine } from "./phrases.js";
import { sourceLabel } from "./words.js";

/** A hard flag, in one plain sentence about what the plugin does. `title` fits "Остановлено: …"; `line` says what it means. Unknown rules fall back to a general text. */
export const RED: Record<string, { title: string; line: string }> = {
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
  "agent-config": { title: "в папке плагина лежат свои настройки для агентов", line: "Это файлы вроде .claude или CLAUDE.md внутри самого плагина. Плагин сам их не применяет; посмотрите, что в них написано, прежде чем включать." },
  npmrc: { title: "плагин приносит файл с настройками загрузки пакетов", line: "Через него можно подменить место, откуда берутся пакеты." },
  "writable-by-others": { title: "файлы плагина может менять кто угодно", line: "После проверки их можно подменить, поэтому проверка ничего не значит." },
  "escaping-symlink": { title: "плагин ссылается на файлы вне своей папки", line: "Он может прочитать или подменить то, что ему не принадлежит." },
  "special-file": { title: "в плагине лежит необычный файл", line: "Проверить такой файл нельзя." },
  "sqlite-extension": { title: "плагин подгружает расширение базы данных", line: "Это чужая программа внутри базы secure-bb." },
};

export const RED_FALLBACK = { title: "плагин ведёт себя как вредоносный", line: "Проверки нашли в нём признак, который бывает только у вредного кода." };

/** Where the data of a red card goes, in one sentence, from the hosts the code names; null when the plugin does not go to the network. */
export function redWhere(caps: CapLike[]): string | null {
  const net = caps.find((c) => c.kind === "network");
  if (!net) return null;
  const hosts = hostsOf(caps);
  if (hosts.length === 0) return "Куда он отправляет данные, из кода не видно: адрес может быть любым.";
  return `Данные уходят на: ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ", …" : ""}.`;
}

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

/**
 * A version the guard could not read itself: red (it can be lifted only with the acknowledgement and a fresh touch) but honest. `why` is the guard's note, as it wrote it
 * (not a verdict about the plugin): «источник не назван…», «каталог вне каталогов плагинов ядра», «сторож занят…».
 */
export function unreadText(pluginId: string, version: string, why: string | null): RedText {
  const reason = why !== null && why.trim() !== "" ? ` Причина: ${why.trim().replace(/[.。]+$/, "")}.` : " Причина в записи сторожа не указана.";
  return {
    title: "Сторож не смог сам прочитать эту версию",
    line: `Плагин «${pluginId}» ${version}.${reason} Что в ней, неизвестно: плохого в ней не нашли, но и не смотрели. Разрешить можно только с подтверждением риска и свежим касанием. Плагин не запущен.`,
    rule: null,
  };
}

export const MISMATCH_HINT = "Переустановите плагин из его источника. Если код снова не совпадёт, сообщите об этом в разделе журнала.";

/** A version whose code is not what the guard checked: red, with its own words. */
export function mismatchText(pluginId: string, version: string): RedText {
  return {
    title: "Остановлено: код плагина не совпал с тем, что проверила защита",
    line: `Плагин «${pluginId}» ${version}: код не совпал с тем, что проверила защита. Так бывает при подмене файлов. Не разрешайте, если не знаете причину. Плагин не запущен. ${MISMATCH_HINT}`,
    rule: null,
  };
}

/** Red: a hard flag. Yellow: everything else that waits for a person (a new right, an unknown source). */
export const cardColor = (e: Pick<ReviewEntry, "reason" | "findings" | "reasonKind" | "blocks">): CardColor => (isBlockedEntry(e) ? "red" : "yellow");

export type Level = "own" | "known" | "unknown";

export interface YellowInput {
  pluginId: string;
  version: string;
  level: Level;
  sourceLabel: string;
  /** The guard's reason in its words (it may mention a new right). */
  reason: string | null;
  /** The guard's fact about why it is held, when the entry has one. */
  reasonKind?: string | null;
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
  switch (entryReasonKind({ reason: y.reason, ...(y.reasonKind !== undefined ? { reasonKind: y.reasonKind } : {}) })) {
    case "growth":
      line = `Плагин из ${who} источника (${y.sourceLabel}) просит новое, чего раньше не просил.${can || " Что именно, видно в подробностях."}`;
      break;
    case "unknown-source":
      line = `Плагин из места, которое вы раньше не отмечали (${y.sourceLabel}).${can || " Особых прав он не просит."}`;
      break;
    case "strict":
      line = `Режим «Строгий»: каждый плагин ждёт вас, даже из ${y.level === "unknown" ? "источника" : who + " источника"} (${y.sourceLabel}).${can}`;
      break;
    case "first":
      line = `Плагин из ${y.level === "unknown" ? "источника" : who + " источника"} (${y.sourceLabel}), который вы ещё не разрешали.${can || " Особых прав он не просит."}`;
      break;
    default:
      line = `Плагин из ${y.sourceLabel} ждёт вашего «да»: сам он не проходит, даже когда ничего опасного не видно.${can}`;
  }
  return { title: `«${y.pluginId}» ${y.version} ждёт вашего решения`, line: `${line}${tail}` };
}

export type RiskLevel = "safe" | "caution" | "danger";

export interface Risk {
  level: RiskLevel;
  /** One plain line: the essence of what the plugin can do. */
  text: string;
  /** The line sends the person to the technical part of the card: it is shown open then. */
  look?: boolean;
}

const SAFE_KINDS = new Set(["ui", "database"]);

/**
 * The first line of a card: what the worst thing the plugin can do means for a person. `caps` are the rights worth showing (`meaningfulCaps`);
 * `reviewRules` the rules of the checks that asked for a look (only `agent-config`, a folder of settings the plugin does not apply itself, does not spoil «безопасно»).
 */
/** The rights of bb's own API and of pressing bb's buttons, worst first, each in the words of the card. */
const SDK_LINES: Array<{ kind: string; danger: boolean; text: string }> = [
  { kind: "sdk_answer", danger: true, text: "отвечает на вопросы агентов за вас" },
  { kind: "ui_click", danger: false, text: "может нажимать элементы интерфейса bb" },
  { kind: "sdk_send", danger: true, text: "отправляет сообщения от вашего имени" },
  { kind: "sdk_agents", danger: true, text: "может запускать и останавливать агентов" },
  { kind: "sdk_settings", danger: true, text: "меняет настройки bb" },
  { kind: "sdk_read", danger: false, text: "читает ваши переписки в bb" },
  { kind: "sdk_questions", danger: false, text: "видит, какие вопросы агенты задают" },
  { kind: "sdk_meta", danger: false, text: "знает названия и состояние ваших тредов (когда агенты начинают и заканчивают)" },
];

/** The first line for a plugin that uses bb's own API or presses bb's buttons; null when it does neither. «Безопасно: только оформление» is never said of it. */
export function sdkHeadline(caps: CapLike[], downgrade = false): Risk | null {
  const mine = SDK_LINES.filter((l) => caps.some((c) => c.kind === l.kind));
  if (mine.length === 0) return null;
  const click = caps.find((c) => c.kind === "ui_click");
  const lines = mine.map((l) => (l.kind === "ui_click" && click ? { ...l, danger: uiClickLine(click).danger, text: uiClickLine(click).text } : l));
  const sendsOut = caps.some((c) => c.kind === "network");
  // Where the conversations go, when the checks followed them: the line says it, and a plugin that has the network but does not send them there is not red for that.
  const flowOf = (kind: string): FlowLike | undefined => caps.find((c) => c.kind === kind)?.flow;
  const readsFlow = flowOf("sdk_read");
  const readsKnown = downgrade && readsFlow !== undefined && readsFlow.verdict !== "unknown";
  const danger = lines.some((l) => l.danger) || (lines.some((l) => l.kind === "sdk_read") && sendsOut && !readsKnown);
  // The network is in the plugin and the level is not lowered: said ONCE, at the end of the line, and not after each right. The purpose follows the verdict at once.
  let netTold = false;
  const shown = lines.slice(0, 3).map((l) => {
    const f = l.kind === "sdk_read" || l.kind === "sdk_questions" ? flowOf(l.kind) : undefined;
    const why = l.kind === "sdk_read" ? (caps.find((c) => c.kind === "sdk_read")?.purpose ?? []) : [];
    if (!f) return l.text;
    if (sendsOut && f.verdict !== "unknown" && f.verdict !== "leaves" && !downgrade) netTold = true;
    return `${READS_PLAIN[l.kind] ?? l.text}${flowSuffix({ kind: l.kind, detail: [], flow: f, purpose: why }, false)}`;
  });
  const text = shown.join("; ") + (lines.length > 3 ? `; и ещё ${lines.length - 3}` : "") + (netTold ? ". Сеть в плагине есть, с прочитанным по коду не связана." : "");
  return { level: danger ? "danger" : "caution", text: text.charAt(0).toUpperCase() + text.slice(1) };
}

export function riskHeadline(caps: CapLike[], reviewRules: string[] = [], opts: { downgrade?: boolean } = {}): Risk {
  const downgrade = opts.downgrade === true;
  const has = (k: string): CapLike | undefined => caps.find((c) => c.kind === k);
  // What was read and where it goes, red, first: the checks followed the data to the network, another program, a file outside, a message in the person's name.
  const leak = leakHeadline(caps);
  if (leak) {
    // The rest of what it can do follows the red line: starting agents, knowing the state of threads…
    const leaking = new Set(caps.filter((c) => c.flow?.verdict === "leaves" && READS_PLAIN[c.kind]).map((c) => c.kind));
    const rest = sdkHeadline(caps.filter((c) => !leaking.has(c.kind)), downgrade)?.text;
    return { level: "danger", text: rest ? `${leak}; ${rest.charAt(0).toLowerCase()}${rest.slice(1)}` : leak };
  }
  // Other programs' logins come first and are said outright: that is more than any variable of the environment. Red when the plugin can also send it out.
  const creds = has("credentials");
  if (creds) {
    // «Никуда не отправляет» lowers the level only where the policy `flow.downgrade` says so (off: the analysis is not yet proven complete)
    const known = downgrade && creds.flow && creds.flow.verdict !== "unknown";
    return { level: has("network") && !known ? "danger" : "caution", text: `Читает ваши учётные данные других программ: ${creds.detail.slice(0, 3).join(", ")}${creds.detail.length > 3 ? ", …" : ""}${creds.flow ? flowSuffix({ ...creds, purpose: [] }, false) : ""}` };
  }
  const env = has("env");
  if (env) {
    const names = [...new Set(env.detail.map((d) => d.replace(/^env:/, "")))].filter((n) => n !== "");
    if (names.length === 0 || names.includes("*") || names.some((n) => SECRETISH.test(n))) return { level: "danger", text: `Может читать ваши пароли и токены${env.flow ? flowSuffix({ ...env, purpose: [] }, true) : ""}` };
  }
  const fs = has("fs");
  // «Ваши документы» only where the code reaches the person's own folders; files the code does not name are said as what they are: not known.
  if (fs && !(fs.paths && fs.paths.length > 0) && fs.detail.includes(FS_HOME)) return { level: "danger", text: "Может читать и менять ваши документы" };
  if (has("server_access") || has("builtin_rpc")) return { level: "danger", text: "Может управлять самим bb: аккаунтом, подключениями, инструкциями" };
  const sdk = sdkHeadline(caps, downgrade);
  if (sdk) return sdk;
  if (fs && fs.paths && fs.paths.length > 0) return { level: "caution", text: `Может читать и менять файлы: ${fs.paths.slice(0, 2).join(", ")}${fs.paths.length > 2 ? ", …" : ""}` };
  if (fs) return { level: "caution", text: "Работает с файлами (какими — из кода не видно)" };
  const child = has("child_process");
  if (child) {
    const names = [...new Set((child.programs ?? []).map(programName))];
    const text = names.length === 0 ? "Может запускать программы на вашем компьютере" : `${names.length === 1 ? "Запускает программу" : "Запускает программы"}: ${names.slice(0, 2).join(", ")}${names.length > 2 ? ", …" : ""}${child.programsUnknown ? " (и другие, не видные в коде)" : ""}`;
    return { level: child.programsUnknown || (child.programs ?? []).some(riskyProgram) ? "danger" : "caution", text };
  }
  if (has("contribute_env") || has("host_artifact")) return { level: "caution", text: "Может менять окружение запускаемых программ и класть свои файлы на компьютер" };
  const net = has("network");
  if (net) {
    const hosts = hostsOf(caps);
    return { level: "caution", text: hosts.length === 0 ? "Может обращаться по сети к адресам, которые не видны в коде" : `Может обращаться по сети к ${hosts.slice(0, 2).join(", ")}${hosts.length > 2 ? ", …" : ""}${net.detail.includes(UNRESOLVED_HOST) ? " и к другим адресам, не видным в коде" : ""}` };
  }
  if (has("http_routes")) return { level: "caution", text: "Может открывать свои адреса на сервере bb" };
  if (env) return { level: "caution", text: "Может узнавать некоторые сведения о вашем компьютере (имя пользователя, язык)" };
  if (caps.some((c) => !SAFE_KINDS.has(c.kind)) || reviewRules.some((r) => r !== "agent-config")) return { level: "caution", text: "Похоже на оформление, но в коде есть особенности: они перечислены в «Технических подробностях» ниже", look: true };
  return { level: "safe", text: "Безопасно: только оформление — ничего не читает" };
}

/** What a card needs of a check result to say the rights: the capabilities and the findings that asked for a look. */
type FoundLike = (Parameters<typeof capsWithPaths>[0] & object) & { findings?: Array<{ severity: string; rule: string }> };

/**
 * The first line of a card for a version, from the check of THAT version: one function for the card and for «Под защитой», so that the two never say different things.
 * A version the guard has no record of is not judged by its code (see NO_RECORD_HEADLINE).
 */
export function cardRisk(q: { kind: string; contentHash: string | null }, found: FoundLike | undefined, downgrade: boolean): Risk {
  if (hasNoGuardRecord(q)) return { level: "caution", text: NO_RECORD_HEADLINE };
  return riskHeadline(capsWithPaths(found), (found?.findings ?? []).filter((f) => f.severity === "review").map((f) => f.rule), { downgrade });
}

/**
 * The rights of a plugin in «Под защитой»: for a version that waits, by the check the card shows (`queueChecks`, else the check of its hash); for an approved one,
 * by the check of the approved version. null only when there is no check at all.
 */
export function pluginRightsText(
  pluginId: string,
  pin: { contentHash: string } | null,
  ctx: { queue: Array<{ id: number; pluginId: string; status: string; kind: string; contentHash: string | null }>; queueChecks: Record<number, FoundLike>; checks: Record<string, FoundLike> },
  downgrade: boolean,
): string | null {
  const waiting = ctx.queue.filter((q) => q.pluginId === pluginId && q.status === "held").sort((a, b) => Math.abs(b.id) - Math.abs(a.id));
  for (const q of waiting) {
    const found = ctx.queueChecks[q.id] ?? (q.contentHash ? ctx.checks[q.contentHash] : undefined);
    if (found || hasNoGuardRecord(q)) return cardRisk(q, found, downgrade).text;
  }
  const approved = pin ? ctx.checks[pin.contentHash] : undefined;
  return approved ? cardRisk({ kind: "hook", contentHash: pin!.contentHash }, approved, downgrade).text : null;
}

/** The main button of a yellow card: a harmless plugin is simply switched on. */
export const approveVerb = (risk: Risk): string => (risk.level === "safe" ? "Включить" : "Разрешить");

/** What the «Готово» stub says after an allow. */
export const enabledWhat = (pluginId: string, version: string): string => `включён ${pluginId} ${version}`;

/** A line about the plugin's own agent settings (not a stop: it does not run them), for the main text of a yellow card; null when there are none. */
export function agentConfigNote(findings: Array<{ rule: string }>): string | null {
  return findings.some((f) => f.rule === "agent-config") ? "В папке плагина лежат свои настройки для агентов (например .claude). Плагин сам их не применяет; подробности — в «Подробнее»." : null;
}

/** The explanation moved off the first lines of a card into «Подробнее». */
export const scopeText = (version: string): string => `Версия ${version}: всё, что вы нажмёте на этой карточке, относится только к ней.`;

export const NO_RECORD_HEADLINE = "Эту версию нельзя разрешить здесь: защита её не проверяла";

export const NO_RECORD_LINE = "Плагин загрузился в обход проверки, поэтому одобрить его по отпечатку нельзя. Исправляется так: удалите эту версию и поставьте плагин заново через «bb secure-bb propose» — тогда защита проверит его и карточка станет обычной.";

export const NO_RECORD_FIX = "Удалить, чтобы поставить заново";

/**
 * The version of the words and layout of the card, written into the journal beside each decision, so that a change of the texts can be told apart from a change
 * of the person's habits when the journal is read later. Bump it whenever the card's sentences, buttons or order change in a way a person could notice.
 */
export const CARD_TEXTS_VERSION = 1;
