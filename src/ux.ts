// UX v1, PR 2: the page's decisions as pure functions (no React, no I/O, no clock): which status, which problem first, which colour a
// card has, what its plain words are, what "while you were away" says, what a key's AAGUID means. The page only draws what these say.
//
// Nothing here decides anything about plugins: approving and holding stay with the guard. These functions choose what to SHOW.
import type { TrustMode } from "./guardlink.js";
import { FS_HOME, UI_CLICK_ANSWERS, UI_CLICK_GATE, UI_CLICK_NAV } from "./checks/sdk-rights.js";

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
  /** For `fs`: the literal paths the code hands to file calls, when it names any. */
  paths?: string[];
  /** For `child_process`: the programs the code starts by name, and whether it also starts one it does not name. */
  programs?: string[];
  programsUnknown?: boolean;
}
/** The detail of a network right whose address the code does not show (the guard's `UNRESOLVED_HOST`). */
const UNRESOLVED_HOST = "unresolved-host";
/**
 * The capabilities of a check result, with the file paths of the result put on the `fs` one and the programs on the `child_process` one (so that a card can
 * name them), and, when the code reaches other programs' credential files, a first right `credentials` naming whose.
 */
export const capsWithPaths = (r: { capabilities: CapLike[]; fsPaths?: string[]; programs?: string[]; programsUnknown?: boolean; credentials?: string[] } | undefined): CapLike[] => {
  const caps = meaningfulCaps(r?.capabilities ?? []).map((c) =>
    c.kind === "fs" && r?.fsPaths && r.fsPaths.length > 0 ? { ...c, paths: r.fsPaths } : c.kind === "child_process" && r ? { ...c, programs: r.programs ?? [], programsUnknown: r.programsUnknown ?? false } : c,
  );
  return r?.credentials && r.credentials.length > 0 ? [{ kind: "credentials", detail: r.credentials }, ...caps] : caps;
};

/** Known system programs in a person's words (by file name). `risky`: it is not just a helper: it drives other programs or the system. */
const PROGRAM_NAMES: Record<string, { name: string; risky?: boolean }> = {
  afplay: { name: "проигрыватель звука macOS" },
  say: { name: "голос macOS (читает текст вслух)" },
  osascript: { name: "скрипты macOS (может управлять другими программами)", risky: true },
  open: { name: "открывалка macOS (открывает файлы, ссылки и программы)" },
  "notify-send": { name: "уведомления Linux" },
  "xdg-open": { name: "открывалка Linux (открывает файлы и ссылки)" },
  git: { name: "git (работа с кодом)" },
  npm: { name: "npm (установка пакетов и запуск скриптов)" },
  npx: { name: "npx (запуск пакетов из интернета)", risky: true },
  node: { name: "Node.js" },
  pbcopy: { name: "буфер обмена macOS" },
  pbpaste: { name: "буфер обмена macOS" },
  security: { name: "связка ключей macOS (пароли)", risky: true },
  curl: { name: "curl (загрузка из интернета)" },
  wget: { name: "wget (загрузка из интернета)" },
  sh: { name: "командная оболочка (выполняет любые команды)", risky: true },
  bash: { name: "командная оболочка (выполняет любые команды)", risky: true },
  zsh: { name: "командная оболочка (выполняет любые команды)", risky: true },
  powershell: { name: "PowerShell (выполняет любые команды)", risky: true },
  cmd: { name: "командная строка Windows (выполняет любые команды)", risky: true },
  sudo: { name: "sudo (команды с правами администратора)", risky: true },
};
export const programName = (p: string): string => PROGRAM_NAMES[p.toLowerCase()]?.name ?? p;
const riskyProgram = (p: string): boolean => PROGRAM_NAMES[p.toLowerCase()]?.risky === true;
/** «запускает программу …», by the names the code gives; the rest of the programs, when the code names none, are «какие — из кода не видно». */
function programsText(c: CapLike): string {
  const list = c.programs ?? [];
  if (list.length === 0) return "запускать программы на компьютере (какие именно, из кода не видно)";
  const names = [...new Set(list.map(programName))];
  return `${names.length === 1 ? "запускает программу" : "запускает программы"}: ${names.slice(0, 3).join(", ")}${names.length > 3 ? ", …" : ""}${c.programsUnknown ? "; и другие, которые не видны в коде" : ""}`;
}

/**
 * What of a plugin's rights is worth a person's attention. «dynamic_code» is raised by many harmless things (bundles, `Function("return this")`, property
 * access by a computed name); the person is shown it only for `eval`, `new Function`, `vm` with an argument that is not a plain string literal. The rest of the
 * checks (the findings, the technical part of the card) are not touched: this chooses only what is told in the main text.
 */
export function meaningfulCaps(caps: CapLike[]): CapLike[] {
  const out: CapLike[] = [];
  for (const c of caps) {
    if (c.kind !== "dynamic_code") {
      out.push(c);
      continue;
    }
    const real = c.detail.filter((d) => /^(eval|Function|new Function|vm(\.|$)|node:vm)/.test(d) && !/\(literal\)$/.test(d));
    if (real.length > 0) out.push({ ...c, detail: real });
  }
  return out;
}
/** A piece of a phrase; `red` marks the word that must catch the eye («все»). */
export interface Segment {
  text: string;
  red?: boolean;
  /** A plain explanation of a term in `text` (shown as a hint under the word). */
  hint?: string;
}
const ENV_PLAIN: Record<string, string> = {
  HOME: "узнать путь к вашей домашней папке (только где она лежит, не её содержимое)",
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
  const hidden = detail.includes(UNRESOLVED_HOST);
  if (hosts.length === 0) return "обращаться по сети к адресам, которые не видны в коде";
  const list = `${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ", …" : ""}`;
  return hidden ? `обращаться по сети к ${list} и к другим адресам, которые не видны в коде` : `обращаться по сети только к ${list} (других адресов в коде не найдено)`;
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
      return programsText(c);
    case "credentials":
      return `читать ваши учётные данные других программ: ${c.detail.join(", ")}`;
    case "fs":
      return c.paths && c.paths.length > 0
        ? `читать и писать файлы (в коде названы: ${c.paths.slice(0, 3).join(", ")}${c.paths.length > 3 ? ", …" : ""}; остальное из кода не видно)`
        : c.detail.includes(FS_HOME)
        ? "читать и писать любые файлы, к которым у bb есть доступ — в том числе ваши документы (в коде есть ваша домашняя папка или «Документы»)"
        : "работать с файлами (какими именно — из кода не видно)";
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
      return "хранить свои настройки и данные в bb";
    case "sdk_read":
      return "читать ваши переписки с агентами в bb (что вы и агенты пишете в тредах)";
    case "sdk_meta":
      return "знать названия и состояние ваших тредов (когда агенты начинают и заканчивают), но не то, что в них написано";
    case "sdk_questions":
      return "видеть, какие вопросы и запросы разрешений агенты задают";
    case "sdk_agents":
      return "запускать, останавливать и архивировать агентов";
    case "sdk_send":
      return "отправлять сообщения в ваши переписки от вашего имени";
    case "sdk_answer":
      return "отвечать на вопросы и запросы разрешений агентов за вас";
    case "sdk_settings":
      return "менять настройки bb: ставить и включать плагины, задавать переменные окружения";
    case "ui_click":
      return uiClickLine(c).phrase;
    default:
      return "использовать возможность «" + c.kind + "»";
  }
}
/** Tokens of the guard's rights (`network:stats.example`, `env:HOME`, `fs`) in the words of a person; hosts and names stay as they are. */
function tokensText(tokens: string[]): string {
  const kinds = new Map<string, string[]>();
  for (const t of tokens) {
    const i = t.indexOf(":");
    const kind = i < 0 ? t : t.slice(0, i);
    const list = kinds.get(kind) ?? [];
    if (i >= 0) list.push(t.slice(i + 1));
    kinds.set(kind, list);
  }
  const out: string[] = [];
  for (const [kind, detail] of kinds) {
    if (kind === "network") out.push(detail.length > 0 ? `сеть ${detail.map((d) => (d === UNRESOLVED_HOST ? "адреса, не видные в коде" : d)).join(", ")}` : "выход в сеть");
    else if (kind === "env") out.push(detail.length > 0 ? `переменные окружения ${detail.join(", ")}` : "переменные окружения");
    else out.push(capabilityPhrase({ kind, detail }));
  }
  return out.join("; ");
}
/**
 * Why a version was let in, for the version history: the guard's note in plain words. «прошла сама: свой источник, права те же» stays as it is;
 * «касанием: новое право: network, network:stats.example» becomes «касанием: новое право — сеть stats.example».
 */
export function approvalWhy(a: { via: string; why?: string | null }): string {
  if (!a.why) {
    const by: Record<string, string> = { window: "в окне временного доверия", pin: "закреплена при заморозке окна", auto: "прошла сама: безопасный класс", source: "прошла сама: источник и права те же", touch: "вы, касанием" };
    return by[a.via] ?? a.via;
  }
  // A touch is the person's own act; the guard's note says «касанием: …», the line says who.
  const why = a.via === "touch" && /^касанием/.test(a.why) && !/(^|\s)вы(\s|$)/i.test(a.why) ? `вы, ${a.why}` : a.why;
  return why.replace(/новое право: ([^;]+?)(?= и ещё \d+|$)/, (_m, list: string) => `новое право — ${tokensText(list.split(", ").map((t) => t.trim()).filter(Boolean))}`);
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
  "agent-config": { title: "в папке плагина лежат свои настройки для агентов", line: "Это файлы вроде .claude или CLAUDE.md внутри самого плагина. Плагин сам их не применяет; посмотрите, что в них написано, прежде чем включать." },
  npmrc: { title: "плагин приносит файл с настройками загрузки пакетов", line: "Через него можно подменить место, откуда берутся пакеты." },
  "writable-by-others": { title: "файлы плагина может менять кто угодно", line: "После проверки их можно подменить, поэтому проверка ничего не значит." },
  "escaping-symlink": { title: "плагин ссылается на файлы вне своей папки", line: "Он может прочитать или подменить то, что ему не принадлежит." },
  "special-file": { title: "в плагине лежит необычный файл", line: "Проверить такой файл нельзя." },
  "sqlite-extension": { title: "плагин подгружает расширение базы данных", line: "Это чужая программа внутри базы secure-bb." },
};
const RED_FALLBACK = { title: "плагин ведёт себя как вредоносный", line: "Проверки нашли в нём признак, который бывает только у вредного кода." };

/** The hosts a plugin names in its code (network capability), without the `host:` mark. */
export const hostsOf = (caps: CapLike[]): string[] => caps.filter((c) => c.kind === "network").flatMap((c) => c.detail.filter((d) => d.startsWith("host:")).map((d) => d.slice(5)));
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
    title: "Остановлено: код плагина не совпал с тем, что проверила защита",
    line: `Плагин «${pluginId}» ${version}: код не совпал с тем, что проверила защита. Так бывает при подмене файлов. Не разрешайте, если не знаете причину. Плагин не запущен. ${MISMATCH_HINT}`,
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
      line = `Защита не пропустила плагин сама (${y.sourceLabel}).${can}`;
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
export const touchWithHint = (description: string, slow: boolean): string => `Подтвердите касанием. Защита: «${description}»${slow ? `. ${TOUCH_SLOW_HINT}` : ""}`;

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
  /** When the entry first appeared: a mark made BEFORE this is about an earlier entry of the same number (the data was reset), not about this one. */
  firstSeen?: number;
}
export type CardDecision = "open" | "deferred" | "kept";
/** A mark as the page stores it: the key, and when the person made it (`key@ms`). */
export const stampMark = (key: string, at: number): string => `${key}@${Math.round(at)}`;
/** The marks that stand for `key`: a stamped one counts only if it was made at or after `since` (when the entry appeared); an unstamped (older) one always counts. */
export function hasMark(list: string[], key: string, since?: number): boolean {
  return list.some((m) => {
    if (m === key) return true;
    if (!m.startsWith(`${key}@`)) return false;
    const at = Number(m.slice(key.length + 1));
    return !Number.isFinite(at) || since === undefined || at >= since;
  });
}
/** The list without the marks of `key` (stamped or not). */
export const withoutMark = (list: string[], key: string): string[] => list.filter((m) => m !== key && !m.startsWith(`${key}@`));
/** The stored list with the old unstamped marks dropped: they cannot be told from a mark about an entry of an earlier data set. Only marks the person made on this version of the page stay. */
export const dropUnstamped = (list: string[]): string[] => list.filter((m) => /@\d+$/.test(m));
export const decisionOf = (e: HeldLike, d: Decisions): CardDecision => {
  const k = deferKey(e.pluginId, e.contentHash, e.id);
  return hasMark(d.kept, k, e.firstSeen) ? "kept" : hasMark(d.deferred, k, e.firstSeen) ? "deferred" : "open";
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

/**
 * What a card IS, for React and for its folds: the plugin, the version and the code (the hash), not the number of the queue entry. The same version held again
 * gets a new entry number (after a rejection, a restart, a second ask of the core); a key made of the number would build the card anew at every such change and
 * lose what the person had just opened. A version of another content is another card.
 */
export const cardKey = (q: { pluginId: string; version: string; contentHash: string | null; id: number }): string => `${q.pluginId}@${q.version}#${q.contentHash ?? `n${q.id}`}`;
/** The id of a fold on a card: the same for the same version, whatever the entry's number. */
export const cardFoldId = (q: { pluginId: string; version: string; contentHash: string | null; id: number }, part: string): string => `card:${cardKey(q)}:${part}`;

/** «Готово: удалён плагин X 1.0.0»: what the page says for a few seconds where the card was. */
export const doneMessage = (what: string): string => `Готово: ${what.replace(/[.\s]+$/, "")}`;

/** The action on a card names the version it is about. */
export const actionLabel = (verb: string, pluginId: string, version: string): string => `${verb} ${pluginId} ${version}`;
export const deleteConfirmText = (pluginId: string, version: string): string => `Удалить плагин ${pluginId} ${version}? Чтобы вернуть, установите плагин снова`;
/** Where the buttons were, after «Разрешить»: the same kind of line as «Удалён: …». */
export const approvedNote = (pluginId: string, version: string): string => `Разрешено: плагин ${pluginId} ${version}.`;
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
      note: `Временное доверие недоступно: плагин взят из папки на компьютере, а не из чата агента. ${i.level === "own" ? "Ваш источник уже в доверенных: версии без новых прав проходят сами." : "Вместо него доверьте источник кнопкой «Разрешить и доверять источнику»: тогда версии без новых прав будут проходить сами."}`,
    };
  }
  return { available: false, note: "Временное доверие недоступно: плагин пришёл не из чата агента. Разрешайте версию или доверьте источник." };
}
/**
 * «Открыть окно на N мин» on a plugin's own row. A window is bound to the thread an agent put the plugin in from, so it is possible only for a plugin with such a
 * thread (and only with a guard); otherwise the row says why not and what to use instead — never a bare «окно закрыто».
 */
export function pluginWindowAvail(i: { guard: boolean; threadId: string | null; level: Level }): WindowAvail {
  if (!i.guard) return { available: false, note: "Временное доверие открывается с карточки версии, которая ждёт решения; кнопка на строке плагина есть при включённой защите." };
  if (i.threadId) return { available: true, note: null };
  const instead = i.level === "own" ? "Версии из ваших источников и без окна проходят сами, пока не просят новых прав." : "Версию можно одобрить касанием или доверить её источник.";
  return { available: false, note: `Временное доверие здесь невозможно: оно привязано к чату, из которого агент поставил плагин, а у этого плагина такого чата нет. ${instead}` };
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
  if (i.level === "own") return { enabled: false, note: "Ваш источник уже в доверенных: версии без новых прав проходят сами." };
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
/**
 * The action Enter presses in a code field: the first enabled button that follows the field in the document order inside the nearest group
 * (the field's parent, then up to two levels higher) — the buttons of a card stand next to its code field.
 */
export function firstButtonAfter(field: Element): HTMLButtonElement | null {
  let scope: Element | null = field.parentElement;
  for (let up = 0; scope && up < 3; up++, scope = scope.parentElement) {
    const buttons = Array.from(scope.querySelectorAll("button"));
    const after = buttons.find((b) => !b.disabled && (field.compareDocumentPosition(b) & 4) !== 0);
    if (after) return after;
  }
  return null;
}
/** Why the approval session is closed, in words, for the strip that tells the person (a session that goes quietly looked like «my click did nothing»). */
export type SessionCloseReason = "idle" | "ceiling" | "locked" | "server";
export function sessionClosedText(reason: SessionCloseReason): string {
  const why: Record<SessionCloseReason, string> = {
    idle: "прошло 15 минут без действий",
    ceiling: "прошёл час, дольше сессия не живёт",
    locked: "вы нажали «Заблокировать»",
    server: "сервер её больше не признаёт (закончилось время или её закрыли на другой странице)",
  };
  return `Сессия закрыта: ${why[reason]}. Чтобы не вводить код каждый раз, откройте её снова.`;
}
/** The page's own count of the end: which of the two limits ran out. */
export const sessionEndReason = (s: { idleUntil: number; hardUntil: number }, now: number): SessionCloseReason => (now >= s.hardUntil ? "ceiling" : "idle");
/** After a use the idle end moves ahead by 15 minutes, but never back: a session opened for an hour keeps its hour. */
export const slideIdle = (cur: { idleUntil: number }, startedAt: number, idleMs: number, marginMs: number): number => Math.max(cur.idleUntil, startedAt + idleMs - marginMs);
export const SESSION_LINE = "Открыть на 15 минут или на час, чтобы не вводить код каждый раз";
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
/** When a hook of this event runs, in plain words. */
const HOOK_WHEN: Record<string, string> = {
  PreToolUse: "перед каждым действием агент будет запускать",
  PostToolUse: "после каждого действия агент будет запускать",
  UserPromptSubmit: "при каждом вашем сообщении агент будет запускать",
  SessionStart: "при начале сессии агент будет запускать",
  SessionEnd: "в конце сессии агент будет запускать",
  Stop: "по окончании каждого ответа агент будет запускать",
  SubagentStop: "по окончании работы помощника агент будет запускать",
  Notification: "при каждом уведомлении агент будет запускать",
  PreCompact: "перед сжатием контекста агент будет запускать",
};
/** «перед каждым действием агент будет запускать: `curl x.example`» — the command itself, from the guard's reason (`hooks: … — Event: command ¦ Event: command`). */
function hookMeaning(reason: string): string {
  const tail = reason.split(" — ")[1];
  if (!tail) return "агент будет сам запускать команды при своих действиях (хуки)";
  return tail
    .split(" ¦ ")
    .map((part) => {
      const i = part.indexOf(": ");
      const ev = i > 0 ? part.slice(0, i) : "";
      const cmd = i > 0 ? part.slice(i + 2) : part;
      return `${HOOK_WHEN[ev] ?? `при событии «${ev || "hooks"}» агент будет запускать`}: \`${cmd}\``;
    })
    .join("; ");
}
const MEANINGS: Array<[RegExp, (m: RegExpExecArray) => string]> = [
  [/permissions\.defaultMode: bypassPermissions/, () => "агент будет делать всё без вопросов к вам (режим bypassPermissions)"],
  [/permissions\.defaultMode: acceptEdits/, () => "агент будет сам менять файлы, не спрашивая вас"],
  [/^permissions\.allow: сужено — (.*)$/, (m) => `права сужены: ${m[1]} (агент получает меньше свободы, не больше)`],
  [/^permissions\.allow: убрано (.*)$/, (m) => `права убраны: ${m[1]} (агент получает меньше свободы)`],
  [/permissions\.allow «Bash(?:\(\s*(?:\*|:\*|\*:\*)?\s*\))?»/, () => "агент сможет выполнять любые команды без спроса"],
  [/permissions\.allow «([^»]*)»: сеть/, (m) => `агент сможет без спроса выполнять «${m[1]}» (команды с выходом в сеть)`],
  [/permissions\.allow «([^»]*)»: путь вне/, (m) => `агент сможет без спроса работать с «${m[1]}» (файлы вне рабочей папки)`],
  [/permissions\.allow «([^»]*)»/, (m) => `агент сможет без спроса: «${m[1]}»`],
  [/permissions\.allow/, () => "агент сможет выполнять часть действий без спроса"],
  [/permissions\.additionalDirectories/, () => "агент получит доступ к папке вне рабочей"],
  [/^hooks/, (m) => hookMeaning(m.input)],
  [/^MCP-сервер ([^:]+): новый — запуск: (.*)$/, (m) => {
    const [launch, ...rest] = m[2]!.split(" ¦ ");
    return `агент получит новый внешний инструмент «${m[1]}» (MCP-сервер); он запускается командой \`${launch}\`${rest.length > 0 ? ` (${rest.join("; ")})` : ""}`;
  }],
  [/^MCP-сервер ([^:]+): новый/, (m) => `агент получит новый внешний инструмент «${m[1]}» (MCP-сервер): он сможет выполнять действия, о которых bb не знает`],
  [/^MCP-сервер ([^:]+): изменён — (.*)$/, (m) => `у внешнего инструмента «${m[1]}» (MCP-сервер) изменили запуск: ${m[2]!.replace(" ¦ ", " → ")}`],
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
  [/файл не разобран как JSON/, () => "файл нельзя прочитать как настройки: агент может понять его иначе, чем защита"],
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

/**
 * How to roll back a critical change BY HAND (the guard only reads the agents' files, it cannot write them): which file, and what exactly to remove.
 * Built from the guard's reasons, so it names the same command, server or entry the red text names.
 */
export function manualRollback(path: string, reasons: string[]): string {
  const steps: string[] = [];
  for (const r of reasons) {
    let m: RegExpExecArray | null;
    if ((m = /^hooks: новые или изменённые — (.*)$/.exec(r))) steps.push(`в разделе hooks уберите: ${m[1]!.split(" ¦ ").map((c) => `\`${c}\``).join(", ")}`);
    else if (/^hooks/.test(r)) steps.push("уберите раздел hooks");
    else if ((m = /^MCP-сервер ([^:]+): новый/.exec(r))) steps.push(`в mcpServers уберите сервер «${m[1]}»`);
    else if ((m = /^MCP-сервер ([^:]+): изменён — было: (.*) ¦ стало: .*$/.exec(r))) steps.push(`у сервера «${m[1]}» верните запуск: \`${m[2]}\``);
    else if ((m = /^permissions\.allow «([^»]*)»/.exec(r))) steps.push(`в permissions.allow уберите «${m[1]}»`);
    else if ((m = /^permissions\.defaultMode: (\S+)/.exec(r))) steps.push(`верните permissions.defaultMode (сейчас «${m[1]}»)`);
    else if ((m = /^permissions\.additionalDirectories: (.*?) \(/.exec(r))) steps.push(`в permissions.additionalDirectories уберите ${m[1]}`);
    else if ((m = /^env ([A-Z0-9_]+)/i.exec(r))) steps.push(`в env уберите или верните ${m[1]}`);
    else if (/^permissions\.allow: (сужено|убрано)/.test(r)) continue;
    else steps.push(r);
  }
  const what = steps.length > 0 ? [...new Set(steps)].join("; ") : "верните файл к прежнему виду (см. diff)";
  return `Откройте файл ${path} и: ${what}. Через минуту защита перечитает файл; когда всё вернётся к одобренным настройкам, тревога уйдёт сама.`;
}

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

/**
 * Terms that a person who is not a programmer meets in the main text, with a plain explanation (a hint on the word; the technical part stays in «Подробнее»).
 * The order matters: the first term that matches wins at a place.
 */
export const GLOSSARY: Array<{ re: RegExp; hint: string }> = [
  { re: /MCP-сервер\w*/i, hint: "MCP-сервер — внешний инструмент, который агент может вызывать: отдельная программа или сервис. Агент передаёт ему данные, и что он с ними делает, bb не видит." },
  { re: /хуки|хуков|hooks/i, hint: "Хуки — команды, которые агент сам запускает в определённые моменты (например, перед каждым своим действием)." },
  { re: /окн(?:о|а|ом|е|у) доверия/i, hint: "Окно доверия — короткое время, пока новые версии плагина проходят без вопросов. Закрывается само по истечении времени." },
  { re: /\bdiff\b/i, hint: "diff — построчное сравнение: что было в файле и что в нём стало." },
  { re: /\bexfil\b/i, hint: "«exfil» — просто имя, которое дали серверу (от exfiltration, «вынос данных»). Имя ничего не доказывает: смотрите, какой командой сервер запускается." },
  { re: /путь к вашей домашней папке/i, hint: "Путь — это только адрес папки на компьютере (где она лежит). Содержимое папки, документы и файлы он при этом не читает." },
  { re: /конфигураци(?:я|и|й|ях|ями) агентов/i, hint: "Файлы с настройками ваших ИИ-агентов: что им разрешено делать без вопросов, какие инструменты и команды у них подключены." },
];
/** Splits segments at the glossary's terms, so that each term carries its explanation. */
export function glossSegments(segments: Segment[]): Segment[] {
  const out: Segment[] = [];
  for (const seg of segments) {
    if (seg.red || seg.hint) {
      out.push(seg);
      continue;
    }
    let rest = seg.text;
    while (rest !== "") {
      let best: { index: number; len: number; hint: string } | null = null;
      for (const g of GLOSSARY) {
        const m = g.re.exec(rest);
        if (m && (best === null || m.index < best.index)) best = { index: m.index, len: m[0].length, hint: g.hint };
      }
      if (best === null) {
        out.push({ text: rest });
        break;
      }
      if (best.index > 0) out.push({ text: rest.slice(0, best.index) });
      out.push({ text: rest.slice(best.index, best.index + best.len), hint: best.hint });
      rest = rest.slice(best.index + best.len);
    }
  }
  return out;
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

// ---- errors in plain Russian ---------------------------------------------------------------------------------------------------
/** What the server and the guard answer (English, with internal words) → what the person reads. Anything not known gets a general sentence, never the English text. */
const ERROR_TEXT: Array<[RegExp, string]> = [
  [/hash did not match|never approved/i, "Эту версию вернуть нельзя: её файлы изменились после проверки. Установите плагин заново из его источника."],
  [/hard flag|blocked by the checks/i, "У этой версии жёсткий признак опасности: обычным разрешением её не пропустить."],
  [/fresh touch|session does not cover/i, "Для этого нужен свежий код или касание: сессия здесь не помогает."],
  [/invalid or expired session|expired session/i, "Сессия закрылась. Откройте её снова или введите код."],
  [/invalid or already used code|invalid_code|code does not match/i, "Код не подошёл. Подождите, пока в приложении появится новый, и введите его."],
  [/a code or a touch is needed|a code is needed|code, or an open session/i, "Нужен код из приложения (или касание ключом)."],
  [/too many|blocked until|block/i, "Слишком много неверных кодов: ввод закрыт на час."],
  [/third-party plugins first|interface code could read/i, "Пока работают чужие плагины с интерфейсом, сессию открыть нельзя: они могли бы подсмотреть её."],
  [/directory that others can write/i, "Папка плагина доступна на запись другим пользователям: после проверки файлы можно подменить. Исправьте права или ставьте плагин другим способом."],
  [/is already (approved|dismissed|accepted|reverted|superseded)|already approved/i, "Это уже решено: обновите страницу."],
  [/no such|not found|no review|no request|no difference/i, "Этого уже нет: обновите страницу."],
  [/list expired|does not match the one that was shown|prepare it again/i, "Список устарел: соберите его заново."],
  [/did not come from a thread|trust window/i, "Для этого плагина временное доверие недоступно: разрешайте версию целиком."],
  [/challenge/i, "Подтверждение устарело. Нажмите ещё раз."],
  [/acknowledgeBlock|Строгий/i, "В строгом режиме остановку обойти нельзя. Сначала смягчите режим."],
  [/guard|ECONN|ENOENT|timeout|socket/i, "Защита не ответила. Проверьте, что она запущена, и повторите."],
];
export function humanError(raw: string): string {
  for (const [re, text] of ERROR_TEXT) if (re.test(raw)) return text;
  // Already in Russian: the page's own words, shown as they are.
  if (/[А-Яа-яЁё]/.test(raw)) return raw;
  return "Не получилось. Подробности записаны в журнал; повторите или позовите того, кто настраивал защиту.";
}

// ---- who, when and how ---------------------------------------------------------------------------------------------------------
/** «21:26» for today, «20.11 21:26» for another day. */
export function clockText(ms: number, now: number): string {
  const d = new Date(ms);
  const n = new Date(now);
  const hhmm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  return d.toDateString() === n.toDateString() ? hhmm : `${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")} ${hhmm}`;
}
/** A rejected version (a card the person dismissed): the version's own version can be put back only if its files are what was checked. */
export const canRestore = (q: { reason: string | null; contentHash: string | null }): boolean => !isMismatch(q.reason) && q.contentHash !== null;
/** When the person rejected a version: the guard's journal knows (a `dismissed` record of this entry), the entry itself only knows when it last saw it. */
export function rejectedAtOf(q: { id: number; pluginId: string; version: string; lastSeen: number }, events: Array<{ ts: number; kind: string; pluginId: string | null; detail?: unknown }>): number {
  let best: number | null = null;
  for (const e of events) {
    if (e.kind !== "dismissed" || e.pluginId !== q.pluginId) continue;
    const d = e.detail !== null && typeof e.detail === "object" ? (e.detail as Record<string, unknown>) : {};
    if (d.review !== q.id && d.version !== q.version) continue;
    if (best === null || e.ts > best) best = e.ts;
  }
  return best ?? q.lastSeen;
}
/** «отклонено вами 21:20». */
export const rejectedByText = (at: number, now: number): string => `отклонено вами ${clockText(at, now)}`;
/** «вы, касанием, 21:26» / «прошла сама: свой источник, 21:20»: who let the version in, how, when. */
export function approvedByText(a: { via: string; why?: string | null; approvedAt: number }, now: number): string {
  return `${approvalWhy(a)}, ${clockText(a.approvedAt, now)}`;
}

/** The notes under the «срок» fold: each sentence once (the window's note and the button's note both may say that the source is already trusted). */
export function uniqueSentences(notes: Array<string | null | undefined>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const note of notes) {
    for (const part of (note ?? "").split(/(?<=[.!?])\s+/)) {
      const t = part.trim();
      if (t === "" || seen.has(t)) continue;
      seen.add(t);
      out.push(t);
    }
  }
  return out;
}

// ---- round 4: what a card says first, and a page that holds still ------------------------------------------------------------
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
/**
 * What a plugin that presses elements of bb's page presses, by where its code goes for them: the buttons of an agent's question (answers for the
 * person: red), the protection's own buttons or a target the code hides next to words of approval (red), a row or a link of the navigation (opens a thread
 * or a section: soft yellow), anything else (yellow).
 */
export function uiClickLine(c: CapLike): { danger: boolean; text: string; phrase: string } {
  const has = (d: string): boolean => c.detail.includes(d);
  if (has(UI_CLICK_GATE)) return { danger: true, text: "может нажимать кнопки защиты secure-bb и «Разрешить» за вас", phrase: "нажимать кнопки защиты secure-bb и «Разрешить» за вас (кнопки защиты ещё требуют код, но плагин может нажать и их)" };
  if (has(UI_CLICK_ANSWERS)) return { danger: true, text: "отвечает на вопросы агентов за вас (нажимает кнопки их виджета)", phrase: "отвечать на вопросы агентов за вас: плагин находит виджет вопроса на странице и нажимает «Next» или «Submit»" };
  if (has(UI_CLICK_NAV) && !has("target:other")) return { danger: false, text: "открывает треды и разделы bb за вас", phrase: "открывать треды и разделы bb за вас (нажимает на строки списка и ссылки)" };
  return { danger: false, text: "может нажимать элементы интерфейса bb", phrase: "нажимать элементы интерфейса bb за вас (какие именно — из кода видно не всегда)" };
}
/** The first line for a plugin that uses bb's own API or presses bb's buttons; null when it does neither. «Безопасно: только оформление» is never said of it. */
export function sdkHeadline(caps: CapLike[]): Risk | null {
  const mine = SDK_LINES.filter((l) => caps.some((c) => c.kind === l.kind));
  if (mine.length === 0) return null;
  const click = caps.find((c) => c.kind === "ui_click");
  const lines = mine.map((l) => (l.kind === "ui_click" && click ? { ...l, danger: uiClickLine(click).danger, text: uiClickLine(click).text } : l));
  const sendsOut = caps.some((c) => c.kind === "network");
  const danger = lines.some((l) => l.danger) || (lines.some((l) => l.kind === "sdk_read") && sendsOut);
  const shown = lines.slice(0, 3).map((l) => l.text);
  const text = shown.join("; ") + (lines.length > 3 ? `; и ещё ${lines.length - 3}` : "");
  return { level: danger ? "danger" : "caution", text: text.charAt(0).toUpperCase() + text.slice(1) };
}
export function riskHeadline(caps: CapLike[], reviewRules: string[] = []): Risk {
  const has = (k: string): CapLike | undefined => caps.find((c) => c.kind === k);
  // Other programs' logins come first and are said outright: that is more than any variable of the environment. Red when the plugin can also send it out.
  const creds = has("credentials");
  if (creds) return { level: has("network") ? "danger" : "caution", text: `Читает ваши учётные данные других программ: ${creds.detail.slice(0, 3).join(", ")}${creds.detail.length > 3 ? ", …" : ""}` };
  const env = has("env");
  if (env) {
    const names = [...new Set(env.detail.map((d) => d.replace(/^env:/, "")))].filter((n) => n !== "");
    if (names.length === 0 || names.includes("*") || names.some((n) => SECRETISH.test(n))) return { level: "danger", text: "Может читать ваши пароли и токены" };
  }
  const fs = has("fs");
  // «Ваши документы» only where the code reaches the person's own folders; files the code does not name are said as what they are: not known.
  if (fs && !(fs.paths && fs.paths.length > 0) && fs.detail.includes(FS_HOME)) return { level: "danger", text: "Может читать и менять ваши документы" };
  if (has("server_access") || has("builtin_rpc")) return { level: "danger", text: "Может управлять самим bb: аккаунтом, подключениями, инструкциями" };
  const sdk = sdkHeadline(caps);
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

/** A resolved card is replaced by a stub of the same height, and the stub stays until the person closes it. */
export interface Stub {
  key: string;
  text: string;
  height: number;
  /** A stub of a card put aside: the entry to bring back («Вернуть»). Absent on the «Готово» stub of a decided card. */
  restore?: { id: number; pluginId: string; version: string; contentHash: string | null };
}
export const MIN_STUB_HEIGHT = 56;
export function makeStub(key: string, what: string, height: number): Stub {
  return { key, text: doneMessage(what), height: Number.isFinite(height) ? Math.max(MIN_STUB_HEIGHT, Math.round(height)) : MIN_STUB_HEIGHT };
}
/**
 * The order of a list while the page is open: what was there keeps its place, what is new goes to the end and is marked «новое». The first call (`prev` null)
 * takes the list as it comes, and marks nothing. Keys in `keep` (a stub stands there) keep their place though the entry is gone.
 */
export function stableOrder(prev: string[] | null, cur: string[], keep: string[] = []): { order: string[]; fresh: string[] } {
  if (prev === null) return { order: [...cur], fresh: [] };
  const alive = new Set([...cur, ...keep]);
  const order = prev.filter((k) => alive.has(k));
  const have = new Set(order);
  const fresh = cur.filter((k) => !have.has(k));
  return { order: [...order, ...fresh], fresh };
}
export interface ListItem {
  key: string;
  stub?: Stub;
}
/** The list as drawn: a card where there is one, the stub where it was resolved. */
export function layoutItems(order: string[], present: ReadonlySet<string>, stubs: Stub[]): ListItem[] {
  const out: ListItem[] = [];
  for (const key of order) {
    if (present.has(key)) out.push({ key });
    else {
      const stub = stubs.find((s) => s.key === key);
      if (stub) out.push({ key, stub });
    }
  }
  return out;
}

/** Wizard, step 2: a source in words a person knows. */
export function friendlySource(entry: string): string {
  const gh = /^github:([^/\s]+\/[^\s]+)$/i.exec(entry);
  if (gh) return `${gh[1]} (на GitHub)`;
  if (/^path:/.test(entry)) return `папка ${entry.slice(5)}`;
  return entry;
}
export const WIZARD_SOURCES_TEXT = "Ставили плагины из каталога bb? Тогда здесь ничего отмечать не нужно: защита спросит вас про каждую новую версию. Отмечайте только то, что вы сами пишете или ведёте: новые версии оттуда будут проходить без вопросов, пока плагин не попросит новых прав.";
/** Wizard, step 3: the second factor in words, without a count of keys. */
export function secondFactorText(i: { codes: boolean; keys: number }): string {
  if (i.codes && i.keys > 0) return "Второй фактор настроен: коды из приложения на телефоне и ключ.";
  if (i.codes) return "Второй фактор настроен: коды из приложения на телефоне.";
  if (i.keys > 0) return "Второй фактор настроен: ключ (отпечаток или ключ безопасности).";
  return "Второй фактор ещё не настроен.";
}
export const AWAY_HIDE_LABEL = "Понятно, скрыть";

// ---- round 5 -------------------------------------------------------------------------------------------------------------------

// ---- findings in a person's words ------------------------------------------------------------------------------------------------
/** What a check that asks for a look says, in a sentence (the rules that stop a version have their own, in `RED`). */
const REVIEW_TEXT: Record<string, string> = {
  "dynamic-access": "код обращается к функциям по имени, собранному на лету: что именно он вызывает, из кода не видно",
  "require-alias": "код подключает модули непрямым способом, который трудно проследить",
  "module-load": "код подгружает модули внутренним способом bb",
  "dynamic-constructor": "код создаёт функции из текста",
  "global-proxy": "код подменяет глобальные объекты",
  webassembly: "в плагине есть скомпилированный код (WebAssembly)",
  "native-load": "плагин загружает готовую программу",
  "unknown-builtin": "плагин использует системный модуль, которого проверки не знают",
  "secret-path": "в коде упомянуты файлы с паролями или ключами",
  "secret-literal": "в коде есть строка, похожая на пароль или ключ",
  "secret-reference": "в коде упомянуты пароли или ключи",
  "env-secret-network": "плагин читает переменные с паролями и умеет выходить в сеть",
  "env-passed": "плагин передаёт все переменные окружения другой функции",
  "parse-failed": "часть кода не удалось разобрать: проверить её нечем",
  "limit-exceeded": "проверка не смогла просмотреть всё: файлов или кода слишком много",
  "file-too-large": "один из файлов слишком большой, чтобы его проверить",
  "executable-file": "в плагине лежит исполняемый файл",
  "sdk-unclassified": "плагин обращается к частям bb, которых проверки не знают",
  "bad-package-json": "описание плагина (package.json) составлено неправильно",
  "workspace-dependency": "плагин зависит от соседней папки, а не от опубликованного пакета",
  "dep-lookalike": "название одного из пакетов похоже на название известного: так подделывают пакеты",
  "dep-modified": "один из пакетов отличается от того, что лежит в реестре npm",
  "dep-name-mismatch": "название пакета не совпадает с тем, под которым он лежит",
  "dep-young": "один из пакетов выпущен меньше трёх дней назад",
  "external-script-link": "страница плагина подключает скрипт из интернета",
  "injection-phrase": "в тексте есть фраза, которой пытаются управлять агентом",
  "network-command": "в тексте есть команда, которая ходит в сеть",
  "too-large": "файл слишком большой для проверки",
};
const NOT_SHOWN_RULES = new Set(["ignored-findings", "unreachable-files", "dep-content-unverified", "parse-note", "config-path", "shell-pipe-string", "agent-config"]);
export interface FindingLine {
  /** One sentence in Russian. */
  text: string;
  severity: "block" | "review";
  /** Where, at most three places. */
  where: string[];
  /** How many places in all. */
  count: number;
}
/**
 * The findings a person is told of: only those that matter (a version is stopped, or a look is asked for), grouped by what they say, in Russian. What is only
 * noted («info»), the book-keeping of the checks («not scanned»), and the raw rule names stay in the developer's fold.
 */
export function significantFindings(findings: Array<{ rule: string; severity: string; file: string; line: number }>): FindingLine[] {
  const by = new Map<string, FindingLine>();
  for (const f of findings) {
    if ((f.severity !== "block" && f.severity !== "review") || NOT_SHOWN_RULES.has(f.rule)) continue;
    const text = f.severity === "block" ? (RED[f.rule]?.title ?? RED_FALLBACK.title) : (REVIEW_TEXT[f.rule] ?? "проверка нашла особенность в коде");
    const key = `${f.severity}|${text}`;
    const e = by.get(key) ?? { text: text.charAt(0).toUpperCase() + text.slice(1), severity: f.severity, where: [], count: 0 };
    e.count++;
    const place = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "";
    if (place !== "" && e.where.length < 3 && !e.where.includes(place)) e.where.push(place);
    by.set(key, e);
  }
  return [...by.values()].sort((a, b) => (a.severity === b.severity ? b.count - a.count : a.severity === "block" ? -1 : 1));
}
/** The fold's summary on a card: what the findings come to, in the same terms as the card's colour. */
export function checksSummary(lines: FindingLine[], capabilities: number): string {
  const n = lines.reduce((x, l) => x + l.count, 0);
  const things = lines.length === 0 ? "значимых находок нет" : `${n} ${plural(n, "находка", "находки", "находок")} (${lines.length} ${plural(lines.length, "вид", "вида", "видов")})`;
  return `Проверки: ${things} · возможностей: ${capabilities}`;
}

// ---- one set of counts for the whole page ---------------------------------------------------------------------------------------
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

// ---- «Решить позже» leaves a stub, not a hole ------------------------------------------------------------------------------------
export interface DeferStubSource {
  id: number;
  pluginId: string;
  version: string;
  contentHash: string | null;
}
/** The stub that stands where a card was put aside: the card's height, «Отложено: X · Вернуть». The next card does not slide under the cursor. */
export function makeDeferStub(q: DeferStubSource, height: number): Stub {
  return { key: q.pluginId, text: `Отложено: ${q.pluginId} ${q.version}`, height: Number.isFinite(height) ? Math.max(MIN_STUB_HEIGHT, Math.round(height)) : MIN_STUB_HEIGHT, restore: { id: q.id, pluginId: q.pluginId, version: q.version, contentHash: q.contentHash } };
}
export const DEFER_STUB_RESTORE = "Вернуть";

// ---- the delete question: one place, one order -----------------------------------------------------------------------------------
/** The buttons of «Удалить плагин …?», in the order they are always drawn, on their own line under the question. */
export const DELETE_CONFIRM_BUTTONS = ["Да, удалить", "Нет"] as const;

// ---- a held version without a record at the guard ----------------------------------------------------------------------------------
/** The page's own record of a version that loaded without the guard's check: it has no core hash, so it cannot be approved by hash. */
export const hasNoGuardRecord = (q: { kind: string; contentHash: string | null }): boolean => q.kind === "afterfact" && q.contentHash === null;
export const NO_RECORD_HEADLINE = "Эту версию нельзя разрешить здесь: защита её не проверяла";
export const NO_RECORD_LINE = "Плагин загрузился в обход проверки, поэтому одобрить его по отпечатку нельзя. Исправляется так: удалите эту версию и поставьте плагин заново через «bb secure-bb propose» — тогда защита проверит его и карточка станет обычной.";
export const NO_RECORD_FIX = "Удалить, чтобы поставить заново";
/**
 * In guard mode the card of a version comes from the guard's own record. A page-side record of the same version (it has no core hash) is dropped when
 * the guard has one; otherwise two cards would stand for one version, and the one without the hash would say «Включить» where nothing can be enabled.
 */
export function dropShadowedLocal<T extends { pluginId: string; version: string }>(guardEntries: Array<{ pluginId: string; version: string }>, local: T[]): T[] {
  const have = new Set(guardEntries.map((g) => `${g.pluginId}\0${g.version}`));
  return local.filter((l) => !have.has(`${l.pluginId}\0${l.version}`));
}

// ---- restoring while a session is open --------------------------------------------------------------------------------------------
/** Under «Вернуть как было»: a session does not cover it (it changes the agent's files), and the card says so. */
export const RESTORE_FRESH_CODE = "Нужен свежий код: меняются файлы агента — сессия здесь не помогает.";
export const restoreNote = (sessionOpen: boolean): string | null => (sessionOpen ? RESTORE_FRESH_CODE : null);
