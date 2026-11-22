// What a plugin's rights and the flows of what it reads sound like in a person's words (capabilities, programs, hosts, variables, glossary). Words only: nothing is decided here.
import { FS_HOME, UI_CLICK_ANSWERS, UI_CLICK_GATE, UI_CLICK_NAV } from "../checks/sdk-rights.js";

export interface CapLike {
  kind: string;
  detail: string[];
  /** For `fs`: the literal paths the code hands to file calls, when it names any. */
  paths?: string[];
  /** For `child_process`: the programs the code starts by name, and whether it also starts one it does not name. */
  programs?: string[];
  programsUnknown?: boolean;
  /** Where what this right reads goes (the checks' data flow); absent where the checks did not follow it. */
  flow?: FlowLike;
  /** «Зачем» by the pair access → sink: short sentences. */
  purpose?: string[];
}

/** The guard's own reading of where one source goes (`guard/src/checks/flow.ts`, `FlowSummary`). Declared here: the page does not import the checks. */
export interface FlowLike {
  source: string;
  detail: string[];
  verdict: "nowhere" | "shown" | "kept" | "leaves" | "unknown";
  sinks: Array<{ kind: string; target?: string; choice?: boolean }>;
  why?: string;
}

export interface PurposeLike {
  on: string[];
  text: string;
}

/** The detail of a network right whose address the code does not show (the guard's `UNRESOLVED_HOST`). */
export const UNRESOLVED_HOST = "unresolved-host";

/**
 * The capabilities of a check result, with the file paths of the result put on the `fs` one and the programs on the `child_process` one (so that a card can
 * name them), and, when the code reaches other programs' credential files, a first right `credentials` naming whose.
 */
export const capsWithPaths = (r: { capabilities: CapLike[]; fsPaths?: string[]; programs?: string[]; programsUnknown?: boolean; credentials?: string[]; flows?: FlowLike[]; purposes?: PurposeLike[] } | undefined): CapLike[] => {
  const caps = meaningfulCaps(r?.capabilities ?? []).map((c) =>
    c.kind === "fs" && r?.fsPaths && r.fsPaths.length > 0 ? { ...c, paths: r.fsPaths } : c.kind === "child_process" && r ? { ...c, programs: r.programs ?? [], programsUnknown: r.programsUnknown ?? false } : c,
  );
  const all = r?.credentials && r.credentials.length > 0 ? [{ kind: "credentials", detail: r.credentials }, ...caps] : caps;
  return all.map((c) => attachFlow(r ?? {}, c));
};

/** The right with where its data goes and why, from a check result's `flows` and `purposes`. */
export function attachFlow(r: { flows?: FlowLike[]; purposes?: PurposeLike[] }, c: CapLike): CapLike {
  const flow = r.flows?.find((f) => f.source === FLOW_SOURCE_OF[c.kind]);
  const purpose = [...new Set((r.purposes ?? []).filter((p) => p.on.includes(c.kind)).map((p) => p.text))];
  return flow || purpose.length > 0 ? { ...c, ...(flow ? { flow } : {}), ...(purpose.length > 0 ? { purpose } : {}) } : c;
}

/** The right whose line a source's verdict belongs to. */
const FLOW_SOURCE_OF: Record<string, string> = { sdk_read: "threads", sdk_questions: "questions", env: "env", credentials: "credentials", fs: "files" };

/** What the right is called when a sentence is built around it: «Читает ваши переписки в bb и …». */
export const READS_PLAIN: Record<string, string> = {
  sdk_read: "читает ваши переписки в bb",
  sdk_questions: "видит вопросы ваших агентов",
  env: "читает ваши пароли и токены (переменные окружения)",
  credentials: "читает ваши учётные данные других программ",
  fs: "читает ваши файлы",
};

/** «a и b», «a, b и c»; when a part has an «и» of its own, the parts are only set off by commas. */
const joinAnd = (parts: string[]): string => {
  if (parts.length <= 1) return parts[0] ?? "";
  if (parts.some((p) => p.includes(" и "))) return parts.join(", ");
  return `${parts.slice(0, -1).join(", ")} и ${parts[parts.length - 1]}`;
};

const unnamed = (t: string | undefined): boolean => t === undefined || /^(a |an )/.test(t);

/** One dangerous or shown sink, in a verb: `[third person, infinitive]`. The names the code gives (hosts, programs, files) are named; what it does not give is said so. */
function sinkVerb(kind: string, target: string | undefined): [string, string] {
  switch (kind) {
    case "network":
      return unnamed(target) ? ["отправляет по сети (куда — из кода не видно)", "отправлять по сети (куда — из кода не видно)"] : [`отправляет на ${target}`, `отправлять на ${target}`];
    case "process":
      return unnamed(target) ? ["передаёт программе, название которой из кода не видно", "передавать программе, название которой из кода не видно"] : [`передаёт программе ${target}`, `передавать программе ${target}`];
    case "file":
      return unnamed(target) ? ["записывает в файл вне своей папки (какой — из кода не видно)", "записывать в файл вне своей папки (какой — из кода не видно)"] : [`записывает в файл ${target}`, `записывать в файл ${target}`];
    case "send":
      return target === "threads.spawn" ? ["передаёт запускаемому агенту", "передавать запускаемому агенту"] : ["отправляет в ваши переписки от вашего имени", "отправлять в ваши переписки от вашего имени"];
    case "settings":
      return ["передаёт в настройки bb", "передавать в настройки bb"];
    case "route":
      return ["отдаёт по адресу плагина на сервере bb", "отдавать по адресу плагина на сервере bb"];
    case "notify":
      return ["показывает вам в уведомлении", "показывать вам в уведомлении"];
    case "sound":
      return ["передаёт проигрывателю звука", "передавать проигрывателю звука"];
    case "ui":
      return ["показывает вам в окне плагина", "показывать вам в окне плагина"];
    case "log":
      return ["пишет в журнал плагина", "писать в журнал плагина"];
    default:
      return ["", ""];
  }
}

const DANGEROUS_KINDS = new Set(["network", "process", "file", "send", "settings"]);

/** The ways out, one verb per kind: the hosts named together, the programs named together; what the code does not name is said once. */
function leaveVerbs(bad: Array<{ kind: string; target?: string }>, i: number): string[] {
  const out: string[] = [];
  const of = (kind: string) => bad.filter((k) => k.kind === kind);
  const named = (kind: string): string[] => [...new Set(of(kind).filter((k) => !unnamed(k.target)).map((k) => k.target!))];
  const hidden = (kind: string): boolean => of(kind).some((k) => unnamed(k.target));
  const list = (xs: string[]): string => `${xs.slice(0, 3).join(", ")}${xs.length > 3 ? ", …" : ""}`;
  if (of("network").length > 0) {
    const hosts = named("network");
    out.push(hosts.length === 0 ? sinkVerb("network", undefined)[i] : `${i === 0 ? "отправляет" : "отправлять"} на ${list(hosts)}${hidden("network") ? " и на адреса, которых в коде не видно" : ""}`);
  }
  if (of("process").length > 0) {
    const progs = named("process");
    out.push(progs.length === 0 ? sinkVerb("process", undefined)[i] : `${i === 0 ? "передаёт" : "передавать"} ${progs.length === 1 && !hidden("process") ? "программе" : "программам"} ${list(progs)}${hidden("process") ? " и другим, названия которых из кода не видно" : ""}`);
  }
  if (of("file").length > 0) {
    const files = named("file");
    out.push(files.length === 0 ? sinkVerb("file", undefined)[i] : `${i === 0 ? "записывает" : "записывать"} в ${files.length === 1 ? "файл" : "файлы"} ${list(files)}${hidden("file") ? " и в другие, которые из кода не видно" : ""}`);
  }
  for (const kind of ["send", "settings", "route"]) {
    const ks = [...new Set(of(kind).map((k) => sinkVerb(kind, k.target)[i]))];
    out.push(...ks);
  }
  return out;
}

/** The part of a sentence that says where it goes: «и никуда не отправляет», «и показывает вам в уведомлении», «и отправляет на stats.example». `inf`: after «сможет:». */
export function flowClause(flow: FlowLike, inf = false, maxVerbs = 3): { text: string; level: "ok" | "unknown" | "danger" } {
  const i = inf ? 1 : 0;
  const secret = flow.source === "env" || flow.source === "credentials";
  const sinks = flow.sinks.filter((k) => k.kind !== "unknown");
  const bad = sinks.filter((k) => DANGEROUS_KINDS.has(k.kind) || (secret && k.kind === "route"));
  if (flow.verdict === "leaves" && bad.length > 0) {
    const data = bad.filter((k) => !k.choice);
    const verbs = leaveVerbs(data, i);
    // Only the choice goes: what is sent, where, or whether at all is decided by what was read
    if (data.length < bad.length) verbs.push(i === 0 ? "по содержимому выбирает, что и куда отправить" : "по содержимому выбирать, что и куда отправлять");
    return { text: `и ${joinAnd(verbs.slice(0, maxVerbs))}${verbs.length > maxVerbs ? ` и ещё ${verbs.length - maxVerbs}` : ""}`, level: "danger" };
  }
  if (flow.verdict === "nowhere") return { text: inf ? "и никуда не отправлять" : "и никуда не отправляет", level: "ok" };
  if (flow.verdict === "shown") {
    // for what was said in a conversation, the plugin's own route is its own page
    const verbs = [...new Set(sinks.map((k) => sinkVerb(k.kind === "route" ? "ui" : k.kind, k.target)[i]).filter(Boolean))];
    return { text: `и ${joinAnd(verbs)}`, level: "ok" };
  }
  if (flow.verdict === "kept") return { text: inf ? "и только хранить у себя в bb (дальше не отправлять)" : "и только хранит у себя в bb (дальше не отправляет)", level: "ok" };
  return { text: "куда уходит — из кода не видно", level: "unknown" };
}

/** What follows the phrase of a right on a card: where it goes, then why. Empty when the checks followed nothing for it. */
export function flowSuffix(c: CapLike, inf: boolean): string {
  const clause = c.flow ? flowClause(c.flow, inf) : null;
  const why = c.purpose && c.purpose.length > 0 ? ` — ${c.purpose.join("; ")}` : "";
  if (!clause) return why;
  return `${clause.level === "unknown" ? "; " : " "}${clause.text}${why}`;
}

/** The red first line of a card: what it reads and where it sends it. null when no source reaches a dangerous sink. */
export function leakHeadline(caps: CapLike[]): string | null {
  const leaks = caps.filter((c) => c.flow?.verdict === "leaves" && flowClause(c.flow, false).level === "danger" && READS_PLAIN[c.kind]);
  if (leaks.length === 0) return null;
  const parts = leaks.slice(0, 2).map((c) => `${READS_PLAIN[c.kind]} ${flowClause(c.flow!, false, 2).text}`);
  const text = parts.join("; ") + (leaks.length > 2 ? `; и ещё ${leaks.length - 2}` : "");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

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

export const riskyProgram = (p: string): boolean => PROGRAM_NAMES[p.toLowerCase()]?.risky === true;

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

export const SECRETISH = /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH/i;

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
      return [...envSegments(c.detail), ...(flowSuffix(c, true) ? [{ text: flowSuffix(c, true) }] : [])];
    case "network":
      return [{ text: networkText(c.detail) }];
    default:
      return [{ text: capabilityPhrase(c) }];
  }
}

/** What a right means for a person. Hosts of the network right are named; the environment is named variable by variable, or «все»; the rest is one phrase. */
export function capabilityPhrase(c: CapLike): string {
  return `${capabilityBase(c)}${FLOW_SOURCE_OF[c.kind] || c.purpose ? flowSuffix(c, true) : ""}`;
}

function capabilityBase(c: CapLike): string {
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

/** `threads>network:stats.example` in a person's words: «переписки → сеть stats.example». */
function flowTokenText(t: string): string {
  const [src, rawSink = ""] = t.split(">");
  const choice = rawSink.startsWith("choice-");
  const sink = choice ? rawSink.slice(7) : rawSink;
  const source = ({ threads: "переписки", questions: "вопросы агентов", env: "переменные окружения", credentials: "учётные данные", files: "файлы" } as Record<string, string>)[src!] ?? src!;
  const i = sink.indexOf(":");
  const kind = i < 0 ? sink : sink.slice(0, i);
  const target = i < 0 ? "" : sink.slice(i + 1);
  const where = ({ network: "сеть", process: "программа", file: "файл", send: "сообщение в тред", settings: "настройки bb", route: "адрес плагина на сервере bb", unknown: "не видно из кода" } as Record<string, string>)[kind] ?? kind;
  return `${source} → ${choice ? "выбор, что и куда отправить: " : ""}${where}${target ? ` ${target}` : ""}`;
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
    else if (kind === "flow") out.push(detail.length > 0 ? `куда уходит прочитанное: ${detail.map(flowTokenText).join(", ")}` : "куда уходит прочитанное");
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

/** The hosts a plugin names in its code (network capability), without the `host:` mark. */
export const hostsOf = (caps: CapLike[]): string[] => caps.filter((c) => c.kind === "network").flatMap((c) => c.detail.filter((d) => d.startsWith("host:")).map((d) => d.slice(5)));

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
