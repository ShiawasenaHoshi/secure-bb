// The words of the agents' settings: critical differences, parts of settings.json («Оставить» / «Вернуть»), the list of exceptions and its reset.
import { approvedByText } from "./decisions.js";
import { friendlySource } from "./modes.js";
import type { TabId } from "./status.js";

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

/** Where the card of the agents' differences is shown: on the «Обзор» tab while something critical or an alarm waits there, else in «Журнал». */
export function agentsSectionTab(i: { critical: number; alarms: number }): TabId {
  return i.critical > 0 || i.alarms > 0 ? "status" : "more";
}

/** Under «Вернуть как было»: a session does not cover it (it changes the agent's files), and the card says so. */
export const RESTORE_FRESH_CODE = "Нужен свежий код: меняются файлы агента — сессия здесь не помогает.";

export const restoreNote = (sessionOpen: boolean): string | null => (sessionOpen ? RESTORE_FRESH_CODE : null);

export interface PartLike {
  id: string;
  path: string[];
  kind: "key-added" | "key-changed" | "key-removed" | "elem-added" | "elem-removed";
  before: string | null;
  after: string | null;
  elem: string | null;
  danger: string | null;
  /** Why putting it back makes the agent more dangerous (then it needs a fresh code or touch), or null. */
  backDanger: string | null;
  restorable: boolean;
}

export const PART_KEEP = "Оставить";

export const PART_BACK = "Вернуть";

export const PART_STALE = "Файл изменился между показом и действием: ничего не записано, показано заново.";

export const PARTS_HEADLINE = "Что именно изменилось — каждое по отдельности";

export const PARTS_HELP = "«Оставить» — это моё: оно войдёт в одобренные настройки. «Вернуть» — это чужое: из файла уйдёт только оно, остальное не трогается и кода не нужно.";

/** «Оставить» for a part that makes the agent more dangerous needs a fresh touch; for the rest a session is enough. */
export const partNeedsFresh = (p: Pick<PartLike, "danger">): boolean => p.danger !== null;

export const PART_FRESH_NOTE = "Это делает агента опаснее: чтобы оставить, нужен свежий код или касание.";

export const PART_BACK_FRESH_NOTE = "Вернуть это значит ослабить агента: чтобы вернуть, нужен свежий код или касание.";

export const PART_NO_BACK = "Эту часть по отдельности вернуть нельзя — только весь файл (кнопка ниже).";

const q = (v: string | null): string => `«${v ?? ""}»`;

/** One line for a part, in plain words: what the agent can do now that it could not before (or no longer can). */
export function partTitle(p: PartLike): string {
  const at = p.path.join(".");
  const [a, b] = p.path;
  if (at === "permissions.defaultMode") return p.after === "bypassPermissions" ? "Режим bypassPermissions: агент будет делать всё, не спрашивая вас" : p.kind === "key-removed" ? "Режим разрешений убран" : `Режим разрешений: ${p.after ?? ""}`;
  if (at === "permissions.allow") return p.kind === "elem-added" ? `Агенту разрешено без вопросов: ${q(p.elem)}` : `Больше не разрешено без вопросов: ${q(p.elem)}`;
  if (at === "permissions.deny") return p.kind === "elem-added" ? `Добавлен запрет: ${q(p.elem)}` : `Снят запрет: ${q(p.elem)}`;
  if (at === "permissions.ask") return p.kind === "elem-added" ? `Теперь будет спрашивать про: ${q(p.elem)}` : `Больше не будет спрашивать про: ${q(p.elem)}`;
  if (at === "permissions.additionalDirectories") return p.kind === "elem-added" ? `Агенту открыта папка: ${q(p.elem)}` : `Папка закрыта: ${q(p.elem)}`;
  if (a === "hooks") return p.kind === "elem-removed" ? `Хук убран (${b ?? ""}): ${p.elem ?? ""}` : `Хук (${b ?? ""}): агент будет запускать сам — ${p.elem ?? p.after ?? ""}`;
  if (a === "env" && b !== undefined) return p.kind === "key-removed" ? `Переменная окружения агента ${b} убрана` : `Переменная окружения агента ${b}: ${p.after ?? ""}`;
  switch (p.kind) {
    case "elem-added":
      return `${at}: добавлено ${q(p.elem)}`;
    case "elem-removed":
      return `${at}: убрано ${q(p.elem)}`;
    case "key-added":
      return `${at}: задано ${q(p.after)}`;
    case "key-removed":
      return `${at}: убрано (было ${q(p.before)})`;
    case "key-changed":
      return `${at}: было ${q(p.before)}, стало ${q(p.after)}`;
  }
}

/** The parts to draw: none when the difference cannot be split or is a single part (then the card's own buttons say it all). */
export const drawableParts = (parts: PartLike[] | null | undefined): PartLike[] => (parts && parts.length > 1 ? parts : []);

export const partKeptNote = (p: PartLike, remaining: number): string => `Оставлено: ${partTitle(p)}${remaining > 0 ? `. Осталось решить: ${remaining}` : ". Больше расхождений в этом файле нет"}`;

export const partBackNote = (p: PartLike): string => `Возвращено: ${partTitle(p)}`;

/** The guard says the file is not the one the page showed (or the part is gone): nothing was written, the page must draw again. */
export const isStalePart = (raw: string): boolean => /changed since it was shown|not in the difference|not what the page showed|already (accepted|reverted|superseded)/i.test(raw);

export type ExceptionKind = "window" | "cfgWindow" | "approval" | "source" | "kept";

export const EXCEPTION_LABEL: Record<ExceptionKind, string> = { window: "Окно доверия", cfgWindow: "Окно доверия", approval: "Одобрение", source: "Мой источник", kept: "Оставлено в настройках агента" };

export interface ExceptionRow {
  key: string;
  kind: ExceptionKind;
  title: string;
  /** One more line (the thread, who approved, why it is dangerous), or null. */
  detail: string | null;
  /** When it began (for «за 24 часа» and the order); null when the list has no time for it. */
  at: number | null;
  /** What «Отозвать» takes back, by the id each rpc wants. */
  revoke: { kind: ExceptionKind; id: number | string };
  /** Taking it back would make the agent more dangerous (a kept ban): then it needs a fresh code or touch, and a reset skips it. Why, or null. */
  needsCode: string | null;
}

export interface ExceptionInput {
  windows: Array<{ id: number; pluginId: string; openedAt: number; remainingSec: number }>;
  cfgWindows: Array<{ id: number; openedAt: number; scopeLabels: string[]; remainingSec: number }>;
  approvals: Array<{ id: number; pluginId: string; version: string; via: string; why?: string | null; approvedAt: number; revokedAt: number | null }>;
  sources: string[];
  kept: Array<{ id: number; rel: string; keptAt: number; danger: string | null; part: PartLike }>;
}

export const minutesLeft = (sec: number): string => `${Math.max(1, Math.ceil(sec / 60))} мин`;

/** Every exception the person made — windows, approvals, «мои источники», kept changes of the agents — in one list, newest first (sources, which have no time, last). */
export function exceptionRows(i: ExceptionInput, now: number, onlyDay = false): ExceptionRow[] {
  const rows: ExceptionRow[] = [
    ...i.windows.map((w): ExceptionRow => ({ key: `window:${w.id}`, kind: "window", title: `${EXCEPTION_LABEL.window}: плагин ${w.pluginId} — ещё ${minutesLeft(w.remainingSec)}`, detail: "новые версии проходят без вопросов, пока окно открыто", at: w.openedAt, revoke: { kind: "window", id: w.id }, needsCode: null })),
    ...i.cfgWindows.map((w): ExceptionRow => ({ key: `cfgWindow:${w.id}`, kind: "cfgWindow", title: `${EXCEPTION_LABEL.cfgWindow}: ${w.scopeLabels.join(", ")} — ещё ${minutesLeft(w.remainingSec)}`, detail: "изменения этих настроек bb проходят без вопросов, пока окно открыто", at: w.openedAt, revoke: { kind: "cfgWindow", id: w.id }, needsCode: null })),
    ...i.approvals.filter((a) => a.revokedAt === null).map((a): ExceptionRow => ({ key: `approval:${a.id}`, kind: "approval", title: `${EXCEPTION_LABEL.approval}: ${a.pluginId} ${a.version}`, detail: approvedByText(a, now), at: a.approvedAt, revoke: { kind: "approval", id: a.id }, needsCode: null })),
    ...i.kept.map((k): ExceptionRow => ({ key: `kept:${k.id}`, kind: "kept", title: `${EXCEPTION_LABEL.kept}: ${partTitle(k.part)}`, detail: `${k.rel}${k.danger ? `. Делает агента опаснее: ${k.danger}` : ""}`, at: k.keptAt, revoke: { kind: "kept", id: k.id }, needsCode: k.part.backDanger })),
    ...i.sources.map((e): ExceptionRow => ({ key: `source:${e}`, kind: "source", title: `${EXCEPTION_LABEL.source}: ${friendlySource(e)}`, detail: "новые версии оттуда проходят без вопросов, пока плагин не попросит новых прав", at: null, revoke: { kind: "source", id: e }, needsCode: null })),
  ];
  return rows
    .filter((r) => !onlyDay || r.at === null || now - r.at < 24 * 3_600_000)
    .sort((a, b) => (a.at === null ? 1 : 0) - (b.at === null ? 1 : 0) || (b.at ?? 0) - (a.at ?? 0));
}

export const exceptionsHeadline = (n: number): string => `Исключения (${n})`;

export const EXCEPTIONS_HELP = "Всё, что вы разрешили в обход обычных вопросов. «Отозвать» — это ужесточение: кода не нужно, плагин или настройка снова спросит вас.";

export const EXCEPTIONS_EMPTY = "Исключений нет: защита спрашивает про всё новое.";

/** What a reset takes back: everything that only tightens. What would weaken the agent when taken back (a kept ban) stays, and is taken back one by one, with a code. */
export const resetRows = (rows: ExceptionRow[]): ExceptionRow[] => rows.filter((r) => r.needsCode === null);

export const resetSkipped = (rows: ExceptionRow[]): number => rows.length - resetRows(rows).length;

export const resetConfirmText = (rows: ExceptionRow[]): string => `Точно? Отзовётся исключений: ${resetRows(rows).length}.${resetSkipped(rows) > 0 ? ` Останется ${resetSkipped(rows)}: их отзыв ослабил бы агента, поэтому каждое отзывается отдельно, с кодом.` : ""}`;

export const REVOKE_CODE_NOTE = "Отзыв ослабит агента (оставленный запрет вернётся к разрешённому): нужен свежий код или касание.";

export const RESET_NOTE = "Закрывает все окна, отзывает одобрения и оставленные изменения агентов, очищает «мои источники». Это ужесточение, касание не нужно, кроме оставленных запретов: их отзыв ослабил бы агента, они остаются и отзываются по одному, с кодом. Плагины, у которых отозвано одобрение, перестанут загружаться, пока вы не решите заново. Режим не меняется.";
