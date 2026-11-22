// What the card of a waiting version shows, as data (the page only draws it): the level, the one line of «why», the rights as rows. No new judgement
// here: the words and the verdicts come from ux.ts (riskHeadline, capabilityPhrase, flowClause, …); this file only arranges them.
import type { QueueRow } from "./store";
import type { CheckResult } from "./checks/types";
import type { QueueUx } from "./uxview";
import {
  actionLabel, agentConfigNote, approveVerb, capabilityPhrase, capsWithPaths, cardColor, cardRisk, flowClause, hasNoGuardRecord, hostsOf, isMismatchEntry, isUnreadOnly, meaningfulCaps, mismatchText, NO_RECORD_HEADLINE, NO_RECORD_LINE, programName,
  redText, redWhere, riskHeadline, trustButton, uiClickLine, unreadText, windowAvailability, yellowText, type CapLike, type Risk, type RedText, type TrustButton, type WindowAvail,
} from "./ux";

/** The detail of a network right whose address the code does not show (the same word ux.ts uses). */
const UNRESOLVED_HOST_TOKEN = "unresolved-host";

/** «Опасно» (red: the only red on the page), «Нужна проверка» (neutral, with a warning mark), «Только оформление» (calm). */
export type CardLevel = "danger" | "check" | "calm";

export const LEVEL_LABEL: Record<CardLevel, string> = { danger: "Опасно", check: "Нужна проверка", calm: "Только оформление" };

export function cardLevel(i: { red: boolean; risk: Pick<Risk, "level"> }): CardLevel {
  if (i.red || i.risk.level === "danger") return "danger";
  return i.risk.level === "safe" ? "calm" : "check";
}

export interface PermissionRow {
  kind: string;
  /** A name of a bb icon (lucide style). */
  icon: string;
  /** Short: «Читает ваши переписки в bb». */
  label: string;
  /** Muted, after the label: «никуда не отправляет». */
  detail: string | null;
  danger: boolean;
}

export const VISIBLE_ROWS = 5;

const SHORT: Record<string, { icon: string; label: string }> = {
  network: { icon: "Globe", label: "Выходит в сеть" },
  env: { icon: "Lock", label: "Читает переменные окружения" },
  credentials: { icon: "Lock", label: "Читает учётные данные других программ" },
  fs: { icon: "Folder", label: "Работает с файлами" },
  child_process: { icon: "Terminal", label: "Запускает программы на компьютере" },
  dynamic_code: { icon: "Code", label: "Выполняет код, собранный на лету" },
  server_access: { icon: "Settings", label: "Управляет самим bb" },
  builtin_rpc: { icon: "Settings", label: "Управляет самим bb" },
  sdk_read: { icon: "MessageSquare", label: "Читает ваши переписки в bb" },
  sdk_meta: { icon: "Eye", label: "Знает названия и состояние тредов" },
  sdk_questions: { icon: "CircleQuestion", label: "Видит вопросы, которые задают агенты" },
  sdk_agents: { icon: "Bot", label: "Запускает и останавливает агентов" },
  sdk_send: { icon: "Sent", label: "Пишет в ваши переписки от вашего имени" },
  sdk_answer: { icon: "Bot", label: "Отвечает на вопросы агентов за вас" },
  sdk_settings: { icon: "Settings", label: "Меняет настройки bb" },
  ui: { icon: "Palette", label: "Меняет внешний вид bb" },
  ui_click: { icon: "AppWindow", label: "Нажимает элементы интерфейса bb" },
  http_routes: { icon: "Link", label: "Открывает свои адреса на сервере bb" },
  contribute_env: { icon: "Layers", label: "Меняет окружение запускаемых программ" },
  host_artifact: { icon: "PackageReceive", label: "Кладёт свои файлы на компьютер" },
  database: { icon: "Layers", label: "Хранит свои данные в bb" },
};

const SECRETISH = /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH/i;

/** Reading the environment as a whole, or a variable that looks like a secret. */
const secretEnv = (c: CapLike): boolean => c.kind === "env" && (c.detail.length === 0 || c.detail.some((d) => d === "*" || d === "env:*" || SECRETISH.test(d.replace(/^env:/, ""))));

const trimJoin = (s: string): string => s.replace(/^[;\s—-]+/, "").replace(/^и /, "").trim();

/** The muted part of a row: what the checks found out about where it goes, or the names the code gives. */
function detailOf(c: CapLike): string | null {
  const flow = c.flow ? flowClause(c.flow, false) : null;
  const flowText = flow ? trimJoin(flow.text) : "";
  const why = c.purpose && c.purpose.length > 0 ? c.purpose.join("; ") : "";
  const tail = [flowText, why].filter(Boolean).join(" — ");
  switch (c.kind) {
    case "network": {
      const hosts = hostsOf([c]);
      const hidden = c.detail.includes(UNRESOLVED_HOST_TOKEN);
      if (hosts.length === 0) return "адреса не видны в коде";
      return `${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ", …" : ""}${hidden ? " и другие, не видные в коде" : ""}`;
    }
    case "child_process": {
      const names = [...new Set((c.programs ?? []).map(programName))];
      const list = names.length === 0 ? "какие — из кода не видно" : `${names.slice(0, 2).join(", ")}${names.length > 2 ? ", …" : ""}${c.programsUnknown ? " и другие" : ""}`;
      return [list, tail].filter(Boolean).join(" · ");
    }
    case "fs":
      return c.paths && c.paths.length > 0 ? `в коде названы: ${c.paths.slice(0, 2).join(", ")}${c.paths.length > 2 ? ", …" : ""}` : "какие именно — из кода не видно";
    case "credentials":
      return [c.detail.slice(0, 3).join(", "), tail].filter(Boolean).join(" · ") || null;
    case "env": {
      const names = [...new Set(c.detail.map((d) => d.replace(/^env:/, "")))].filter((n) => n !== "");
      const all = names.length === 0 || names.includes("*");
      const list = all ? "все переменные (там бывают пароли и токены)" : names.slice(0, 4).join(", ") + (names.length > 4 ? `, и ещё ${names.length - 4}` : "");
      return [list, tail].filter(Boolean).join(" · ");
    }
    case "ui_click":
      return uiClickLine(c).text;
    default:
      return tail || null;
  }
}

/** One right as a row. Danger is judged on the right alone, by the same headline the card uses. */
export function permissionRow(c: CapLike, downgrade: boolean): PermissionRow {
  const short = SHORT[c.kind];
  const danger = riskHeadline([c], [], { downgrade }).level === "danger";
  return {
    kind: c.kind,
    icon: short?.icon ?? "AlertCircle",
    label: secretEnv(c) ? "Может читать ваши пароли и токены" : (short?.label ?? capabilityPhrase(c)),
    detail: detailOf(c),
    danger,
  };
}

export interface PermissionList {
  rows: PermissionRow[];
  visible: PermissionRow[];
  /** «ещё N»: never holds a right of the level «Опасно». */
  more: PermissionRow[];
  /** One muted line under the list: the network is there but not tied to what is read. */
  networkNote: string | null;
}

export const NETWORK_UNRELATED_NOTE = "Сеть в плагине есть, с прочитанным по коду не связана.";

const READS = new Set(["sdk_read", "sdk_questions", "env", "credentials"]);

/**
 * Where a right stands in the list. First what a plugin can get at that is worth something to a person (conversations, secrets, files at home, the questions of
 * agents); then what it does (presses, starts, goes to the network); last the looks. Inside a group the dangerous come first, then the order of the checks.
 */
function tierOf(c: CapLike): 0 | 1 | 2 {
  switch (c.kind) {
    case "sdk_read":
    case "credentials":
    case "sdk_questions":
      return 0;
    case "env":
      return secretEnv(c) ? 0 : 1;
    case "fs":
      return c.detail.includes("home") ? 0 : 1;
    case "ui":
    case "database":
      return 2;
    default:
      return 1;
  }
}

/** The rights as rows, in the order above; no more than five are visible, but a dangerous one is never put under «ещё N». */
export function permissionList(caps: CapLike[], downgrade: boolean): PermissionList {
  const rows = caps.filter((c) => c.kind !== "database" || caps.length === 1).map((c) => ({ c, row: permissionRow(c, downgrade) }));
  const sorted = rows
    .map((x, i) => ({ ...x, i }))
    .sort((a, b) => tierOf(a.c) - tierOf(b.c) || Number(b.row.danger) - Number(a.row.danger) || a.i - b.i)
    .map((x) => x.row);
  const visible = sorted.filter((r, i) => i < VISIBLE_ROWS || r.danger);
  const more = sorted.filter((r) => !visible.includes(r));
  const hasNet = caps.some((c) => c.kind === "network");
  const followed = caps.filter((c) => READS.has(c.kind) && c.flow !== undefined);
  const unrelated = hasNet && followed.length > 0 && followed.every((c) => c.flow!.verdict !== "unknown" && c.flow!.verdict !== "leaves");
  return { rows: sorted, visible, more, networkNote: unrelated ? NETWORK_UNRELATED_NOTE : null };
}

/** The one line of «why»: the author's words if there are any (marked as unchecked by the page), else what the checks found the plugin does it for, else the reason it waits. */
export function whyLine(i: { authorWhy: string | null | undefined; caps: CapLike[]; reasonLine: string }): { text: string; byAuthor: boolean } {
  if (i.authorWhy) return { text: i.authorWhy, byAuthor: true };
  const purposes = [...new Set(i.caps.flatMap((c) => c.purpose ?? []))];
  if (purposes.length > 0) return { text: `${purposes.slice(0, 2).join("; ")}.`.replace(/^./, (ch) => ch.toUpperCase()), byAuthor: false };
  // The reason: the first sentence of the card's text (what is it that waits), without «Он сможет …» and the tail.
  const first = i.reasonLine.split(/(?<=[.!?])\s+/)[0] ?? i.reasonLine;
  return { text: first, byAuthor: false };
}

// ---- the extended queue card («Журнал»): what it shows, as data -----------------------------------------------------------------
/** The facts the extended card is drawn from. `blocked` is the page's verdict on the entry (`isBlockedEntry`, which asks the guard's rule). */
export interface QueueFacts {
  held: boolean;
  blocked: boolean;
  /** The directory can be changed by someone other than the server's user: no code approves it; fix the directory, then it is looked at again. */
  unsafeDir: boolean;
}

export const UNSAFE_DIR_PREFIX = "каталог доступен на запись другим";

export function queueFacts(q: { status: string; reason: string | null }, blocked: boolean): QueueFacts {
  return { held: q.status === "held", blocked, unsafeDir: q.reason?.startsWith(UNSAFE_DIR_PREFIX) ?? false };
}

/** The word at the top right of the card. */
export function queueStatusWord(status: string, blocked: boolean): string {
  if (status === "held") return blocked ? "заблокировано" : "держится";
  if (status === "approved") return "одобрено";
  return status === "stale" ? "устарело" : "отклонено";
}

/** Where the version came from, in one line, with what is special about the entry. */
export function queueSourceLine(q: { sourceKind: string; source: string; threadId: string | null; kind: string; contentHash: string | null }): string {
  const parts = [`${q.sourceKind}: ${q.source}`];
  if (q.threadId) parts.push(`из чата ${q.threadId}`);
  if (q.kind === "afterfact") parts.push("выключен после загрузки (его код уже выполнялся)");
  if (q.kind === "proposal" && !q.contentHash) parts.push("предложен агентом, окно было закрыто");
  return parts.join(" · ");
}

/** The one-line summary of the proposal's id: a local proposal has a negative id inside; the person reads "предложение 4", not "#-4". */
export const queueLabel = (id: number): string => (id < 0 ? `предложение ${-id}` : `#${id}`);

// ---- the card of a waiting version: what it shows, as data -----------------------------------------------------------------------
export interface ReviewView {
  red: boolean;
  level: CardLevel;
  risk: Risk;
  /** A version the guard has no record of (it loaded without the guard's check): nothing here can approve it, and a green «можно включить» would be a lie. */
  noRecord: boolean;
  mismatch: boolean;
  unsafeDir: boolean;
  /** The title and the sentence of the red / mismatch / yellow text. */
  text: RedText | { title: string; line: string };
  caps: CapLike[];
  rights: PermissionList;
  why: { text: string; byAuthor: boolean };
  configNote: string | null;
  /** «Разрешить chime 0.1.0». */
  approveWhat: string;
  /** What the line that takes the card's place says (after «Готово: »). */
  allowedWhat: string;
  win: WindowAvail;
  trust: TrustButton;
  /** «Разрешить» is offered: the card is neither red nor without a record at the guard. */
  canApprove: boolean;
}

export interface ReviewInput {
  q: QueueRow;
  found: CheckResult | undefined;
  ux: QueueUx | undefined;
  flowDowngrade: boolean;
}

/** The words of the card for a version that is held: red (a hard flag, or files that did not match), or yellow (a new right, an unknown source). */
function reviewText(i: ReviewInput, red: boolean, caps: CapLike[]): ReviewView["text"] {
  const { q, found, ux } = i;
  if (isMismatchEntry(q)) return mismatchText(q.pluginId, q.version);
  if (!red) return yellowText({ pluginId: q.pluginId, version: q.version, level: ux?.level ?? "unknown", sourceLabel: ux?.sourceLabel ?? q.source, reason: q.reason, reasonKind: q.reasonKind, caps });
  // Red because the guard did not read the version, with no hard flag found by anyone: told as «not read» (the lifting is the same, the words are true).
  if (isUnreadOnly({ reason: q.reason, reasonKind: q.reasonKind, blocks: q.blocks, findings: found?.findings ?? [] })) return unreadText(q.pluginId, q.version, q.reason);
  const r = redText((found?.findings ?? []).filter((f) => f.severity === "block").map((f) => f.rule));
  const where = redWhere(caps);
  return { title: `Остановлено: ${r.title}`, line: `Плагин «${q.pluginId}» ${q.version}. ${r.line}${where ? ` ${where}` : ""} Плагин не запущен.` };
}

export function reviewView(i: ReviewInput): ReviewView {
  const { q, found, ux } = i;
  const caps = capsWithPaths(found);
  const red = cardColor({ reason: q.reason, reasonKind: q.reasonKind, blocks: q.blocks, findings: found?.findings ?? [] }) === "red";
  const noRecord = hasNoGuardRecord(q);
  const risk: Risk = noRecord ? { level: "caution", text: NO_RECORD_HEADLINE } : cardRisk(q, found, i.flowDowngrade);
  const text = reviewText(i, red, caps);
  const level = ux?.level ?? "unknown";
  return {
    red,
    level: cardLevel({ red, risk }),
    risk,
    noRecord,
    mismatch: isMismatchEntry(q),
    unsafeDir: q.reason?.startsWith(UNSAFE_DIR_PREFIX) ?? false,
    text,
    caps,
    rights: permissionList(red ? caps : meaningfulCaps(caps), i.flowDowngrade),
    why: whyLine({ authorWhy: ux?.why, caps, reasonLine: noRecord ? NO_RECORD_LINE : text.line }),
    configNote: agentConfigNote(found?.findings ?? []),
    approveWhat: actionLabel(approveVerb(risk), q.pluginId, q.version),
    allowedWhat: `${q.pluginId} ${q.version} разрешён и включён`,
    win: windowAvailability({ threadId: q.threadId, queueId: q.id, sourceKind: q.sourceKind, level }),
    trust: trustButton({ entry: ux?.entry ?? null, level, queueId: q.id }),
    canApprove: !(red || noRecord),
  };
}

// ---- the row of a third-party plugin («Журнал») ----------------------------------------------------------------------------------
/** What the row says of the approved version: pinned (or frozen with a window), who confirmed it and how, or that it was never looked at. */
export function pluginPinText(p: { pin: { version: string } | null; frozenPin: boolean; unreviewedBaseline: boolean }, approvedBy: string | null): string {
  if (p.pin) return `${p.frozenPin ? "закреплена при заморозке" : "пин"}: ${p.pin.version} (${approvedBy})`;
  return p.unreviewedBaseline ? "стоял до secure-bb, не проверялся" : "не одобрен";
}

/** The scan of the pinned version says whether it is the pinned one. */
export const scanCurrentWord = (scan: { current: boolean } | undefined): string | undefined => (scan ? (scan.current ? "это закреплённая версия" : "не закреплённая версия") : undefined);

// ---- the row of a skill («Журнал») -----------------------------------------------------------------------------------------------
/** The findings worth a line (information is not), at most twelve. */
export const skillFindingsShown = <F extends { severity: string }>(findings: F[]): F[] => findings.filter((f) => f.severity !== "info").slice(0, 12);

/** What the scripts of a skill can do, in one line; null when nothing. */
export function skillCapsLine(caps: Array<{ kind: string; detail: string[] }>): string | null {
  if (caps.length === 0) return null;
  return `Возможности скриптов: ${caps.map((c) => `${c.kind}${c.detail.length ? ` (${c.detail.slice(0, 3).join(", ")})` : ""}`).join("; ")}`;
}

// ---- the result of the AI scan next to a version ---------------------------------------------------------------------------------
interface ScanLike {
  status: string;
  startedAt: number;
  finishedAt: number | null;
  note?: string | null;
  models: Array<{ status: string; label: string }>;
}

/** The head of the scan's line: running, clean (when, by which models), a suspicion, or unavailable with the reason. `when` writes a time. */
export function scanHeadText(scan: ScanLike, when: (ms: number) => string): string {
  const at = when(scan.finishedAt ?? scan.startedAt);
  if (scan.status === "running") return "идёт…";
  if (scan.status === "clean") return `чисто (${at}, ${scan.models.filter((m) => m.status !== "unavailable").map((m) => m.label).join(", ")})`;
  if (scan.status === "suspect") return `ПОДОЗРЕНИЕ (${at})`;
  return `недоступен${scan.note ? `: ${scan.note}` : ""}`;
}
