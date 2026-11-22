// What the card of a waiting version shows, as data (the page only draws it): the level, the one line of «why», the rights as rows. No new judgement
// here: the words and the verdicts come from ux.ts (riskHeadline, capabilityPhrase, flowClause, …); this file only arranges them.
import { capabilityPhrase, flowClause, hostsOf, programName, riskHeadline, uiClickLine, type CapLike, type Risk } from "./ux";

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
