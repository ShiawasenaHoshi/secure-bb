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
  env: { icon: "KeyRound", label: "Читает переменные окружения" },
  credentials: { icon: "KeyRound", label: "Читает учётные данные других программ" },
  fs: { icon: "Folder", label: "Работает с файлами" },
  child_process: { icon: "Terminal", label: "Запускает программы на компьютере" },
  dynamic_code: { icon: "Code", label: "Выполняет код, собранный на лету" },
  server_access: { icon: "ServerCog", label: "Управляет самим bb" },
  builtin_rpc: { icon: "ServerCog", label: "Управляет самим bb" },
  sdk_read: { icon: "MessageSquare", label: "Читает ваши переписки в bb" },
  sdk_meta: { icon: "MessagesSquare", label: "Знает названия и состояние тредов" },
  sdk_questions: { icon: "CircleHelp", label: "Видит вопросы, которые задают агенты" },
  sdk_agents: { icon: "Bot", label: "Запускает и останавливает агентов" },
  sdk_send: { icon: "Send", label: "Пишет в ваши переписки от вашего имени" },
  sdk_answer: { icon: "Bot", label: "Отвечает на вопросы агентов за вас" },
  sdk_settings: { icon: "Settings", label: "Меняет настройки bb" },
  ui: { icon: "Palette", label: "Меняет внешний вид bb" },
  ui_click: { icon: "MousePointerClick", label: "Нажимает элементы интерфейса bb" },
  http_routes: { icon: "Link", label: "Открывает свои адреса на сервере bb" },
  contribute_env: { icon: "Variable", label: "Меняет окружение запускаемых программ" },
  host_artifact: { icon: "FileDown", label: "Кладёт свои файлы на компьютер" },
  database: { icon: "Database", label: "Хранит свои данные в bb" },
};

const SECRETISH = /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH/i;

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
  const secretEnv = c.kind === "env" && (c.detail.length === 0 || c.detail.some((d) => d === "*" || d === "env:*" || SECRETISH.test(d.replace(/^env:/, ""))));
  const danger = riskHeadline([c], [], { downgrade }).level === "danger";
  return {
    kind: c.kind,
    icon: short?.icon ?? "ShieldQuestion",
    label: secretEnv ? "Может читать ваши пароли и токены" : (short?.label ?? capabilityPhrase(c)),
    detail: detailOf(c),
    danger,
  };
}

export interface PermissionList {
  rows: PermissionRow[];
  visible: PermissionRow[];
  /** «ещё N» */
  more: PermissionRow[];
  /** One muted line under the list: the network is there but not tied to what is read. */
  networkNote: string | null;
}

export const NETWORK_UNRELATED_NOTE = "Сеть в плагине есть, с прочитанным по коду не связана.";

const READS = new Set(["sdk_read", "sdk_questions", "env", "credentials"]);

/** The rights as rows, dangerous first; no more than five are visible. */
export function permissionList(caps: CapLike[], downgrade: boolean): PermissionList {
  const rows = caps.filter((c) => c.kind !== "database" || caps.length === 1).map((c) => permissionRow(c, downgrade));
  // A stable sort: dangerous first, the order of the checks kept inside each group.
  const sorted = rows.map((r, i) => ({ r, i })).sort((a, b) => Number(b.r.danger) - Number(a.r.danger) || a.i - b.i).map((x) => x.r);
  const hasNet = caps.some((c) => c.kind === "network");
  const followed = caps.filter((c) => READS.has(c.kind) && c.flow !== undefined);
  const unrelated = hasNet && followed.length > 0 && followed.every((c) => c.flow!.verdict !== "unknown" && c.flow!.verdict !== "leaves");
  return { rows: sorted, visible: sorted.slice(0, VISIBLE_ROWS), more: sorted.slice(VISIBLE_ROWS), networkNote: unrelated ? NETWORK_UNRELATED_NOTE : null };
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
