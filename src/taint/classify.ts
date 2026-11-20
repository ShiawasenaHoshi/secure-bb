// Which thread events mean "this thread read something it should not trust" (spec §0, §6)?
//
// Input is a thread event row from bb's events API (`threads.events.list`): items the agent
// started or finished. Only what those items show can be seen; see `NOT_OBSERVED` for what cannot.

export type TaintKind = "web" | "repo" | "mcp" | "skill" | "env-setup";

export const TAINT_LABEL: Record<TaintKind, string> = {
  web: "веб (WebFetch/WebSearch, curl/wget)",
  repo: "чужой репозиторий (git clone/fetch, gh)",
  mcp: "инструмент MCP",
  skill: "установка скилла",
  "env-setup": "проект с .bb-env-setup.sh",
};

export interface EventLike {
  seq: number;
  createdAt: number;
  type: string;
  data: unknown;
}
export interface Hit {
  kind: TaintKind;
  /** What kind of thing, never what was read: a tool name, a host, a verb. */
  note: string;
}

/** Event types that carry an agent's tool use. */
export const TAINT_EVENT_TYPES = ["item/started", "item/completed"] as const;

/** What the events API cannot tell us. Shown on the page and printed by `bb secure-bb taint`. */
export const NOT_OBSERVED: readonly string[] = [
  "почта и любое чтение, которое провайдер не показывает как веб-/MCP-инструмент или команду (например, внутренние инструменты провайдера без события)",
  "содержимое прочитанного: событие говорит «был WebFetch», но не то, что вернул сайт, и не то, что агент из этого извлёк",
  "`git fetch`/`git pull` без адреса в команде (из уже настроенного remote) и `git submodule update`: непонятно, чей это репозиторий",
  "установка пакетов (npm/pip/brew): чужой код, но не «прочитанное содержимое» в смысле спецификации; закрывают это проверки плагинов, а не загрязнение",
  "скилл, подложенный в каталог скиллов способом, который не виден в команде или в списке изменённых файлов события",
  "действия вне тредов bb (человек в обычном терминале) и треды, события которых API не отдаёт (удалены)",
  "файлы, скачанные раньше, чем началась история треда, или другим процессом",
];

const URL_RE = /\b(?:https?|ssh|git|ftp):\/\/\S+|\bgit@[\w.-]+:\S+/i;
const GIT_REMOTE_VERBS = /\bgit\b(?:\s+-[-\w]+(?:[= ]\S+)?)*\s+(clone|fetch|pull|ls-remote|submodule\s+add|remote\s+add|remote\s+set-url)\b/i;
const GH_REPO = /\bgh\s+(?:repo\s+(?:clone|fork)|pr\s+checkout|pr\s+diff|issue\s+view|release\s+download)\b/i;
const SHELL_WEB = /\b(curl|wget|http|https|xh|aria2c)\b(?=[^|;&]*\b(?:https?:\/\/|ftp:\/\/))/i;
const SKILL_INSTALL = /\bbb\s+skills?\s+install\b|\bnpx\s+(?:-y\s+)?skills(?:@\S+)?\s+add\b|\bskills\.sh\b/i;
const SKILL_DIR = /(?:^|[\s/"'=])\.(?:claude|agents|bb)\/skills\b/;
const WRITE_VERB = /\b(cp|mv|ln|tee|rsync|unzip|tar|curl|wget|install|mkdir)\b|>>?|\bgit\s+clone\b/;

const record = (v: unknown): Record<string, unknown> | null => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);
const str = (v: unknown): string => (typeof v === "string" ? v : "");

function hostOf(url: string): string {
  try {
    return new URL(url).host.slice(0, 80);
  } catch {
    return "?";
  }
}

/** Classifies the item inside one event. Null: nothing untrusted was read. */
export function classifyItem(item: Record<string, unknown>): Hit | null {
  switch (item.type) {
    case "webFetch":
      return { kind: "web", note: `WebFetch ${hostOf(str(item.url))}` };
    case "webSearch":
      return { kind: "web", note: "WebSearch" };
    case "toolCall": {
      const tool = str(item.tool);
      const server = str(item.server);
      if (/^(WebFetch|WebSearch)$/i.test(tool)) return { kind: "web", note: tool };
      if (server !== "" || /^mcp__/i.test(tool)) return { kind: "mcp", note: `MCP ${server !== "" ? server : tool.split("__")[1] ?? "?"}`.slice(0, 80) };
      return null;
    }
    case "fileChange": {
      const changes = Array.isArray(item.changes) ? item.changes : [];
      for (const c of changes) {
        const p = str(record(c)?.path);
        if (SKILL_DIR.test(` ${p}`) || /\/skills\/[^/]+\/SKILL\.md$/.test(p)) return { kind: "skill", note: "файл в каталоге скиллов" };
      }
      return null;
    }
    case "commandExecution": {
      const cmd = str(item.command);
      if (cmd === "") return null;
      if (SKILL_INSTALL.test(cmd)) return { kind: "skill", note: "установка скилла" };
      if (SKILL_DIR.test(cmd) && WRITE_VERB.test(cmd)) return { kind: "skill", note: "запись в каталог скиллов" };
      if (GH_REPO.test(cmd)) return { kind: "repo", note: "gh" };
      const git = GIT_REMOTE_VERBS.exec(cmd);
      if (git && URL_RE.test(cmd)) return { kind: "repo", note: `git ${git[1]!.toLowerCase()}` };
      if (SHELL_WEB.test(cmd)) return { kind: "web", note: "загрузка из shell" };
      return null;
    }
    default:
      return null;
  }
}

export function classifyEvent(ev: EventLike): Hit | null {
  if (ev.type !== "item/started" && ev.type !== "item/completed") return null;
  const item = record(record(ev.data)?.item);
  return item ? classifyItem(item) : null;
}
