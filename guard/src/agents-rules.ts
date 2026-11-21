// Agent watch, the meaning of a change: its class, decided by code (never by a model), the checks of instruction text, and the diff.
//
// Classes (design doc, "Как", item 3):
//  - critical: the agent would run with weaker permissions or a foreign tool/endpoint — a settings file that now says
//    bypassPermissions/acceptEdits, a dangerous new `permissions.allow` entry, hooks, MCP servers, `env` with *_BASE_URL / *_PROXY /
//    NODE_OPTIONS, `apiKeyHelper`, the sandbox switched off; also code the agent runs by itself (hook scripts, opencode plugins);
//  - instructions: CLAUDE.md, AGENTS.md, rules, agents, commands — a diff and the text checks (the same module that checks skills and plugin text);
//  - other: any other change, and a file that disappeared.
// A reason is reported only for what the change brings in: what the accepted baseline already had is not a new reason.
import { instructionFindings, type Finding } from "./text-rules.ts";
import type { FileKind } from "./agents-scan.ts";

export type DriftClass = "critical" | "instructions" | "other";
export type Change = "added" | "changed" | "removed";

export interface Analysis {
  cls: DriftClass;
  /** Why it is critical (or notable): one short sentence each, in Russian like the page. */
  reasons: string[];
  /** Instruction text checks (instructions class only), only what is new relative to the baseline. */
  findings: Finding[];
}

type Json = unknown;
const isObj = (v: Json): v is Record<string, Json> => typeof v === "object" && v !== null && !Array.isArray(v);
const same = (a: Json, b: Json): boolean => JSON.stringify(a) === JSON.stringify(b);

/** Parses JSON, also with comments and trailing commas (opencode.jsonc). Null: not parseable. */
export function parseJsonLoose(text: string): Json | null {
  const tryParse = (t: string): Json | null => {
    try {
      return JSON.parse(t) as Json;
    } catch {
      return null;
    }
  };
  const plain = tryParse(text);
  if (plain !== null) return plain;
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inStr) {
      out += c;
      if (c === "\\") out += text[++i] ?? "";
      else if (c === '"') inStr = false;
    } else if (c === '"') {
      inStr = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") while (i < text.length && text[i] !== "\n") i++;
    else if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
    } else out += c;
  }
  return tryParse(out.replace(/,(\s*[}\]])/g, "$1"));
}

// ---- Claude Code permissions -------------------------------------------------------------------------------------------
const NET_WORDS = /\b(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|telnet|nslookup|dig)\b|https?:\/\//i;
/** Is a permissions.allow entry one that gives away the shell, the network or paths outside the working directory? */
export function dangerousAllow(entry: string): string | null {
  const e = entry.trim();
  if (/^Bash(?:\(\s*(?:\*|:\*|\*:\*)?\s*\))?$/.test(e)) return "Bash без ограничений";
  if (/^(?:WebFetch|WebSearch)\b/.test(e)) return "сеть";
  const m = /^(\w+)\((.*)\)$/s.exec(e);
  if (m) {
    const tool = m[1]!;
    const arg = m[2]!.trim();
    if (tool === "Bash" && NET_WORDS.test(arg)) return "сеть в команде";
    if (/^(?:Read|Edit|Write|MultiEdit|NotebookEdit|Glob|Grep)$/.test(tool) && (/^(?:\/|~|[A-Za-z]:[\\/]|\\\\)/.test(arg) || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(arg))) return "путь вне рабочего каталога";
  }
  return null;
}

function strArray(v: Json): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function mcpEntries(obj: Record<string, Json>): Map<string, Json> {
  const out = new Map<string, Json>();
  for (const key of ["mcpServers", "mcp", "mcp_servers"] as const) {
    const sec = obj[key];
    if (isObj(sec)) for (const [name, cfg] of Object.entries(sec)) out.set(`${key}.${name}`, cfg);
  }
  // ~/.claude.json: per project
  if (isObj(obj.projects)) for (const [dir, p] of Object.entries(obj.projects)) if (isObj(p) && isObj(p.mcpServers)) for (const [name, cfg] of Object.entries(p.mcpServers)) out.set(`projects.${dir}.mcpServers.${name}`, cfg);
  return out;
}

// ---- the concrete content of a change (what the red text says: the command, not "commands") ----------------------------------------------
const clip = (t: string, n = 120): string => (t.length > n ? `${t.slice(0, n)}…` : t);
/** Hook commands (and urls/prompts of the other hook kinds) with their event: `Event: command`. Secrets in them are masked like in a diff. */
export function hookCommands(hooks: Json): string[] {
  const out: string[] = [];
  const walk = (v: Json, event: string): void => {
    if (Array.isArray(v)) return void v.forEach((x) => walk(x, event));
    if (!isObj(v)) return;
    for (const k of ["command", "url", "prompt"] as const) if (typeof v[k] === "string") out.push(`${event}: ${clip(maskSecrets(v[k] as string))}`);
    for (const [k, x] of Object.entries(v)) if (k !== "command" && k !== "url" && k !== "prompt") walk(x, event);
  };
  if (isObj(hooks)) for (const [event, v] of Object.entries(hooks)) walk(v, event);
  else walk(hooks, "hooks");
  return [...new Set(out)];
}
/** How an MCP server starts: the command with its arguments, or its address. */
function mcpLaunch(cfg: Json): string {
  if (!isObj(cfg)) return "не разобрано";
  const parts = typeof cfg.command === "string" ? [cfg.command, ...strArray(cfg.args)] : Array.isArray(cfg.command) ? strArray(cfg.command) : [];
  if (parts.length > 0) return clip(maskSecrets(parts.join(" ")));
  if (typeof cfg.url === "string") return clip(maskSecrets(cfg.url));
  return "не указано";
}
/** Does an `allow` entry that was already there cover this (narrower) one? `Bash` / `Bash(*)` covers every `Bash(...)`; a tool without arguments covers all of its. */
function allowCovers(wide: string, narrow: string): boolean {
  const w = wide.trim();
  const n = narrow.trim();
  if (w === n) return true;
  const tool = /^(\w+)/.exec(n)?.[1];
  if (!tool) return false;
  return w === tool || new RegExp(`^${tool}\\(\\s*(?:\\*|:\\*|\\*:\\*)?\\s*\\)$`).test(w);
}
/** Reasons that only say something got narrower or went away: not a reason to ask for a code (but the card tells it, so the red text never contradicts the diff). */
export const isTightening = (reason: string): boolean => /^permissions\.allow: (?:сужено|убрано)/.test(reason);

/** Top-level settings keys that make the agent run a command, load plugins/marketplaces/MCP, change its login, or widen what it may do. */
export const RISKY_KEYS: ReadonlyArray<readonly [string, string]> = [
  ["statusLine", "команда, которую агент запускает для строки состояния"],
  ["fileSuggestion", "команда, которую агент запускает для подсказок файлов"],
  ["otelHeadersHelper", "команда, которую агент запускает для заголовков телеметрии"],
  ["awsAuthRefresh", "команда входа в AWS, которую агент запускает сам"],
  ["awsCredentialExport", "команда, выдающая ключи AWS"],
  ["gcpAuthRefresh", "команда входа в Google Cloud, которую агент запускает сам"],
  ["policyHelper", "программа, которая выдаёт агенту политику"],
  ["processWrapper", "программа, через которую агент запускает процессы"],
  ["sshHostCommands", "команды для SSH-хостов"],
  ["enabledPlugins", "подключены плагины агента"],
  ["extraKnownMarketplaces", "добавлен каталог плагинов агента"],
  ["pluginConfigs", "настройки плагинов агента"],
  ["allowedMcpServers", "разрешены MCP-серверы"],
  ["enableAllProjectMcpServers", "все MCP-серверы проекта включаются без вопросов"],
  ["enabledMcpjsonServers", "включены MCP-серверы проекта"],
  ["forceLoginMethod", "изменён способ входа агента"],
  ["forceLoginOrgUUID", "изменена организация, под которой входит агент"],
  ["forceLoginGatewayUrl", "изменён шлюз входа агента"],
  ["skipDangerousModePermissionPrompt", "агент не переспрашивает про опасный режим"],
  ["modelOverrides", "подменены модели агента"],
];
const BAD_ENV = /(?:_BASE_URL|_PROXY)$|^NODE_OPTIONS$/i;

/** Critical reasons of a JSON config that is new or changed, relative to the previous (accepted) one. */
export function jsonReasons(kind: FileKind, next: Record<string, Json>, prev: Record<string, Json> | null): string[] {
  const out: string[] = [];
  const old = prev ?? {};

  // hooks
  if (next.hooks !== undefined && !same(next.hooks, old.hooks) && !(isObj(next.hooks) && Object.keys(next.hooks).length === 0)) {
    const had = new Set(hookCommands(old.hooks));
    const fresh = hookCommands(next.hooks).filter((c) => !had.has(c));
    out.push(fresh.length > 0 ? `hooks: новые или изменённые — ${fresh.join(" ¦ ")}` : "hooks: новые или изменённые (команды, которые агент запускает сам)");
  }
  // MCP servers
  const mcpNew = mcpEntries(next);
  const mcpOld = mcpEntries(old);
  const shortName = (n: string): string => n.replace(/^(?:mcpServers|mcp|mcp_servers)\./, "");
  const gone = [...mcpOld.keys()].filter((n) => !mcpNew.has(n));
  const added = [...mcpNew.keys()].filter((n) => !mcpOld.has(n));
  for (const [name, cfg] of mcpNew) {
    if (mcpOld.has(name) && same(mcpOld.get(name), cfg)) continue;
    if (mcpOld.has(name)) out.push(`MCP-сервер ${shortName(name)}: изменён — было: ${mcpLaunch(mcpOld.get(name))} ¦ стало: ${mcpLaunch(cfg)}`);
    else {
      // One server out and one in at once: say it is a replacement, with what the old one ran (the person may not remember accepting it).
      const repl = gone.length === 1 && added.length === 1 ? ` ¦ вместо «${shortName(gone[0]!)}»: ${mcpLaunch(mcpOld.get(gone[0]!))}` : "";
      out.push(`MCP-сервер ${shortName(name)}: новый — запуск: ${mcpLaunch(cfg)}${repl}`);
    }
  }
  // env
  if (isObj(next.env)) {
    const oldEnv = isObj(old.env) ? old.env : {};
    for (const [k, v] of Object.entries(next.env)) if (BAD_ENV.test(k) && !same(oldEnv[k], v)) out.push(`env ${k}: ${oldEnv[k] === undefined ? "задан" : "изменён"}`);
  }
  // Keys through which the agent runs a command, loads somebody else's code or tools, changes who it signs in as, or gets more of the machine
  // (Claude Code's settings reference: code.claude.com/docs/en/settings-reference, read up to its first 100 000 characters). Any change to one is critical.
  for (const [k, what] of RISKY_KEYS) if (next[k] !== undefined && !same(next[k], old[k])) out.push(`${k}: ${what}`);
  if (isObj(next.sandbox)) {
    const oldSb = isObj(old.sandbox) ? old.sandbox : {};
    for (const [k, v] of Object.entries(next.sandbox)) if (k !== "enabled" && !same(v, oldSb[k])) out.push(`sandbox.${k}: меняет границы песочницы`);
  }
  // other ways to run code or redirect the agent
  if (next.apiKeyHelper !== undefined && !same(next.apiKeyHelper, old.apiKeyHelper)) out.push("apiKeyHelper: команда выдаёт ключ API");
  if (isObj(next.sandbox) && next.sandbox.enabled === false && !(isObj(old.sandbox) && old.sandbox.enabled === false)) out.push("песочница отключена (sandbox.enabled: false)");
  if (next.dangerouslyDisableSandbox === true && old.dangerouslyDisableSandbox !== true) out.push("песочница отключена (dangerouslyDisableSandbox)");
  if (kind === "json-config") {
    // opencode and similar: a provider's base URL redirects the agent's traffic
    const walk = (v: Json, path: string, oldV: Json): void => {
      if (!isObj(v)) return;
      for (const [k, x] of Object.entries(v)) {
        const o = isObj(oldV) ? oldV[k] : undefined;
        if (/^(?:base_?url|api_?base|endpoint)$/i.test(k) && typeof x === "string" && !same(x, o)) out.push(`${path}${k}: адрес сервера модели ${o === undefined ? "задан" : "изменён"}`);
        else walk(x, `${path}${k}.`, o);
      }
    };
    walk(next, "", old);
    if (isObj(next.permission) || typeof next.permission === "string") {
      const flat = JSON.stringify(next.permission);
      if (flat !== JSON.stringify(old.permission) && /"allow"/.test(flat)) out.push("permission: правила allow изменены");
    }
  }
  // permissions
  if (isObj(next.permissions)) {
    const oldP = isObj(old.permissions) ? old.permissions : {};
    const mode = next.permissions.defaultMode;
    if ((mode === "bypassPermissions" || mode === "acceptEdits") && mode !== oldP.defaultMode) out.push(`permissions.defaultMode: ${mode}`);
    const oldAllow = strArray(oldP.allow);
    const had = new Set(oldAllow);
    const nextAllow = strArray(next.permissions.allow);
    const removed = oldAllow.filter((a) => !nextAllow.includes(a));
    const q = (a: string): string => `«${clip(a, 80)}»`;
    const added = nextAllow.filter((a) => !had.has(a));
    // What an added entry brings that nothing before it covered; what is covered by what was there (and by what was removed) is a narrowing, not a new right.
    const brandNew = added.filter((a) => !oldAllow.some((o) => allowCovers(o, a)));
    for (const a of brandNew) {
      const why = dangerousAllow(a);
      if (why) out.push(`permissions.allow «${clip(a, 80)}»: ${why}`);
    }
    const narrowed = added.filter((a) => !brandNew.includes(a));
    if (narrowed.length > 0 && removed.length > 0) out.push(`permissions.allow: сужено — было ${removed.map(q).join(", ")}, стало ${narrowed.map(q).join(", ")}`);
    else if (removed.length > 0 && added.length === 0) out.push(`permissions.allow: убрано ${removed.map(q).join(", ")}`);
    const hadDirs = new Set(strArray(oldP.additionalDirectories));
    for (const d of strArray(next.permissions.additionalDirectories)) if (!hadDirs.has(d)) out.push(`permissions.additionalDirectories: ${d} (путь вне рабочего каталога)`);
  }
  return [...new Set(out)];
}

// ---- Codex config.toml ----------------------------------------------------------------------------------------------------
const TOML_RULES: Array<[RegExp, string]> = [
  [/^\[(?:mcp_servers|mcp-servers)(?:[.\]])/i, "MCP-сервер"],
  [/^\[(?:model_providers|hooks)(?:[.\]])/i, "провайдер модели или hooks"],
  [/^(?:notify|hooks)\s*=/i, "команда, которую агент запускает сам (notify/hooks)"],
  [/^approval_policy\s*=\s*["']never["']/i, 'approval_policy = "never"'],
  [/^sandbox_mode\s*=\s*["']danger-full-access["']/i, 'sandbox_mode = "danger-full-access"'],
  [/^network_access\s*=\s*true/i, "network_access = true"],
  [/^[A-Za-z0-9_]*(?:base_url|_BASE_URL|_PROXY|NODE_OPTIONS)\s*=/i, "адрес сервера модели, прокси или NODE_OPTIONS"],
];
const tomlLines = (text: string): string[] => text.split("\n").map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"));

export function tomlReasons(next: string, prev: string | null): string[] {
  const had = new Set(prev === null ? [] : tomlLines(prev));
  const out: string[] = [];
  for (const line of tomlLines(next)) {
    if (had.has(line)) continue;
    for (const [re, why] of TOML_RULES) if (re.test(line)) out.push(`${why}: ${line.length > 100 ? `${line.slice(0, 100)}…` : line}`);
  }
  return [...new Set(out)];
}

// ---- one change ---------------------------------------------------------------------------------------------------------------
export interface AnalyzeInput {
  rel: string;
  kind: FileKind;
  change: Change;
  next: string | null;
  prev: string | null;
}

export function analyze(i: AnalyzeInput): Analysis {
  if (i.change === "removed") return { cls: "other", reasons: ["файл удалён"], findings: [] };
  const next = i.next ?? "";
  switch (i.kind) {
    case "claude-settings":
    case "claude-json":
    case "mcp-json":
    case "json-config": {
      const obj = parseJsonLoose(next);
      if (!isObj(obj)) return { cls: "critical", reasons: ["файл не разобран как JSON: проверить вручную (агент может понимать его иначе)"], findings: [] };
      const prevObj = i.prev === null ? null : parseJsonLoose(i.prev);
      const reasons = jsonReasons(i.kind, obj, isObj(prevObj) ? prevObj : null);
      return { cls: reasons.some((r) => !isTightening(r)) ? "critical" : "other", reasons, findings: [] };
    }
    case "toml-config": {
      const reasons = tomlReasons(next, i.prev);
      return { cls: reasons.length > 0 ? "critical" : "other", reasons, findings: [] };
    }
    case "hook-script":
      return { cls: "critical", reasons: ["скрипт хука: код, который агент запускает сам"], findings: [] };
    case "code":
      return { cls: "critical", reasons: ["код расширения агента (плагин или инструмент opencode)"], findings: [] };
    case "instructions": {
      const all = instructionFindings({ path: i.rel, content: next });
      // What the baseline text already had is not new: compare by rule and excerpt (lines move).
      const had = new Set(i.prev === null ? [] : instructionFindings({ path: i.rel, content: i.prev }).map((f) => `${f.rule}\0${f.excerpt}`));
      return { cls: "instructions", reasons: [], findings: all.filter((f) => !had.has(`${f.rule}\0${f.excerpt}`)).slice(0, 30) };
    }
  }
}

// ---- diff ------------------------------------------------------------------------------------------------------------------------
export const MAX_DIFF_BYTES = 20 * 1024;
const SECRET_KEY = /(["']?[\w.-]*(?:token|secret|password|passwd|api[_-]?key|apikey|authorization|credential|private[_-]?key)[\w.-]*["']?\s*[:=]\s*)(\S.*)$/i;
const SECRET_LITERAL = /\bgh[pousr]_[A-Za-z0-9]{30,}|\bsk-[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bnpm_[A-Za-z0-9]{30,}|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/g;

/**
 * What leaves the guard in a diff must not carry a credential: the guard's answer goes to the server's process. The value of a key that
 * names a secret and anything shaped like one is hidden; the line stays, so that a changed secret still shows as a changed line.
 */
export function maskSecrets(line: string): string {
  return line.replace(SECRET_KEY, (_m, key: string) => `${key}«скрыто»`).replace(SECRET_LITERAL, "«скрыто»");
}

/** A line diff (LCS) with three lines of context; `text` is already masked. Old null: a new file, everything added. */
export function unifiedDiff(oldText: string | null, newText: string | null, max = MAX_DIFF_BYTES): string {
  const a = oldText === null ? [] : oldText.replace(/\r\n/g, "\n").split("\n");
  const b = newText === null ? [] : newText.replace(/\r\n/g, "\n").split("\n");
  if (a.length > 0 && a[a.length - 1] === "") a.pop();
  if (b.length > 0 && b[b.length - 1] === "") b.pop();
  type Op = { t: " " | "+" | "-"; s: string };
  let ops: Op[] = [];
  if (a.length * b.length > 4_000_000) {
    ops = [...a.map((s): Op => ({ t: "-", s })), ...b.map((s): Op => ({ t: "+", s }))];
  } else {
    const n = a.length;
    const m = b.length;
    const w = m + 1;
    const lcs = new Uint32Array((n + 1) * w);
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) lcs[i * w + j] = a[i] === b[j] ? lcs[(i + 1) * w + j + 1]! + 1 : Math.max(lcs[(i + 1) * w + j]!, lcs[i * w + j + 1]!);
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
      if (a[i] === b[j]) (ops.push({ t: " ", s: a[i]! }), i++, j++);
      else if (lcs[(i + 1) * w + j]! >= lcs[i * w + j + 1]!) ops.push({ t: "-", s: a[i++]! });
      else ops.push({ t: "+", s: b[j++]! });
    }
    while (i < n) ops.push({ t: "-", s: a[i++]! });
    while (j < m) ops.push({ t: "+", s: b[j++]! });
  }
  const keep = new Array<boolean>(ops.length).fill(false);
  ops.forEach((o, k) => {
    if (o.t !== " ") for (let d = -3; d <= 3; d++) if (k + d >= 0 && k + d < ops.length) keep[k + d] = true;
  });
  const lines: string[] = [];
  let skipped = false;
  ops.forEach((o, k) => {
    if (!keep[k]) {
      skipped = true;
      return;
    }
    if (skipped && lines.length > 0) lines.push("…");
    skipped = false;
    lines.push(`${o.t} ${maskSecrets(o.s)}`);
  });
  let text = lines.join("\n");
  if (Buffer.byteLength(text) > max) {
    let cut = text.slice(0, max);
    while (Buffer.byteLength(cut) > max) cut = cut.slice(0, -64);
    text = `${cut}\n… (diff обрезан: больше ${Math.round(max / 1024)} КБ)`;
  }
  return text;
}
