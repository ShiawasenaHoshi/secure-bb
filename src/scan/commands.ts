// How the two model CLIs are started and how their output is read (spec §8). Pure: no process is
// started here, so tests assert the exact command line, environment and working directory.
//
// Claude Code is started with every tool off and one turn, in an empty directory, with the plugin's
// code only on stdin. The login token (if the server was given a file for it) goes to this child
// as CLAUDE_CODE_OAUTH_TOKEN and nowhere else: not to logs, not to settings, not to the database.
import { accessSync, constants, readFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { isFlag, flagLines, parseReport, SYSTEM_PROMPT } from "./prompt.js";
import type { ModelId, ModelOutcome } from "./types.js";

export const TOKEN_FILE_ENV = "BB_SECURE_BB_CLAUDE_TOKEN_FILE";
export const CLAUDE_BIN_ENV = "BB_SECURE_BB_CLAUDE_BIN";
export const CURSOR_BIN_ENV = "BB_SECURE_BB_CURSOR_BIN";

export const SCAN_TIMEOUT_MS = 240_000;
export const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/** Everything the CLI could use to touch the machine or the net. `--tools ""` already leaves none; this is the second lock. */
export const DENIED_TOOLS = ["Bash", "BashOutput", "KillShell", "Edit", "MultiEdit", "Write", "NotebookEdit", "Read", "Glob", "Grep", "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite", "Skill", "SlashCommand", "ExitPlanMode"];

export interface CommandSpec {
  file: string;
  args: string[];
  env: Record<string, string>;
  /** Empty directory the child starts in. */
  cwd: string;
  stdin: string;
  timeoutMs: number;
  maxOutput: number;
}
export type RawRun =
  | { kind: "exit"; code: number | null; stdout: string; stderr: string; truncated: boolean }
  | { kind: "spawn-failed"; errno: string; message: string }
  | { kind: "timeout" };
/** Starts a command. The one seam tests replace: real models are never called from tests. */
export type ProcessRunner = (spec: CommandSpec) => Promise<RawRun>;

/** Variables a model CLI legitimately needs. Everything else of the server's environment stays behind. */
const PASS_ENV = ["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"];

function baseEnv(server: NodeJS.ProcessEnv): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of PASS_ENV) {
    const v = server[k];
    if (typeof v === "string" && v !== "") env[k] = v;
  }
  return env;
}

export type Built = { ok: true; spec: CommandSpec; secret: string | null } | { ok: false; unavailable: string };

/** The token from the file named by `BB_SECURE_BB_CLAUDE_TOKEN_FILE`; null when the variable is not set. */
export function readToken(server: NodeJS.ProcessEnv): { ok: true; token: string | null } | { ok: false; reason: string } {
  const path = server[TOKEN_FILE_ENV]?.trim();
  if (!path) return { ok: true, token: null };
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { ok: false, reason: `файл токена (${TOKEN_FILE_ENV}) не читается` };
  }
  const token = text.trim();
  if (!/^[\x21-\x7e]{8,4096}$/.test(token)) return { ok: false, reason: `в файле токена (${TOKEN_FILE_ENV}) нет токена` };
  return { ok: true, token };
}

export function claudeCommand(o: { prompt: string; cwd: string; home: string; server: NodeJS.ProcessEnv; timeoutMs?: number }): Built {
  const t = readToken(o.server);
  if (!t.ok) return { ok: false, unavailable: t.reason };
  const env = baseEnv(o.server);
  if (t.token !== null) {
    // The server's own account is not used: a clean home keeps its settings, hooks and history out of the run.
    env.HOME = o.home;
    env.CLAUDE_CODE_OAUTH_TOKEN = t.token;
  }
  return {
    ok: true,
    secret: t.token,
    spec: {
      file: o.server[CLAUDE_BIN_ENV]?.trim() || "claude",
      args: [
        "-p",
        "--output-format", "json",
        "--max-turns", "1",
        "--tools", "",
        "--disallowedTools", DENIED_TOOLS.join(","),
        "--permission-mode", "dontAsk",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--setting-sources", "",
        "--no-session-persistence",
        "--system-prompt", SYSTEM_PROMPT,
      ],
      env,
      cwd: o.cwd,
      stdin: o.prompt,
      timeoutMs: o.timeoutMs ?? SCAN_TIMEOUT_MS,
      maxOutput: MAX_OUTPUT_BYTES,
    },
  };
}

/** Names that would make the "other vendor" model an Anthropic one. */
const ANTHROPIC_NAME = /claude|anthropic|sonnet|opus|haiku|fable/i;
/** A model name is data in an argument list: no leading dash, no spaces, nothing that is not a plain name. */
export function validateSecondModel(name: string): string | null {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/.test(name)) return "имя модели: латиница, цифры и . _ : / -, до 64 знаков, не с дефиса";
  if (ANTHROPIC_NAME.test(name)) return "вторая модель должна быть другого вендора, не Anthropic";
  return null;
}

export function cursorCommand(o: { prompt: string; cwd: string; model: string; server: NodeJS.ProcessEnv; timeoutMs?: number }): Built {
  const bad = validateSecondModel(o.model);
  if (bad) return { ok: false, unavailable: bad };
  return {
    ok: true,
    secret: null,
    spec: {
      file: o.server[CURSOR_BIN_ENV]?.trim() || "cursor-agent",
      // --trust: headless cursor-agent refuses an untrusted workspace; ours is an empty directory made for this one run.
      args: ["-p", "--trust", "--mode", "ask", "--model", o.model],
      env: baseEnv(o.server),
      cwd: o.cwd,
      stdin: o.prompt,
      timeoutMs: o.timeoutMs ?? SCAN_TIMEOUT_MS,
      maxOutput: MAX_OUTPUT_BYTES,
    },
  };
}

/** Is `name` (or the path given by an override) an executable file? */
export function findExecutable(nameOrPath: string, server: NodeJS.ProcessEnv): boolean {
  const candidates = nameOrPath.includes("/") ? [nameOrPath] : (server.PATH ?? "").split(delimiter).filter(Boolean).map((d) => join(d, nameOrPath));
  return candidates.some((p) => {
    try {
      accessSync(p, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

// ---- reading what came back -----------------------------------------------------
const AUTH_FAILURE = /not logged in|please run \/?login|\/login|invalid api key|authentication|unauthori[sz]ed|oauth|credential|log ?in required|sign in|api key/i;
const REFUSAL = /^\s*(i('m| am)? (sorry|unable)|i can('|no)t|i cannot|sorry,|i won('|no)t)/i;

const redact = (text: string, secret: string | null): string => {
  let out = secret ? text.split(secret).join("[токен]") : text;
  out = out.replace(/sk-ant-[A-Za-z0-9_-]{8,}/g, "[токен]");
  return out;
};
const brief = (text: string, secret: string | null, max = 240): string => {
  const t = redact(text, secret).replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
};

interface Envelope {
  result: string | null;
  isError: boolean;
  refusal: boolean;
  subtypeError: string | null;
}
function readEnvelope(stdout: string): Envelope | null {
  try {
    const v: unknown = JSON.parse(stdout.trim());
    if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
    const o = v as Record<string, unknown>;
    if (o.type !== "result" && typeof o.result !== "string" && o.is_error === undefined) return null;
    const sub = typeof o.subtype === "string" ? o.subtype : null;
    return {
      result: typeof o.result === "string" ? o.result : null,
      isError: o.is_error === true,
      refusal: o.stop_reason === "refusal" || sub === "refusal",
      subtypeError: sub && sub !== "success" && sub !== "refusal" ? sub : null,
    };
  } catch {
    return null;
  }
}

/** Turns what a model CLI printed into one outcome. Every failure is a failure, never a pass. */
export function interpret(model: ModelId, label: string, raw: RawRun, secret: string | null, ms: number): ModelOutcome {
  const out = (status: ModelOutcome["status"], detail: string, report: ModelOutcome["report"] = null): ModelOutcome => ({ model, label, status, detail, report, ms });
  if (raw.kind === "timeout") return out("timeout", "не ответила за отведённое время");
  if (raw.kind === "spawn-failed") {
    return raw.errno === "ENOENT" || raw.errno === "EACCES"
      ? out("unavailable", `программа не найдена или не запускается (${raw.errno})`)
      : out("error", `не удалось запустить: ${brief(raw.message, secret)}`);
  }
  if (raw.truncated) return out("error", "вывод больше допустимого, ответ отброшен");
  const env = readEnvelope(raw.stdout);
  const text = env ? env.result : raw.stdout;
  const failed = raw.code !== 0 || env?.isError === true;
  if (failed) {
    const all = `${text ?? ""}\n${raw.stderr}`;
    if (AUTH_FAILURE.test(all)) return out("unavailable", "нет входа: " + brief(all, secret, 160));
    if (env?.refusal) return out("refusal", "модель отказалась отвечать");
    return out("error", `завершилась с ошибкой (код ${raw.code}): ${brief(all, secret)}`);
  }
  if (env?.refusal) return out("refusal", "модель отказалась отвечать");
  if (env?.subtypeError) return out("error", `ответ не получен: ${env.subtypeError}`);
  if (text === null || text.trim() === "") return out("invalid", "пустой ответ");
  const parsed = parseReport(text);
  if (!parsed.ok) return REFUSAL.test(text) ? out("refusal", "модель отказалась: " + brief(text, secret, 160)) : out("invalid", `${parsed.reason}: ${brief(text, secret, 160)}`);
  const lines = flagLines(parsed.report);
  return isFlag(parsed.report) ? out("flag", lines.join("; ") || "флаг", parsed.report) : out("clean", parsed.report.summary.slice(0, 240), parsed.report);
}
