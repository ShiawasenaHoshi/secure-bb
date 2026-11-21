// What the solver sees: the task, and the action behind an approval card. Everything is masked here, in code,
// before it can leave the machine (spec §9), and cut to a short length.
import { maskAndCut } from "./mask.js";

export const TASK_MAX = 600;
export const ARGS_MAX = 500;

export interface ActionInfo {
  provider: string;
  /** Kind of card: command, file_change, permission_grant, plan, tool_use. */
  kind: string;
  /** Tool or command family shown to the human. */
  tool: string;
  /** Masked, shortened. */
  args: string;
  cwd: string | null;
  reason: string | null;
}

const rec = (v: unknown): Record<string, unknown> | null => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);
const str = (v: unknown): string => (typeof v === "string" ? v : "");

function perms(p: unknown): string {
  const r = rec(p);
  if (!r) return "";
  const fs = rec(r.fileSystem);
  const parts: string[] = [];
  if (fs) {
    const read = Array.isArray(fs.read) ? fs.read.map(String) : [];
    const write = Array.isArray(fs.write) ? fs.write.map(String) : [];
    if (read.length) parts.push(`read ${read.join(", ")}`);
    if (write.length) parts.push(`write ${write.join(", ")}`);
  }
  const net = rec(r.network);
  if (net && net.enabled !== null && net.enabled !== undefined) parts.push(`network ${net.enabled ? "on" : "off"}`);
  return parts.join("; ");
}

/**
 * Reads an approval card (`interaction.payload.kind === "approval"`). Returns null for any other kind of
 * interaction. Unknown shapes are described as far as they can be, never thrown on.
 */
export function describeAction(interaction: unknown): ActionInfo | null {
  const i = rec(interaction);
  const payload = rec(i?.payload);
  if (!i || !payload || payload.kind !== "approval") return null;
  const subject = rec(payload.subject) ?? {};
  const kind = str(subject.kind) || "unknown";
  let tool = kind;
  let args = "";
  let cwd: string | null = null;
  switch (kind) {
    case "command":
      tool = "command";
      args = str(subject.command);
      cwd = str(subject.cwd) || null;
      break;
    case "file_change":
      tool = "file_change";
      args = str(subject.writeScope) || "(file changes)";
      break;
    case "permission_grant":
      tool = str(subject.toolName) || "permission_grant";
      args = perms(subject.permissions);
      break;
    case "plan":
      tool = "plan";
      args = str(subject.planFilePath) || str(subject.plan);
      break;
    case "tool_use": {
      tool = str(subject.tool) || "tool_use";
      const pres = rec(subject.presentation);
      const label = rec(pres?.label);
      args = str(pres?.detail) || str(pres?.title) || str(label?.pending);
      break;
    }
    default:
      args = JSON.stringify(subject).slice(0, 2000);
  }
  return {
    provider: str(i.providerId) || "unknown",
    kind,
    tool: maskAndCut(tool, 80),
    args: maskAndCut(args, ARGS_MAX),
    cwd: cwd === null ? null : maskAndCut(cwd, 200),
    reason: str(payload.reason) ? maskAndCut(str(payload.reason), 300) : null,
  };
}

/** The `state` sent to the solver. Plain data; nothing from outside this object goes out. */
export function buildState(task: string | null, action: ActionInfo): Record<string, unknown> {
  return {
    task: task === null ? null : maskAndCut(task, TASK_MAX),
    action: { provider: action.provider, kind: action.kind, tool: action.tool, arguments: action.args, cwd: action.cwd, reason: action.reason },
  };
}

/**
 * The first message a human sent into a thread, from its event rows (`client/thread/start`, `client/turn/requested`).
 * NOT VERIFIED against a live bb: the place of the text inside `request.params` is guessed from the event schema
 * (`params` is an open record), so several likely shapes are tried. Returns null when none matches.
 */
export function humanTaskFromEvents(rows: ReadonlyArray<{ type: string; data: unknown }>): string | null {
  for (const row of rows) {
    const d = rec(row.data);
    if (!d || d.initiator !== "user") continue;
    const text = textOfRequest(rec(rec(d.request)?.params));
    if (text) return text;
  }
  return null;
}

function textOfRequest(params: Record<string, unknown> | null): string {
  if (!params) return "";
  for (const key of ["prompt", "text", "message"]) if (typeof params[key] === "string" && params[key]) return params[key] as string;
  for (const key of ["input", "items", "content"]) {
    const v = params[key];
    if (typeof v === "string" && v) return v;
    if (Array.isArray(v)) {
      const parts = v.map((x) => (typeof x === "string" ? x : str(rec(x)?.text))).filter(Boolean);
      if (parts.length) return parts.join("\n");
    }
  }
  return "";
}
