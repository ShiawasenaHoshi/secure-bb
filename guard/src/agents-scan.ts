// Agent watch, the file side: which files of the agents' home and of the working directories are looked at, and what they say.
// Pure over the file system (a directory is passed in; the tests give a temporary one instead of /var/bbagent). No database here.
//
// What is watched (design: secure-bb-agent-watch-design.md):
//  - globally, in the agents' home: Claude Code (.claude/settings*.json, CLAUDE.md, agents/, commands/, hooks/; .claude.json — its `mcpServers`
//    sections only), Codex (.codex/config.toml, AGENTS.md), Cursor (.cursor/mcp.json, rules/), opencode (.config/opencode/);
//    skills (.claude/skills/) are the skills module's: not repeated;
//  - in working directories: CLAUDE.md, AGENTS.md, .claude/settings*.json, .claude/agents|commands|hooks/, .mcp.json, .cursorrules,
//    .cursor/rules/, .github/copilot-instructions.md — to a depth of 3, skipping node_modules and .git.
// v1 finds the working directories of threads by itself: <home>/data/plugins/*/host-data/workspaces/*, plus the roots the console names
// (`--agents-root`). Project directories in the owner's home are not watched in v1.
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync, statSync } from "node:fs";
import type { Stats } from "node:fs";
import { basename, join, sep } from "node:path";

export const MAX_DEPTH = 3;
export const MAX_ROOTS = 300;
export const MAX_FILES = 3000;
/** Directories read per root and in all: a checkout with a huge tree must not stall the guard. */
export const MAX_DIRS_PER_ROOT = 400;
export const MAX_DIRS = 6000;
/** Larger files are not read at all (a note says so); the content of a smaller one is kept for the diff up to KEEP_BYTES. */
export const MAX_READ_BYTES = 2 * 1024 * 1024;
export const KEEP_BYTES = 256 * 1024;

export type RootKind = "global" | "workspace" | "extra";

/** What kind of file it is decides how a change is read (agents-rules.ts). */
export type FileKind =
  | "claude-settings" // .claude/settings.json, settings.local.json
  | "claude-json" // ~/.claude.json: only the mcpServers sections are looked at
  | "mcp-json" // .mcp.json, .cursor/mcp.json
  | "json-config" // opencode.json(c) and the like
  | "toml-config" // .codex/config.toml
  | "hook-script" // .claude/hooks/*: code the agent runs
  | "code" // opencode plugins/tools: code the agent loads
  | "instructions"; // CLAUDE.md, AGENTS.md, rules, agents, commands

export interface Observed {
  path: string;
  root: string;
  rootKind: RootKind;
  /** Relative to the root, with `/`. */
  rel: string;
  kind: FileKind;
  sha256: string;
  size: number;
  mtimeMs: number;
  /** The text the checks and the diff work on (for `.claude.json`: the mcpServers sections only). Null: too large to keep, or not text. */
  content: string | null;
  symlink: string | null;
}
export interface Alarm {
  path: string;
  /** `unreadable` (no access: the ACL was taken off, or the permissions changed) or `vanished-root`. */
  kind: "unreadable";
  error: string;
}
export interface Note {
  kind: "limit" | "missing-root" | "too-large";
  text: string;
}
export interface ScanResult {
  observed: Map<string, Observed>;
  alarms: Alarm[];
  notes: Note[];
  roots: number;
}

export interface Limits {
  roots: number;
  files: number;
  dirsPerRoot: number;
  dirs: number;
  readBytes: number;
  keepBytes: number;
}
export const DEFAULT_LIMITS: Limits = { roots: MAX_ROOTS, files: MAX_FILES, dirsPerRoot: MAX_DIRS_PER_ROOT, dirs: MAX_DIRS, readBytes: MAX_READ_BYTES, keepBytes: KEEP_BYTES };

export interface ScanOptions {
  home: string;
  extraRoots?: readonly string[];
  /** Tests lower these; the defaults are the constants above. */
  limits?: Partial<Limits>;
}

const SKIP_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "target"]);
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
const errCode = (e: unknown): string => (e as { code?: string }).code ?? "ERR";
const isDenied = (e: unknown): boolean => ["EACCES", "EPERM"].includes(errCode(e));
const rel2 = (root: string, p: string): string => (p === root ? "" : p.slice(root.length + 1).split(sep).join("/"));

// ---- what a path is -----------------------------------------------------------------------------------------------
const CODE_EXT = /\.(?:[cm]?[jt]sx?)$/i;

/** The kind of a file in the agents' home, from its path relative to the home; null: not watched. */
export function globalKind(rel: string): FileKind | null {
  const p = rel;
  if (p === ".claude/settings.json" || p === ".claude/settings.local.json") return "claude-settings";
  if (p === ".claude/CLAUDE.md") return "instructions";
  if (p === ".claude.json") return "claude-json";
  if (p === ".codex/config.toml") return "toml-config";
  if (p === ".codex/AGENTS.md") return "instructions";
  if (p === ".cursor/mcp.json") return "mcp-json";
  if (p.startsWith(".claude/hooks/")) return "hook-script";
  if (p.startsWith(".claude/agents/") || p.startsWith(".claude/commands/") || p.startsWith(".cursor/rules/")) return "instructions";
  if (p.startsWith(".config/opencode/")) {
    if (CODE_EXT.test(p)) return "code";
    if (/\.jsonc?$/i.test(p)) return "json-config";
    if (/\.(?:md|mdx|markdown|txt)$/i.test(p)) return "instructions";
  }
  return null;
}

/** The kind of a file in a working directory, from its path relative to the root. The structure is matched at any place down to MAX_DEPTH. */
export function workspaceKind(rel: string): FileKind | null {
  const parts = rel.split("/");
  const name = parts[parts.length - 1]!;
  const dirs = parts.slice(0, -1);
  const lower = name.toLowerCase();
  if (name === "CLAUDE.md" || name === "CLAUDE.local.md" || name === "AGENTS.md" || name === ".cursorrules") return "instructions";
  if (name === ".mcp.json") return "mcp-json";
  const last = dirs[dirs.length - 1];
  if (last === ".claude" && (name === "settings.json" || name === "settings.local.json")) return "claude-settings";
  const claude = dirs.indexOf(".claude");
  if (claude >= 0 && dirs.length > claude + 1) {
    const sub = dirs[claude + 1];
    if (sub === "hooks") return "hook-script";
    if (sub === "agents" || sub === "commands") return "instructions";
  }
  const cursor = dirs.indexOf(".cursor");
  if (cursor >= 0 && dirs[cursor + 1] === "rules") return "instructions";
  if (last === ".cursor" && lower === "mcp.json") return "mcp-json";
  if (last === ".github" && lower === "copilot-instructions.md") return "instructions";
  return null;
}

// ---- reading ------------------------------------------------------------------------------------------------------
/** `.claude.json` is a state file that changes all the time; what matters here is its MCP servers, top-level and per project. */
export function claudeJsonView(text: string): string | null {
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) return null;
  const o = obj as Record<string, unknown>;
  const out: Record<string, unknown> = { mcpServers: o.mcpServers ?? {} };
  const projects: Record<string, unknown> = {};
  if (typeof o.projects === "object" && o.projects !== null) {
    for (const [dir, p] of Object.entries(o.projects as Record<string, unknown>)) {
      const m = typeof p === "object" && p !== null ? (p as Record<string, unknown>).mcpServers : undefined;
      if (m !== undefined && typeof m === "object" && m !== null && Object.keys(m).length > 0) projects[dir] = { mcpServers: m };
    }
  }
  out.projects = projects;
  return `${stable(out)}\n`;
}

/** JSON with sorted keys and two-space indent: the same text for the same data, and a diff that reads. */
export function stable(v: unknown): string {
  const sort = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(sort);
    if (typeof x === "object" && x !== null) return Object.fromEntries(Object.entries(x as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, val]) => [k, sort(val)]));
    return x;
  };
  return JSON.stringify(sort(v), null, 2);
}

class Budget {
  readonly lim: Limits;
  constructor(lim: Limits) {
    this.lim = lim;
  }
  files = 0;
  dirs = 0;
  limitNoted = false;
}

function observe(
  res: ScanResult,
  budget: Budget,
  root: string,
  rootKind: RootKind,
  path: string,
  rel: string,
  kind: FileKind,
  st: Stats,
): void {
  if (budget.files >= budget.lim.files) {
    if (!budget.limitNoted) res.notes.push({ kind: "limit", text: `больше ${budget.lim.files} файлов под наблюдением: остальные не просмотрены` });
    budget.limitNoted = true;
    return;
  }
  budget.files++;
  if (st.isSymbolicLink()) {
    let target = "?";
    try {
      target = readlinkSync(path);
    } catch {
      /* the link itself is what is recorded */
    }
    res.observed.set(path, { path, root, rootKind, rel, kind, sha256: sha(`symlink:${target}`), size: target.length, mtimeMs: st.mtimeMs, content: `-> ${target}\n`, symlink: target });
    return;
  }
  if (st.size > budget.lim.readBytes) {
    res.notes.push({ kind: "too-large", text: `${path}: ${st.size} байт, больше ${budget.lim.readBytes}: не читается` });
    return;
  }
  let buf: Buffer;
  try {
    buf = readFileSync(path);
  } catch (e) {
    if (errCode(e) === "ENOENT") return; // gone while we looked
    res.alarms.push({ path, kind: "unreadable", error: errCode(e) });
    return;
  }
  let content: string | null = buf.length <= budget.lim.keepBytes ? buf.toString("utf8") : null;
  let hashed: Buffer | string = buf;
  let size = buf.length;
  if (kind === "claude-json") {
    // Only the MCP sections count: the hash is of that view, not of the whole state file.
    const view = claudeJsonView(buf.toString("utf8"));
    content = view ?? "(не разобран как JSON)\n";
    hashed = view ?? buf;
    size = content.length;
  }
  res.observed.set(path, { path, root, rootKind, rel, kind, sha256: sha(hashed), size, mtimeMs: st.mtimeMs, content, symlink: null });
}

function walkDir(res: ScanResult, budget: Budget, root: string, rootKind: RootKind, dir: string, depth: number, state: { dirs: number }, classify: (rel: string) => FileKind | null): void {
  if (state.dirs >= budget.lim.dirsPerRoot || budget.dirs >= budget.lim.dirs) {
    if (!budget.limitNoted) res.notes.push({ kind: "limit", text: `${root}: просмотр обрезан по числу каталогов` });
    budget.limitNoted = true;
    return;
  }
  state.dirs++;
  budget.dirs++;
  let entries: import("node:fs").Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    if (errCode(e) === "ENOENT") return;
    res.alarms.push({ path: dir, kind: "unreadable", error: errCode(e) });
    return;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const e of entries) {
    const path = join(dir, e.name);
    if (e.isDirectory()) {
      if (depth < MAX_DEPTH && !SKIP_DIRS.has(e.name)) walkDir(res, budget, root, rootKind, path, depth + 1, state, classify);
      continue;
    }
    const rel = rel2(root, path);
    const kind = classify(rel);
    if (kind === null) continue;
    let st: Stats;
    try {
      st = lstatSync(path);
    } catch (err) {
      if (errCode(err) !== "ENOENT") res.alarms.push({ path, kind: "unreadable", error: errCode(err) });
      continue;
    }
    observe(res, budget, root, rootKind, path, rel, kind, st);
  }
}

/** Working directories the guard finds by itself: <home>/data/plugins/*\/host-data/workspaces/*. */
export function discoverWorkspaces(home: string, res?: ScanResult): string[] {
  const out: string[] = [];
  const plugins = join(home, "data", "plugins");
  let names: string[];
  try {
    names = readdirSync(plugins);
  } catch (e) {
    if (res && isDenied(e)) res.alarms.push({ path: plugins, kind: "unreadable", error: errCode(e) });
    return out;
  }
  for (const plugin of names.sort()) {
    const ws = join(plugins, plugin, "host-data", "workspaces");
    let dirs: import("node:fs").Dirent[];
    try {
      dirs = readdirSync(ws, { withFileTypes: true });
    } catch (e) {
      if (res && isDenied(e)) res.alarms.push({ path: ws, kind: "unreadable", error: errCode(e) });
      continue;
    }
    for (const d of dirs.sort((a, b) => (a.name < b.name ? -1 : 1))) if (d.isDirectory()) out.push(join(ws, d.name));
  }
  return out;
}

const GLOBAL_ENTRIES = [".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md", ".claude/agents", ".claude/commands", ".claude/hooks", ".claude.json", ".codex/config.toml", ".codex/AGENTS.md", ".cursor/mcp.json", ".cursor/rules", ".config/opencode"];

export function scan(o: ScanOptions): ScanResult {
  const res: ScanResult = { observed: new Map(), alarms: [], notes: [], roots: 0 };
  const budget = new Budget({ ...DEFAULT_LIMITS, ...o.limits });
  // The agents' home. A home that does not exist is a note (this machine may have no agents); one that cannot be entered is an alarm.
  let homeSt: Stats | null = null;
  try {
    homeSt = statSync(o.home);
  } catch (e) {
    if (isDenied(e)) res.alarms.push({ path: o.home, kind: "unreadable", error: errCode(e) });
    else res.notes.push({ kind: "missing-root", text: `${o.home}: каталога нет` });
  }
  if (homeSt?.isDirectory()) {
    res.roots++;
    // The home's own listing is the proof that it can be entered at all: with the ACL gone this fails and says so.
    try {
      readdirSync(o.home);
    } catch (e) {
      res.alarms.push({ path: o.home, kind: "unreadable", error: errCode(e) });
    }
    for (const entry of GLOBAL_ENTRIES) {
      const path = join(o.home, entry);
      let st: Stats;
      try {
        st = lstatSync(path);
      } catch (e) {
        if (isDenied(e)) res.alarms.push({ path, kind: "unreadable", error: errCode(e) });
        continue; // ENOENT: not there
      }
      if (st.isDirectory()) walkDir(res, budget, o.home, "global", path, 1, { dirs: 0 }, (rel) => globalKind(rel));
      else {
        const kind = globalKind(entry);
        if (kind) observe(res, budget, o.home, "global", path, entry, kind, st);
      }
    }
  }
  const roots: Array<{ dir: string; kind: RootKind }> = [];
  for (const dir of discoverWorkspaces(o.home, res)) roots.push({ dir, kind: "workspace" });
  for (const dir of o.extraRoots ?? []) roots.push({ dir, kind: "extra" });
  if (roots.length > budget.lim.roots) {
    res.notes.push({ kind: "limit", text: `рабочих каталогов ${roots.length}, наблюдаются первые ${budget.lim.roots}` });
    roots.length = budget.lim.roots;
  }
  for (const r of roots) {
    res.roots++;
    walkDir(res, budget, r.dir, r.kind, r.dir, 0, { dirs: 0 }, (rel) => workspaceKind(rel));
  }
  return res;
}

/** The name of a working directory (for a thread-shaped name, the thread's id: the plugin still asks bb for the real link). */
export const rootName = (root: string): string => basename(root);
