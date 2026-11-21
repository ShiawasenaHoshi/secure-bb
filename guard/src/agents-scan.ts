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
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readlinkSync, readSync, realpathSync, statSync } from "node:fs";
import type { Stats } from "node:fs";
import { basename, dirname, join, sep } from "node:path";

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
  /**
   * `unreadable`: no access (the ACL was taken off, or the permissions changed).
   * `outside`: a link (the file, or a directory on its way) leads out of what is watched, or into the guard's own directories: nothing was read.
   * `swapped`: the file was replaced under our hands (a link or another file between looking and opening): nothing was read.
   */
  kind: "unreadable" | "outside" | "swapped";
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
  /** Directories that are never read, whatever links lead there and whatever roots the console named: the guard's data and its socket. */
  deny?: readonly string[];
  /** Tests: called between looking at a file (lstat) and opening it, to play the agent that swaps it. */
  hooks?: { beforeOpen?: (path: string) => void };
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
  /** realpath of the home and of the roots the console named: a real path must lie inside one of them. */
  readonly allowed: string[];
  readonly deny: string[];
  readonly hooks: { beforeOpen?: (path: string) => void };
  constructor(lim: Limits, allowed: string[], deny: string[], hooks: { beforeOpen?: (path: string) => void }) {
    this.lim = lim;
    this.allowed = allowed;
    this.deny = deny;
    this.hooks = hooks;
  }
  files = 0;
  dirs = 0;
  limitNoted = false;
}

const inside = (real: string, base: string): boolean => real === base || real.startsWith(base.endsWith(sep) ? base : base + sep);

/** Is this real path (links resolved) somewhere we may read? Else an alarm says why, and the caller reads nothing. */
function permitted(res: ScanResult, b: Budget, path: string, real: string): boolean {
  if (b.deny.some((d) => inside(real, d))) {
    res.alarms.push({ path, kind: "outside", error: "ведёт в каталог сторожа (данные или сокет): не читается" });
    return false;
  }
  if (!b.allowed.some((r) => inside(real, r))) {
    res.alarms.push({ path, kind: "outside", error: `ведёт за пределы наблюдаемого (${real}): не читается` });
    return false;
  }
  return true;
}

/** The real path of a directory, if it may be read: links on the way are followed by the OS, so where they lead is checked first. null: not there, or an alarm was raised. */
function realDir(res: ScanResult, b: Budget, dir: string): string | null {
  let real: string;
  try {
    real = realpathSync(dir);
  } catch (e) {
    if (!["ENOENT", "ENOTDIR"].includes(errCode(e))) res.alarms.push({ path: dir, kind: "unreadable", error: errCode(e) });
    return null;
  }
  return permitted(res, b, dir, real) ? real : null;
}

/** Reads a file through ONE descriptor: no link is followed at the last step, and what was opened is checked to be the very file that was looked at. */
function readGuarded(res: ScanResult, b: Budget, path: string, st: Stats, expectedReal: string): Buffer | null {
  b.hooks.beforeOpen?.(path);
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    const code = errCode(e);
    if (code === "ENOENT") return null; // gone while we looked
    if (code === "ELOOP") res.alarms.push({ path, kind: "swapped", error: "стала ссылкой во время чтения: не читается" });
    else res.alarms.push({ path, kind: "unreadable", error: code });
    return null;
  }
  try {
    const fst = fstatSync(fd);
    if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) {
      res.alarms.push({ path, kind: "swapped", error: "подменён во время чтения (другой файл или не обычный файл): не читается" });
      return null;
    }
    if (fst.size > b.lim.readBytes) {
      res.notes.push({ kind: "too-large", text: `${path}: ${fst.size} байт, больше ${b.lim.readBytes}: не читается` });
      return null;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const chunk = Buffer.alloc(Math.min(65536, b.lim.readBytes + 1 - total));
      if (chunk.length === 0) break;
      const n = readSync(fd, chunk, 0, chunk.length, null);
      if (n === 0) break;
      chunks.push(chunk.subarray(0, n));
      total += n;
    }
    if (total > b.lim.readBytes) {
      res.notes.push({ kind: "too-large", text: `${path}: больше ${b.lim.readBytes} байт: не читается` });
      return null;
    }
    // The directories on the way may have been swapped for links during the read: if the path no longer leads where it led, what was read is thrown away.
    let after: string | null = null;
    try {
      after = realpathSync(path);
    } catch {
      /* gone: the same as swapped */
    }
    if (after !== expectedReal) {
      res.alarms.push({ path, kind: "swapped", error: "путь к файлу изменился во время чтения: прочитанное отброшено" });
      return null;
    }
    return Buffer.concat(chunks);
  } catch (e) {
    res.alarms.push({ path, kind: "unreadable", error: errCode(e) });
    return null;
  } finally {
    closeSync(fd);
  }
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
  // Where the path leads, links on the way included, is decided before anything is read.
  const parent = realDir(res, budget, dirname(path));
  if (parent === null) return;
  const expectedReal = join(parent, basename(path));
  if (st.isSymbolicLink()) {
    // A link is recorded as a link and never followed; one that leads out of the watched places is an alarm.
    let real: string | null = null;
    try {
      real = realpathSync(path);
    } catch {
      /* dangling: the link itself is what is recorded */
    }
    if (real !== null && !permitted(res, budget, path, real)) return;
    let target = "?";
    try {
      target = readlinkSync(path);
    } catch {
      /* ditto */
    }
    res.observed.set(path, { path, root, rootKind, rel, kind, sha256: sha(`symlink:${target}`), size: target.length, mtimeMs: st.mtimeMs, content: `-> ${target}\n`, symlink: target });
    return;
  }
  if (!st.isFile()) {
    res.alarms.push({ path, kind: "swapped", error: "не обычный файл: не читается" });
    return;
  }
  if (st.size > budget.lim.readBytes) {
    res.notes.push({ kind: "too-large", text: `${path}: ${st.size} байт, больше ${budget.lim.readBytes}: не читается` });
    return;
  }
  const buf = readGuarded(res, budget, path, st, expectedReal);
  if (buf === null) return;
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
  // A directory that is a link (or sits behind one) is listed only if it leads to somewhere watched.
  if (realDir(res, budget, dir) === null) return;
  state.dirs++;
  budget.dirs++;
  let entries: import("node:fs").Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    if (errCode(e) === "ENOENT" || errCode(e) === "ENOTDIR") return;
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
    if (e.isSymbolicLink() && !SKIP_DIRS.has(e.name)) {
      // A link to a directory is not followed; one that leads out of the watched places (or into the guard's own) is said aloud.
      try {
        if (statSync(path).isDirectory()) {
          const real = realpathSync(path);
          if (!budget.allowed.some((r) => inside(real, r)) || budget.deny.some((d) => inside(real, d))) permitted(res, budget, path, real);
          continue;
        }
      } catch {
        /* dangling or not a directory: handled as a file below */
      }
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
    // A link here is listed too: walking it checks where it leads (and says so when it leads out).
    for (const d of dirs.sort((a, b) => (a.name < b.name ? -1 : 1))) if (d.isDirectory() || d.isSymbolicLink()) out.push(join(ws, d.name));
  }
  return out;
}

const GLOBAL_ENTRIES = [".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md", ".claude/agents", ".claude/commands", ".claude/hooks", ".claude.json", ".codex/config.toml", ".codex/AGENTS.md", ".cursor/mcp.json", ".cursor/rules", ".config/opencode"];

export function scan(o: ScanOptions): ScanResult {
  const res: ScanResult = { observed: new Map(), alarms: [], notes: [], roots: 0 };
  const realOrSelf = (p: string): string => {
    try {
      return realpathSync(p);
    } catch {
      return p;
    }
  };
  // What may be read: the home and the roots the console named, by their real paths. The guard's own directories never.
  const allowed = [o.home, ...(o.extraRoots ?? [])].map(realOrSelf);
  const deny = (o.deny ?? []).map(realOrSelf);
  const budget = new Budget({ ...DEFAULT_LIMITS, ...o.limits }, allowed, deny, o.hooks ?? {});
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
      // `.claude`, `.config` and the like may be links: where the directory of the entry really is must be inside the home (looked at even if the file is not there).
      if (dirname(entry) !== "." && realDir(res, budget, dirname(path)) === null) continue;
      let st: Stats;
      try {
        st = lstatSync(path);
      } catch (e) {
        if (isDenied(e)) res.alarms.push({ path, kind: "unreadable", error: errCode(e) });
        continue; // ENOENT: not there
      }
      if (st.isSymbolicLink()) {
        let real: string;
        try {
          real = realpathSync(path);
        } catch {
          continue; // dangling
        }
        if (!permitted(res, budget, path, real)) continue;
        try {
          if (statSync(path).isDirectory()) st = statSync(path); // a directory link that stays inside the home is walked; a file link is recorded as a link
        } catch {
          continue;
        }
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
