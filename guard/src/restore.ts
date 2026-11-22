// sbb-restore: the helper that puts an agent's file back (design: secure-bb-agent-rollback-design.md).
//
// It runs as the agents' user, because only that user may write there (the guard only reads, the plugin's user cannot). It listens on a socket that
// only the guard's user can reach (directory 0750 and socket 0660, both of the group whose one member is the guard's user): the plugin and
// everything running as the bb user cannot even connect. Whoever connects can do exactly one thing:
//
//   {"op":"restore","path":ABS,"sha256":HEX,"content":TEXT}   write exactly TEXT (sha256 is the hash of TEXT)
//   {"op":"restore","path":ABS,"sha256":HEX,"delete":true}    remove the file (sha256: the hash the guard saw, for the record)
//   {"op":"restore-json-key","path":ABS/.claude.json,"key":[…],"sha256":HEX,"value":{…}|"delete":true}   replace or remove one section of .claude.json
//
// (plus `restore-json-key`, below, for one section of .claude.json) and only on a path that the guard's watch looks at (agents-scan.ts: the same lists), inside the agents' home. It reads nothing and returns
// nothing but `ok` or an error: no content, no listing, no hash of what was there. Zero dependencies (node:*); the code is root-owned, in the same archive.
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, realpathSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import net from "node:net";
import { basename, dirname, isAbsolute, join, normalize, sep } from "node:path";
import { chownGroup, SocketGroupError, type ChownFn } from "./chown.ts";
import { KEEP_BYTES, MAX_DEPTH, MAX_READ_BYTES, globalKind, workspaceKind } from "./agents-scan.ts";

export const VERSION = "0.1.0";
export const DEFAULT_SOCKET = "/var/sbb-restore-run/restore.sock";
export const DEFAULT_HOME = "/var/bbagent";
const MAX_LINE_BYTES = KEEP_BYTES * 2 + 4096;
const MAX_CONNECTIONS = 8;
const REQUEST_TIMEOUT_MS = 5000;
/** The mode of a file this helper has to create (the file was gone: nothing remembers its mode). The agents' files may hold keys. */
const NEW_FILE_MODE = 0o600;
const NEW_DIR_MODE = 0o700;

export class RestoreError extends Error {
  // No parameter properties: Node only strips the types of these files, it does not compile them.
  readonly code: "invalid" | "not_watched" | "link" | "outside" | "io" | "stale";
  constructor(code: "invalid" | "not_watched" | "link" | "outside" | "io" | "stale", message: string) {
    super(message);
    this.code = code;
  }
}

const sha256hex = (t: string): string => createHash("sha256").update(t, "utf8").digest("hex");
const errCode = (e: unknown): string => (e as { code?: string }).code ?? "ERR";

/**
 * Is this a file the watch looks at? `rel` is the path inside the home. The home's own files by `globalKind`; a working directory
 * (<home>/data/plugins/*\/host-data/workspaces/*) by `workspaceKind`, to the depth the watch goes. `.claude.json` is not restorable: the watch
 * keeps only a view of it (its MCP sections), never the file.
 */
export function watchedRel(rel: string): boolean {
  const g = globalKind(rel);
  if (g !== null) return g !== "claude-json";
  const parts = rel.split("/");
  // data / plugins / <plugin> / host-data / workspaces / <dir> / <path in the working directory...>
  if (parts.length < 7 || parts[0] !== "data" || parts[1] !== "plugins" || parts[3] !== "host-data" || parts[4] !== "workspaces") return false;
  if (parts[2] === "" || parts[5] === "") return false;
  const inner = parts.slice(6);
  if (inner.length > MAX_DEPTH + 1) return false;
  return workspaceKind(inner.join("/")) !== null;
}

/** The path inside the home, relative with `/`, or an error: the path must be absolute, already normal (no `..`, no `//`) and lie under the home. */
export function relUnderHome(home: string, path: unknown): string {
  if (typeof path !== "string" || path === "" || path.length > 4096 || path.includes("\0")) throw new RestoreError("invalid", "path is an absolute path");
  if (!isAbsolute(path) || normalize(path) !== path) throw new RestoreError("invalid", "path must be absolute and normal (no .., no //, no trailing /)");
  const base = home.endsWith(sep) ? home : home + sep;
  if (!path.startsWith(base)) throw new RestoreError("outside", "the path is not inside the agents' home");
  return path.slice(base.length).split(sep).join("/");
}

export interface RestoreRequest {
  path: string;
  sha256: string;
  content?: string;
  delete?: boolean;
}
export type RestoreResult = "written" | "deleted" | "absent";

/** Checks the shape of a request; nothing here touches the disk. */
export function parseRequest(raw: unknown): RestoreRequest {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new RestoreError("invalid", "a request is a JSON object");
  const r = raw as Record<string, unknown>;
  if (r.op !== "restore") throw new RestoreError("invalid", "the operations are restore, restore-json-key and restore-json-path");
  if (typeof r.path !== "string") throw new RestoreError("invalid", "path is a string");
  if (typeof r.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(r.sha256)) throw new RestoreError("invalid", "sha256 is 64 hex digits");
  const hasContent = r.content !== undefined;
  const hasDelete = r.delete !== undefined;
  if (hasContent === hasDelete) throw new RestoreError("invalid", "exactly one of content and delete");
  if (hasDelete && r.delete !== true) throw new RestoreError("invalid", "delete is true");
  if (hasContent) {
    if (typeof r.content !== "string") throw new RestoreError("invalid", "content is a string");
    if (Buffer.byteLength(r.content, "utf8") > KEEP_BYTES) throw new RestoreError("invalid", `content is at most ${KEEP_BYTES} bytes`);
    if (sha256hex(r.content) !== r.sha256) throw new RestoreError("invalid", "sha256 is not the hash of content");
    return { path: r.path, sha256: r.sha256, content: r.content };
  }
  return { path: r.path, sha256: r.sha256, delete: true };
}

/**
 * Walks from the home down to the directory of the file, one component at a time, and only through real directories: a link on the way is a refusal
 * (that is the "realpath of the parent" check, done by construction: the path of every step is exactly what the disk says). `create`: a missing
 * directory is made (the file is to be put back and its directory was removed with it); otherwise a missing one means there is nothing to do.
 * Returns the real directory, or null when it does not exist and is not to be created.
 */
function walkParent(realHome: string, relDir: string[], create: boolean): string | null {
  let cur = realHome;
  for (const part of relDir) {
    const next = join(cur, part);
    let st;
    try {
      st = lstatSync(next);
    } catch (e) {
      if (errCode(e) !== "ENOENT") throw new RestoreError("io", `${errCode(e)} on the way to the file`);
      if (!create) return null;
      try {
        mkdirSync(next, { mode: NEW_DIR_MODE });
      } catch (e2) {
        throw new RestoreError("io", `${errCode(e2)} making a directory on the way to the file`);
      }
      cur = next;
      continue;
    }
    if (st.isSymbolicLink()) throw new RestoreError("link", "a link on the way to the file: refused");
    if (!st.isDirectory()) throw new RestoreError("io", "something that is not a directory on the way to the file");
    cur = next;
  }
  // The same thing said by the system: what the path really is must be what was walked.
  let real: string;
  try {
    real = realpathSync(cur);
  } catch (e) {
    throw new RestoreError("io", `${errCode(e)} resolving the directory of the file`);
  }
  if (real !== cur) throw new RestoreError("link", "the directory of the file is not where its path says: refused");
  return cur;
}

/** The one operation. `home` is the agents' home. Throws RestoreError; returns what was done. */
export function restore(home: string, req: RestoreRequest): RestoreResult {
  let realHome: string;
  try {
    realHome = realpathSync(home);
  } catch {
    throw new RestoreError("io", "the agents' home is not there");
  }
  // The request names the path the way the guard sees it: under the home as configured, or (a home that is itself a link, like /var on macOS) under its real path.
  const rel = ((): string => {
    try {
      return relUnderHome(home, req.path);
    } catch (e) {
      if (realHome !== home) return relUnderHome(realHome, req.path);
      throw e;
    }
  })();
  if (!watchedRel(rel)) throw new RestoreError("not_watched", "this is not a file the watch looks at");
  const parts = rel.split("/");
  const name = parts[parts.length - 1]!;
  const dir = walkParent(realHome, parts.slice(0, -1), req.delete !== true);
  const target = dir === null ? null : join(dir, name);

  if (req.delete === true) {
    if (target === null) return "absent";
    try {
      lstatSync(target);
    } catch (e) {
      if (errCode(e) === "ENOENT") return "absent";
      throw new RestoreError("io", `${errCode(e)} looking at the file`);
    }
    // unlink never follows: a link at that place is removed as the link it is.
    try {
      unlinkSync(target);
    } catch (e) {
      if (errCode(e) === "ENOENT") return "absent";
      throw new RestoreError("io", `${errCode(e)} removing the file`);
    }
    return "deleted";
  }

  // Write: the mode of the file that is there is kept; a directory or anything but a file (or a link, which is replaced) is not touched.
  let mode = NEW_FILE_MODE;
  try {
    const st = lstatSync(target!);
    if (st.isDirectory()) throw new RestoreError("io", "a directory is where the file should be: refused");
    if (st.isFile()) mode = st.mode & 0o7777;
    // a link: replaced by the rename below; nothing is written through it and nothing it points at is touched; its mode is not the file's
  } catch (e) {
    if (e instanceof RestoreError) throw e;
    if (errCode(e) !== "ENOENT") throw new RestoreError("io", `${errCode(e)} looking at the file`);
  }
  atomicReplace(dir!, target!, name, req.content!, mode);
  return "written";
}


/** Temporary file (O_EXCL | O_NOFOLLOW) + fsync + chmod + rename. `beforeRename` runs last and may refuse (the file moved under us). */
function atomicReplace(dir: string, target: string, name: string, text: string, mode: number, beforeRename?: () => void): void {
  const tmp = join(dir, `.${basename(name)}.sbb-restore-${randomBytes(6).toString("hex")}.tmp`);
  let fd: number | null = null;
  try {
    // O_EXCL | O_NOFOLLOW: a fresh file of ours, never one that somebody laid there (a link included).
    fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, NEW_FILE_MODE);
    const buf = Buffer.from(text, "utf8");
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    chmodSync(tmp, mode);
    // The path may have been swapped for a link while we wrote: looked at again right before the rename (a rename replaces a link, it does not follow it).
    if (realpathSync(dir) !== dir) throw new RestoreError("link", "the directory of the file changed under the helper: refused");
    beforeRename?.();
    renameSync(tmp, target);
  } catch (e) {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        /* closed */
      }
    }
    try {
      unlinkSync(tmp);
    } catch {
      /* it was not made, or it is already renamed */
    }
    if (e instanceof RestoreError) throw e;
    throw new RestoreError("io", `${errCode(e)} writing the file`);
  }
}

// ---- restore-json-key: one section of ~/.claude.json ---------------------------------------------------------------------------
// Claude Code keeps its MCP servers in the state file `.claude.json`, which it also rewrites all the time, so the file cannot be put back whole:
// only the section the watch looks at is replaced (or removed), the rest of the file is left as it is. This is the one operation that READS a file
// (that very one, to a size limit, never through a link); it returns nothing of what it read.
export const JSON_FILE = ".claude.json";
export type JsonKey = ["mcpServers"] | ["projects", string, "mcpServers"];
export interface RestoreJsonRequest {
  path: string;
  key: JsonKey;
  sha256: string;
  /** The section's new value (an object). */
  value?: Record<string, unknown>;
  /** Remove the section. */
  delete?: boolean;
}

const MAX_JSON_BYTES = MAX_READ_BYTES;
const STALE = "changed meanwhile";
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const has = (o: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

export function parseJsonRequest(r: Record<string, unknown>): RestoreJsonRequest {
  if (typeof r.path !== "string") throw new RestoreError("invalid", "path is a string");
  if (typeof r.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(r.sha256)) throw new RestoreError("invalid", "sha256 is 64 hex digits");
  const k = r.key;
  const okKey = Array.isArray(k) && ((k.length === 1 && k[0] === "mcpServers") || (k.length === 3 && k[0] === "projects" && typeof k[1] === "string" && k[1] !== "" && k[1].length <= 4096 && k[1] !== "__proto__" && k[2] === "mcpServers"));
  if (!okKey) throw new RestoreError("not_watched", "this key is not one the watch looks at (mcpServers, projects.<dir>.mcpServers)");
  const hasValue = r.value !== undefined;
  const hasDelete = r.delete !== undefined;
  if (hasValue === hasDelete) throw new RestoreError("invalid", "exactly one of value and delete");
  const key = k as JsonKey;
  if (hasDelete) {
    if (r.delete !== true) throw new RestoreError("invalid", "delete is true");
    return { path: r.path, key, sha256: r.sha256, delete: true };
  }
  if (!isPlain(r.value)) throw new RestoreError("invalid", "value is an object");
  const text = JSON.stringify(r.value);
  if (Buffer.byteLength(text, "utf8") > KEEP_BYTES) throw new RestoreError("invalid", `value is at most ${KEEP_BYTES} bytes`);
  if (sha256hex(text) !== r.sha256) throw new RestoreError("invalid", "sha256 is not the hash of JSON.stringify(value)");
  return { path: r.path, key, sha256: r.sha256, value: r.value };
}

/** Replaces or removes exactly one section of `.claude.json`; the rest of the file is as it was. Throws RestoreError. */
export function restoreJsonKey(home: string, req: RestoreJsonRequest): RestoreResult {
  let realHome: string;
  try {
    realHome = realpathSync(home);
  } catch {
    throw new RestoreError("io", "the agents' home is not there");
  }
  const rel = ((): string => {
    try {
      return relUnderHome(home, req.path);
    } catch (e) {
      if (realHome !== home) return relUnderHome(realHome, req.path);
      throw e;
    }
  })();
  if (rel !== JSON_FILE) throw new RestoreError("not_watched", "this operation is for .claude.json only");
  const target = join(realHome, JSON_FILE);
  for (let attempt = 0; attempt < 3; attempt++) {
    // One descriptor: no link is followed at the last step, and what is read is the very file that was looked at.
    let fd: number;
    try {
      fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (e) {
      if (errCode(e) === "ELOOP") throw new RestoreError("link", ".claude.json is a link: refused");
      if (errCode(e) === "ENOENT") throw new RestoreError("io", ".claude.json is not there");
      throw new RestoreError("io", `${errCode(e)} opening the file`);
    }
    let raw: string;
    let before;
    try {
      before = fstatSync(fd);
      if (!before.isFile()) throw new RestoreError("io", ".claude.json is not a regular file");
      if (before.size > MAX_JSON_BYTES) throw new RestoreError("invalid", "the file is larger than the limit");
      const buf = Buffer.alloc(before.size);
      let off = 0;
      while (off < buf.length) {
        const n = readSync(fd, buf, off, buf.length - off, off);
        if (n === 0) break;
        off += n;
      }
      raw = buf.subarray(0, off).toString("utf8");
    } finally {
      closeSync(fd);
    }
    let doc: unknown;
    try {
      doc = JSON.parse(raw);
    } catch {
      throw new RestoreError("invalid", "the file is not JSON: refused");
    }
    if (!isPlain(doc)) throw new RestoreError("invalid", "the file is not a JSON object: refused");
    let holder: Record<string, unknown>;
    let name: string;
    let result: RestoreResult;
    if (req.key.length === 1) {
      holder = doc;
      name = "mcpServers";
    } else {
      const projects = has(doc, "projects") ? doc.projects : undefined;
      if (projects !== undefined && !isPlain(projects)) throw new RestoreError("invalid", "projects is not an object: refused");
      let proj = projects === undefined ? undefined : has(projects, req.key[1]) ? projects[req.key[1]] : undefined;
      if (proj !== undefined && !isPlain(proj)) throw new RestoreError("invalid", "the project's entry is not an object: refused");
      if (proj === undefined) {
        if (req.delete === true) return "absent";
        const all = projects ?? ((doc.projects = {}) as Record<string, unknown>);
        proj = all[req.key[1]] = {};
      }
      holder = proj as Record<string, unknown>;
      name = "mcpServers";
    }
    if (req.delete === true) {
      if (!has(holder, name)) return "absent";
      delete holder[name];
      result = "deleted";
    } else {
      holder[name] = req.value;
      result = "written";
    }
    const text = `${JSON.stringify(doc, null, 2)}${raw.endsWith("\n") ? "\n" : ""}`;
    try {
      atomicReplace(realHome, target, JSON_FILE, text, before.mode & 0o7777, () => {
        // Claude Code rewrites this file itself: if it did so while we worked, our copy is stale, and is thrown away (then read again).
        const now = lstatSync(target);
        if (!now.isFile() || now.ino !== before.ino || now.dev !== before.dev || now.size !== before.size || now.mtimeMs !== before.mtimeMs) throw new RestoreError("io", STALE);
      });
    } catch (e) {
      if (e instanceof RestoreError && e.message === STALE) continue;
      throw e;
    }
    return result;
  }
  throw new RestoreError("io", ".claude.json keeps changing under the helper: nothing written, try again");
}

// ---- restore-json-path: one key (or one array element) of a settings file ----------------------------------------------------------
// Part of a Claude Code settings file (`.claude/settings.json`, `.claude/settings.local.json`) is put back or taken out, the rest of the file is as it was:
// «keep mine, give back theirs». The helper is told exactly one change: a path (only the paths of SETTINGS_PATHS), what to do there, and the SHA-256 of the
// whole file the guard looked at. If the file is not exactly that file any more, nothing is written (`stale`): the guard says so and the page draws again.
export type PathAction = "set" | "delete" | "array-add" | "array-remove";
export interface RestoreJsonPathRequest {
  path: string;
  /** The SHA-256 (hex) of the raw file the change was worked out from. */
  fileSha256: string;
  pointer: string[];
  action: PathAction;
  /** `set`: the value; `array-add` / `array-remove`: the element. */
  value?: unknown;
}
const MAX_POINTER_DEPTH = 8;
const FORBIDDEN_KEY = new Set(["__proto__", "constructor", "prototype"]);
/** Top-level keys of a settings file that the helper edits, and (for `permissions`) which of its entries. Everything else is for «Вернуть всё». */
const SETTINGS_TOP = new Set(["permissions", "hooks", "env", "enableAllProjectMcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "apiKeyHelper", "sandbox", "dangerouslyDisableSandbox", "statusLine", "fileSuggestion", "otelHeadersHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "policyHelper", "processWrapper", "sshHostCommands", "enabledPlugins", "extraKnownMarketplaces", "pluginConfigs", "allowedMcpServers", "forceLoginMethod", "forceLoginOrgUUID", "forceLoginGatewayUrl", "skipDangerousModePermissionPrompt", "modelOverrides", "model", "theme", "outputStyle", "cleanupPeriodDays", "includeCoAuthoredBy", "spinnerTipsEnabled"]);
const PERMISSION_KEYS = new Set(["allow", "deny", "ask", "defaultMode", "additionalDirectories", "disableBypassPermissionsMode"]);
/** Is this a path of a settings file the helper may change? A pure function: the guard uses it to say what can be split, the helper to refuse the rest. */
export function settingsPathAllowed(pointer: readonly string[]): boolean {
  if (pointer.length < 1 || pointer.length > MAX_POINTER_DEPTH) return false;
  if (pointer.some((k) => typeof k !== "string" || k === "" || k.length > 300 || FORBIDDEN_KEY.has(k))) return false;
  if (!SETTINGS_TOP.has(pointer[0]!)) return false;
  if (pointer[0] === "permissions") return pointer.length >= 2 && PERMISSION_KEYS.has(pointer[1]!);
  return true;
}
/** The settings files by their place inside the agents' home: the home's own and those of the working directories. */
export function settingsRel(rel: string): boolean {
  if (!watchedRel(rel)) return false;
  const parts = rel.split("/");
  const name = parts[parts.length - 1]!;
  return parts[parts.length - 2] === ".claude" && (name === "settings.json" || name === "settings.local.json");
}

export function parseJsonPathRequest(r: Record<string, unknown>): RestoreJsonPathRequest {
  if (typeof r.path !== "string") throw new RestoreError("invalid", "path is a string");
  if (typeof r.fileSha256 !== "string" || !/^[0-9a-f]{64}$/.test(r.fileSha256)) throw new RestoreError("invalid", "fileSha256 is 64 hex digits");
  const k = r.pointer;
  if (!Array.isArray(k) || !k.every((x) => typeof x === "string")) throw new RestoreError("invalid", "pointer is a list of keys");
  if (!settingsPathAllowed(k as string[])) throw new RestoreError("not_watched", "this path of a settings file is not one the helper edits");
  const action = r.action;
  if (action !== "set" && action !== "delete" && action !== "array-add" && action !== "array-remove") throw new RestoreError("invalid", "action is set, delete, array-add or array-remove");
  if (action === "delete" ? r.value !== undefined : r.value === undefined) throw new RestoreError("invalid", action === "delete" ? "delete has no value" : "value is needed");
  if (r.value !== undefined && Buffer.byteLength(JSON.stringify(r.value) ?? "", "utf8") > KEEP_BYTES) throw new RestoreError("invalid", `value is at most ${KEEP_BYTES} bytes`);
  return { path: r.path, fileSha256: r.fileSha256, pointer: k as string[], action, ...(r.value !== undefined ? { value: r.value } : {}) };
}

const stableJson = (v: unknown): string => {
  if (Array.isArray(v)) return `[${v.map(stableJson).join(",")}]`;
  if (isPlain(v)) return `{${Object.keys(v).sort().map((x) => `${JSON.stringify(x)}:${stableJson(v[x])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
};

/** Applies one change to a parsed document. Returns "written" or "absent" (there was nothing to do). Pure; exported for tests and for the guard's own check. */
export function applyPathChange(doc: Record<string, unknown>, pointer: readonly string[], action: PathAction, value: unknown): RestoreResult {
  const parents: Array<{ holder: Record<string, unknown>; key: string }> = [];
  let holder: Record<string, unknown> = doc;
  for (const key of pointer.slice(0, -1)) {
    let next = has(holder, key) ? holder[key] : undefined;
    if (next === undefined) {
      if (action === "delete" || action === "array-remove") return "absent";
      next = holder[key] = {};
    }
    if (!isPlain(next)) throw new RestoreError("invalid", "something that is not an object on the way to the key: refused");
    parents.push({ holder, key });
    holder = next;
  }
  const last = pointer[pointer.length - 1]!;
  const prune = (): void => {
    // An object that this change emptied goes too (a key that was not there before must not stay behind as `{}`).
    for (let i = parents.length - 1; i >= 0; i--) {
      const { holder: h, key } = parents[i]!;
      const v = h[key];
      if (isPlain(v) && Object.keys(v).length === 0) delete h[key];
      else break;
    }
  };
  switch (action) {
    case "set":
      holder[last] = value;
      return "written";
    case "delete":
      if (!has(holder, last)) return "absent";
      delete holder[last];
      prune();
      return "deleted";
    case "array-add": {
      const cur = has(holder, last) ? holder[last] : undefined;
      if (cur === undefined) {
        holder[last] = [value];
        return "written";
      }
      if (!Array.isArray(cur)) throw new RestoreError("invalid", "the key is not a list: refused");
      if (cur.some((e) => stableJson(e) === stableJson(value))) return "absent";
      cur.push(value);
      return "written";
    }
    case "array-remove": {
      const cur = has(holder, last) ? holder[last] : undefined;
      if (!Array.isArray(cur)) return "absent";
      const at = cur.findIndex((e) => stableJson(e) === stableJson(value));
      if (at < 0) return "absent";
      cur.splice(at, 1);
      if (cur.length === 0) {
        delete holder[last];
        prune();
      }
      return "deleted";
    }
  }
}

/** Changes exactly one path of a settings file; the rest is as it was. Throws RestoreError (`stale`: the file is not the one the guard looked at). */
export function restoreJsonPath(home: string, req: RestoreJsonPathRequest): RestoreResult {
  let realHome: string;
  try {
    realHome = realpathSync(home);
  } catch {
    throw new RestoreError("io", "the agents' home is not there");
  }
  const rel = ((): string => {
    try {
      return relUnderHome(home, req.path);
    } catch (e) {
      if (realHome !== home) return relUnderHome(realHome, req.path);
      throw e;
    }
  })();
  if (!settingsRel(rel)) throw new RestoreError("not_watched", "this operation is for the settings files of the agents only");
  const parts = rel.split("/");
  const name = parts[parts.length - 1]!;
  const dir = walkParent(realHome, parts.slice(0, -1), false);
  if (dir === null) throw new RestoreError("io", "the settings file is not there");
  const target = join(dir, name);
  for (let attempt = 0; attempt < 3; attempt++) {
    let fd: number;
    try {
      fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (e) {
      if (errCode(e) === "ELOOP") throw new RestoreError("link", "the settings file is a link: refused");
      if (errCode(e) === "ENOENT") throw new RestoreError("stale", "the settings file is not there any more");
      throw new RestoreError("io", `${errCode(e)} opening the file`);
    }
    let raw: string;
    let before;
    try {
      before = fstatSync(fd);
      if (!before.isFile()) throw new RestoreError("io", "the settings file is not a regular file");
      if (before.size > MAX_JSON_BYTES) throw new RestoreError("invalid", "the file is larger than the limit");
      const buf = Buffer.alloc(before.size);
      let off = 0;
      while (off < buf.length) {
        const n = readSync(fd, buf, off, buf.length - off, off);
        if (n === 0) break;
        off += n;
      }
      raw = buf.subarray(0, off).toString("utf8");
    } finally {
      closeSync(fd);
    }
    // The change was worked out from one file; if this is another one, nothing is written.
    if (sha256hex(raw) !== req.fileSha256) throw new RestoreError("stale", "the file is not the one the change was worked out from");
    let doc: unknown;
    try {
      doc = JSON.parse(raw);
    } catch {
      throw new RestoreError("invalid", "the file is not JSON: refused");
    }
    if (!isPlain(doc)) throw new RestoreError("invalid", "the file is not a JSON object: refused");
    const result = applyPathChange(doc, req.pointer, req.action, req.value);
    if (result === "absent") return "absent";
    const text = `${JSON.stringify(doc, null, 2)}${raw.endsWith("\n") ? "\n" : ""}`;
    try {
      atomicReplace(dir, target, name, text, before.mode & 0o7777, () => {
        const now = lstatSync(target);
        if (!now.isFile() || now.ino !== before.ino || now.dev !== before.dev || now.size !== before.size || now.mtimeMs !== before.mtimeMs) throw new RestoreError("io", STALE);
      });
    } catch (e) {
      if (e instanceof RestoreError && e.message === STALE) continue;
      throw e;
    }
    return result;
  }
  throw new RestoreError("stale", "the settings file keeps changing under the helper: nothing written");
}

// ---- the socket ------------------------------------------------------------------------------------------------------------
export interface ServeOptions {
  socket: string;
  /** The group whose only member is the guard's user. null (tests): left as the system made it. */
  socketGid: number | null;
  home: string;
  timeoutMs?: number;
  /** Tests: stands in for chown. */
  chown?: ChownFn;
  /** Where the service says what it did (never content). */
  log?: (line: string) => void;
}

/** One line in, one line out. Exported for tests. */
export function answer(home: string, line: string, log: (l: string) => void = () => undefined): string {
  let id: unknown;
  try {
    const raw = JSON.parse(line) as unknown;
    if (typeof raw === "object" && raw !== null && "id" in raw) id = (raw as { id: unknown }).id;
    let result: RestoreResult;
    let req: { path: string; sha256: string };
    if (typeof raw === "object" && raw !== null && (raw as { op?: unknown }).op === "restore-json-path") {
      const pr = parseJsonPathRequest(raw as Record<string, unknown>);
      result = restoreJsonPath(home, pr);
      req = { path: pr.path, sha256: pr.fileSha256 };
      log(`restore-json-path ${result} ${pr.path} ${pr.action} ${pr.pointer.join(".")}`);
    } else if (typeof raw === "object" && raw !== null && (raw as { op?: unknown }).op === "restore-json-key") {
      const jr = parseJsonRequest(raw as Record<string, unknown>);
      result = restoreJsonKey(home, jr);
      req = jr;
      log(`restore-json-key ${result} ${jr.path} ${jr.key.slice(1, 2).join("")}.${jr.key[jr.key.length - 1]}`);
    } else {
      const r = parseRequest(raw);
      result = restore(home, r);
      req = r;
      log(`restore ${result} ${r.path} ${r.sha256.slice(0, 16)}`);
    }
    return JSON.stringify({ ...(id !== undefined ? { id } : {}), ok: true, result });
  } catch (err) {
    if (err instanceof RestoreError) {
      log(`restore refused (${err.code}): ${err.message}`);
      return JSON.stringify({ ...(id !== undefined ? { id } : {}), ok: false, error: { code: err.code, message: err.message } });
    }
    if (err instanceof SyntaxError) return JSON.stringify({ ok: false, error: { code: "invalid", message: "not JSON" } });
    log(`internal error: ${err instanceof Error ? err.message : String(err)}`);
    return JSON.stringify({ ...(id !== undefined ? { id } : {}), ok: false, error: { code: "internal", message: "internal error" } });
  }
}

/** Asks by connecting (and at once closing): is something already listening there? Not a pure check. */
function probeListener(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const c = net.connect(path);
    c.once("connect", () => (c.destroy(), resolve(true)));
    c.once("error", () => resolve(false));
  });
}

/**
 * Listens. The socket's directory must not be reachable by "others": a directory that already exists with such a mode is a refusal
 * (the installer makes it 0750, owner the agents' user, group the guard's); a missing one is made 0750 (tests).
 */
export async function listen(o: ServeOptions): Promise<net.Server> {
  const log = o.log ?? (() => undefined);
  const dir = dirname(o.socket);
  if (existsSync(dir)) {
    if ((statSync(dir).mode & 0o007) !== 0) throw new Error(`${dir} is reachable by others; it must be 0750 (owner: the agents' user, group: the guard's)`);
  } else {
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    chmodSync(dir, 0o750);
    if (o.socketGid !== null) chownGroup({ program: "sbb-restore" }, dir, o.socketGid, o.chown);
  }
  if (await probeListener(o.socket)) throw new Error(`another sbb-restore is already listening on ${o.socket}`);
  try {
    unlinkSync(o.socket);
  } catch {
    /* there was none */
  }
  let open = 0;
  const server = net.createServer((conn) => {
    if (open >= MAX_CONNECTIONS) return void conn.destroy();
    open++;
    conn.once("close", () => open--);
    conn.setTimeout(o.timeoutMs ?? REQUEST_TIMEOUT_MS, () => conn.destroy());
    let buf = "";
    conn.setEncoding("utf8");
    conn.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() !== "" && !conn.destroyed) conn.write(`${answer(o.home, line, log)}\n`);
      }
      if (buf.length > MAX_LINE_BYTES) conn.destroy();
    });
    conn.on("error", () => conn.destroy());
  });
  // The socket is born with the umask's mode: nobody gets in through the directory (0750) before the group and mode below are set.
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(o.socket, resolve);
  });
  try {
    if (o.socketGid !== null) chownGroup({ program: "sbb-restore" }, o.socket, o.socketGid, o.chown);
    chmodSync(o.socket, 0o660);
  } catch (err) {
    server.close(); // not listening in a state nobody asked for (the group is wrong)
    throw err;
  }
  return server;
}

// ---- the command line --------------------------------------------------------------------------------------------------------
const USAGE = `sbb-restore ${VERSION} — puts an agent's file back for sbb-guard (one operation: restore)

  sbb-restore serve [--socket PATH] [--socket-gid GID] [--agents-home DIR] [--allow-root]

--socket / SBB_RESTORE_SOCKET (default ${DEFAULT_SOCKET}); --socket-gid / SBB_RESTORE_SOCKET_GID: the group whose only member is the guard's user;
--agents-home / SBB_RESTORE_AGENTS_HOME (default ${DEFAULT_HOME}). Run it as the agents' user; it refuses to run as root without --allow-root.
The socket's directory must be 0750 (owner: the agents' user, group: the same group) and the socket is 0660.`;

export async function main(argv: string[]): Promise<number> {
  const opts: Record<string, string | boolean> = {};
  let cmd: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--allow-root" || a === "--help") opts[a.slice(2)] = true;
    else if (a.startsWith("--")) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith("--")) {
        process.stderr.write(`--${a.slice(2)} needs a value\n`);
        return 64;
      }
      opts[a.slice(2)] = v;
      i++;
    } else if (cmd === undefined) cmd = a;
  }
  if (cmd !== "serve" || opts.help === true) {
    process.stdout.write(`${USAGE}\n`);
    return cmd === undefined || opts.help === true ? 0 : 64;
  }
  if (typeof process.getuid === "function" && process.getuid() === 0 && opts["allow-root"] !== true) {
    process.stderr.write("sbb-restore: run it as the agents' user, not as root (the files it writes would belong to root)\n");
    return 64;
  }
  const str = (k: string, env: string, def: string): string => (typeof opts[k] === "string" ? (opts[k] as string) : (process.env[env] ?? def));
  const home = str("agents-home", "SBB_RESTORE_AGENTS_HOME", DEFAULT_HOME).replace(/(.)\/+$/, "$1");
  const socket = str("socket", "SBB_RESTORE_SOCKET", DEFAULT_SOCKET);
  const gidText = str("socket-gid", "SBB_RESTORE_SOCKET_GID", "");
  const socketGid = gidText === "" ? null : Number(gidText);
  if (!isAbsolute(home) || !isAbsolute(socket) || (socketGid !== null && (!Number.isInteger(socketGid) || socketGid < 0))) {
    process.stderr.write("sbb-restore: --agents-home and --socket are absolute paths, --socket-gid a group id\n");
    return 64;
  }
  let server: net.Server;
  try {
    server = await listen({ socket, socketGid, home, log: (l) => process.stderr.write(`sbb-restore: ${l}\n`) });
  } catch (err) {
    // The administrator's to fix (the user is not in the socket's group): a sentence, not a stack.
    if (err instanceof SocketGroupError) {
      process.stderr.write(`${err.message}\n`);
      return 78;
    }
    throw err;
  }
  process.stderr.write(`sbb-restore ${VERSION}: listening on ${socket}, writing under ${home}\n`);
  for (const sig of ["SIGINT", "SIGTERM"] as const) process.once(sig, () => (server.close(), process.exit(0)));
  return await new Promise<number>(() => undefined);
}
