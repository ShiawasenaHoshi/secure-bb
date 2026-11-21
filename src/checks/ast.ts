// Capability and hard-sign detection by AST (spec §5.1), never by regex over
// source text. Parser: vendored acorn with acorn-jsx (.jsx) and
// @sveltejs/acorn-typescript (.ts/.tsx, no type stripping: line numbers are
// the file's own). Principle for the gate (stage 2.2): whatever the analysis
// cannot classify with confidence is a `review` finding, never silence.
import * as acorn from "../../vendor/acorn.mjs";
import jsx from "../../vendor/acorn-jsx.mjs";
import { tsPlugin } from "../../vendor/acorn-typescript.mjs";
import { excerptOf } from "./files.js";
import type { CapabilityKind, Finding } from "./types.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type N = any;

export interface Site {
  kind: CapabilityKind;
  detail: string;
  line: number;
}

export interface FileFacts {
  findings: Finding[];
  sites: Site[];
  /** Literal hosts seen in this file (url strings). */
  hosts: Array<{ host: string; line: number }>;
  /** Secret / rc / agent-config paths that reach a file-system, path or process call. */
  secretPaths: Array<{ line: number; text: string }>;
  rcPaths: Array<{ line: number; text: string }>;
  network: boolean;
  childProcess: boolean;
  execSink: boolean;
  fsWrite: boolean;
  parsed: boolean;
  /**
   * Cross-file resolution of `env-passed` (see runChecks): calls that hand the whole environment to a
   * function this file does not define, the relative imports that could define it, and, for the functions
   * this file defines, which parameters are only used to read named variables.
   */
  envCalls: Array<{ callee: string; argIndex: number; line: number }>;
  relImports: Map<string, { from: string; imported: string }>;
  envReaders: Map<string, boolean[]>;
}

// ---- module tables --------------------------------------------------------
const NETWORK_MODULES = new Set(["http", "https", "http2", "net", "tls", "dgram", "dns", "dns/promises", "undici", "ws", "axios", "node-fetch", "cross-fetch", "got", "superagent", "request", "needle", "socket.io-client", "isomorphic-ws", "node-ftp", "ssh2", "socks", "net-ping"]);
const CHILD_MODULES = new Set(["child_process", "cross-spawn", "execa", "shelljs", "node-pty", "cluster"]);
const FS_MODULES = new Set(["fs", "fs/promises", "fs-extra", "graceful-fs", "original-fs"]);
/**
 * `v8` (heap snapshots hold every secret of the process), `diagnostics_channel` (sees other plugins' requests) and `async_hooks`
 * reach the whole process without any import that looks dangerous: they count as dynamic code, not as plain built-ins.
 */
const DYNAMIC_MODULES = new Set(["vm", "module", "vm2", "isolated-vm", "worker_threads", "inspector", "inspector/promises", "repl", "wasi", "v8", "diagnostics_channel", "async_hooks"]);
/** A database handle: `ATTACH` / `load_extension` through it reach files of other plugins (threat model F2). */
const DATABASE_MODULES = new Set(["sqlite", "better-sqlite3", "sqlite3", "libsql", "@libsql/client", "node-sqlite3"]);
/** Node built-ins with no capability of their own. Any other `node:` module is an unknown: review. */
const PLAIN_BUILTINS = new Set(["assert", "assert/strict", "buffer", "console", "constants", "crypto", "events", "os", "path", "path/posix", "path/win32", "perf_hooks", "process", "punycode", "querystring", "readline", "readline/promises", "stream", "stream/promises", "stream/web", "stream/consumers", "string_decoder", "test", "timers", "timers/promises", "tty", "url", "util", "util/types", "zlib"]);
const BUILTIN_RPC = new Set(["bb-account", "connect", "mcp", "custom-instructions"]);
const GLOBAL_OBJECTS = new Set(["globalThis", "global", "window", "self"]);
const NETWORK_GLOBALS = new Set(["fetch", "WebSocket", "XMLHttpRequest", "EventSource"]);
const FS_WRITE = new Set(["writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream", "copyFile", "copyFileSync", "rename", "renameSync", "cp", "cpSync", "symlink", "symlinkSync", "outputFile", "outputFileSync", "writeSync", "chmod", "chmodSync", "fchmod"]);
const VM_SINKS = new Set(["runInThisContext", "runInNewContext", "runInContext", "compileFunction"]);
const ENV_SERIALIZERS = new Set(["JSON.stringify", "Object.entries", "Object.keys", "Object.values", "Object.fromEntries", "util.inspect", "inspect"]);
const DECODE_FUNCS = new Set(["atob", "unescape", "gunzipSync", "inflateSync", "inflateRawSync", "unzipSync", "brotliDecompressSync", "createDecipheriv", "createDecipher"]);

const BAD_ENV = /^(NODE_OPTIONS|PATH|DYLD_.*|LD_.*|GIT_.*|.*_PROXY)$/i;
const SECRET_PATH = /(^|[\\/~])\.(ssh|aws|npmrc|env|netrc|gnupg|kube|docker)(?![\w-])|\bid_(rsa|ed25519|ecdsa)\b|\.git-credentials/;
const RC_PATH = /(^|[\\/~])\.(bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin|profile)(?![\w-])|(^|[\\/])\.(claude|cursor|windsurf)([\\/]|$)|CLAUDE\.md|AGENTS\.md|\.mcp\.json|\.cursorrules|LaunchAgents/;
const PIPE_SHELL = /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/;
const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s'"`<>)\]}\\]+/gi;

// ---- parsing ----------------------------------------------------------------
const TS_EXT = /\.(m|c)?tsx?$/i;
const JSX_EXT = /\.(jsx|tsx)$/i;
const PARSERS = {
  js: acorn.Parser,
  jsx: acorn.Parser.extend(jsx()),
  ts: acorn.Parser.extend(tsPlugin() as never),
  tsx: acorn.Parser.extend(tsPlugin({ jsx: true }) as never),
};

export type Parsed = { ok: true; ast: N; code: string; note?: string } | { ok: false; reason: string };

/**
 * acorn-typescript does not accept `<K extends X>(…) =>` in .tsx. As a last resort the type
 * parameter list is blanked out (same length, newlines kept, so positions stay true). Only a
 * list with no calls, templates or arrows in it qualifies: type parameters hold no code.
 */
const GENERIC_ARROW = /(?<=(?:=|\(|,|:|\breturn|\basync)\s*)<\s*[A-Za-z_$][\w$]*\s+extends\b[^()`=;{}]*?>(?=\s*\()/g;
/**
 * In a `.ts` file (no JSX, so `<` cannot start an element) the plain form `async <T>(x: T) =>` and
 * `<T, U>(…) =>` are also type parameters; acorn-typescript rejects them after `async`.
 */
const GENERIC_ARROW_TS = /(?<=(?:=|\(|,|:|\breturn|\basync)\s*)<\s*[A-Za-z_$][\w$]*\s*(?:\bextends\b[^()`=;{}]*?|,[^()`=;{}]*?)?>(?=\s*\()/g;
const blank = (m: string): string => m.replace(/[^\n]/g, " ");

export function parseSource(rel: string, text: string, comments?: Array<{ start: number; end: number }>): Parsed {
  // Every attempt starts over, so comments seen by a failed attempt must not stay.
  const onComment = comments ? (_block: boolean, _text: string, start: number, end: number) => void comments.push({ start, end }) : undefined;
  const kind = rel.endsWith(".tsx") ? "tsx" : TS_EXT.test(rel) ? "ts" : JSX_EXT.test(rel) ? "jsx" : "js";
  // TypeScript is always an ES module; `.cjs` is a script first; everything else tries module, then script.
  const types: Array<"module" | "script"> = kind === "ts" || kind === "tsx" ? ["module"] : rel.endsWith(".cjs") ? ["script", "module"] : ["module", "script"];
  // `<K extends X>(…) =>` generic arrows trip the JSX-enabled TypeScript parser, and a `.ts` file that
  // the plain parser rejects is retried with JSX on: the second opinion costs nothing.
  const kinds: Array<keyof typeof PARSERS> = kind === "tsx" ? ["tsx", "ts"] : kind === "ts" ? ["ts", "tsx"] : [kind];
  let firstErr = "";
  for (const k of kinds) {
    for (const sourceType of types) {
      if (comments) comments.length = 0;
      try {
        const ast = (PARSERS[k] as typeof acorn.Parser).parse(text, { ecmaVersion: "latest", sourceType, locations: true, allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, onComment });
        return { ok: true, ast, code: text };
      } catch (err) {
        firstErr ||= String(err instanceof Error ? err.message : err).split("\n")[0]!.slice(0, 200);
      }
    }
  }
  if (kind === "tsx" || kind === "ts") {
    const padded = text.replace(kind === "ts" ? GENERIC_ARROW_TS : GENERIC_ARROW, blank);
    if (padded !== text) {
      for (const k of kinds) {
        if (comments) comments.length = 0;
        try {
          const ast = (PARSERS[k] as typeof acorn.Parser).parse(padded, { ecmaVersion: "latest", sourceType: "module", locations: true, allowHashBang: true, onComment });
          return { ok: true, ast, code: padded, note: "parsed with generic-arrow type parameters blanked out" };
        } catch {
          /* fall through to the original error */
        }
      }
    }
  }
  return { ok: false, reason: firstErr };
}

// ---- the walker ---------------------------------------------------------------
/** Type-only keys of TypeScript nodes: never runtime code. */
const SKIP_KEYS = new Set(["loc", "start", "end", "type", "typeAnnotation", "typeParameters", "typeArguments", "returnType", "superTypeParameters", "superTypeArguments", "implements", "range"]);
/** TS nodes that carry runtime code; every other `TS*` node is a type and is not entered. */
const RUNTIME_TS = new Set(["TSEnumDeclaration", "TSEnumBody", "TSEnumMember", "TSModuleDeclaration", "TSModuleBlock", "TSParameterProperty", "TSAsExpression", "TSSatisfiesExpression", "TSNonNullExpression", "TSTypeAssertion", "TSInstantiationExpression", "TSExportAssignment", "TSImportEqualsDeclaration", "TSExternalModuleReference"]);

/** Pre-order walk with the ancestor chain (the node itself is last). Handles JSX and TypeScript nodes. */
function walkAst(root: N, visit: (n: N, anc: N[]) => void): void {
  const anc: N[] = [];
  const rec = (n: N): void => {
    if (!n || typeof n.type !== "string") return;
    if (n.type.startsWith("TS") && !RUNTIME_TS.has(n.type)) return;
    anc.push(n);
    visit(n, anc);
    for (const k of Object.keys(n)) {
      if (SKIP_KEYS.has(k)) continue;
      const v = n[k];
      if (Array.isArray(v)) for (const x of v) rec(x);
      else if (v && typeof v === "object") rec(v);
    }
    anc.pop();
  };
  rec(root);
}

/** Is this Identifier node a *reference* (not a property name, declaration, label or specifier)? */
function isRef(n: N, parent: N | undefined): boolean {
  if (!parent) return true;
  switch (parent.type) {
    case "MemberExpression":
      return parent.object === n || parent.computed;
    case "Property":
      return parent.value === n || parent.computed;
    case "MethodDefinition":
    case "PropertyDefinition":
    case "TSEnumMember":
      return parent.value === n || parent.computed;
    case "VariableDeclarator":
      return parent.init === n;
    case "FunctionDeclaration":
    case "FunctionExpression":
    case "ArrowFunctionExpression":
      return parent.body === n;
    case "ClassDeclaration":
    case "ClassExpression":
      return parent.superClass === n;
    case "ImportSpecifier":
    case "ImportDefaultSpecifier":
    case "ImportNamespaceSpecifier":
    case "ExportSpecifier":
    case "LabeledStatement":
    case "BreakStatement":
    case "ContinueStatement":
    case "CatchClause":
    case "RestElement":
    case "ObjectPattern":
    case "ArrayPattern":
    case "TSModuleDeclaration":
      return false;
    case "AssignmentPattern":
      return parent.right === n;
    default:
      return true;
  }
}

// ---- helpers ------------------------------------------------------------------
type Consts = Map<string, string | null>;

function foldArray(n: N, consts: Consts): string[] | null {
  if (n.type === "ArrayExpression") {
    const out: string[] = [];
    for (const el of n.elements) {
      const f = el ? fold(el, consts) : null;
      if (f === null) return null;
      out.push(f);
    }
    return out;
  }
  if (n.type === "CallExpression" && n.callee.type === "MemberExpression" && !n.callee.computed) {
    const prop = n.callee.property.name;
    if (prop === "split" && n.arguments.length === 1) {
      const s = fold(n.callee.object, consts);
      const sep = fold(n.arguments[0], consts);
      return s === null || sep === null ? null : s.split(sep);
    }
    if (prop === "reverse" && n.arguments.length === 0) return foldArray(n.callee.object, consts)?.slice().reverse() ?? null;
  }
  return null;
}

/** Constant folding of string expressions: `"ev" + "al"`, templates, `String.fromCharCode(…)`, `atob("…")`, `["a","b"].join("")`. */
export function fold(n: N, consts: Consts): string | null {
  if (!n) return null;
  switch (n.type) {
    case "Literal":
      return typeof n.value === "string" ? n.value : typeof n.value === "number" || typeof n.value === "boolean" ? String(n.value) : null;
    case "TemplateLiteral": {
      let s = "";
      for (let i = 0; i < n.quasis.length; i++) {
        s += n.quasis[i].value.cooked ?? "";
        if (i < n.expressions.length) {
          const f = fold(n.expressions[i], consts);
          if (f === null) return null;
          s += f;
        }
      }
      return s;
    }
    case "BinaryExpression": {
      if (n.operator !== "+") return null;
      const l = fold(n.left, consts);
      const r = l === null ? null : fold(n.right, consts);
      return l === null || r === null ? null : l + r;
    }
    case "Identifier":
      return consts.get(n.name) ?? null;
    case "CallExpression": {
      const c = n.callee;
      if (c.type === "Identifier" && c.name === "atob" && n.arguments.length === 1) {
        const a = fold(n.arguments[0], consts);
        return a === null ? null : Buffer.from(a, "base64").toString("latin1");
      }
      if (c.type !== "MemberExpression" || c.computed) return null;
      const prop = c.property.name;
      if (c.object.type === "Identifier" && c.object.name === "String" && (prop === "fromCharCode" || prop === "fromCodePoint")) {
        const codes: number[] = [];
        for (const a of n.arguments) {
          if (a.type !== "Literal" || typeof a.value !== "number") return null;
          codes.push(a.value);
        }
        try {
          return String.fromCodePoint(...codes);
        } catch {
          return null;
        }
      }
      if (prop === "concat") {
        let s = fold(c.object, consts);
        for (const a of n.arguments) {
          const f = s === null ? null : fold(a, consts);
          if (f === null) return null;
          s += f;
        }
        return s;
      }
      if (prop === "join") {
        const arr = foldArray(c.object, consts);
        const sep = n.arguments.length === 0 ? "," : fold(n.arguments[0], consts);
        return arr === null || sep === null ? null : arr.join(sep);
      }
      if (prop === "toString" && c.object.type === "CallExpression") {
        const inner = c.object;
        const ic = inner.callee;
        if (ic.type === "MemberExpression" && !ic.computed && ic.object.name === "Buffer" && ic.property.name === "from" && inner.arguments.length >= 1) {
          const data = fold(inner.arguments[0], consts);
          const enc = inner.arguments[1] ? fold(inner.arguments[1], consts) : "utf8";
          if (data !== null && (enc === "base64" || enc === "hex" || enc === "utf8" || enc === "base64url")) return Buffer.from(data, enc as BufferEncoding).toString("latin1");
        }
        return null;
      }
      if (prop === "toLowerCase" || prop === "toUpperCase") {
        const s = fold(c.object, consts);
        return s === null ? null : prop === "toLowerCase" ? s.toLowerCase() : s.toUpperCase();
      }
      return null;
    }
    default:
      return null;
  }
}

function collectConsts(ast: N): Consts {
  const consts: Consts = new Map();
  const declared = new Map<string, number>();
  const decls: N[] = [];
  walkAst(ast, (n) => {
    if (n.type === "VariableDeclarator") decls.push(n);
  });
  for (const d of decls) if (d.id.type === "Identifier") declared.set(d.id.name, (declared.get(d.id.name) ?? 0) + 1);
  for (let pass = 0; pass < 3; pass++) {
    for (const d of decls) {
      if (d.id.type !== "Identifier" || !d.init || declared.get(d.id.name) !== 1) continue;
      const v = fold(d.init, consts);
      if (v !== null) consts.set(d.id.name, v);
    }
  }
  return consts;
}

const anyNode = (n: N, pred: (x: N) => boolean): boolean => {
  if (!n || typeof n !== "object") return false;
  if (Array.isArray(n)) return n.some((x) => anyNode(x, pred));
  if (typeof n.type === "string" && pred(n)) return true;
  for (const k of Object.keys(n)) {
    if (k === "loc" || k === "start" || k === "end" || k === "type") continue;
    const v = n[k];
    if (v && typeof v === "object" && anyNode(v, pred)) return true;
  }
  return false;
};

function normalizeModule(spec: string): string {
  return spec.replace(/^node:/, "");
}

function moduleCapability(spec: string): { kind: CapabilityKind; detail: string } | null {
  const full = normalizeModule(spec);
  const root = full.startsWith("@") ? full.split("/").slice(0, 2).join("/") : full.split("/")[0]!;
  const key = full.startsWith("@") ? root : NETWORK_MODULES.has(full) || FS_MODULES.has(full) ? full : root;
  const label = spec.startsWith("node:") || /^[a-z_]+(\/promises)?$/.test(full) ? full : root;
  if (NETWORK_MODULES.has(key)) return { kind: "network", detail: label };
  if (CHILD_MODULES.has(key)) return { kind: "child_process", detail: label };
  if (FS_MODULES.has(key)) return { kind: "fs", detail: label };
  if (DYNAMIC_MODULES.has(key)) return { kind: "dynamic_code", detail: label };
  if (DATABASE_MODULES.has(key)) return { kind: "database", detail: label };
  if (full.startsWith("@get-bb/plugin-sdk/app")) return { kind: "ui", detail: spec };
  return null;
}

// ---- the analysis -------------------------------------------------------------
const FS_FUNCS = new Set(["readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync", "createReadStream", "createWriteStream", "open", "openSync", "readdir", "readdirSync", "stat", "statSync", "lstat", "lstatSync", "access", "accessSync", "exists", "existsSync", "copyFile", "copyFileSync", "cp", "cpSync", "rename", "renameSync", "unlink", "unlinkSync", "rm", "rmSync", "mkdir", "mkdirSync", "symlink", "symlinkSync", "readlink", "realpath", "chmod", "chmodSync", "opendir", "watch", "truncate", "outputFile", "readJson", "writeJson"]);
const CHILD_FUNCS = new Set(["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"]);
const PATH_FUNCS = new Set(["join", "resolve", "normalize", "relative"]);
const SINK_NAMES = new Set([...FS_FUNCS, ...CHILD_FUNCS, ...PATH_FUNCS]);
/** Calls that change files or start processes: where an rc / agent-config path is dangerous. Reading or joining such a path is not. */
const WRITE_SINKS = new Set([...FS_WRITE, ...CHILD_FUNCS, "mkdir", "mkdirSync", "unlink", "unlinkSync", "rm", "rmSync", "truncate", "writeJson"]);
/** Calls whose result still is (a transformation of) the whole environment. */
const ENV_COPIERS = new Set(["Object.entries", "Object.keys", "Object.values", "Object.fromEntries", "Object.assign", "structuredClone", "Array.from"]);
/** Methods that keep tainted data tainted when called on it: `Object.entries(env).map(…)`. */
const TAINT_METHODS = new Set(["map", "filter", "reduce", "join", "slice", "concat", "flatMap", "sort", "toString", "toJSON"]);
/** Where a copy of the whole environment is a leak: serialisation, files, the network, a handler's response. */
const ENV_SINK_CALLS = new Set(["JSON.stringify", "String", "util.inspect", "inspect", "fetch", "send", "write", "end", "post", "put", "request", "json", "text", "respond", "reply", "writeFile", "writeFileSync", "appendFile", "appendFileSync", "writeSync", "sendBeacon", "emit"]);
/** Registering a handler: what a function inside returns goes to HTTP / RPC clients. */
const HANDLER_REGISTRARS = new Set(["route", "register", "experimental_websocket"]);
const TIMER_FUNCS = new Set(["setTimeout", "setInterval", "setImmediate"]);


// ---- SQL that reaches past the plugin's own database (threat model F2) -----------------------------------------
/** PRAGMAs that only tune the plugin's own database; any other assignment (or any schema-qualified one) is a block. */
const BENIGN_PRAGMAS = new Set(["journal_mode", "synchronous", "foreign_keys", "busy_timeout", "user_version", "cache_size", "temp_store", "wal_autocheckpoint", "secure_delete", "auto_vacuum", "recursive_triggers", "case_sensitive_like", "locking_mode", "page_size", "application_id", "mmap_size"]);

const LOAD_EXTENSION_METHODS = new Set(["loadExtension", "enableLoadExtension"]);

/** Rule ids for the dangerous SQL a string holds (empty: none). `?` stands in for a part that is not constant. */
export function sqlRules(value: string): string[] {
  const out: string[] = [];
  if (/\bATTACH\s+(?:DATABASE\s+)?[^;]*?\bAS\b/i.test(value)) out.push("sqlite-attach");
  if (/\bload_extension\b/i.test(value)) out.push("sqlite-extension");
  if (/\bVACUUM\s+(?:[\w"`\[\]]+\s+)?INTO\b/i.test(value)) out.push("sqlite-vacuum-into");
  for (const m of value.matchAll(/\bPRAGMA\s+(?:([\w"`]+)\s*\.\s*)?(\w+)\s*(=|\()/gi)) {
    const qualified = m[1] !== undefined;
    const assigns = m[3] === "=" || qualified; // `PRAGMA x(…)` of an unqualified read pragma (table_info(t)) is not an assignment
    if (assigns && (qualified || !BENIGN_PRAGMAS.has(m[2]!.toLowerCase()))) out.push("sqlite-pragma");
  }
  return out;
}

export function analyze(rel: string, parsed: { ast: N; code: string }): FileFacts {
  const { ast, code } = parsed;
  const lines = code.split("\n");
  const facts: FileFacts = { findings: [], sites: [], hosts: [], secretPaths: [], rcPaths: [], network: false, childProcess: false, execSink: false, fsWrite: false, parsed: true, envCalls: [], relImports: new Map(), envReaders: new Map() };
  const consts = collectConsts(ast);
  const lineOf = (n: N): number => n.loc?.start.line ?? 0;
  const text = (line: number): string => excerptOf(lines[line - 1] ?? "");
  const seen = new Set<string>();
  const once = (key: string): boolean => (seen.has(key) ? false : (seen.add(key), true));

  const cap = (kind: CapabilityKind, detail: string, n: N): void => {
    const line = lineOf(n);
    if (kind === "network") facts.network = true;
    if (kind === "child_process") facts.childProcess = true;
    if (once(`${kind}:${detail}:${line}`)) facts.sites.push({ kind, detail, line });
  };
  const finding = (rule: string, severity: Finding["severity"], n: N, excerpt?: string): void => {
    const line = lineOf(n);
    if (once(`f:${rule}:${line}`)) facts.findings.push({ rule, severity, file: rel, line, excerpt: excerpt ?? text(line) });
  };

  const propName = (m: N): string | null => (m.computed ? fold(m.property, consts) : m.property.type === "Identifier" ? m.property.name : m.property.type === "PrivateIdentifier" ? `#${m.property.name}` : null);
  const isGlobalObj = (n: N): boolean => n.type === "Identifier" && GLOBAL_OBJECTS.has(n.name);
  const isProcess = (n: N): boolean => (n.type === "Identifier" && n.name === "process") || (n.type === "MemberExpression" && isGlobalObj(n.object) && propName(n) === "process");
  const unwrap = (n: N): N => (n && (n.type === "TSAsExpression" || n.type === "TSSatisfiesExpression" || n.type === "TSNonNullExpression" || n.type === "TSTypeAssertion" ? unwrap(n.expression) : n.type === "ChainExpression" ? unwrap(n.expression) : n));
  const dottedName = (n0: N): string | null => {
    const n = unwrap(n0);
    if (n.type === "Identifier") return n.name;
    if (n.type === "MemberExpression") {
      const o = dottedName(n.object);
      const p = propName(n);
      return o && p ? `${o}.${p}` : null;
    }
    return null;
  };
  /** The global/property name an expression denotes when used as a callee: `eval`, `globalThis["ev"+"al"]`, `(0, eval)`. */
  const resolveName = (n0: N): string | null => {
    const n = unwrap(n0);
    if (n.type === "Identifier") return n.name;
    if (n.type === "SequenceExpression") return resolveName(n.expressions.at(-1));
    if (n.type === "MemberExpression" && isGlobalObj(n.object)) return propName(n);
    if (n.type === "MemberExpression" && propName(n) === "require") return "require";
    return null;
  };
  const propNameOf = (n0: N): string | null => {
    const n = unwrap(n0);
    return n?.type === "MemberExpression" ? propName(n) : n?.type === "Identifier" ? n.name : null;
  };
  const calleeSimpleName = (c0: N): string | null => {
    const c = unwrap(c0);
    return c.type === "Identifier" ? c.name : c.type === "MemberExpression" ? propName(c) : null;
  };

  // ---- pre-passes: module bindings, env aliases, decoded values, path literals ----
  const nodes: Array<{ n: N; anc: N[] }> = [];
  const decls: N[] = [];
  /** Functions declared in this file by name (null: the name is declared more than once, so it is not known which one runs). */
  const localFns = new Map<string, N | null>();
  const noteFn = (name: string, fn: N): void => void localFns.set(name, localFns.has(name) ? null : fn);
  walkAst(ast, (n, anc) => {
    if (n.type === "VariableDeclarator") decls.push(n);
    if (n.type === "AssignmentExpression") decls.push({ id: n.left, init: n.right, type: "VariableDeclarator" });
    if (n.type === "FunctionDeclaration" && n.id) noteFn(n.id.name, n);
    if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init && (n.init.type === "ArrowFunctionExpression" || n.init.type === "FunctionExpression")) noteFn(n.id.name, n.init);
    void anc;
  });
  void nodes;

  /**
   * Does `fn` use its `index`-th parameter only to read named variables (`env.HOME`, `env[key]`,
   * `({ HOME, PATH })`)? Then handing it the whole environment cannot leak the environment as a
   * whole. Anything else — passing it on, spreading, serialising, assigning to it — is not that.
   */
  const readsOnlyNamedProps = (fn: N, index: number): boolean => {
    if (index < 0) return false;
    const param0 = fn.params[index];
    const param = param0?.type === "AssignmentPattern" ? param0.left : param0;
    if (!param) return false;
    if (param.type === "ObjectPattern") return param.properties.every((p: N) => p.type === "Property" && !p.computed);
    if (param.type !== "Identifier") return false;
    let ok = true;
    walkAst(fn.body, (n, anc) => {
      if (!ok || n.type !== "Identifier" || n.name !== param.name) return;
      const parent = anc[anc.length - 2];
      if (!isRef(n, parent)) return;
      const grand = anc[anc.length - 3];
      const readsMember = parent?.type === "MemberExpression" && parent.object === n && !(grand && ((grand.type === "AssignmentExpression" && grand.left === parent) || grand.type === "UpdateExpression" || (grand.type === "UnaryExpression" && grand.operator === "delete")));
      if (!readsMember) ok = false;
    });
    return ok;
  };

  const requireSpec = (init0: N): string | null => {
    let init = unwrap(init0);
    if (init?.type === "AwaitExpression") init = unwrap(init.argument);
    if (!init) return null;
    if (init.type === "ImportExpression") return fold(init.source, consts);
    if (init.type === "CallExpression") {
      const c = unwrap(init.callee);
      const name = c.type === "Identifier" ? c.name : c.type === "MemberExpression" ? propName(c) : null;
      if ((name === "require" || name === "getBuiltinModule") && init.arguments[0]) return fold(init.arguments[0], consts);
    }
    return null;
  };
  /** local name -> module it was bound to (import / require / import() / getBuiltinModule) */
  const moduleBindings = new Map<string, string>();
  walkAst(ast, (n) => {
    if (n.type === "ImportDeclaration") {
      for (const sp of n.specifiers) moduleBindings.set(sp.local.name, normalizeModule(String(n.source.value)));
    }
  });
  for (const d of decls) {
    const spec = requireSpec(d.init);
    if (spec === null) continue;
    if (d.id.type === "Identifier") moduleBindings.set(d.id.name, normalizeModule(spec));
    else if (d.id.type === "ObjectPattern") for (const p of d.id.properties) if (p.type === "Property" && p.value.type === "Identifier") moduleBindings.set(p.value.name, normalizeModule(spec));
  }

  // env aliases: `const e = process.env`, `{...process.env}`, `Object.assign({}, e)`, `structuredClone(e)` …
  const envAliases = new Set<string>();
  const isEnvExpr = (n0: N): boolean => {
    const n = unwrap(n0);
    if (!n) return false;
    if (n.type === "MemberExpression") return isProcess(n.object) && propName(n) === "env";
    if (n.type === "Identifier") return envAliases.has(n.name);
    if (n.type === "ObjectExpression") return n.properties.some((p: N) => p.type === "SpreadElement" && isEnvExpr(p.argument));
    if (n.type === "CallExpression") {
      const d = dottedName(n.callee);
      return d !== null && ENV_COPIERS.has(d) && n.arguments.some(isEnvExpr);
    }
    return false;
  };
  for (let pass = 0; pass < 3; pass++) {
    for (const d of decls) {
      if (!d.init || !isEnvExpr(d.init)) continue;
      if (d.id.type === "Identifier") envAliases.add(d.id.name);
      // `const { HOME, ...rest } = process.env`: `rest` is a copy of the environment
      else if (d.id.type === "ObjectPattern") for (const p of d.id.properties) if (p.type === "RestElement" && p.argument.type === "Identifier") envAliases.add(p.argument.name);
    }
  }
  // Names bound to the global object / process (for `new Proxy(g, …)` where g = globalThis)
  const globalAliases = new Set<string>();
  const isGlobalLike = (n0: N): boolean => {
    const n = unwrap(n0);
    return !!n && (isGlobalObj(n) || isProcess(n) || (n.type === "Identifier" && (globalAliases.has(n.name) || n.name === "module")));
  };
  for (let pass = 0; pass < 2; pass++) for (const d of decls) if (d.id.type === "Identifier" && d.init && isGlobalLike(d.init)) globalAliases.add(d.id.name);

  // decode → eval: names assigned from decoders (two passes so chains resolve)
  const tainted = new Set<string>();
  const isDecodeCall = (n: N): boolean => {
    if (n.type !== "CallExpression") return false;
    const c = unwrap(n.callee);
    if (c.type === "Identifier") return DECODE_FUNCS.has(c.name);
    if (c.type !== "MemberExpression") return false;
    const prop = propName(c);
    if (prop === null) return false;
    if (DECODE_FUNCS.has(prop)) return true;
    if (c.object.type === "Identifier" && c.object.name === "String" && (prop === "fromCharCode" || prop === "fromCodePoint")) return n.arguments.some((a: N) => a.type !== "Literal");
    if (c.object.type === "Identifier" && c.object.name === "Buffer" && prop === "from" && n.arguments[1]) {
      const enc = fold(n.arguments[1], consts);
      return enc === "base64" || enc === "hex" || enc === "base64url";
    }
    return false;
  };
  const decoded = (n: N): boolean => anyNode(n, (x) => isDecodeCall(x) || (x.type === "Identifier" && tainted.has(x.name)));
  for (let pass = 0; pass < 2; pass++) for (const d of decls) if (d.id.type === "Identifier" && d.init && decoded(d.init)) tainted.add(d.id.name);

  // Path literals per variable (so `const p = home + "/.ssh/id_rsa"; readFileSync(p)` still reaches the sink).
  const pathMatches = (value: string): Array<"secret" | "rc"> => {
    const out: Array<"secret" | "rc"> = [];
    if (SECRET_PATH.test(value)) out.push("secret");
    if (RC_PATH.test(value)) out.push("rc");
    return out;
  };
  /** Strings in a subtree, including constant-folded concatenations. */
  const stringsIn = (root: N): Array<{ value: string; n: N }> => {
    const out: Array<{ value: string; n: N }> = [];
    const visit = (n: N): void => {
      if (!n || typeof n !== "object") return;
      if (Array.isArray(n)) return n.forEach(visit);
      if (typeof n.type !== "string") return;
      if (n.type.startsWith("TS") && !RUNTIME_TS.has(n.type)) return;
      if (n.type === "Literal" && typeof n.value === "string") out.push({ value: n.value, n });
      else if (n.type === "TemplateElement") out.push({ value: n.value.cooked ?? "", n });
      else if (n.type === "BinaryExpression" && n.operator === "+") {
        const f = fold(n, consts);
        if (f !== null) out.push({ value: f, n });
      }
      for (const k of Object.keys(n)) if (!SKIP_KEYS.has(k)) visit(n[k]);
    };
    visit(root);
    return out;
  };
  const varPaths = new Map<string, Array<{ kind: "secret" | "rc"; value: string }>>();
  for (const d of decls) {
    if (d.id.type !== "Identifier" || !d.init) continue;
    for (const { value } of stringsIn(d.init)) for (const kind of pathMatches(value)) varPaths.set(d.id.name, [...(varPaths.get(d.id.name) ?? []), { kind, value }]);
  }

  // ---- visitors ----------------------------------------------------------------
  const handleSpec = (specNode: N, n: N, how: "import" | "require"): void => {
    const spec = fold(specNode, consts);
    if (spec === null) {
      cap("dynamic_code", `${how}(expression)`, n);
      finding(how === "import" ? "dynamic-import" : "dynamic-require", "review", n);
      return;
    }
    if (/^(https?:|data:)/i.test(spec)) {
      finding("url-import", "block", n);
      cap("network", spec.slice(0, 80), n);
      return;
    }
    const mc = moduleCapability(spec);
    if (mc) cap(mc.kind, mc.detail, n);
    else if (spec.startsWith("node:") && !PLAIN_BUILTINS.has(normalizeModule(spec))) finding("unknown-builtin", "review", n, `unclassified Node built-in: ${spec}`);
  };

  const consumed = new Set<N>();
  let bareReported = 0;
  /** A call that touches files, paths or processes: path-like literals in its arguments are real uses, not mentions. */
  const scanSink = (call: N, simple: string): void => {
    const writes = WRITE_SINKS.has(simple);
    const child = CHILD_FUNCS.has(simple);
    const push = (kind: "secret" | "rc", n: N, value: string): void => {
      if (kind === "secret") facts.secretPaths.push({ line: lineOf(n), text: excerptOf(value, 100) });
      else if (writes) facts.rcPaths.push({ line: lineOf(n), text: excerptOf(value, 100) });
      else finding("config-path", "info", n, excerptOf(value));
    };
    for (const arg of call.arguments) {
      for (const { value, n } of stringsIn(arg)) {
        consumed.add(n);
        for (const kind of pathMatches(value)) push(kind, n, value);
        if (child && PIPE_SHELL.test(value)) finding("download-exec", "block", n, excerptOf(value));
      }
      anyNode(arg, (x) => {
        if (x.type === "Identifier" && varPaths.has(x.name)) for (const m of varPaths.get(x.name)!) push(m.kind, x, m.value);
        return false;
      });
    }
  };

  /**
   * Whole-environment use. Copying it into a child process's `env` option is ordinary and only a
   * capability; `env-dump` (block) is when the whole thing reaches a serialiser, a file, the
   * network, a template/concatenation or the response of an HTTP/RPC handler. `source` is
   * `process.env`, an alias of it or a copy; the walk follows the data upwards.
   */
  const isSinkCall = (x: N): boolean => {
    if (x.type !== "CallExpression") return false;
    const d = dottedName(x.callee);
    const simple = calleeSimpleName(x.callee);
    return (d !== null && ENV_SINK_CALLS.has(d)) || (simple !== null && ENV_SINK_CALLS.has(simple) && !CHILD_FUNCS.has(simple));
  };
  const checkEnvWhole = (source: N, anc: N[]): void => {
    let cur = source;
    for (let i = anc.length - 2; i >= 0; i--) {
      const p = anc[i];
      switch (p.type) {
        case "SpreadElement":
        case "ObjectExpression":
        case "Property":
        case "ArrayExpression":
        case "ConditionalExpression":
        case "LogicalExpression":
        case "AwaitExpression":
        case "TSAsExpression":
        case "TSNonNullExpression":
        case "TSSatisfiesExpression":
        case "ChainExpression":
          cur = p;
          continue;
        case "TemplateLiteral":
          finding("env-dump", "block", p);
          return;
        case "BinaryExpression":
          if (p.operator === "+") finding("env-dump", "block", p);
          return;
        case "ForOfStatement":
        case "ForInStatement":
          // `for (const [k, v] of Object.entries(process.env)) navigator.sendBeacon(url, k + v)`:
          // the whole environment is walked and something in the body sends data out.
          if (p.right === cur && anyNode(p.body, isSinkCall)) finding("env-dump", "block", p, "the whole environment is enumerated and the loop body sends data out");
          return;
        case "MemberExpression": {
          // `Object.entries(env).map(…)`: a method on tainted data keeps it tainted; a property read does not.
          const call = anc[i - 1];
          const method = String(propName(p));
          if (p.object === cur && call?.type === "CallExpression" && call.callee === p) {
            if (method === "forEach" || TAINT_METHODS.has(method)) {
              if (call.arguments.some((a: N) => (a.type === "ArrowFunctionExpression" || a.type === "FunctionExpression") && anyNode(a.body, isSinkCall)))
                finding("env-dump", "block", call, "the whole environment is enumerated and the callback sends data out");
            }
            if (TAINT_METHODS.has(method)) {
              cur = call;
              i--;
              continue;
            }
          }
          return;
        }
        case "CallExpression": {
          if (p.callee === cur) return;
          const d = dottedName(p.callee);
          const simple = calleeSimpleName(p.callee);
          if (d !== null && ENV_COPIERS.has(d)) {
            cur = p; // a copy: keep following it
            continue;
          }
          const local = p.callee.type === "Identifier" ? localFns.get(p.callee.name) : null;
          if (isSinkCall(p)) finding("env-dump", "block", p);
          else if (local && p.arguments.includes(cur) && readsOnlyNamedProps(local, p.arguments.indexOf(cur)))
            // a function of this file that only reads named variables from what it is given: still listed, but not a finding to review
            finding("env-passed", "info", p, `the whole environment is passed to ${simple}(…), which only reads named variables`);
          else if (!(simple !== null && CHILD_FUNCS.has(simple)) && !(d !== null && /^(Object|Array|Reflect|Number|Boolean|Math|Map|Set)\./.test(d)) && p.arguments.includes(cur)) {
            // spawn/exec/fork(env) is ordinary; handing the whole environment to any other function is not a leak we can show, but it is not nothing
            finding("env-passed", "review", p, `the whole environment is passed to ${d ?? simple ?? "a function"}(…)`);
            if (p.callee.type === "Identifier" && !local) facts.envCalls.push({ callee: p.callee.name, argIndex: p.arguments.indexOf(cur), line: lineOf(p) });
          }
          return;
        }
        case "NewExpression":
          return;
        case "ReturnStatement":
        case "ArrowFunctionExpression": {
          // The value a registered HTTP route / RPC method hands back to its caller.
          if (p.type === "ArrowFunctionExpression" && p.body !== cur) return;
          for (let j = i - 1; j >= 0; j--) {
            const q = anc[j];
            if (q.type === "CallExpression" && HANDLER_REGISTRARS.has(String(calleeSimpleName(q.callee)))) {
              finding("env-dump", "block", p, `the whole environment is returned from a handler passed to ${calleeSimpleName(q.callee)}(…)`);
              return;
            }
          }
          return;
        }
        default:
          return;
      }
    }
  };
  const handleEnvUse = (envNode: N, anc: N[]): void => {
    const parent = anc[anc.length - 2];
    const names: string[] = [];
    // `const e = process.env`: a plain alias is tracked, and reads through it are counted where they happen.
    if (parent?.type === "VariableDeclarator" && parent.init === envNode && parent.id.type === "Identifier") return;
    if (parent?.type === "MemberExpression" && parent.object === envNode) {
      const p = propName(parent);
      if (p === null) {
        names.push("*");
        finding("dynamic-access", "review", parent);
      } else names.push(p);
    } else if ((parent?.type === "VariableDeclarator" && parent.init === envNode && parent.id.type === "ObjectPattern") || (parent?.type === "AssignmentExpression" && parent.right === envNode && parent.left.type === "ObjectPattern")) {
      const pat = parent.type === "VariableDeclarator" ? parent.id : parent.left;
      for (const p of pat.properties) {
        if (p.type === "RestElement") {
          names.push("*"); // the rest copy is followed as an alias
        } else {
          const k = p.computed ? fold(p.key, consts) : p.key.type === "Identifier" ? p.key.name : String(p.key.value);
          names.push(k ?? "*");
        }
      }
    } else {
      names.push("*");
      checkEnvWhole(envNode, anc);
    }
    for (const name of names) cap("env", name, envNode);
  };

  const handleContributeEnv = (call: N): void => {
    const names = new Set<string>();
    let dynamic = false;
    anyNode(call.arguments, (x) => {
      if (x.type === "Literal" && typeof x.value === "string" && /^[A-Za-z_][A-Za-z0-9_]*$/.test(x.value) && x.value.length > 1) {
        if (/^[A-Z][A-Z0-9_]+$/.test(x.value) || BAD_ENV.test(x.value)) names.add(x.value);
      }
      if (x.type === "Property" && x.computed && fold(x.key, consts) === null) dynamic = true;
      if (x.type === "Property" && !x.computed) {
        const k = x.key.type === "Identifier" ? x.key.name : String(x.key.value);
        if (/^[A-Z][A-Z0-9_]+$/.test(k)) names.add(k);
      }
      return false;
    });
    if (dynamic) names.add("*");
    if (names.size === 0) names.add("*");
    for (const name of names) {
      cap("contribute_env", name, call);
      if (name !== "*" && BAD_ENV.test(name)) finding("contribute-env-dangerous", "block", call, `experimental_contributeEnv(… ${name} …)`);
    }
  };

  const markExec = (call: N, label: string): void => {
    facts.execSink = true;
    cap("dynamic_code", label, call);
    if (call.arguments.some((a: N) => decoded(a))) finding("decode-eval", "block", call);
  };

  const builtinCandidates: Array<{ n: N; value: string }> = [];
  const stringChecks = (value: string, n: N): void => {
    const line = lineOf(n);
    if (value.length < 3) return;
    for (const m of value.matchAll(URL_RE)) {
      try {
        facts.hosts.push({ host: new URL(m[0]).host, line });
      } catch {
        /* not a URL */
      }
    }
    if (!consumed.has(n) && bareReported < 3) {
      const kinds = pathMatches(value);
      if (kinds.length > 0) {
        bareReported++;
        finding(kinds[0] === "secret" ? "secret-path-string" : "config-path-string", "info", n, excerptOf(value));
      }
    }
    if (!consumed.has(n) && PIPE_SHELL.test(value)) finding("shell-pipe-string", "info", n, excerptOf(value));
    if (BUILTIN_RPC.has(value)) builtinCandidates.push({ n, value });
  };
  /** Text of a string expression with every non-constant part replaced by `?` (so `ATTACH '${p}' AS s` is still seen). */
  const sqlText = (n: N): string | null => {
    if (n.type === "Literal") return typeof n.value === "string" ? n.value : null;
    if (n.type === "TemplateLiteral") return n.quasis.map((q: N, i: number) => (q.value.cooked ?? "") + (i < n.expressions.length ? (fold(n.expressions[i], consts) ?? "?") : "")).join("");
    if (n.type === "BinaryExpression" && n.operator === "+") {
      const f = fold(n, consts);
      if (f !== null) return f;
      const l = sqlText(n.left) ?? (fold(n.left, consts) ?? "?");
      const r = sqlText(n.right) ?? (fold(n.right, consts) ?? "?");
      return l + r;
    }
    return null;
  };
  const sqlChecks = (n: N, extra = ""): void => {
    const v = sqlText(n);
    if (v === null) return;
    for (const rule of sqlRules(extra + v)) finding(rule, "block", n);
  };
  const rpcCall = (call: N): void => {
    for (const a of call.arguments) {
      const v = fold(a, consts);
      if (v !== null && BUILTIN_RPC.has(v)) cap("builtin_rpc", v, call);
    }
  };

  const visitors: Record<string, (n: N, anc: N[]) => void> = {
    Literal(n) {
      if (typeof n.value === "string") {
        stringChecks(n.value, n);
        sqlChecks(n);
      }
    },
    TemplateLiteral(n) {
      sqlChecks(n);
    },
    TemplateElement(n) {
      if (n.value.cooked) stringChecks(n.value.cooked, n);
    },
    BinaryExpression(n, anc) {
      if (n.operator !== "+" || anc[anc.length - 2]?.type === "BinaryExpression") return;
      sqlChecks(n);
      const f = fold(n, consts);
      if (f !== null) stringChecks(f, n);
    },
    ImportDeclaration(n) {
      handleSpec(n.source, n, "import");
      if (typeof n.source.value === "string" && /^\.\.?(\/|$)/.test(n.source.value)) {
        for (const sp of n.specifiers) {
          if (sp.type === "ImportSpecifier") facts.relImports.set(sp.local.name, { from: n.source.value, imported: sp.imported.type === "Identifier" ? sp.imported.name : String(sp.imported.value) });
          else if (sp.type === "ImportDefaultSpecifier") facts.relImports.set(sp.local.name, { from: n.source.value, imported: "default" });
        }
      }
      if (normalizeModule(String(n.source.value)) === "process") {
        for (const s of n.specifiers) if (s.type === "ImportSpecifier" && s.imported.name === "env") cap("env", "*", n);
      }
    },
    TSExternalModuleReference(n) {
      handleSpec(n.expression, n, "require");
    },
    ExportAllDeclaration(n) {
      if (n.source) handleSpec(n.source, n, "import");
    },
    ExportNamedDeclaration(n) {
      if (n.source) handleSpec(n.source, n, "import");
    },
    ImportExpression(n) {
      handleSpec(n.source, n, "import");
    },
    Identifier(n, anc) {
      const parent = anc[anc.length - 2];
      if (!isRef(n, parent)) return;
      if (n.name === "eval") {
        cap("dynamic_code", "eval", n);
        facts.execSink = true;
      }
      if (NETWORK_GLOBALS.has(n.name)) cap("network", n.name, n);
      if (n.name === "WebAssembly") {
        cap("dynamic_code", "WebAssembly", n);
        finding("webassembly", "review", n);
      }
      if (n.name === "require") {
        const isCallee = parent?.type === "CallExpression" && parent.callee === n;
        const benign = (parent?.type === "UnaryExpression" && parent.operator === "typeof") || (parent?.type === "MemberExpression" && parent.object === n && ["resolve", "main", "cache", "extensions"].includes(String(propName(parent))));
        if (!isCallee && !benign) finding("require-alias", "review", n);
      }
      if (envAliases.has(n.name)) {
        if (parent?.type === "MemberExpression" && parent.object === n) handleEnvUse(n, anc);
        else if (parent?.type !== "VariableDeclarator" || parent.init === n) handleEnvUse(n, anc);
      }
    },
    MemberExpression(n, anc) {
      const name = propName(n);
      const parent = anc[anc.length - 2];
      if (isProcess(n.object)) {
        if (name === "env") handleEnvUse(n, anc);
        else if (name === null) {
          finding("dynamic-access", "review", n);
          cap("env", "*", n);
        } else if (name === "dlopen" || name === "binding") {
          cap("dynamic_code", `process.${name}`, n);
          finding("native-load", "review", n);
        } else if (name === "mainModule") finding("require-alias", "review", n);
        else if (name === "getBuiltinModule") cap("dynamic_code", "process.getBuiltinModule", n);
      } else if (isGlobalObj(n.object)) {
        if (name === null) {
          finding("dynamic-access", "review", n);
          cap("dynamic_code", "dynamic property access", n);
        } else if (name === "eval") {
          cap("dynamic_code", "eval", n);
          facts.execSink = true;
        } else if (NETWORK_GLOBALS.has(name)) cap("network", name, n);
        else if (name === "WebAssembly") {
          cap("dynamic_code", "WebAssembly", n);
          finding("webassembly", "review", n);
        }
      } else if (n.computed && name === null && n.object.type === "Identifier" && moduleBindings.has(n.object.name)) {
        // `cp[name](…)` on a module namespace: which function is that?
        const mc = moduleCapability(moduleBindings.get(n.object.name)!);
        if (mc) {
          finding("dynamic-access", "review", n, `${text(lineOf(n))}  (computed member of ${moduleBindings.get(n.object.name)})`);
          cap(mc.kind, mc.detail, n);
        }
      }
      // Any read of `.constructor` can reach Function / AsyncFunction / GeneratorFunction / Module,
      // however the value is then used (`const F = fn.constructor; F("…")()`). The one exception:
      // `new [].constructor()` / `new (class {}).constructor()`.
      if (name === "constructor") {
        const literalOwner = unwrap(n.object).type === "ArrayExpression" || unwrap(n.object).type === "ClassExpression" || unwrap(n.object).type === "ObjectExpression";
        // Reading only the name, or comparing it (`o.constructor.name`, `o.constructor === Foo`), cannot run code.
        const harmless =
          (parent?.type === "MemberExpression" && parent.object === n && !parent.computed && ["name", "length"].includes(String(propName(parent)))) ||
          (parent?.type === "BinaryExpression" && ["==", "===", "!=", "!==", "instanceof"].includes(parent.operator)) ||
          (parent?.type === "UnaryExpression" && (parent.operator === "typeof" || parent.operator === "!"));
        if (!harmless && !(parent?.type === "NewExpression" && parent.callee === n && literalOwner)) {
          cap("dynamic_code", ".constructor", n);
          finding("dynamic-constructor", "review", n);
        }
      }
      if (n.object.type === "Identifier" && n.object.name === "bb") {
        if (name === "hosts") cap("host_artifact", "bb.hosts", n);
        if (name === "experimental_serverAccess") cap("server_access", "bb.experimental_serverAccess", n);
      }
      if (name === "experimental_serverAccess") cap("server_access", "experimental_serverAccess", n);
      // `bb.storage.database()`: a handle that runs in the gate's own process and uid, and can ATTACH its database. Any
      // `.database` property counts (`const s = bb.storage; s.database()`), and so does an unreadable key on `bb` / `storage`.
      if (name === "database") cap("database", "bb.storage.database", n);
      else if (name === null && n.computed && ((n.object.type === "Identifier" && n.object.name === "bb") || propNameOf(n.object) === "storage")) {
        cap("database", "bb.storage[?]", n);
        finding("dynamic-access", "review", n);
      }
      if (name !== null && /^(experimental_)?(contentScripts?|composer)$/.test(name)) cap("ui", name, n);
      if (name === "sendBeacon") cap("network", "navigator.sendBeacon", n);
    },
    ObjectPattern(n) {
      for (const p of n.properties) {
        if (p.type === "Property" && (p.computed ? fold(p.key, consts) : p.key.type === "Identifier" ? p.key.name : p.key.value) === "database") cap("database", "bb.storage.database", p);
        if (p.type === "Property" && (p.computed ? fold(p.key, consts) : p.key.type === "Identifier" ? p.key.name : p.key.value) === "constructor") {
          cap("dynamic_code", ".constructor", p);
          finding("dynamic-constructor", "review", p);
        }
      }
    },
    CallExpression(n) {
      const callee = unwrap(n.callee);
      const name = resolveName(callee);
      const simple = calleeSimpleName(callee);
      if (name === "eval") markExec(n, "eval");
      else if (name === "Function") markExec(n, "Function");
      if (name === "require" || (callee.type === "MemberExpression" && propName(callee) === "require")) {
        if (n.arguments[0]) handleSpec(n.arguments[0], n, "require");
      }
      if (name === "createRequire") {
        cap("dynamic_code", "createRequire", n);
        finding("require-alias", "review", n);
      }
      if (simple === "getBuiltinModule" && n.arguments[0]) handleSpec(n.arguments[0], n, "require");
      if (simple === "_load") {
        cap("dynamic_code", "Module._load", n);
        finding("module-load", "review", n);
        if (n.arguments[0]) handleSpec(n.arguments[0], n, "require");
      }
      if (simple !== null && TIMER_FUNCS.has(simple) && n.arguments[0]) {
        const a = unwrap(n.arguments[0]);
        if (a.type === "Literal" ? typeof a.value === "string" : a.type === "TemplateLiteral" || fold(a, consts) !== null) markExec(n, `${simple}(string)`);
      }
      if (callee.type === "MemberExpression") {
        const p = propName(callee);
        if (p === "eval") markExec(n, "eval"); // g.eval(…) on a proxy / alias of globalThis
        if (p !== null && VM_SINKS.has(p)) markExec(n, `vm.${p}`);
        if (p === "experimental_contributeEnv") handleContributeEnv(n);
        if (p === "route" || p === "experimental_websocket") {
          const chain = dottedName(callee.object) ?? "";
          if (/(^|\.)http$/.test(chain)) {
            const args = n.arguments;
            const path = p === "route" ? fold(args[1], consts) : fold(args[0], consts);
            const method = p === "route" ? fold(args[0], consts) : "WS";
            const optsNode = args[p === "route" ? 3 : 2];
            let auth = "local";
            if (optsNode?.type === "ObjectExpression") {
              for (const prop of optsNode.properties) if (prop.type === "Property" && !prop.computed && prop.key.name === "auth") auth = fold(prop.value, consts) ?? "dynamic";
            }
            cap("http_routes", `${method ?? "?"} ${path ?? "?"} (auth: ${auth})`, n);
          }
        }
        if (p !== null && /rpc|plugin/i.test(p)) rpcCall(n);
        // Reflect.get(globalThis, x) and friends reach the same things as globalThis[x]
        if (callee.object.type === "Identifier" && callee.object.name === "Reflect" && n.arguments[0] && isGlobalLike(n.arguments[0])) finding("dynamic-access", "review", n);
      }
      if (simple !== null && LOAD_EXTENSION_METHODS.has(simple)) finding("sqlite-extension", "block", n);
      if (simple === "pragma" && n.arguments[0]) sqlChecks(n.arguments[0], "PRAGMA ");
      if (simple !== null && FS_WRITE.has(simple)) facts.fsWrite = true;
      if (callee.type === "Identifier" && /rpc/i.test(callee.name)) rpcCall(n);
      if (simple !== null && SINK_NAMES.has(simple)) scanSink(n, simple);
    },
    NewExpression(n) {
      const name = resolveName(n.callee);
      if (name === "Proxy" && n.arguments[0] && isGlobalLike(n.arguments[0])) {
        cap("dynamic_code", "Proxy(globalThis)", n);
        finding("global-proxy", "review", n);
      }
      if (name === "Function") markExec(n, "new Function");
      else if (n.callee.type === "MemberExpression" && propName(n.callee) === "Script") markExec(n, "vm.Script");
      else if (name === "Script") markExec(n, "vm.Script");
      else if (name !== null && NETWORK_GLOBALS.has(name)) cap("network", name, n);
    },
  };

  walkAst(ast, (n, anc) => visitors[n.type]?.(n, anc));

  // `{ pluginId: "connect" }` style references to built-in plugins
  for (const { n, value } of builtinCandidates) {
    if (anyNode(ast, (x) => x.type === "Property" && x.value === n && !x.computed && /plugin/i.test(String(x.key.name ?? x.key.value)))) cap("builtin_rpc", value, n);
  }

  // download and execute: a network call and an execution sink in one file
  if (facts.network) {
    const exec = facts.sites.find((s) => s.kind === "dynamic_code" && /^(eval|Function|new Function|vm\.|setTimeout|setInterval)/.test(s.detail));
    if (exec) finding("download-exec", "block", { loc: { start: { line: exec.line } } }, `network call and ${exec.detail} in one file`);
    else if (facts.childProcess && facts.fsWrite) {
      const site = facts.sites.find((s) => s.kind === "child_process")!;
      finding("download-exec", "block", { loc: { start: { line: site.line } } }, "network call, file write and child_process in one file");
    }
  }
  // For cross-file resolution: which parameters of this file's functions only read named variables.
  for (const [name, fn] of localFns) {
    if (fn) facts.envReaders.set(name, fn.params.map((_: N, i: number) => readsOnlyNamedProps(fn, i)));
  }
  return facts;
}

export const isBadEnvName = (name: string): boolean => BAD_ENV.test(name);
