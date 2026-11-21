// Where does what a plugin reads go? Data flow «source → sink» over the code the core loads (design «Зачем»: назначение доступа по коду).
//
// Sources: what is written in conversations, the questions of agents, environment variables, other programs' credentials, the person's files.
// Sinks:   the network, another process, a file outside the plugin's own folder, a message in the person's name (dangerous);
//          a notification, a sound, the plugin's own page, a log (shown to the person); the plugin's own storage (kept).
//
// How it is worked out: a flow-insensitive points-to / taint analysis over the abstract values of the plugin's own files (assignments, fields of
// objects, arguments and returns, between functions and modules, methods of classes, callbacks), to a fixed point. No model, no network, no I/O.
//
// CONSERVATIVE, on purpose: «nowhere» is said only where no path exists. Whatever the analysis cannot follow — a call into a library it has not read,
// a computed call (`obj[k](data)`), `eval`, a budget that ran out — is «unknown», never «nowhere». A path that is found is reported even when the
// rest is unknown. Not followed: implicit flows (a branch on the data), and what a dependency does with a capability handed to it (`bb`, `sdk`).
//
// Pure: no file access (the tree scan has read it all). The plugin's checks and the guard's are the same module.
import { CHILD_FUNCS, collectConsts, credentialLabels, FS_FUNCS, FS_WRITE, fold, moduleCapability, normalizeModule, PLAIN_BUILTINS, RUNTIME_TS, SKIP_KEYS } from "./ast.ts";
import { resolveSpecifier, type GraphContext } from "./reach.ts";
import { classifySdkChain } from "./sdk-rights.ts";

/* eslint-disable @typescript-eslint/no-explicit-any */
type N = any;

export type SourceKind = "threads" | "questions" | "env" | "credentials" | "files";
export type SinkKind = "network" | "process" | "file" | "send" | "settings" | "notify" | "sound" | "ui" | "route" | "log" | "store" | "unknown";
/**
 * nowhere — no path from the source to any sink was found, and the analysis saw the whole code.
 * shown   — it reaches only what is shown to the person (a notification, a sound, the plugin's own page, a log).
 * kept    — it reaches only the plugin's own storage.
 * leaves  — it reaches a dangerous sink: the network, another program, a file outside, a message in the person's name.
 * unknown — the analysis could not tell (a library, a computed call, dynamic code, a limit).
 */
export type Verdict = "nowhere" | "shown" | "kept" | "leaves" | "unknown";

export const DANGEROUS_SINKS: ReadonlySet<SinkKind> = new Set(["network", "process", "file", "send", "settings"]);
export const SOURCE_KINDS: readonly SourceKind[] = ["threads", "questions", "env", "credentials", "files"];

export interface FlowSink {
  kind: SinkKind;
  /** Only the choice reaches it: what is sent, to where, or whether at all depends on what was read (a branch, a comparison, a length, a delay), though the content itself is not in it. */
  choice?: boolean;
  /** The host, the program, the path, the call: what the code names. */
  target?: string;
  file: string;
  line: number;
}
export interface FlowSummary {
  source: SourceKind;
  /** Environment variable names, whose credentials: what the source is, concretely. */
  detail: string[];
  verdict: Verdict;
  /** The sinks it reaches (a few, dangerous first). Empty for «nowhere». */
  sinks: FlowSink[];
  /** For «unknown»: why. */
  why?: string;
}
/** «Зачем» by the pair access → sink (second step): one short sentence, deterministic. */
export interface Purpose {
  /** The capability kinds whose line it belongs to. */
  on: string[];
  text: string;
  /** The pair it comes from (`thread.idle → sound`). */
  pair: string;
}
export interface FlowAnalysis {
  summaries: FlowSummary[];
  purposes: Purpose[];
  /** The whole fixed point was reached and all the code was read. */
  complete: boolean;
  notes: string[];
  /** The clock stopped the analysis (an emergency stop, not a verdict): nothing of it is kept, nothing counts as a right, and the check is made again later. */
  timedOut?: boolean;
}
/**
 * The part of the flow result that counts as a right: where a source reaches a dangerous sink (`flow:threads>network:stats.example`) and that it
 * could not be followed (`flow:env>unknown`). A window lets a version through only while it brings none the window lacks. Sorted, unique.
 */
export function flowTokens(flows: readonly FlowSummary[] | undefined): string[] {
  const out = new Set<string>();
  for (const f of flows ?? []) {
    const secret = f.source === "env" || f.source === "credentials";
    if (f.verdict === "leaves") for (const s of f.sinks) if (DANGEROUS_SINKS.has(s.kind) || (secret && s.kind === "route")) out.add(`flow:${f.source}>${s.choice ? "choice-" : ""}${s.kind}${s.target ? `:${s.target}` : ""}`);
    if (f.verdict === "unknown") out.add(`flow:${f.source}>unknown`);
  }
  if (out.size > 0) out.add("flow");
  return [...out].sort();
}

export interface FlowFile {
  rel: string;
  ast: N;
  code: string;
}
export interface FlowOptions {
  files: FlowFile[];
  graph: GraphContext;
  /** Sources the capabilities say the plugin has (a source the analysis does not see is «unknown», not «nowhere»). */
  expect: ReadonlySet<SourceKind>;
  /** The code builds code on the fly, loads a computed module, or reaches globals by a computed name: nothing can be said to be «nowhere». */
  dynamic: boolean;
  /** Part of the loaded code could not be read (parse failure, limits). */
  incomplete: boolean;
  /** The plugin has `ui_click` of this kind of target (for the second step). */
  navClick: boolean;
  /** The files bb itself loads (`bb.server`, `bb.app`, …): what they export goes to the core, which the analysis does not read. */
  entries?: ReadonlySet<string>;
}

// ---- tables --------------------------------------------------------------------------------------------------------------------
/** Environment variables that tell nothing worth a person's attention (the card already treats them so). */
const ORDINARY_ENV = /^(HOME|USER|LOGNAME|PATH|SHELL|LANG|LC_\w+|TZ|PWD|TMPDIR|TERM|NODE_ENV|NO_COLOR|FORCE_COLOR|CI|DEBUG|PLATFORM)$/;
/** Fields that carry an identity or a state, not what was said: reading them does not bring the content with it. */
const META_FIELD = /^(id|seq|sequence|status|kind|type|index|version|length|size|count|\w+Id|\w+Ids|\w+At|\w+Time|timestamp)$/;
const THREAD_TEXT_FIELDS = new Set(["lastAssistantText"]);
const PURE_PACKAGES = /^(react|react-dom|react\/.*|react-dom\/.*|clsx|classnames|tailwind-merge|class-variance-authority|zod|zod\/.*|nanoid|uuid|lucide-react|@radix-ui\/.*|framer-motion|motion|motion\/.*|date-fns|dayjs|hono|hono\/.*|@get-bb\/plugin-sdk|@get-bb\/plugin-sdk\/.*|@bb-kit\/core|@bb-kit\/core\/.*)$/;
const DB_MODULES = new Set(["sqlite", "better-sqlite3", "sqlite3", "libsql", "@libsql/client", "node-sqlite3"]);
const GLOBAL_OBJECTS = new Set(["globalThis", "global", "window", "self"]);
/** Global functions and namespaces that only compute: what goes in comes out, nothing is sent anywhere. */
const PURE_GLOBALS = new Set(["String", "Number", "Boolean", "parseInt", "parseFloat", "isNaN", "isFinite", "encodeURIComponent", "decodeURIComponent", "encodeURI", "decodeURI", "escape", "unescape", "BigInt", "Symbol", "structuredClone", "atob", "btoa", "Object", "Array", "JSON", "Math", "Date", "Promise", "Reflect", "Intl", "Buffer", "URL", "URLSearchParams", "TextEncoder", "TextDecoder", "Error", "TypeError", "RangeError", "RegExp", "Map", "Set", "WeakMap", "WeakSet", "Uint8Array", "Uint16Array", "Uint32Array", "Float32Array", "Float64Array", "ArrayBuffer", "DataView", "AbortController", "Headers", "FormData", "Blob", "performance", "crypto", "Proxy"]);
const TIMERS = new Set(["setTimeout", "setInterval", "setImmediate", "queueMicrotask", "requestAnimationFrame", "requestIdleCallback"]);
const EMIT_METHODS = new Set(["emit", "dispatchEvent", "postMessage", "publish", "broadcast"]);
const LISTEN_METHODS = new Set(["on", "once", "addListener", "addEventListener", "prependListener", "prependOnceListener", "subscribe", "onmessage"]);
/** Calls the analysis does not resolve that cannot carry a choice out: a sound player, a timer's handle, a clock. A list, not a guess: anything else under a branch on what was read is «не видно». */
const BENIGN_UNRESOLVED = /(^|\.)(Audio|play|pause|load|unref|ref|timeout|now|hasOwnProperty|(Object\.prototype\.)?hasOwnProperty\.call|getTime|performance\.now|AbortSignal\.timeout|AbortSignal\.any|onDispose|bb\.onDispose|close|focus|blur|hasFocus|Notification|locks\.request|settings\.(define|get|onChange)|onChange)$/;
const TIMER_CLEARS = new Set(["clearTimeout", "clearInterval", "clearImmediate", "cancelAnimationFrame", "cancelIdleCallback"]);
/** Methods of strings, arrays, maps and promises: the result is made of the receiver and the arguments. */
const PURE_METHODS = new Set(["toString", "toJSON", "toLowerCase", "toUpperCase", "toLocaleLowerCase", "toLocaleUpperCase", "trim", "trimStart", "trimEnd", "padStart", "padEnd", "slice", "substring", "substr", "split", "join", "concat", "replace", "replaceAll", "match", "matchAll", "normalize", "repeat", "charAt", "charCodeAt", "codePointAt", "indexOf", "lastIndexOf", "includes", "startsWith", "endsWith", "localeCompare", "at", "flat", "reverse", "toSorted", "toReversed", "toSpliced", "with", "test", "exec", "toFixed", "toISOString", "toLocaleString", "toLocaleDateString", "toLocaleTimeString", "getTime", "valueOf", "has", "hasOwnProperty", "isArray", "keys", "entries", "values", "get", "set", "add", "delete", "clear", "push", "pop", "shift", "unshift", "splice", "fill", "copyWithin", "next", "return", "bind", "encode", "decode", "toBase64", "readUInt8", "writeUInt8", "subarray", "update", "digest", "format", "resolve", "reject", "all", "allSettled", "race", "any", "from", "of", "assign", "freeze", "create", "entries", "fromEntries", "stringify", "parse", "defineProperty", "getPrototypeOf", "isFrozen", "min", "max", "floor", "ceil", "round", "abs", "random", "pow", "sqrt", "now", "UTC", "parseISO", "dirname", "basename", "extname", "join", "normalize", "relative", "isAbsolute", "sep", "fileURLToPath", "pathToFileURL", "homedir", "tmpdir", "hostname", "platform", "arch", "cwd", "uptime", "randomUUID", "randomBytes", "createHash", "createHmac", "timingSafeEqual", "on", "once", "off", "addEventListener", "removeEventListener", "json", "text", "blob", "arrayBuffer", "formData", "clone", "abort"]);
const HOF_METHODS = new Set(["map", "forEach", "filter", "find", "findIndex", "findLast", "findLastIndex", "some", "every", "flatMap", "reduce", "reduceRight", "sort", "then", "catch", "finally", "toSorted", "replace", "replaceAll", "mapValues", "each"]);
/** Programs that show or say something to the person instead of doing a job with the data. */
const NOTIFY_PROGRAMS = new Set(["notify-send", "terminal-notifier", "say", "kdialog", "zenity", "growlnotify", "msg", "toast"]);
const SOUND_PROGRAMS = new Set(["afplay", "paplay", "aplay", "play", "mpg123", "mpv", "ffplay", "cvlc", "canberra-gtk-play", "powershell-sound"]);
const OSASCRIPT_DISPLAY = /\bdisplay\s+(notification|dialog|alert)\b/i;
const URL_ATTRS = new Set(["src", "srcSet", "srcset", "href", "action", "formAction", "poster", "data", "background", "ping", "cite", "manifest"]);
/** Events a plugin registers for; what each says, for the second step. */
const EVENT_PURPOSE: Record<string, string> = {
  "thread.idle": "чтобы сообщить вам, когда агент закончил",
  "thread.failed": "чтобы сообщить вам, когда у агента случилась ошибка",
  "thread.active": "чтобы сообщить вам, когда агент начал работу",
  "interaction.pending": "чтобы сообщить вам, когда агент ждёт вашего ответа или разрешения",
};

const MAX_PASSES = 40;
/** About a second on an ordinary machine: the guard's evaluation has 3.5 s for all of its checks. A plugin that needs more is «из кода не видно». */
const MAX_VISITS = 4_000_000;
/** The same limit in time, for a slow machine: it only ever turns a verdict into the conservative one. */
const MAX_MS = 2_500;
const MAX_CELL = 600;

// ---- the engine ----------------------------------------------------------------------------------------------------------------
interface FileCtx {
  rel: string;
  index: number;
  ast: N;
  consts: Map<string, string | null>;
  /** Declared exactly once: its initializer (for paths and credential names). */
  inits: Map<string, N>;
  sdkAlias: Map<string, string>;
  module: Scope;
  /** Uses CommonJS exports: what it exports is not followed. */
  cjs: boolean;
}
interface Scope {
  id: number;
  parent: Scope | null;
  names: Set<string>;
  fn: FnInfo | null;
  /** A class body or field initializer: what `this` is there. */
  thisTok: string | null;
  cls: ClassInfo | null;
  file: FileCtx;
}
interface FnInfo {
  id: number;
  node: N;
  file: FileCtx;
  scope: Scope;
  arrow: boolean;
  params: N[];
  restIndex: number;
  isModule: boolean;
}
interface ClassInfo {
  id: number;
  node: N;
  scope: Scope;
  file: FileCtx;
}
interface SinkSite {
  kind: SinkKind;
  fnId: number;
}

const unwrap = (n: N): N => (n && (n.type === "TSAsExpression" || n.type === "TSSatisfiesExpression" || n.type === "TSNonNullExpression" || n.type === "TSTypeAssertion" || n.type === "ChainExpression" || n.type === "ParenthesizedExpression" ? unwrap(n.expression) : n));
const isFnNode = (n: N): boolean => n && (n.type === "FunctionDeclaration" || n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression");
const R_CELL = "R";
const EXC_CELL = "EXC";

class Engine {
  private cells = new Map<string, Set<string>>();
  private dirty = false;
  private record = false;
  /** The data the branch we are in depends on (`k:` labels): what is called under it is called, or not, by what was read. */
  private ctl = new Set<string>();
  private timedOut = false;
  /** Choices made by a wait (a timer, a promise that resolves after one): what follows an `await` of it runs when that choice says. */
  private pendingK = new Set<string>();
  /** Phase two: what a call the analysis cannot resolve does to its arguments. Not before the callees are settled, or a callee resolved later would stay tainted by the guess. */
  private fallback = false;
  private visits = 0;
  private overflow = false;
  private aborted = false;
  private idSeq = 0;
  private ids = new WeakMap<object, number>();
  private fns: FnInfo[] = [];
  private fnByNode = new Map<N, FnInfo>();
  private classByNode = new Map<N, ClassInfo>();
  private files: FileCtx[] = [];
  private fileByRel = new Map<string, FileCtx>();
  private fieldNames = new Map<string, Set<string>>();
  private flows = new Map<string, { label: string; sink: FlowSink }>();
  private seen = new Map<SourceKind, Set<number>>();
  private sinkSites: SinkSite[] = [];
  private edges = new Map<number, Set<number>>();
  private triggers: Array<{ event: string; fns: number[] }> = [];
  private escaped = new Set<string>();
  readonly notes: string[] = [];
  /** A construct the analysis does not follow was met (CommonJS exports, a cell too large): nothing is «nowhere». */
  private blind: string | null = null;

  private readonly o: FlowOptions;
  constructor(o: FlowOptions) {
    this.o = o;
  }

  // ---- cells and values ---------------------------------------------------------------------------------------------------------
  private cell(k: string): Set<string> {
    let s = this.cells.get(k);
    if (!s) this.cells.set(k, (s = new Set()));
    return s;
  }
  private add(k: string, v: Iterable<string>): void {
    const s = this.cell(k);
    for (const x of v) {
      if (s.has(x)) continue;
      if (s.size >= MAX_CELL) {
        this.overflow = true;
        break;
      }
      s.add(x);
      this.dirty = true;
    }
  }
  /** The choice a value makes: what it says depends on what was read (a comparison, a length, a condition), the content itself is not in it. */
  private kOf(v: Iterable<string>): Set<string> {
    const out = new Set<string>();
    for (const l of this.labels(v)) out.add(l.startsWith("t:") ? `k:${l.slice(2)}` : l);
    return out;
  }
  private under<T>(extra: Iterable<string>, f: () => T): T {
    const saved = this.ctl;
    const next = new Set(saved);
    for (const x of extra) next.add(x);
    this.ctl = next;
    try {
      return f();
    } finally {
      this.ctl = saved;
    }
  }
  private excChoice(): string[] {
    return [...this.cell(EXC_CELL)].filter((x) => x.startsWith("k:"));
  }
  private ctlV(v: Set<string>): Set<string> {
    return this.ctl.size > 0 ? new Set([...v, ...this.ctl]) : v;
  }
  private idOf(n: object): number {
    let i = this.ids.get(n);
    if (i === undefined) this.ids.set(n, (i = ++this.idSeq));
    return i;
  }
  private fieldKey(tok: string, name: string): string {
    return `fld:${tok}.${name}`;
  }
  private setField(tok: string, name: string, v: Iterable<string>): void {
    let names = this.fieldNames.get(tok);
    if (!names) this.fieldNames.set(tok, (names = new Set()));
    names.add(name);
    this.add(this.fieldKey(tok, name), this.ctl.size > 0 ? [...v, ...this.ctl] : v);
  }
  private readField(tok: string, name: string, out: Set<string>, depth = 0): void {
    if (depth > 8) return;
    this.tick();
    const direct = this.cells.get(this.fieldKey(tok, name));
    if (direct) for (const x of direct) out.add(x);
    const star = this.cells.get(this.fieldKey(tok, "*"));
    if (star) for (const x of star) out.add(x);
    const protos = this.cells.get(`proto:${tok}`);
    if (protos) for (const p of protos) this.readField(p, name, out, depth + 1);
    if (tok.startsWith("ns:")) {
      const stars = this.cells.get(`${this.fieldKey(tok, "*star")}`);
      if (stars) for (const p of stars) this.readField(p, name, out, depth + 1);
    }
  }
  private allFields(tok: string, out: Set<string>, depth = 0): void {
    if (depth > 8) return;
    this.tick();
    for (const name of this.fieldNames.get(tok) ?? []) {
      const c = this.cells.get(this.fieldKey(tok, name));
      if (c) for (const x of c) out.add(x);
    }
    for (const p of this.cells.get(`proto:${tok}`) ?? []) this.allFields(p, out, depth + 1);
  }
  /** What a read of a property of `v` gives. */
  private member(v: Iterable<string>, name: string | null): Set<string> {
    const out = new Set<string>();
    for (const t of v) {
      if (t === "x:env") {
        if (name === null) out.add("t:env:*");
        else if (!ORDINARY_ENV.test(name)) out.add(`t:env:${name}`);
        continue;
      }
      if (t.startsWith("t:") || t.startsWith("k:")) {
        // the length of what was read is a choice made by it, not its content
        if (name !== null && /^(length|size|count)$/.test(name)) for (const x of this.kOf([t])) out.add(x);
        else if (name === null || !META_FIELD.test(name)) out.add(t);
      } else if (t.startsWith("x:")) {
        out.add(t);
      } else if (t.startsWith("o:") || t.startsWith("c:") || t.startsWith("f:") || t.startsWith("ns:")) {
        if (name !== null && /^(length|size|count)$/.test(name)) {
          for (const x of this.kOf([t])) out.add(x);
          this.readField(t, name, out);
        } else if (name === null) {
          this.allFields(t, out);
          this.readField(t, "*", out);
        } else this.readField(t, name, out);
      }
    }
    return out;
  }
  /** The taints inside a value, deep: what a sink that gets it would carry out. */
  private labels(v: Iterable<string>, out = new Set<string>(), seen = new Set<string>(), depth = 0): Set<string> {
    for (const t of v) {
      this.tick();
      if (t.startsWith("t:") || t.startsWith("k:")) out.add(t);
      else if (t === "x:env") out.add("t:env:*");
      else if ((t.startsWith("o:") || t.startsWith("c:") || t.startsWith("ns:")) && depth < 7 && !seen.has(t)) {
        seen.add(t);
        const inner = new Set<string>();
        this.allFields(t, inner);
        this.labels(inner, out, seen, depth + 1);
      }
    }
    return out;
  }
  /** Tokens that survive turning the value into text/numbers: the taints, deep, and nothing else. */
  private flat(v: Iterable<string>): Set<string> {
    return this.labels(v);
  }
  private tokens(v: Iterable<string>, prefix: string): string[] {
    const out: string[] = [];
    for (const t of v) if (t.startsWith(prefix)) out.push(t);
    return out;
  }

  // ---- scopes ---------------------------------------------------------------------------------------------------------------------
  private newScope(parent: Scope | null, file: FileCtx, extra: Partial<Scope> = {}): Scope {
    return { id: ++this.idSeq, parent, names: new Set(), fn: null, thisTok: null, cls: null, file, ...extra };
  }
  private lookup(sc: Scope, name: string): string | null {
    for (let s: Scope | null = sc; s; s = s.parent) if (s.names.has(name)) return `v:${s.id}:${name}`;
    return null;
  }
  private patNames(p: N, out: string[] = []): string[] {
    if (!p) return out;
    switch (p.type) {
      case "Identifier":
        out.push(p.name);
        break;
      case "ObjectPattern":
        for (const x of p.properties) this.patNames(x.type === "RestElement" ? x.argument : x.value, out);
        break;
      case "ArrayPattern":
        for (const x of p.elements) this.patNames(x, out);
        break;
      case "AssignmentPattern":
        this.patNames(p.left, out);
        break;
      case "RestElement":
        this.patNames(p.argument, out);
        break;
      case "TSParameterProperty":
        this.patNames(p.parameter, out);
        break;
    }
    return out;
  }
  private enclosingFn(sc: Scope): FnInfo | null {
    for (let s: Scope | null = sc; s; s = s.parent) if (s.fn) return s.fn;
    return null;
  }

  // ---- collecting: scopes, functions, classes -----------------------------------------------------------------------------------
  private children(n: N, f: (c: N) => void): void {
    for (const k of Object.keys(n)) {
      if (SKIP_KEYS.has(k)) continue;
      const v = n[k];
      if (Array.isArray(v)) {
        for (const x of v) if (x && typeof x.type === "string") f(x);
      } else if (v && typeof v === "object" && typeof v.type === "string") f(v);
    }
  }
  private collectFile(file: FileCtx): void {
    const decls: N[] = [];
    const initCount = new Map<string, number>();
    const initOf = new Map<string, N>();
    const makeFn = (n: N, parent: Scope, isModule = false): FnInfo => {
      const sc = this.newScope(parent, file);
      const params: N[] = isModule ? [] : n.params ?? [];
      const fn: FnInfo = { id: ++this.idSeq, node: n, file, scope: sc, arrow: n.type === "ArrowFunctionExpression", params, restIndex: params.findIndex((p) => p?.type === "RestElement"), isModule };
      sc.fn = fn;
      this.fns.push(fn);
      this.fnByNode.set(n, fn);
      for (const p of params) for (const name of this.patNames(p)) sc.names.add(name);
      if (n.type === "FunctionExpression" && n.id) sc.names.add(n.id.name);
      return fn;
    };
    const visit = (n: N, sc: Scope): void => {
      if (!n || typeof n.type !== "string") return;
      if (n.type.startsWith("TS") && !RUNTIME_TS.has(n.type)) return;
      switch (n.type) {
        case "FunctionDeclaration":
        case "FunctionExpression":
        case "ArrowFunctionExpression": {
          if (n.type === "FunctionDeclaration" && n.id) sc.names.add(n.id.name);
          const fn = makeFn(n, sc);
          for (const p of fn.params) visit(p, fn.scope);
          visit(n.body, fn.scope);
          return;
        }
        case "ClassDeclaration":
        case "ClassExpression": {
          if (n.type === "ClassDeclaration" && n.id) sc.names.add(n.id.name);
          const ci: ClassInfo = { id: ++this.idSeq, node: n, scope: null as never, file };
          ci.scope = this.newScope(sc, file, { thisTok: `o:${ci.id}`, cls: ci });
          this.classByNode.set(n, ci);
          if (n.superClass) visit(n.superClass, sc);
          for (const m of n.body.body) {
            if (m.computed && m.key) visit(m.key, ci.scope);
            if (m.type === "MethodDefinition") visit(m.value, ci.scope);
            else if (m.type === "PropertyDefinition") visit(m.value, ci.scope);
            else if (m.type === "StaticBlock") for (const s of m.body) visit(s, ci.scope);
          }
          return;
        }
        case "VariableDeclaration":
          for (const d of n.declarations) {
            for (const name of this.patNames(d.id)) sc.names.add(name);
            if (d.id.type === "Identifier" && d.init) {
              initCount.set(d.id.name, (initCount.get(d.id.name) ?? 0) + 1);
              initOf.set(d.id.name, d.init);
            }
            decls.push(d);
          }
          break;
        case "AssignmentExpression":
          decls.push({ id: n.left, init: n.right });
          break;
        case "ImportDeclaration":
          for (const s of n.specifiers) sc.names.add(s.local.name);
          break;
        case "CatchClause":
          if (n.param) for (const name of this.patNames(n.param)) sc.names.add(name);
          break;
        case "AssignmentPattern":
          break;
      }
      this.children(n, (c) => visit(c, sc));
    };
    const mod = this.newScope(null, file);
    file.module = mod;
    const modFn = makeFn(file.ast, mod, true);
    mod.fn = modFn;
    visit(file.ast, mod);
    for (const [k, c] of initCount) if (c === 1) file.inits.set(k, initOf.get(k));
    // bb's own API under another name: `const sdk = useSdk()`, `const { threads } = sdk`, `const t = bb.sdk.threads`
    for (let pass = 0; pass < 3; pass++) {
      for (const d of decls) {
        if (!d.init) continue;
        const c = this.sdkChainRaw(d.init, file);
        if (c === null) continue;
        if (d.id.type === "Identifier") {
          if (c !== d.id.name) file.sdkAlias.set(d.id.name, c);
        } else if (d.id.type === "ObjectPattern") {
          for (const p of d.id.properties) {
            if (p.type !== "Property" || p.computed) continue;
            const key = p.key.type === "Identifier" ? p.key.name : String(p.key.value);
            const local = p.value.type === "Identifier" ? p.value.name : p.value.type === "AssignmentPattern" && p.value.left.type === "Identifier" ? p.value.left.name : null;
            if (local !== null) file.sdkAlias.set(local, `${c}.${key}`);
          }
        }
      }
    }
    // The names of function and class declarations hold them from the start (they are hoisted).
    const hoist = (n: N, sc: Scope): void => {
      if (!n || typeof n.type !== "string") return;
      if (n.type.startsWith("TS") && !RUNTIME_TS.has(n.type)) return;
      const inner = isFnNode(n) ? this.fnByNode.get(n)?.scope : n.type === "ClassDeclaration" || n.type === "ClassExpression" ? sc : undefined;
      if (n.type === "FunctionDeclaration" && n.id) this.add(`v:${sc.id}:${n.id.name}`, [`f:${this.fnByNode.get(n)!.id}`]);
      if (n.type === "ClassDeclaration" && n.id) this.add(`v:${sc.id}:${n.id.name}`, [`c:${this.classByNode.get(n)!.id}`]);
      this.children(n, (c) => hoist(c, inner ?? sc));
    };
    hoist(file.ast, mod);
  }

  // ---- bb's API: the dotted name of a callee, with aliases resolved ---------------------------------------------------------------
  private propName(m: N, file: FileCtx): string | null {
    if (m.computed) return fold(m.property, file.consts);
    return m.property.type === "Identifier" ? m.property.name : null;
  }
  private sdkChainRaw(n0: N, file: FileCtx): string | null {
    const n = unwrap(n0);
    if (!n) return null;
    if (n.type === "Identifier") return file.sdkAlias.get(n.name) ?? n.name;
    if (n.type === "MemberExpression") {
      const o = this.sdkChainRaw(n.object, file);
      const p = this.propName(n, file);
      return o && p ? `${o}.${p}` : null;
    }
    if (n.type === "CallExpression") {
      const c = unwrap(n.callee);
      return (c.type === "Identifier" ? c.name : c.type === "MemberExpression" ? this.propName(c, file) : null) === "useSdk" ? "sdk" : null;
    }
    if (n.type === "AwaitExpression") return this.sdkChainRaw(n.argument, file);
    return null;
  }
  private unboundName(n0: N, sc: Scope): string | null {
    const n = unwrap(n0);
    if (n?.type === "Identifier") return this.lookup(sc, n.name) === null ? n.name : null;
    if (n?.type === "MemberExpression" && !n.computed && n.property.type === "Identifier" && unwrap(n.object).type === "Identifier" && GLOBAL_OBJECTS.has(unwrap(n.object).name) && this.lookup(sc, unwrap(n.object).name) === null) return n.property.name;
    return null;
  }
  private isProcessEnv(n: N, sc: Scope): boolean {
    if (n.type !== "MemberExpression") return false;
    const o = unwrap(n.object);
    const p = this.propName(n, sc.file);
    if (p !== "env") return false;
    if (o.type === "Identifier") return (o.name === "process" || o.name === "Bun") && this.lookup(sc, o.name) === null;
    if (o.type === "MemberExpression") return this.propName(o, sc.file) === "process" && unwrap(o.object).type === "Identifier" && GLOBAL_OBJECTS.has(unwrap(o.object).name);
    if (o.type === "MetaProperty") return true;
    return false;
  }

  // ---- strings, paths, hosts, programs ----------------------------------------------------------------------------------------------
  private strings(root: N, file: FileCtx, out: string[] = [], depth = 0): string[] {
    const visit = (n: N): void => {
      if (!n || typeof n !== "object") return;
      if (Array.isArray(n)) return n.forEach(visit);
      if (typeof n.type !== "string") return;
      if (n.type.startsWith("TS") && !RUNTIME_TS.has(n.type)) return;
      if (n.type === "Literal" && typeof n.value === "string") out.push(n.value);
      else if (n.type === "TemplateElement") out.push(n.value.cooked ?? "");
      else if (n.type === "Identifier" && depth < 3) {
        const init = file.inits.get(n.name);
        if (init) this.strings(init, file, out, depth + 1);
      } else if (n.type === "BinaryExpression" && n.operator === "+") {
        const f = fold(n, file.consts);
        if (f !== null) out.push(f);
      }
      for (const k of Object.keys(n)) if (!SKIP_KEYS.has(k)) visit(n[k]);
    };
    visit(root);
    return out;
  }
  private foldPrefix(n0: N, file: FileCtx, depth = 0): { text: string; complete: boolean } {
    const n = unwrap(n0);
    const whole = n ? fold(n, file.consts) : null;
    if (whole !== null) return { text: whole, complete: true };
    if (!n) return { text: "", complete: false };
    if (n.type === "Identifier") {
      const init = file.inits.get(n.name);
      return init && init !== n ? this.foldPrefix(init, file) : { text: "", complete: false };
    }
    if (n.type === "TemplateLiteral") {
      let text = "";
      for (let i = 0; i < n.quasis.length; i++) {
        text += n.quasis[i].value.cooked ?? "";
        if (i < n.expressions.length) {
          const f = fold(n.expressions[i], file.consts);
          if (f === null) return { text, complete: false };
          text += f;
        }
      }
      return { text, complete: true };
    }
    if (n.type === "BinaryExpression" && n.operator === "+") {
      const l = this.foldPrefix(n.left, file, depth);
      if (!l.complete) return l;
      const r = this.foldPrefix(n.right, file, depth);
      return { text: l.text + r.text, complete: r.complete };
    }
    // `rendererHttpUrl(id, path)`: the text a function of this file builds is what its single `return` says (its parameters are not known)
    if (n.type === "CallExpression" && unwrap(n.callee).type === "Identifier" && depth < 3) {
      const name = unwrap(n.callee).name as string;
      let fnNode = this.fnDeclByName(file, name) ?? (isFnNode(file.inits.get(name)) ? file.inits.get(name) : null);
      // imported: the only function of that name among the plugin's own files
      if (!fnNode) {
        const same = this.fns.filter((f) => f.node.type === "FunctionDeclaration" && f.node.id?.name === name);
        if (same.length === 1) fnNode = same[0]!.node;
      }
      const fn = fnNode ? this.fnByNode.get(fnNode) : undefined;
      if (fn) file = fn.file;
      if (fn && fnNode.body.type !== "BlockStatement") return this.foldPrefix(fnNode.body, file, depth + 1);
      if (fn) {
        const rets: N[] = [];
        const find = (x: N): void => {
          if (!x || typeof x.type !== "string" || isFnNode(x)) return;
          if (x.type === "ReturnStatement" && x.argument) rets.push(x.argument);
          this.children(x, find);
        };
        find(fnNode.body);
        if (rets.length === 1) return this.foldPrefix(rets[0], file, depth + 1);
      }
    }
    if (n.type === "NewExpression" && n.callee.type === "Identifier" && n.callee.name === "URL" && n.arguments[0]) {
      const u = this.foldPrefix(n.arguments[0], file);
      return /^[a-z][a-z0-9+.-]*:/i.test(u.text) || !n.arguments[1] ? u : this.foldPrefix(n.arguments[1], file);
    }
    return { text: "", complete: false };
  }
  private hostOfText(t: { text: string; complete: boolean }): string | null {
    const m = /^(?:https?|wss?|ftp):\/\/(?:[^/?#@\s]*@)?([^/?#\s]+)([/?#]|$)/i.exec(t.text);
    if (!m || (m[2] === "" && !t.complete)) return null;
    return m[1]!.toLowerCase();
  }
  private hostOfAddress(arg0: N | undefined, file: FileCtx): string | null {
    const arg = arg0 ? unwrap(arg0) : null;
    if (!arg) return null;
    if (arg.type === "ObjectExpression") {
      for (const p of arg.properties) {
        if (p.type !== "Property" || p.computed) continue;
        const k = p.key.type === "Identifier" ? p.key.name : String(p.key.value);
        if (k === "hostname" || k === "host") {
          const f = fold(p.value, file.consts);
          if (f !== null && f !== "") return f.toLowerCase();
        }
        if (k === "href" || k === "url") {
          const h = this.hostOfText(this.foldPrefix(p.value, file));
          if (h) return h;
        }
      }
      return null;
    }
    return this.hostOfText(this.foldPrefix(arg, file));
  }
  /** The address is the plugin's own route (`/api/…`, no host): it stays inside bb. */
  private isOwnRoute(arg0: N | undefined, file: FileCtx): boolean {
    if (!arg0) return false;
    const t = this.foldPrefix(arg0, file).text;
    return /^\/(?!\/)/.test(t) || /^\.\.?\//.test(t);
  }
  /** Is this expression a path inside the plugin's own folders (its code, its data directory)? */
  private pathIsOwn(n0: N, sc: Scope, depth = 0): boolean {
    const n = unwrap(n0);
    if (!n || depth > 5) return false;
    const file = sc.file;
    switch (n.type) {
      case "Identifier": {
        if (n.name === "__dirname" || n.name === "__filename") return this.lookup(sc, n.name) === null;
        const init = file.inits.get(n.name);
        return init !== undefined && init !== n0 && this.pathIsOwn(init, sc, depth + 1);
      }
      case "MemberExpression": {
        if (n.object.type === "MetaProperty") return true; // import.meta.url / dirname / filename
        const chain = this.sdkChainRaw(n, file) ?? "";
        if (/(^|\.)(dataDir|pluginDir|storageDir|dataPath|storagePath|assetsDir|stateDir|pluginRoot|rootDir)$/.test(chain)) return true;
        const p = this.propName(n, file);
        return (p === "pathname" || p === "href") && this.pathIsOwn(n.object, sc, depth + 1);
      }
      case "NewExpression":
        return n.callee.type === "Identifier" && n.callee.name === "URL" && n.arguments.length >= 2 && this.pathIsOwn(n.arguments[1], sc, depth + 1);
      case "CallExpression": {
        const c = unwrap(n.callee);
        const name = c.type === "Identifier" ? c.name : c.type === "MemberExpression" ? this.propName(c, file) : null;
        if (name === "fileURLToPath" || name === "dirname") return n.arguments.length > 0 && this.pathIsOwn(n.arguments[0], sc, depth + 1);
        if (name === "join" || name === "resolve" || name === "normalize") {
          if (n.arguments.length === 0) return false;
          let own = false;
          for (const a of n.arguments) {
            if (this.pathIsOwn(a, sc, depth + 1)) own = true;
            else {
              const f = fold(a, file.consts);
              if (f === null || /^(\/|~|[A-Za-z]:)/.test(f) || /(^|[\\/])\.\.([\\/]|$)/.test(f)) return false;
            }
          }
          return own;
        }
        if (c.type === "Identifier") {
          const fnNode = file.inits.get(c.name);
          const decl = this.fnDeclByName(file, c.name) ?? (isFnNode(fnNode) ? fnNode : null);
          if (decl) return this.returnsOwn(decl, sc, depth + 1);
        }
        return false;
      }
      case "TemplateLiteral": {
        let own = false;
        for (const e of n.expressions) {
          if (this.pathIsOwn(e, sc, depth + 1)) own = true;
          else if (fold(e, file.consts) === null) return false;
        }
        const head = n.quasis[0]?.value.cooked ?? "";
        if (/^(\/|~|[A-Za-z]:)/.test(head) && !own) return false;
        return own && !n.quasis.some((q: N) => /(^|[\\/])\.\.([\\/]|$)/.test(q.value.cooked ?? ""));
      }
      case "BinaryExpression":
        return n.operator === "+" && (this.pathIsOwn(n.left, sc, depth + 1) || this.pathIsOwn(n.right, sc, depth + 1)) && [n.left, n.right].every((x) => this.pathIsOwn(x, sc, depth + 1) || (fold(x, file.consts) !== null && !/\.\./.test(fold(x, file.consts)!)));
      case "ConditionalExpression":
        return this.pathIsOwn(n.consequent, sc, depth + 1) && this.pathIsOwn(n.alternate, sc, depth + 1);
      case "AwaitExpression":
        return this.pathIsOwn(n.argument, sc, depth + 1);
      default:
        return false;
    }
  }
  private fnDeclByName(file: FileCtx, name: string): N | null {
    for (const fn of this.fns) if (fn.file === file && fn.node.type === "FunctionDeclaration" && fn.node.id?.name === name) return fn.node;
    return null;
  }
  private returnsOwn(fnNode: N, sc: Scope, depth: number): boolean {
    const fn = this.fnByNode.get(fnNode);
    if (!fn) return false;
    const rets: N[] = [];
    if (fnNode.body.type !== "BlockStatement") rets.push(fnNode.body);
    else {
      const find = (n: N): void => {
        if (!n || typeof n.type !== "string" || isFnNode(n)) return;
        if (n.type === "ReturnStatement" && n.argument) rets.push(n.argument);
        this.children(n, find);
      };
      find(fnNode.body);
    }
    return rets.length > 0 && rets.every((r) => this.pathIsOwn(r, fn.scope, depth + 1));
  }
  private credLabelsOf(argNodes: N[], file: FileCtx): string[] {
    const pieces = argNodes.flatMap((a) => this.strings(a, file));
    return [...new Set([...pieces.flatMap(credentialLabels), ...credentialLabels(pieces.join("/"))])];
  }
  /** The program a call starts, by the name the code gives. */
  private programOf(simple: string, argNodes: N[], file: FileCtx): string | null {
    if (simple === "fork") return "node";
    const t = argNodes[0] ? this.foldPrefix(argNodes[0], file) : { text: "", complete: false };
    const shellLine = simple === "exec" || simple === "execSync";
    const word = shellLine ? /^\s*(?:(?:\w+=\S*)\s+)*("[^"]+"|'[^']+'|[^\s;&|]+)(\s|$)/.exec(t.text) : null;
    const text = shellLine ? (word && (word[2] !== "" || t.complete) ? word[1]!.replace(/^["']|["']$/g, "") : "") : t.complete ? t.text : "";
    if (text === "") return null;
    return text.split(/[\\/]/).pop()!.replace(/\.exe$/i, "");
  }

  // ---- sinks -----------------------------------------------------------------------------------------------------------------------
  private sink(kind: SinkKind, target: string | undefined, vals: Iterable<Iterable<string>>, n: N, sc: Scope, noChoice = false): void {
    const labels = new Set<string>();
    for (const v of vals) this.labels(v, labels);
    for (const l of this.ctl) labels.add(l);
    if (noChoice) for (const l of labels) if (l.startsWith("k:")) labels.delete(l);
    if (kind === "ui" || kind === "store" || kind === "route") this.add(R_CELL, labels);
    if (!this.record) return;
    const fnId = this.enclosingFn(sc)?.id ?? -1;
    if (kind === "notify" || kind === "sound") this.sinkSites.push({ kind, fnId });
    if (labels.size === 0) return;
    this.addFlows(labels, kind, target, sc.file.rel, n?.loc?.start.line ?? 0);
  }
  private addFlows(labels: Iterable<string>, kind: SinkKind, target: string | undefined, file: string, line: number): void {
    for (const label of labels) {
      // A choice that reaches a notification, a sound, the page, a log or the plugin's own storage sends nothing out.
      if (label.startsWith("k:") && !DANGEROUS_SINKS.has(kind) && kind !== "unknown") continue;
      const key = `${label}|${kind}|${target ?? ""}`;
      const prev = this.flows.get(key);
      if (!prev || file < prev.sink.file || (file === prev.sink.file && line < prev.sink.line)) this.flows.set(key, { label, sink: { kind, ...(target !== undefined ? { target } : {}), file, line } });
    }
  }
  /** What the files bb loads export goes to the core: the default function's returns and every exported value are carried to code the analysis has not read. */
  private entryExports(): void {
    for (const f of this.files) {
      if (!this.o.entries?.has(f.rel)) continue;
      const ns = `ns:${f.index}`;
      for (const name of this.fieldNames.get(ns) ?? []) {
        const v = this.cell(this.fieldKey(ns, name));
        const labels = new Set([...this.labels(v)].filter((l) => l.startsWith("t:")));
        for (const t of this.tokens(v, "f:")) for (const l of this.labels(this.cell(`ret:${t.slice(2)}`))) if (l.startsWith("t:")) labels.add(l);
        if (labels.size > 0) this.addFlows(labels, "unknown", `a value that ${f.rel} hands to bb`, f.rel, 0);
      }
    }
  }
  /**
   * What is handed to code the analysis cannot read. A choice counts there only where the callee is a function of a package or a computed one:
   * a call that is only unresolved (`audio.play()`, a parameter nothing was bound to) under a branch is not a way out by itself.
   */
  private unknownSink(why: string, vals: Iterable<Iterable<string>>, n: N, sc: Scope, choiceCounts = false): void {
    this.sink("unknown", why, vals, n, sc, !choiceCounts);
  }
  private source(kind: SourceKind, sc: Scope): void {
    if (!this.record) return;
    let s = this.seen.get(kind);
    if (!s) this.seen.set(kind, (s = new Set()));
    s.add(this.enclosingFn(sc)?.id ?? -1);
  }
  private edge(sc: Scope, toFn: number): void {
    const from = this.enclosingFn(sc)?.id ?? -1;
    let s = this.edges.get(from);
    if (!s) this.edges.set(from, (s = new Set()));
    s.add(toFn);
  }

  // ---- calling a function we have read ------------------------------------------------------------------------------------------------
  private bindCall(fnTok: string, args: Array<Set<string>>, thisV: Iterable<string> | null, sc: Scope | null): Set<string> {
    const id = Number(fnTok.slice(2));
    const fn = this.fns[this.fnIndex(id)];
    if (!fn) return new Set();
    if (sc) this.edge(sc, id);
    if (this.ctl.size > 0) this.add(`ctx:${id}`, this.ctl);
    for (const a of args) this.add(`args:${id}`, a);
    for (let i = 0; i < args.length; i++) {
      const idx = fn.restIndex >= 0 && i >= fn.restIndex ? fn.restIndex : i;
      if (idx >= fn.params.length) continue;
      this.add(`p:${id}:${idx}`, args[i]!);
    }
    if (thisV) this.add(`this:${id}`, thisV);
    return this.cell(`ret:${id}`);
  }
  private fnIdx = new Map<number, number>();
  private fnIndex(id: number): number {
    if (this.fnIdx.size !== this.fns.length) for (let i = this.fnIdx.size; i < this.fns.length; i++) this.fnIdx.set(this.fns[i]!.id, i);
    return this.fnIdx.get(id) ?? -1;
  }
  private callTokens(fnToks: Iterable<string>, args: Array<Set<string>>, thisV: Iterable<string> | null, sc: Scope | null): Set<string> {
    const out = new Set<string>();
    for (const t of fnToks) if (t.startsWith("f:")) for (const x of this.bindCall(t, args, thisV, sc)) out.add(x);
    return out;
  }

  // ---- modules ---------------------------------------------------------------------------------------------------------------------
  private moduleValue(spec: string | null, sc: Scope): Set<string> {
    const out = new Set<string>();
    if (spec === null) return out;
    const targets = resolveSpecifier(sc.file.rel, spec, this.o.graph).filter((f) => this.fileByRel.has(f));
    for (const t of targets) out.add(`ns:${this.fileByRel.get(t)!.index}`);
    if (targets.length > 0) return out;
    const full = normalizeModule(spec);
    const root = full.startsWith("@") ? full.split("/").slice(0, 2).join("/") : full.split("/")[0]!;
    const mc = moduleCapability(spec);
    if (DB_MODULES.has(root)) out.add("x:db");
    else if (mc?.kind === "network") out.add("x:net");
    else if (mc?.kind === "child_process") out.add("x:cp");
    else if (mc?.kind === "fs") out.add("x:fs");
    else if (PURE_PACKAGES.test(full) || PLAIN_BUILTINS.has(full) || PLAIN_BUILTINS.has(root) || spec.startsWith("node:") && PLAIN_BUILTINS.has(normalizeModule(spec))) out.add("x:pure");
    else out.add("x:ext");
    return out;
  }

  // ---- patterns ----------------------------------------------------------------------------------------------------------------------
  private bindPattern(p: N, v: Set<string>, sc: Scope): void {
    if (!p) return;
    switch (p.type) {
      case "Identifier": {
        const k = this.lookup(sc, p.name);
        if (k) this.add(k, this.ctlV(v));
        else if (v.size > 0) {
          this.add(`g:${p.name}`, v);
          // an undeclared name is a global: other code can read it
          this.unknownSink("a value put on a global variable", [v], p, sc);
        }
        return;
      }
      case "ObjectPattern":
        for (const x of p.properties) {
          if (x.type === "RestElement") this.bindPattern(x.argument, v, sc);
          else {
            const key = x.computed ? fold(x.key, sc.file.consts) : x.key.type === "Identifier" ? x.key.name : String(x.key.value);
            const got = this.member(v, key);
            if (key !== null && THREAD_TEXT_FIELDS.has(key)) {
              this.source("threads", sc);
              got.add("t:threads");
            }
            this.bindPattern(x.value, got, sc);
          }
        }
        return;
      case "ArrayPattern": {
        const el = this.member(v, "*");
        for (const x of p.elements) this.bindPattern(x, el, sc);
        return;
      }
      case "AssignmentPattern":
        this.bindPattern(p.left, new Set([...v, ...this.ev(p.right, sc)]), sc);
        return;
      case "RestElement":
        this.bindPattern(p.argument, v, sc);
        return;
      case "MemberExpression":
        this.assignMember(p, v, sc);
        return;
      case "TSParameterProperty":
        this.bindPattern(p.parameter, v, sc);
        return;
      default:
        return;
    }
  }
  /** The data now belongs to the variable an unknown object is held by, whoever else holds it. */
  private taintRoot(node: N, v: Set<string>, sc: Scope): void {
    if (!this.fallback) return;
    let root = unwrap(node);
    while (root && root.type === "MemberExpression") root = unwrap(root.object);
    if (root?.type !== "Identifier") return;
    const k = this.lookup(sc, root.name);
    if (k) this.add(k, this.ctlV(new Set([...v].filter((x) => x.startsWith("t:") || x.startsWith("k:") || x === "x:env"))));
  }
  private assignMember(target: N, v0: Set<string>, sc: Scope, rhs?: N): void {
    const base = this.ev(target.object, sc);
    const name = this.propName(target, sc.file);
    let v = v0;
    // What is put on a global object (or in the environment other programs inherit) is seen by code the analysis does not read.
    const rootNode = unwrap(target.object);
    const globalBase = (rootNode.type === "Identifier" && GLOBAL_OBJECTS.has(rootNode.name) && this.lookup(sc, rootNode.name) === null) || this.unboundName(rootNode, sc) !== null && rootNode.type === "MemberExpression" || base.has("x:process");
    if (this.flat(v0).size > 0 && globalBase) this.unknownSink("a value put on a global object", [v0], target, sc);
    if (this.flat(v0).size > 0 && base.has("x:env")) this.sink("process", "the environment of the programs it starts", [v0], target, sc);
    // `o[secret] = 1`: the key is data, too
    if (target.computed && name === null) v = new Set([...v0, ...this.flat(this.ev(target.property, sc))]);
    // `img.src = "https://x/?" + secret`, `link.href = …`: the page fetches it
    if (name !== null && URL_ATTRS.has(name) && ![...base].some((t) => t.startsWith("o:") || t.startsWith("c:"))) this.sink("network", this.hostOfAddress(rhs, sc.file) ?? undefined, [v], target, sc);
    let placed = false;
    for (const t of base) {
      if (t.startsWith("o:") || t.startsWith("c:") || t.startsWith("f:")) {
        this.setField(t, name ?? "*", v);
        placed = true;
      }
    }
    // An object we know nothing of (a result of bb's API, a parameter): the data now belongs to it, whoever holds it.
    if (!placed || [...v].some((x) => x.startsWith("t:") || x.startsWith("k:") || x === "x:env")) this.taintRoot(target.object, v, sc);
    const chain = this.sdkChainRaw(target, sc.file);
    if (chain && /(^|\.)(location\.href|location|window\.location\.href)$/.test(chain)) this.sink("network", this.hostOfText(this.foldPrefix(target, sc.file)) ?? undefined, [v], target, sc);
  }

  // ---- expressions -------------------------------------------------------------------------------------------------------------------
  private started = Date.now();
  /** The clock is an emergency stop only: it never makes a verdict, it makes the whole result «not finished» (see `timedOut`). */
  private checkClock(): void {
    if (Date.now() - this.started > MAX_MS) {
      this.timedOut = true;
      throw new RangeError("flow time");
    }
  }
  private tick(by = 1): void {
    this.visits += by;
    if ((this.visits & 0x3fff) < by) this.checkClock();
    if (this.visits > MAX_VISITS) {
      this.aborted = true;
      throw new RangeError("flow budget");
    }
  }
  private ev(n0: N, sc: Scope): Set<string> {
    const n = n0;
    if (!n || typeof n.type !== "string") return new Set();
    this.tick();
    switch (n.type) {
      case "Literal":
      case "TemplateElement":
      case "ThisExpression" /* handled below */:
        if (n.type === "ThisExpression") return this.thisOf(sc);
        return new Set();
      case "Identifier":
        return this.evIdentifier(n, sc);
      case "TemplateLiteral": {
        const out = new Set<string>();
        for (const e of n.expressions) for (const x of this.flat(this.ev(e, sc))) out.add(x);
        return out;
      }
      case "TaggedTemplateExpression": {
        const args = [new Set<string>(), ...n.quasi.expressions.map((e: N) => this.ev(e, sc))];
        const tag = this.ev(n.tag, sc);
        const ret = this.callTokens(tag, args, null, sc);
        if (this.tokens(tag, "f:").length > 0) return ret;
        const out = new Set<string>();
        for (const a of args) for (const x of this.flat(a)) out.add(x);
        return out;
      }
      case "TSAsExpression":
      case "TSSatisfiesExpression":
      case "TSNonNullExpression":
      case "TSTypeAssertion":
      case "ChainExpression":
      case "ParenthesizedExpression":
      case "AwaitExpression": {
        const v = n.argument || n.expression ? this.ev(n.argument ?? n.expression, sc) : new Set<string>();
        for (const x of v) if (x.startsWith("k:")) this.pendingK.add(x);
        // the code after an `await` may not run if something before it threw
        for (const x of this.excChoice()) this.pendingK.add(x);
        return v;
      }
      case "YieldExpression": {
        const v = n.argument ? this.ev(n.argument, sc) : new Set<string>();
        const fn = this.enclosingFn(sc);
        if (fn) this.add(`ret:${fn.id}`, v);
        return new Set(v);
      }
      case "SpreadElement":
        return this.ev(n.argument, sc);
      case "SequenceExpression": {
        let last = new Set<string>();
        for (const e of n.expressions) last = this.ev(e, sc);
        return last;
      }
      case "ConditionalExpression": {
        // which branch is taken is a choice made by the test: the value and what is called in the branches carry it
        const k = this.kOf(this.ev(n.test, sc));
        return this.under(k, () => new Set([...this.ev(n.consequent, sc), ...this.ev(n.alternate, sc), ...k]));
      }
      case "LogicalExpression": {
        const l = this.ev(n.left, sc);
        const k = this.kOf(l);
        return this.under(k, () => new Set([...l, ...this.ev(n.right, sc), ...k]));
      }
      case "BinaryExpression": {
        const l = this.ev(n.left, sc);
        const r = this.ev(n.right, sc);
        // text made of text is text; a comparison, a sum, a shift is a choice made by what it was made of
        return n.operator === "+" ? new Set([...this.flat(l), ...this.flat(r)]) : this.kOf([...l, ...r]);
      }
      case "UnaryExpression": {
        const a = this.ev(n.argument, sc);
        return n.operator === "void" ? new Set() : this.kOf(a);
      }
      case "UpdateExpression": {
        this.ev(n.argument, sc);
        // `k++` in a loop whose end depends on what was read: the counter is a choice made by it
        const arg = unwrap(n.argument);
        if (this.ctl.size > 0 && (arg.type === "Identifier" || arg.type === "MemberExpression")) this.bindPattern(arg, new Set(), sc);
        return new Set();
      }
      case "AssignmentExpression": {
        const v = this.ev(n.right, sc);
        const left = unwrap(n.left);
        if (n.operator === "=" || n.operator === "||=" || n.operator === "&&=" || n.operator === "??=") {
          if (left.type === "MemberExpression") this.assignMember(left, v, sc, n.right);
          else this.bindPattern(left, v, sc);
        }
        else if (n.operator === "+=") this.bindPattern(left, this.flat(v) as Set<string>, sc);
        else this.bindPattern(left, this.kOf(v), sc);
        return v;
      }
      case "MemberExpression":
        return this.evMember(n, sc);
      case "CallExpression":
        return this.evCall(n, sc, false);
      case "NewExpression":
        return this.evCall(n, sc, true);
      case "ImportExpression":
        this.ev(n.source, sc);
        return this.moduleValue(fold(n.source, sc.file.consts), sc);
      case "ArrayExpression": {
        const tok = `o:${this.idOf(n)}`;
        for (const e of n.elements) if (e) this.setField(tok, "*", this.ev(e, sc));
        return new Set([tok]);
      }
      case "ObjectExpression":
        return this.evObject(n, sc);
      case "FunctionExpression":
      case "ArrowFunctionExpression": {
        const fn = this.fnByNode.get(n);
        return fn ? new Set([`f:${fn.id}`]) : new Set();
      }
      case "ClassExpression":
      case "ClassDeclaration": {
        const ci = this.classByNode.get(n);
        if (!ci) return new Set();
        this.runClass(ci);
        return new Set([`c:${ci.id}`]);
      }
      case "JSXElement":
      case "JSXFragment":
        return this.evJsx(n, sc, false);
      case "MetaProperty":
        return new Set(["x:pure"]);
      case "Super":
        return new Set();
      default:
        return new Set();
    }
  }
  private thisOf(sc: Scope): Set<string> {
    for (let s: Scope | null = sc; s; s = s.parent) {
      if (s.fn && !s.fn.arrow && !s.fn.isModule) return this.cell(`this:${s.fn.id}`);
      if (s.thisTok) return new Set([s.thisTok]);
    }
    return new Set();
  }
  private evIdentifier(n: N, sc: Scope): Set<string> {
    const k = this.lookup(sc, n.name);
    if (k) return this.cell(k);
    return this.globalValue(n.name, sc);
  }
  /** What a name nothing declared is: the globals the analysis knows (`fetch`, `localStorage`…). `globalThis.fetch` is the same value as `fetch`. */
  private globalValue(name: string, sc: Scope): Set<string> {
    const n = { name };
    switch (n.name) {
      case "undefined":
        return new Set();
      case "fetch":
        return new Set(["x:net=?"]);
      case "arguments": {
        for (let sc2: Scope | null = sc; sc2; sc2 = sc2.parent) if (sc2.fn && !sc2.fn.arrow && !sc2.fn.isModule) return new Set(this.cell(`args:${sc2.fn.id}`));
        return new Set();
      }
      case "module":
      case "exports":
        return new Set();
      case "localStorage":
      case "sessionStorage":
      case "indexedDB":
        return new Set(["x:db"]);
      case "Notification":
        return new Set(["x:notify"]);
      case "BroadcastChannel":
        return new Set(["x:chan"]);
      case "process":
        return new Set(["x:process"]);
      default:
        return new Set(this.cell(`g:${n.name}`));
    }
  }
  private evMember(n: N, sc: Scope): Set<string> {
    if (this.isProcessEnv(n, sc)) {
      this.source("env", sc);
      return new Set(["x:env"]);
    }
    const objNode = unwrap(n.object);
    const gname = this.unboundName(n, sc);
    if (gname !== null && !n.computed) return this.globalValue(gname, sc);
    if (objNode.type === "Super") {
      const ci = this.classOf(sc);
      const out = new Set<string>();
      if (ci) for (const p of this.cell(`super:${ci.id}`)) this.readField(p.replace(/^c:/, "o:"), this.propName(n, sc.file) ?? "*", out);
      return out;
    }
    const base = this.ev(n.object, sc);
    const name = this.propName(n, sc.file);
    // `table[key]`, `list[i]`: which entry is read is a choice made by the key
    const keyChoice = n.computed && name === null ? this.kOf(this.ev(n.property, sc)) : new Set<string>();
    if (keyChoice.size > 0) return new Set([...this.member(base, name), ...keyChoice]);
    if (name !== null && THREAD_TEXT_FIELDS.has(name)) {
      this.source("threads", sc);
      return new Set([...this.member(base, name), "t:threads"]);
    }
    const out = this.member(base, name);
    // `Deno.env.get`-style and `localStorage.getItem` are calls; a plain read of a database/storage object keeps its token.
    return out;
  }
  private classOf(sc: Scope): ClassInfo | null {
    for (let s: Scope | null = sc; s; s = s.parent) if (s.cls) return s.cls;
    return null;
  }
  private evObject(n: N, sc: Scope): Set<string> {
    const tok = `o:${this.idOf(n)}`;
    for (const p of n.properties) {
      if (p.type === "SpreadElement") {
        const s = this.ev(p.argument, sc);
        this.setField(tok, "*", s);
        for (const t of s) {
          if (t.startsWith("o:") || t.startsWith("c:")) {
            const all = new Set<string>();
            this.allFields(t, all);
            this.setField(tok, "*", all);
          }
        }
        continue;
      }
      const key = p.computed ? fold(p.key, sc.file.consts) : p.key.type === "Identifier" ? p.key.name : String(p.key.value);
      if (p.computed && key === null) this.ev(p.key, sc);
      const value = p.value;
      if (value && isFnNode(value)) {
        const fn = this.fnByNode.get(value);
        if (fn && !fn.arrow) this.add(`this:${fn.id}`, [tok]);
        if (fn && p.kind === "get") {
          this.setField(tok, key ?? "*", this.cell(`ret:${fn.id}`));
          continue;
        }
      }
      this.setField(tok, key ?? "*", this.ev(value, sc));
    }
    return new Set([tok]);
  }
  private evJsx(n: N, sc: Scope, asChild: boolean): Set<string> {
    void asChild;
    if (n.type === "JSXFragment") {
      const out = new Set<string>();
      for (const c of n.children) for (const x of this.evJsxChild(c, sc, true)) out.add(x);
      return out;
    }
    const open = n.openingElement;
    const nameNode = open.name;
    const tagName = nameNode.type === "JSXIdentifier" ? nameNode.name : null;
    const isComponent = nameNode.type === "JSXMemberExpression" || (tagName !== null && /^[A-Z]/.test(tagName));
    const props = `o:${this.idOf(n)}`;
    let componentV = new Set<string>();
    if (isComponent) {
      const root = nameNode.type === "JSXIdentifier" ? nameNode.name : (() => { let x = nameNode; while (x.type === "JSXMemberExpression") x = x.object; return x.name as string; })();
      const k = this.lookup(sc, root);
      componentV = k ? this.cell(k) : new Set();
      if (nameNode.type === "JSXMemberExpression") componentV = this.member(componentV, nameNode.property.name);
    }
    const hostVals: Set<string>[] = [];
    for (const a of open.attributes) {
      if (a.type === "JSXSpreadAttribute") {
        const s = this.ev(a.argument, sc);
        this.setField(props, "*", s);
        if (!isComponent) hostVals.push(s);
        continue;
      }
      const name = a.name.type === "JSXIdentifier" ? a.name.name : a.name.name?.name ?? "*";
      let v = new Set<string>();
      if (a.value) v = a.value.type === "JSXExpressionContainer" ? (a.value.expression.type === "JSXEmptyExpression" ? new Set() : this.ev(a.value.expression, sc)) : a.value.type === "JSXElement" ? this.evJsx(a.value, sc, false) : new Set();
      this.setField(props, name, v);
      if (name === "value" && nameNode.type === "JSXMemberExpression" && nameNode.property.name === "Provider") this.add("CTX", v);
      if (!isComponent) {
        if (URL_ATTRS.has(name)) {
          if (!this.isOwnRoute(a.value?.expression, sc.file)) this.sink("network", this.hostOfAddress(a.value?.expression, sc.file) ?? undefined, [v], a, sc);
        } else if (!/^on[A-Z]/.test(name)) hostVals.push(v);
      }
    }
    const childVals = new Set<string>();
    for (const c of n.children) for (const x of this.evJsxChild(c, sc, !isComponent)) childVals.add(x);
    this.setField(props, "children", childVals);
    if (isComponent) {
      this.callTokens(componentV, [new Set([props])], null, sc);
      return new Set(["x:pure"]);
    }
    this.sink("ui", undefined, [...hostVals, childVals], n, sc);
    return new Set(["x:pure"]);
  }
  private evJsxChild(c: N, sc: Scope, host: boolean): Set<string> {
    void host;
    if (c.type === "JSXExpressionContainer") return c.expression.type === "JSXEmptyExpression" ? new Set() : this.ev(c.expression, sc);
    if (c.type === "JSXElement" || c.type === "JSXFragment") return this.evJsx(c, sc, true);
    if (c.type === "JSXSpreadChild") return this.ev(c.expression, sc);
    return new Set();
  }

  // ---- classes -----------------------------------------------------------------------------------------------------------------------
  private classPass = new Map<number, number>();
  private passNo = 0;
  private runClass(ci: ClassInfo): void {
    if (this.classPass.get(ci.id) === this.passNo) return;
    this.classPass.set(ci.id, this.passNo);
    const inst = `o:${ci.id}`;
    const stat = `c:${ci.id}`;
    const n = ci.node;
    if (n.superClass) {
      const sup = this.ev(n.superClass, ci.scope.parent!);
      this.add(`super:${ci.id}`, sup);
      for (const s of sup) {
        if (s.startsWith("c:")) {
          this.add(`proto:${inst}`, [s.replace(/^c:/, "o:")]);
          this.add(`proto:${stat}`, [s]);
        } else if (s.startsWith("x:")) this.add(`proto:${inst}`, [s]);
      }
    }
    for (const m of n.body.body) {
      const key = m.computed ? fold(m.key, ci.file.consts) : m.key?.type === "Identifier" ? m.key.name : m.key ? String(m.key.value) : null;
      const target = m.static ? stat : inst;
      if (m.type === "MethodDefinition") {
        const fn = this.fnByNode.get(m.value);
        if (!fn) continue;
        this.add(`this:${fn.id}`, [target]);
        if (m.kind === "get") this.setField(target, key ?? "*", this.cell(`ret:${fn.id}`));
        else if (m.kind === "constructor") {
          this.add(`ctor:${ci.id}`, [`f:${fn.id}`]);
          // `constructor(private readonly x: T)`: the parameter is also a field
          fn.params.forEach((p, i) => {
            if (p?.type === "TSParameterProperty") for (const name of this.patNames(p.parameter)) this.setField(inst, name, this.cell(`p:${fn.id}:${i}`));
          });
        }
        else this.setField(target, key ?? "*", [`f:${fn.id}`]);
      } else if (m.type === "PropertyDefinition") {
        if (m.value) this.setField(target, key ?? "*", this.ev(m.value, ci.scope));
      } else if (m.type === "StaticBlock") for (const s of m.body) this.exec(s, ci.scope);
    }
  }

  // ---- calls -----------------------------------------------------------------------------------------------------------------------
  private evCall(n: N, sc: Scope, isNew: boolean): Set<string> {
    const saved = this.ctl;
    try {
      return this.evCallInner(n, sc, isNew);
    } finally {
      this.ctl = saved;
    }
  }
  private evCallInner(n: N, sc: Scope, isNew: boolean): Set<string> {
    const callee = unwrap(n.callee);
    const argNodes: N[] = n.arguments ?? [];
    const args: Array<Set<string>> = argNodes.map((a) => this.ev(a, sc));
    const out = new Set<string>();
    const file = sc.file;

    if (callee.type === "Super") {
      const ci = this.classOf(sc);
      if (ci) for (const s of this.cell(`super:${ci.id}`)) if (s.startsWith("c:")) for (const c of this.cell(`ctor:${s.slice(2)}`)) this.bindCall(c, args, [`o:${ci.id}`], sc);
      return out;
    }
    if (callee.type === "Import") return this.moduleValue(argNodes[0] ? fold(argNodes[0], file.consts) : null, sc);
    // require("x")
    if (callee.type === "Identifier" && callee.name === "require" && this.lookup(sc, "require") === null) return this.moduleValue(argNodes[0] ? fold(argNodes[0], file.consts) : null, sc);

    const member = callee.type === "MemberExpression" ? callee : null;
    const methodName = member ? this.propName(member, file) : callee.type === "Identifier" ? callee.name : null;
    const recvNode = member ? unwrap(member.object) : null;
    const recvV = member && recvNode.type !== "Super" ? this.ev(member.object, sc) : new Set<string>();
    const chain0 = this.sdkChainRaw(callee, file);
    // `globalThis.navigator.sendBeacon` is `navigator.sendBeacon`
    const chain = chain0 === null ? null : this.lookup(sc, chain0.split(".")[0]!) === null ? chain0.replace(/^(globalThis|window|self|global)\./, "") : chain0;
    const unbound = this.unboundName(callee, sc);

    // ---- bb's API ----
    if (chain !== null && !isNew) {
      const sdk = chain.replace(/\.(call|apply|bind)$/, "");
      const handled = this.evBb(n, sdk, chain.split(".").includes("sdk"), argNodes, args, sc);
      if (handled) return handled;
    }

    // ---- computed call: which function it is, is not known ----
    let dynamicCall = false;
    if (member && member.computed && methodName === null) {
      dynamicCall = true;
      this.ev(member.property, sc);
    }

    // ---- globals ----
    if (unbound !== null) {
      const g = this.evGlobal(n, unbound, isNew, argNodes, args, sc);
      if (g) return g;
    }
    if (chain === "navigator.sendBeacon") {
      this.sink("network", this.hostOfAddress(argNodes[0], file) ?? undefined, args, n, sc);
      return out;
    }

    // ---- the value of the callee ----
    const calleeV = member ? this.member(recvV, methodName) : this.ev(callee, sc);
    // `fns[bit]()`: the function itself was chosen by what was read, so the call, and all that runs inside it, is made by that choice
    if (member && member.computed && methodName === null) for (const x of this.kOf(this.ev(member.property, sc))) calleeV.add(x);
    const chosen = [...calleeV].filter((x) => x.startsWith("k:"));
    if (chosen.length > 0) this.ctl = new Set([...this.ctl, ...chosen]);
    const thisV = member ? recvV : null;
    let handled = false;

    // `f.call(this, a)`, `f.apply(this, [a])`, `f.bind(this, a)`
    if (member && (methodName === "call" || methodName === "apply" || methodName === "bind") && !dynamicCall) {
      const fns = this.tokens(recvV, "f:");
      if (fns.length > 0) {
        handled = true;
        const rest = args.slice(1);
        let callArgs: Array<Set<string>> = rest;
        if (methodName === "apply") callArgs = [this.member(args[1] ?? new Set(), "*")].map((x) => new Set([...x, ...(args[1] ?? [])]));
        for (const f of fns) {
          if (methodName === "bind") {
            this.bindCall(f, callArgs, args[0] ?? null, sc);
            out.add(f);
          } else for (const x of this.bindCall(f, callArgs, args[0] ?? null, sc)) out.add(x);
        }
      }
    }

    // local functions and classes
    for (const t of calleeV) {
      if (t.startsWith("f:")) {
        handled = true;
        for (const x of this.bindCall(t, args, thisV, sc)) out.add(x);
        // a function whose result the person gets back is a handler; its returns are tracked at its registration
      } else if (t.startsWith("c:") && isNew) {
        handled = true;
        const id = Number(t.slice(2));
        this.runClassById(id);
        out.add(`o:${id}`);
        const ctors = this.cell(`ctor:${id}`);
        if (ctors.size > 0) for (const c of ctors) this.bindCall(c, args, [`o:${id}`], sc);
        else for (const s of this.cell(`super:${id}`)) if (s.startsWith("c:")) for (const c of this.cell(`ctor:${s.slice(2)}`)) this.bindCall(c, args, [`o:${id}`], sc);
      } else if (t.startsWith("r:") && !isNew) {
        handled = true;
        this.add(`res:${t}`, this.ctlV(new Set(args.flatMap((a) => [...a]))));
      }
    }

    // emitters: what is emitted reaches every listener (the name of the event is not told apart)
    if (member && methodName !== null && !dynamicCall) {
      if (EMIT_METHODS.has(methodName)) this.add("EMIT", args.flatMap((a) => [...this.labels(a), ...this.tokens(a, "o:"), ...this.tokens(a, "f:")]));
      else if (LISTEN_METHODS.has(methodName)) {
        for (const cb of args.flatMap((a) => this.tokens(a, "f:"))) this.bindCall(cb, [new Set(this.cell("EMIT")), new Set(this.cell("EMIT"))], null, sc);
      }
    }

    // modules, handles, resources
    const recvX = member ? this.tokens(recvV, "x:") : [];
    const calleeX = this.tokens(calleeV, "x:").filter((t) => !member || !recvX.includes(t) || true);
    // `cp[k](data)`: which function of the module it is, is not known: the dispatch below would pick one
    const xs = dynamicCall ? [] : [...new Set([...calleeX, ...recvX])];
    for (const x of xs) {
      const r = this.extCall(n, x, member ? methodName : null, isNew, argNodes, args, recvV, sc);
      if (r) {
        handled = true;
        for (const y of r) out.add(y);
      }
    }

    if (isNew && !handled) {
      const name = callee.type === "Identifier" ? callee.name : null;
      if (name === "Promise") {
        const tok = `r:${this.idOf(n)}`;
        const executor = args[0] ? this.tokens(args[0], "f:") : [];
        for (const f of executor) this.bindCall(f, [new Set([tok]), new Set([tok])], null, sc);
        for (const x of this.cell(`res:${tok}`)) out.add(x);
        handled = true;
      } else if (name !== null && ["Map", "Set", "WeakMap", "WeakSet", "Array"].includes(name)) {
        const tok = `o:${this.idOf(n)}`;
        for (const a of args) {
          const inner = new Set<string>();
          for (const t of a) if (t.startsWith("o:")) this.allFields(t, inner);
          this.setField(tok, "*", inner);
          this.setField(tok, "*", this.flat(a));
        }
        out.add(tok);
        handled = true;
      } else if (name !== null && this.lookup(sc, name) === null && (PURE_GLOBALS.has(name) || /Error$/.test(name))) {
        for (const a of args) for (const x of this.flat(a)) out.add(x);
        out.add("x:pure");
        handled = true;
      }
    }

    // builtins on plain data
    if (!isNew && this.builtinMethod(n, member ? methodName : null, recvV, calleeV, args, argNodes, out, sc, member !== null)) handled = true;

    if (dynamicCall) {
      this.unknownSink("a call by a computed name", args, n, sc, true);
      if (this.fallback) for (const a of args) for (const x of this.flat(a)) out.add(x);
      handled = true;
    }

    if (!handled) {
      // Unresolved: a function the analysis has not read (a library, a parameter nothing was bound to, a computed property).
      if (this.fallback) {
        for (const a of args) for (const x of this.flat(a)) out.add(x);
        for (const x of this.flat(recvV)) out.add(x);
      }
      const what = chain ?? methodName ?? "a function";
      // Under a branch on what was read an unresolved call is a way out unless it is one of the harmless trifles
      const trifle = BENIGN_UNRESOLVED.test(methodName ?? "") || BENIGN_UNRESOLVED.test(chain ?? "");
      this.unknownSink(`a call to ${what}, which the code does not show`, [...args, recvV], n, sc, !trifle);
      this.escape(args, n, sc);
    }
    return out;
  }
  private runClassById(id: number): void {
    for (const ci of this.classByNode.values()) if (ci.id === id) return this.runClass(ci);
  }
  /** Functions handed to code the analysis cannot read: what they return is carried away. */
  private escape(args: Array<Set<string>>, n: N, sc: Scope): void {
    const seen = new Set<string>();
    const visit = (v: Iterable<string>, depth: number): void => {
      for (const t of v) {
        if (seen.has(t)) continue;
        seen.add(t);
        if (t.startsWith("f:")) {
          this.escaped.add(t);
          const ret = this.cell(`ret:${t.slice(2)}`);
          this.unknownSink("a function handed to code that is not shown", [ret], n, sc);
        } else if ((t.startsWith("o:") || t.startsWith("c:")) && depth < 3) {
          const inner = new Set<string>();
          this.allFields(t, inner);
          visit(inner, depth + 1);
        }
      }
    };
    for (const a of args) visit(a, 0);
  }

  private evGlobal(n: N, name: string, isNew: boolean, argNodes: N[], args: Array<Set<string>>, sc: Scope): Set<string> | null {
    const file = sc.file;
    const out = new Set<string>();
    if (name === "fetch" && !isNew) {
      if (this.isOwnRoute(argNodes[0], file)) {
        this.add(R_CELL, args.flatMap((a) => [...this.labels(a)]));
        return new Set(this.cell(R_CELL));
      }
      this.sink("network", this.hostOfAddress(argNodes[0], file) ?? undefined, args, n, sc);
      return new Set(["x:net=?"]);
    }
    if (isNew && (name === "WebSocket" || name === "EventSource" || name === "XMLHttpRequest")) {
      const host = this.hostOfAddress(argNodes[0], file);
      this.sink("network", host ?? undefined, args, n, sc);
      return new Set([`x:net=${host ?? "?"}`]);
    }
    if (name === "Response") {
      this.sink("route", undefined, args, n, sc);
      return new Set(["x:pure"]);
    }
    if (isNew && name === "Notification") {
      this.sink("notify", undefined, args, n, sc);
      return new Set(["x:notify"]);
    }
    if (isNew && name === "BroadcastChannel") return new Set(["x:chan"]);
    if (TIMER_CLEARS.has(name) && !isNew) return out;
    if (TIMERS.has(name) && !isNew) {
      // the delay is a choice made by what it was computed from, and what runs after it is called by that choice
      const delay = this.kOf(args[1] ?? []);
      // `new Promise((r) => setTimeout(r, delay))`: the promise settles when the delay says
      for (const r of this.tokens(args[0] ?? [], "r:")) this.add(`res:${r}`, delay);
      for (const f of this.tokens(args[0] ?? [], "f:")) {
        this.add(`ctx:${f.slice(2)}`, delay);
        this.bindCall(f, [], null, sc);
      }
      return out;
    }
    if (name === "eval" || name === "Function") {
      for (const a of args) for (const x of this.flat(a)) out.add(x);
      return out;
    }
    if (name === "open" || name === "alert" || name === "confirm" || name === "prompt") {
      if (name === "open") this.sink("network", this.hostOfAddress(argNodes[0], file) ?? undefined, args, n, sc);
      else this.sink("ui", undefined, args, n, sc);
      return out;
    }
    if (name === "require" || name === "import") return null;
    return null;
  }

  /** bb's own API: sources, sinks, registrations. Returns the value, or null when the chain is not one of bb's things. */
  private evBb(n: N, chain: string, rooted: boolean, argNodes: N[], args: Array<Set<string>>, sc: Scope): Set<string> | null {
    const out = new Set<string>();
    const right = classifySdkChain(chain, rooted);
    // events
    if (/(^|\.)events\.on$/.test(chain) && argNodes.length >= 2) {
      const ev = fold(argNodes[0], sc.file.consts);
      const cbs = this.tokens(args[1] ?? [], "f:");
      if (ev !== null) this.triggers.push({ event: ev, fns: cbs.map((c) => Number(c.slice(2))) });
      const payload = ev === null ? new Set<string>() : this.eventPayload(ev, sc);
      for (const c of cbs) this.bindCall(c, [payload], null, sc);
      return out;
    }
    // routes, rpc, commands: what the handlers return goes to whoever asked (the plugin's own page, the terminal)
    if (/(^|\.)http\.(route|websocket|experimental_websocket)$/.test(chain) || /(^|\.)rpc\.register$/.test(chain) || /(^|\.)cli\.register$/.test(chain)) {
      const isHttp = /(^|\.)http\./.test(chain);
      const fnToks = new Set<string>();
      const collect = (v: Iterable<string>, depth: number, seen: Set<string>): void => {
        for (const t of v) {
          if (seen.has(t)) continue;
          seen.add(t);
          if (t.startsWith("f:")) fnToks.add(t);
          else if ((t.startsWith("o:") || t.startsWith("c:")) && depth < 5) {
            const all = new Set<string>();
            this.allFields(t, all);
            collect(all, depth + 1, seen);
          }
        }
      };
      for (const a of args) collect(a, 0, new Set());
      for (const t of fnToks) {
        const id = Number(t.slice(2));
        const fn = this.fns[this.fnIndex(id)];
        const input = isHttp ? new Set(["x:resp", ...this.cell(R_CELL)]) : new Set(this.cell(R_CELL));
        this.bindCall(t, fn ? fn.params.map(() => input) : [input], null, sc);
        this.sink(/(^|\.)cli\.register$/.test(chain) ? "ui" : "route", undefined, [this.cell(`ret:${id}`)], n, sc);
      }
      return out;
    }
    // storage
    const kv = /(^|\.)storage\.kv\.(\w+)$/.exec(chain);
    if (kv) {
      if (/^(set|put|delete|update|merge|clear|remove)/.test(kv[2]!)) this.sink("store", undefined, args, n, sc);
      else for (const x of this.cell(R_CELL)) out.add(x);
      return out;
    }
    if (/(^|\.)storage\.database$/.test(chain)) return new Set(["x:db"]);
    if (/(^|\.)(getPluginMetadata)$/.test(chain)) return new Set(this.cell(R_CELL));
    if (/(^|\.)(updatePluginMetadata)$/.test(chain)) {
      this.sink("store", undefined, args, n, sc);
      return out;
    }
    // the plugin's own page, told in real time
    if (/(^|\.)realtime\.(publish|emit|send|broadcast)$/.test(chain)) {
      this.sink("ui", undefined, args, n, sc);
      return out;
    }
    // logs
    if (/(^|\.)log\.(debug|info|warn|error|trace|log)$/.test(chain) || /^console\.\w+$/.test(chain)) {
      this.sink("log", undefined, args, n, sc);
      return out;
    }
    // the plugin's own RPC from its page
    if (/(^|\.)rpc\.(call|\w+)$/.test(chain) && /(^|\.)(rpc)\./.test(`.${chain}`) && !/(^|\.)rpc\.register$/.test(chain)) {
      this.sink("store", undefined, args, n, sc);
      return new Set(this.cell(R_CELL));
    }
    if (right === null) return rooted && /^(sdk|bb\.sdk)\./.test(chain.replace(/^[\w$]+\.sdk\./, "sdk.")) ? out : null;
    if ("unclassified" in right) {
      this.unknownSink(`${right.detail}, a call into bb's API the checks have no entry for`, args, n, sc);
      for (const a of args) for (const x of this.flat(a)) out.add(x);
      return out;
    }
    switch (right.kind) {
      case "sdk_read":
        this.source("threads", sc);
        return new Set(["t:threads"]);
      case "sdk_questions":
        this.source("questions", sc);
        return new Set(["t:questions"]);
      case "sdk_send":
      case "sdk_answer":
      case "sdk_agents":
        this.sink("send", right.detail, args, n, sc);
        return out;
      case "sdk_settings":
        this.sink("settings", right.detail, args, n, sc);
        for (const x of this.cell(R_CELL)) out.add(x);
        return out;
      case "sdk_meta":
        return out;
      case "fs":
        this.source("files", sc);
        this.sink("file", right.detail, args, n, sc);
        return new Set(["t:files"]);
      case "child_process":
        this.sink("process", right.detail, args, n, sc);
        return out;
      default:
        return null;
    }
  }
  /** What a handler of this event is handed. */
  private eventPayload(ev: string, sc: Scope): Set<string> {
    const tok = `o:ev:${ev}`;
    if (/^(experimental_)?(message|turn)\b|^experimental_thread\.events$/.test(ev)) {
      this.source("threads", sc);
      return new Set(["t:threads"]);
    }
    if (/^interaction\./.test(ev)) {
      this.source("questions", sc);
      return new Set(["t:questions"]);
    }
    if (ev === "thread.idle") {
      this.source("threads", sc);
      this.setField(tok, "lastAssistantText", ["t:threads"]);
      return new Set([tok]);
    }
    if (ev === "thread.failed") {
      this.source("threads", sc);
      this.setField(tok, "error", ["t:threads"]);
      return new Set([tok]);
    }
    return new Set();
  }

  /** A call whose callee is (or is a method of) a value that came from outside the plugin's own code. */
  private extCall(n: N, x: string, method: string | null, isNew: boolean, argNodes: N[], args: Array<Set<string>>, recvV: Set<string>, sc: Scope): Set<string> | null {
    const file = sc.file;
    const out = new Set<string>();
    const kind = x.slice(2).split("=")[0]!;
    const targetOf = x.includes("=") ? x.slice(x.indexOf("=") + 1) : null;
    const simple = method ?? (n.callee.type === "Identifier" ? n.callee.name : null);
    switch (kind) {
      case "pure": {
        // React state: what is put into the setter is what the state holds. `[v, setV] = useState(init)`
        if ((simple === "useState" || simple === "useReducer") && !isNew) {
          const site = `o:${this.idOf(n)}`;
          const setter = `x:set=${site}`;
          if (simple === "useReducer") this.add(`reducer:${site}`, args[0] ?? []);
          for (const a of simple === "useState" ? args.slice(0, 1) : args.slice(1, 2)) {
            const init = new Set<string>();
            for (const t of a) if (t.startsWith("f:")) for (const x of this.bindCall(t, [], null, sc)) init.add(x);
            for (const t of a) if (!t.startsWith("f:")) init.add(t);
            this.setField(site, "*", init);
          }
          this.setField(site, "*", [setter]);
          return new Set([site]);
        }
        if (simple === "useContext" && !isNew) return new Set([...this.cell("CTX"), "x:pure"]);
        if (simple === "useRef" && !isNew) {
          const site = `o:${this.idOf(n)}`;
          this.setField(site, "current", args[0] ?? []);
          return new Set([site]);
        }
        for (const a of args) for (const t of this.flat(a)) out.add(t);
        for (const t of this.flat(recvV)) out.add(t);
        out.add("x:pure");
        for (const t of args.flatMap((a) => this.tokens(a, "f:"))) {
          out.add(t); // useCallback(fn) is fn
          for (const x of this.bindCall(t, [], null, sc)) out.add(x); // useMemo(() => v) is v
        }
        return out;
      }
      case "set": {
        const site = x.slice(6);
        const incoming = new Set<string>();
        for (const a of args) for (const t of a) incoming.add(t);
        for (const f of this.cell(`reducer:${site}`)) {
          if (!f.startsWith("f:")) continue;
          for (const t of this.bindCall(f, [this.cell(this.fieldKey(site, "*")), new Set(incoming)], null, sc)) incoming.add(t);
        }
        for (const a of args) for (const f of this.tokens(a, "f:")) for (const t of this.bindCall(f, [this.cell(this.fieldKey(site, "*"))], null, sc)) incoming.add(t); // setV(prev => next)
        this.setField(site, "*", incoming);
        return out;
      }
      case "env":
        return out;
      case "process":
        // process.env handled as a value; process.exit, nextTick…
        for (const f of args.flatMap((a) => this.tokens(a, "f:"))) this.bindCall(f, [], null, sc);
        return out;
      case "net": {
        // `fetch` handed in as a value (`fetch: typeof fetch = globalThis.fetch`) called for the plugin's own route
        if (method === null && !isNew && targetOf === "?" && this.isOwnRoute(argNodes[0], file)) {
          this.add(R_CELL, args.flatMap((a) => [...this.labels(a)]));
          return new Set(this.cell(R_CELL));
        }
        if (method === null && !isNew && n.callee.type !== "Identifier") return null;
        if (method === "on" || method === "once" || method === "off" || method === "removeListener" || method === "close" || method === "destroy" || method === "abort" || method === "end" && args.length === 0 || method === "setHeader" && args.length === 0) {
          for (const f of args.flatMap((a) => this.tokens(a, "f:"))) this.bindCall(f, [], null, sc);
          return new Set([x]);
        }
        const host = targetOf && targetOf !== "?" ? targetOf : this.hostOfAddress(argNodes[0], file);
        this.sink("network", host ?? undefined, args, n, sc);
        for (const f of args.flatMap((a) => this.tokens(a, "f:"))) this.bindCall(f, [], null, sc);
        return new Set([`x:net=${host ?? "?"}`]);
      }
      case "cp": {
        if (simple === null || (!CHILD_FUNCS.has(simple) && n.callee.type !== "Identifier" && !(method === "spawn" || method === "exec"))) {
          // `cp[k](…)`, `cp.somethingElse(…)`
          if (simple === null || !CHILD_FUNCS.has(simple)) {
            this.sink("process", "a program the code does not name", args, n, sc);
            return new Set(["x:proc=?"]);
          }
        }
        let prog = this.programOf(simple!, argNodes, file);
        const pieces = argNodes.flatMap((a) => this.strings(a, file));
        const all = pieces.join(" ");
        if (prog === "osascript" && OSASCRIPT_DISPLAY.test(all)) this.sink("notify", "osascript", args, n, sc);
        else if (prog !== null && NOTIFY_PROGRAMS.has(prog)) this.sink("notify", prog, args, n, sc);
        else if (prog !== null && SOUND_PROGRAMS.has(prog)) this.sink("sound", prog, args, n, sc);
        else this.sink("process", prog ?? "a program the code does not name", args, n, sc);
        const res = new Set<string>([`x:proc=${prog ?? "?"}`]);
        const creds = this.credLabelsOf(argNodes, file);
        if (prog === "security") creds.push("связка ключей macOS");
        for (const c of creds) {
          this.source("credentials", sc);
          res.add(`t:cred:${c}`);
        }
        for (const f of args.flatMap((a) => this.tokens(a, "f:"))) this.bindCall(f, [res], null, sc);
        prog = null;
        return res;
      }
      case "proc": {
        if (method === "on" || method === "once" || method === "off" || method === "kill" || method === "unref" || method === "ref" || method === "removeListener") {
          for (const f of args.flatMap((a) => this.tokens(a, "f:"))) this.bindCall(f, [], null, sc);
          return new Set([x]);
        }
        const prog = targetOf && targetOf !== "?" ? targetOf : null;
        this.sink(prog !== null && NOTIFY_PROGRAMS.has(prog) ? "notify" : prog !== null && SOUND_PROGRAMS.has(prog) ? "sound" : "process", prog ?? "a program the code does not name", args, n, sc);
        return new Set([x]);
      }
      case "fs": {
        if (simple === null) {
          this.sink("file", "a file the code does not name", args, n, sc);
          return out;
        }
        const pathNode = argNodes[0];
        const own = pathNode ? this.pathIsOwn(pathNode, sc) : false;
        if (FS_WRITE.has(simple) || /^(writeFile|appendFile|createWriteStream|mkdir|rm|unlink|truncate|rename|copyFile|cp)/.test(simple)) {
          const text = pathNode ? this.foldPrefix(pathNode, file).text : "";
          const dataArgs = simple === "createWriteStream" ? [] : args.slice(1);
          if (own) this.sink("store", undefined, dataArgs, n, sc);
          else this.sink("file", text !== "" ? text.slice(0, 80) : "a file the code does not name", dataArgs, n, sc);
          if (simple === "createWriteStream") return new Set([own ? "x:fsw=own" : `x:fsw=${text !== "" ? text.slice(0, 80) : "?"}`]);
          return out;
        }
        if (FS_FUNCS.has(simple) && /^(readFile|createReadStream|readdir|opendir|readJson|readFileSync|readdirSync|open|openSync|readlink|realpath)/.test(simple)) {
          const creds = pathNode ? this.credLabelsOf(argNodes.slice(0, 1), file) : [];
          const res = new Set<string>();
          for (const c of creds) {
            this.source("credentials", sc);
            res.add(`t:cred:${c}`);
          }
          if (creds.length === 0 && !own) {
            this.source("files", sc);
            res.add("t:files");
          }
          return res;
        }
        return out;
      }
      case "notify": {
        // the system's notifications, handed in or global: what is given to it is shown to the person
        if (isNew || method === null) this.sink("notify", undefined, args, n, sc);
        return new Set([x]);
      }
      case "chan": {
        // a channel between the plugin's own tabs: the page of the plugin, not a way out of bb
        if (method === "postMessage") this.sink("ui", undefined, args, n, sc);
        return new Set([x]);
      }
      case "fsw": {
        if (method === "write" || method === "end") {
          if (targetOf === "own") this.sink("store", undefined, args, n, sc);
          else this.sink("file", targetOf ?? undefined, args, n, sc);
        }
        return new Set([x]);
      }
      case "db": {
        // The plugin's own database (or the browser's storage): what is written comes back when it is read.
        this.sink("store", undefined, args, n, sc);
        for (const f of args.flatMap((a) => this.tokens(a, "f:"))) this.bindCall(f, [new Set(this.cell(R_CELL))], null, sc);
        return new Set([x, ...this.cell(R_CELL)]);
      }
      case "resp": {
        if (method !== null && /^(json|text|html|body|send|end|write|render|redirect|stream|sse|status|header|set)$/.test(method)) {
          this.sink("route", undefined, args, n, sc);
          return new Set([x]);
        }
        for (const t of args.flatMap((a) => [...this.flat(a)])) out.add(t);
        out.add(x);
        return out;
      }
      case "ext": {
        const any = args.some((a) => this.labels(a).size > 0) || this.labels(recvV).size > 0;
        if (any || args.some((a) => this.tokens(a, "f:").length > 0)) {
          this.unknownSink(`a call to ${method ?? simple ?? "a function"} of a package whose code is not read`, [...args, recvV], n, sc, true);
          this.escape(args, n, sc);
        }
        for (const a of args) for (const t of this.flat(a)) out.add(t);
        for (const t of this.flat(recvV)) out.add(t);
        out.add("x:ext");
        return out;
      }
      default:
        return null;
    }
  }

  /** Calls on plain data: strings, arrays, maps, promises; and the global namespaces. Returns true when handled. */
  private builtinMethod(n: N, method: string | null, recvV: Set<string>, calleeV: Set<string>, args: Array<Set<string>>, argNodes: N[], out: Set<string>, sc: Scope, isMember: boolean): boolean {
    const callee = unwrap(n.callee);
    const file = sc.file;
    // Object.assign / entries / values / fromEntries / keys / freeze …, Array.from / of, Promise.*, JSON.*
    if (isMember && recvNodeIsGlobal(callee, sc, this)) {
      const ns = (unwrap(callee.object) as N).name as string;
      if (ns === "Object" || ns === "Array" || ns === "Promise" || ns === "JSON") {
        if (ns === "Object" && method === "assign") {
          const target = args[0] ?? new Set<string>();
          for (const t of target) if (t.startsWith("o:")) for (const a of args.slice(1)) { this.setField(t, "*", a); const all = new Set<string>(); for (const x of a) if (x.startsWith("o:")) this.allFields(x, all); this.setField(t, "*", all); }
          for (const t of target) out.add(t);
          return true;
        }
        if ((ns === "Object" && (method === "entries" || method === "values" || method === "fromEntries" || method === "keys")) || (ns === "Array" && (method === "from" || method === "of")) || (ns === "Promise" && (method === "all" || method === "allSettled" || method === "race" || method === "any" || method === "resolve"))) {
          const tok = `o:${this.idOf(n)}`;
          const a = args[0] ?? new Set<string>();
          const elems = new Set<string>();
          for (const t of a) {
            if (t.startsWith("o:") || t.startsWith("c:")) this.allFields(t, elems);
            else elems.add(t);
          }
          if (ns === "Array" && method === "of") for (const x of args) for (const t of x) elems.add(t);
          this.setField(tok, "*", elems);
          if (ns === "Promise" && method !== "all" && method !== "allSettled") for (const t of elems) out.add(t);
          else out.add(tok);
          if (ns === "Promise" && method === "resolve") for (const t of a) out.add(t);
          return true;
        }
        for (const a of args) for (const t of a) out.add(t);
        return true;
      }
    }
    if (!isMember) {
      const name = callee.type === "Identifier" ? callee.name : null;
      if (name !== null && this.lookup(sc, name) === null && (PURE_GLOBALS.has(name) || name === "Symbol")) {
        for (const a of args) for (const t of this.flat(a)) out.add(t);
        return true;
      }
      return false;
    }
    if (method === null) return false;
    const hasObj = [...recvV].some((t) => t.startsWith("o:") || t.startsWith("c:"));
    const knownRecv = [...recvV].every((t) => t.startsWith("t:") || t.startsWith("k:") || t.startsWith("o:") || t === "x:env" || t === "x:pure") && (recvV.size > 0 || PURE_METHODS.has(method) || HOF_METHODS.has(method));
    // methods of values the analysis holds as plain data or containers
    if (!knownRecv && !(recvNodeIsGlobal(callee, sc, this) && PURE_GLOBALS.has((unwrap(callee.object) as N).name))) return false;
    if (HOF_METHODS.has(method) || PURE_METHODS.has(method) || recvNodeIsGlobal(callee, sc, this)) {
      const elems = new Set<string>();
      for (const t of recvV) {
        if (t.startsWith("o:")) {
          this.readField(t, "*", elems);
          this.allFields(t, elems);
        } else elems.add(t);
      }
      const cbs = args.flatMap((a) => this.tokens(a, "f:"));
      const flatElems = new Set([...elems]);
      let cbRet = new Set<string>();
      for (const f of cbs) for (const x of this.bindCall(f, [flatElems, new Set(), recvV], null, sc)) cbRet.add(x);
      // `.then(setState)`: a setter is called with the elements, too
      for (const setter of args.flatMap((a) => this.tokens(a, "x:set="))) this.setField(setter.slice(6), "*", flatElems);
      const writers = new Set(["push", "unshift", "add", "set", "append", "enqueue", "splice", "fill", "offer"]);
      if (writers.has(method)) {
        for (const t of recvV) if (t.startsWith("o:")) for (const a of args) this.setField(t, "*", a);
        if (!hasObj) {
          const taint = new Set<string>();
          for (const a of args) for (const t of this.flat(a)) taint.add(t);
          this.taintRoot(callee.object, taint, sc);
        }
        return true;
      }
      if (method === "map" || method === "flatMap") {
        const tok = `o:${this.idOf(n)}`;
        this.setField(tok, "*", cbRet);
        out.add(tok);
        return true;
      }
      if (method === "reduce" || method === "reduceRight") {
        for (const x of cbRet) out.add(x);
        for (const x of args[1] ?? []) out.add(x);
        // the accumulator sees the elements, too
        return true;
      }
      if (method === "then" || method === "catch" || method === "finally") {
        for (const f of cbs) this.add(`ctx:${f.slice(2)}`, [...[...recvV].filter((x) => x.startsWith("k:")), ...this.excChoice()]);
        for (const x of cbRet) out.add(x);
        if (method !== "then" || cbs.length === 0) for (const t of recvV) out.add(t);
        return true;
      }
      if (method === "forEach" || method === "each") return true;
      if (method === "get" || method === "pop" || method === "shift" || method === "at" || method === "find" || method === "findLast" || method === "values" || method === "entries" || method === "next" || method === "keys" || method === "flat") {
        for (const x of elems) out.add(x);
        // `map.get(key)`, `list.at(i)`: which entry is read is a choice made by the key
        if (method === "get" || method === "at") for (const x of this.kOf(args[0] ?? [])) out.add(x);
        if (method === "values" || method === "entries" || method === "keys" || method === "flat") for (const t of recvV) if (t.startsWith("o:")) out.add(t);
        return true;
      }
      if (method === "filter" || method === "slice" || method === "sort" || method === "toSorted" || method === "reverse" || method === "concat" || method === "toReversed") {
        for (const t of recvV) out.add(t);
        if (method === "concat") for (const a of args) for (const t of a) out.add(t);
        return true;
      }
      // strings and numbers made from the receiver and the arguments
      for (const t of this.flat(recvV)) out.add(t);
      for (const a of args) for (const t of this.flat(a)) out.add(t);
      for (const t of cbRet) out.add(t);
      return true;
    }
    void argNodes;
    void file;
    void calleeV;
    return false;
  }

  // ---- statements ----------------------------------------------------------------------------------------------------------------
  private exec(s: N, sc: Scope): void {
    if (!s || typeof s.type !== "string") return;
    this.tick();
    switch (s.type) {
      case "ExpressionStatement":
        this.ev(s.expression, sc);
        return;
      case "VariableDeclaration":
        for (const d of s.declarations) if (d.init) this.bindPattern(d.id, this.ev(d.init, sc), sc);
        return;
      case "ReturnStatement":
        if (s.argument) {
          const fn = this.enclosingFn(sc);
          if (fn) this.add(`ret:${fn.id}`, this.ctlV(this.ev(s.argument, sc)));
        }
        return;
      case "ThrowStatement":
        this.add(EXC_CELL, this.ctlV(this.ev(s.argument, sc)));
        return;
      case "IfStatement": {
        const k = this.kOf(this.ev(s.test, sc));
        this.under(k, () => {
          this.exec(s.consequent, sc);
          this.exec(s.alternate, sc);
        });
        return;
      }
      case "BlockStatement":
      case "StaticBlock":
        this.execSeq(s.body, sc);
        return;
      case "ForStatement": {
        if (s.init) s.init.type === "VariableDeclaration" ? this.exec(s.init, sc) : this.ev(s.init, sc);
        const k = s.test ? this.kOf(this.ev(s.test, sc)) : new Set<string>();
        this.under(k, () => {
          if (s.update) this.ev(s.update, sc);
          this.exec(s.body, sc);
        });
        return;
      }
      case "ForOfStatement":
      case "ForInStatement": {
        const right = this.ev(s.right, sc);
        const el = s.type === "ForOfStatement" ? this.member(right, "*") : new Set<string>();
        if (s.type === "ForOfStatement") for (const t of right) if (t.startsWith("t:") || t.startsWith("k:")) el.add(t);
        const left = s.left.type === "VariableDeclaration" ? s.left.declarations[0].id : s.left;
        this.bindPattern(left, el, sc);
        // how many times the body runs is a choice made by what is walked
        this.under(this.kOf(right), () => this.exec(s.body, sc));
        return;
      }
      case "WhileStatement":
      case "DoWhileStatement": {
        const k = this.kOf(this.ev(s.test, sc));
        this.under(k, () => this.exec(s.body, sc));
        return;
      }
      case "SwitchStatement": {
        const k = this.kOf(this.ev(s.discriminant, sc));
        this.under(k, () => {
          const seen = new Set<string>();
          for (const c of s.cases) {
            if (c.test) for (const x of this.kOf(this.ev(c.test, sc))) seen.add(x);
            this.under(seen, () => this.execSeq(c.consequent, sc));
          }
        });
        return;
      }
      case "TryStatement":
        this.exec(s.block, sc);
        // what was thrown under a choice made by what was read: whoever catches it, and whoever runs after it, is run by that choice
        const thrown = this.excChoice();
        if (s.handler) {
          if (s.handler.param) this.bindPattern(s.handler.param, new Set(this.cell(EXC_CELL)), sc);
          this.under(thrown, () => this.exec(s.handler.body, sc));
        }
        if (s.finalizer) this.under(thrown, () => this.exec(s.finalizer, sc));
        return;
      case "LabeledStatement":
        this.exec(s.body, sc);
        return;
      case "ClassDeclaration": {
        const ci = this.classByNode.get(s);
        if (ci) this.runClass(ci);
        return;
      }
      case "FunctionDeclaration":
        return;
      case "ExportNamedDeclaration":
        this.execExport(s, sc);
        return;
      case "ExportDefaultDeclaration": {
        const d = s.declaration;
        const nsTok = `ns:${sc.file.index}`;
        if (isFnNode(d)) this.setField(nsTok, "default", [`f:${this.fnByNode.get(d)!.id}`]);
        else if (d.type === "ClassDeclaration" || d.type === "ClassExpression") {
          const ci = this.classByNode.get(d);
          if (ci) {
            this.runClass(ci);
            this.setField(nsTok, "default", [`c:${ci.id}`]);
          }
        } else this.setField(nsTok, "default", this.ev(d, sc));
        return;
      }
      case "ExportAllDeclaration": {
        const mv = this.moduleValue(fold(s.source, sc.file.consts), sc);
        if (s.exported) this.setField(`ns:${sc.file.index}`, s.exported.name ?? String(s.exported.value), mv);
        else this.add(this.fieldKey(`ns:${sc.file.index}`, "*star"), mv);
        return;
      }
      case "ImportDeclaration": {
        const mv = this.moduleValue(String(s.source.value), sc);
        for (const sp of s.specifiers) {
          const k = this.lookup(sc, sp.local.name);
          if (!k) continue;
          if (sp.type === "ImportNamespaceSpecifier") this.add(k, mv);
          else if (sp.type === "ImportDefaultSpecifier") this.add(k, this.member(mv, "default"));
          else {
            const name = sp.imported.type === "Identifier" ? sp.imported.name : String(sp.imported.value);
            if (name === "env" && normalizeModule(String(s.source.value)) === "process") {
              this.source("env", sc);
              this.add(k, ["x:env"]);
            }
            else this.add(k, this.member(mv, name));
          }
        }
        return;
      }
      default:
        if (s.type.endsWith("Expression")) this.ev(s, sc);
        return;
    }
  }
  private execExport(s: N, sc: Scope): void {
    const ns = `ns:${sc.file.index}`;
    if (s.declaration) {
      this.exec(s.declaration, sc);
      const d = s.declaration;
      const names = d.type === "VariableDeclaration" ? d.declarations.flatMap((x: N) => this.patNames(x.id)) : d.id ? [d.id.name] : [];
      for (const name of names) {
        const k = this.lookup(sc, name);
        if (k) this.setField(ns, name, this.cell(k));
      }
      return;
    }
    const mv = s.source ? this.moduleValue(String(s.source.value), sc) : null;
    for (const sp of s.specifiers ?? []) {
      const local = sp.local.type === "Identifier" ? sp.local.name : String(sp.local.value);
      const exported = sp.exported.type === "Identifier" ? sp.exported.name : String(sp.exported.value);
      if (mv) this.setField(ns, exported, this.member(mv, local));
      else {
        const k = this.lookup(sc, local);
        if (k) this.setField(ns, exported, this.cell(k));
      }
    }
  }

  /** A statement list. After a branch on what was read that can leave (`if (bit) return;`), what follows is run, or not, by that choice. */
  private execSeq(stmts: N[], sc: Scope): void {
    const saved = this.ctl;
    try {
      for (const s of stmts) {
        this.exec(s, sc);
        const k = this.exitGuard(s, sc);
        if (k.size > 0) this.ctl = new Set([...this.ctl, ...k]);
        if (this.pendingK.size > 0) this.ctl = new Set([...this.ctl, ...this.pendingK]);
      }
    } finally {
      this.ctl = saved;
    }
  }
  private exitGuard(s: N, sc: Scope): Set<string> {
    if (!s) return new Set();
    const loopish = s.type === "ForStatement" || s.type === "ForOfStatement" || s.type === "ForInStatement" || s.type === "WhileStatement" || s.type === "DoWhileStatement" || s.type === "SwitchStatement";
    if (s.type !== "IfStatement" && !loopish) return new Set();
    let exits = false;
    const walk = (n: N): void => {
      if (exits || !n || typeof n.type !== "string" || isFnNode(n)) return;
      if (n.type === "ReturnStatement" || n.type === "ThrowStatement" || (!loopish && (n.type === "BreakStatement" || n.type === "ContinueStatement"))) exits = true;
      else this.children(n, walk);
    };
    this.children(s, walk);
    if (!exits) return new Set();
    const test = s.type === "SwitchStatement" ? s.discriminant : s.type === "ForOfStatement" || s.type === "ForInStatement" ? s.right : s.test;
    return test ? this.kOf(this.ev(test, sc)) : new Set();
  }

  // ---- running ---------------------------------------------------------------------------------------------------------------------
  private runFn(fn: FnInfo): void {
    const sc = fn.scope;
    // what calls this function (and the choices that made them) decides whether it runs
    this.ctl = new Set(this.cell(`ctx:${fn.id}`));
    this.pendingK = new Set();
    try {
      if (fn.isModule) {
        this.execSeq(fn.node.body, sc);
        return;
      }
      fn.params.forEach((p, i) => this.bindPattern(p, new Set(this.cell(`p:${fn.id}:${i}`)), sc));
      const node = fn.node;
      if (node.body.type === "BlockStatement") this.execSeq(node.body.body, sc);
      else this.add(`ret:${fn.id}`, this.ctlV(this.ev(node.body, sc)));
    } finally {
      this.ctl = new Set();
    }
  }
  private pass(): void {
    this.checkClock();
    this.passNo++;
    for (const fn of [...this.fns]) this.runFn(fn);
  }

  run(): FlowAnalysis {
    const notes: string[] = [];
    let complete = !this.o.incomplete;
    let converged = false;
    try {
      this.files = this.o.files.map((f, i): FileCtx => ({ rel: f.rel, index: i, ast: f.ast, consts: collectConsts(f.ast), inits: new Map(), sdkAlias: new Map(), module: null as never, cjs: false }));
      for (const f of this.files) this.fileByRel.set(f.rel, f);
      for (const f of this.files) this.collectFile(f);
      for (const f of this.files) f.cjs = /\b(module\.exports|exports\.\w+)\s*=/.test(this.o.files[f.index]!.code);
      if (this.files.some((f) => f.cjs)) this.blind = "CommonJS exports are not followed";
      for (const phase of [false, true]) {
        this.fallback = phase;
        converged = false;
        for (let i = 0; i < MAX_PASSES; i++) {
          this.dirty = false;
          this.pass();
          if (!this.dirty) {
            converged = true;
            break;
          }
        }
        if (!converged) break;
      }
      this.record = true;
      this.pass();
      this.entryExports();
    } catch (err) {
      if (this.timedOut) return { summaries: [], purposes: [], complete: false, notes: ["the clock stopped the analysis"], timedOut: true };
      complete = false;
      notes.push(this.aborted ? "the analysis ran out of budget" : `the analysis failed: ${String(err instanceof Error ? err.message : err).slice(0, 120)}`);
    }
    if (!converged) {
      complete = false;
      if (!this.aborted) notes.push("the analysis did not settle");
    }
    if (this.overflow) {
      complete = false;
      notes.push("too many values to follow");
    }
    if (this.blind) {
      complete = false;
      notes.push(this.blind);
    }
    if (this.o.incomplete) notes.push("part of the code could not be read");
    if (this.o.dynamic) notes.push("the code builds code or loads modules by a computed name");
    return { summaries: this.summaries(complete && !this.o.dynamic), purposes: this.purposes(), complete: complete && !this.o.dynamic, notes };
  }

  private kindOfLabel(label: string): { source: SourceKind; detail: string | null } | null {
    const t = label.slice(2);
    if (t === "threads" || t === "questions" || t === "files") return { source: t, detail: null };
    if (t.startsWith("env:")) return { source: "env", detail: t.slice(4) };
    if (t.startsWith("cred:")) return { source: "credentials", detail: t.slice(5) };
    return null;
  }
  private summaries(trusted: boolean): FlowSummary[] {
    // The sources the capabilities say the plugin has, and any that reached a sink: a handler that is handed text and never touches it is not a read.
    const kinds = new Set<SourceKind>([...this.o.expect]);
    for (const { label } of this.flows.values()) {
      const k = this.kindOfLabel(label);
      if (k) kinds.add(k.source);
    }
    const out: FlowSummary[] = [];
    for (const source of SOURCE_KINDS) {
      if (!kinds.has(source)) continue;
      const details = new Set<string>();
      const sinks: FlowSink[] = [];
      const dataSeen = new Set<string>();
      for (const { label, sink } of this.flows.values()) {
        const k = this.kindOfLabel(label);
        if (!k || k.source !== source) continue;
        if (k.detail) details.add(k.detail);
        const id = `${sink.kind}|${sink.target ?? ""}`;
        if (label.startsWith("t:")) dataSeen.add(id);
        if (!sinks.some((s) => s.kind === sink.kind && s.target === sink.target)) sinks.push({ ...sink });
      }
      for (const s of sinks) if (!dataSeen.has(`${s.kind}|${s.target ?? ""}`)) s.choice = true;
      const rank = (s: FlowSink): number => (DANGEROUS_SINKS.has(s.kind) || ((source === "env" || source === "credentials") && s.kind === "route") ? 0 : s.kind === "unknown" ? 1 : s.kind === "store" ? 3 : 2);
      sinks.sort((a, b) => rank(a) - rank(b) || (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
      // What a plugin hands out through its own route or RPC reaches any client of bb's server: for the person's conversations that is the plugin's own page, for secrets it is a way out.
      const secret = source === "env" || source === "credentials";
      const dangerous = sinks.some((s) => DANGEROUS_SINKS.has(s.kind) || (secret && s.kind === "route"));
      const unknown = sinks.some((s) => s.kind === "unknown");
      const sawIt = (this.seen.get(source)?.size ?? 0) > 0;
      let verdict: Verdict;
      let why: string | undefined;
      if (dangerous) verdict = "leaves";
      else if (unknown) {
        verdict = "unknown";
        why = sinks.find((s) => s.kind === "unknown")?.target;
      } else if (!trusted) {
        verdict = "unknown";
        why = this.o.dynamic ? "the code builds code or loads modules by a computed name" : this.o.incomplete ? "part of the code could not be read" : "the analysis could not follow all of the code";
      } else if (!sawIt) {
        verdict = "unknown";
        why = "where the plugin reads it, the analysis did not see";
      } else if (sinks.some((s) => s.kind === "notify" || s.kind === "sound" || s.kind === "ui" || s.kind === "route" || s.kind === "log")) verdict = "shown";
      else if (sinks.some((s) => s.kind === "store")) verdict = "kept";
      else verdict = "nowhere";
      // env: the names the code reads
      out.push({ source, detail: [...details].sort(), verdict, sinks: sinks.slice(0, 8), ...(why ? { why } : {}) });
    }
    return out;
  }

  private purposes(): Purpose[] {
    const out: Purpose[] = [];
    const reach = (from: number[]): Set<number> => {
      const seen = new Set<number>(from);
      const queue = [...from];
      while (queue.length) {
        const f = queue.pop()!;
        for (const t of this.edges.get(f) ?? []) if (!seen.has(t)) (seen.add(t), queue.push(t));
      }
      return seen;
    };
    for (const t of this.triggers) {
      const text = EVENT_PURPOSE[t.event];
      if (!text) continue;
      const r = reach(t.fns);
      const hit = this.sinkSites.filter((s) => r.has(s.fnId));
      if (hit.length === 0) continue;
      const via = [...new Set(hit.map((h) => h.kind))].sort().join("/");
      const reads = [...(this.seen.get("threads") ?? [])].some((f) => r.has(f)) || [...(this.seen.get("questions") ?? [])].some((f) => r.has(f));
      out.push({ on: reads ? ["sdk_meta", "sdk_read", "sdk_questions"] : ["sdk_meta"], text, pair: `${t.event} → ${via}` });
    }
    if (this.o.navClick && this.sinkSites.some((s) => s.kind === "notify")) out.push({ on: ["ui_click"], text: "чтобы открыть тред по клику на уведомление", pair: "click on a thread row → notification" });
    const uniq = new Map<string, Purpose>();
    for (const p of out) uniq.set(`${p.pair}|${p.text}`, p);
    return [...uniq.values()];
  }
}

/** `Object.assign(…)`, `JSON.parse(…)`: the callee's object is a global namespace the code did not shadow. */
function recvNodeIsGlobal(callee: N, sc: Scope, e: Engine): boolean {
  if (callee.type !== "MemberExpression") return false;
  const o = unwrap(callee.object);
  if (o.type !== "Identifier") return false;
  void e;
  for (let s: Scope | null = sc; s; s = s.parent) if (s.names.has(o.name)) return false;
  // `Reflect.apply(fn, …)` and `Proxy` run code the analysis cannot see into
  return PURE_GLOBALS.has(o.name) && o.name !== "Reflect" && o.name !== "Proxy";
}

export function analyzeFlows(o: FlowOptions): FlowAnalysis {
  try {
    return new Engine(o).run();
  } catch (err) {
    return { summaries: [...o.expect].map((source) => ({ source, detail: [], verdict: "unknown" as const, sinks: [], why: "the analysis failed" })), purposes: [], complete: false, notes: [`the analysis failed: ${String(err instanceof Error ? err.message : err).slice(0, 120)}`] };
  }
}
