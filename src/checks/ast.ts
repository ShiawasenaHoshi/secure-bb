// Capability and hard-sign detection by AST (spec §5.1), never by regex over
// source text. Parser: vendored acorn (+ acorn-jsx, acorn-walk); TypeScript
// types are removed first by node:module's stripTypeScriptTypes (it keeps
// every character position, so line numbers stay true).
import { stripTypeScriptTypes } from "node:module";
import * as acorn from "../../vendor/acorn.mjs";
import jsx from "../../vendor/acorn-jsx.mjs";
import * as walk from "../../vendor/walk.mjs";
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
  secretPaths: Array<{ line: number; text: string }>;
  rcPaths: Array<{ line: number; text: string }>;
  network: boolean;
  childProcess: boolean;
  execSink: boolean;
  fsWrite: boolean;
  parsed: boolean;
}

// ---- module tables --------------------------------------------------------
const NETWORK_MODULES = new Set(["http", "https", "http2", "net", "tls", "dgram", "dns", "dns/promises", "undici", "ws", "axios", "node-fetch", "cross-fetch", "got", "superagent", "request", "needle", "socket.io-client", "isomorphic-ws", "node-ftp", "ssh2", "socks", "net-ping"]);
const CHILD_MODULES = new Set(["child_process", "cross-spawn", "execa", "shelljs", "node-pty", "cluster"]);
const FS_MODULES = new Set(["fs", "fs/promises", "fs-extra", "graceful-fs", "original-fs"]);
const DYNAMIC_MODULES = new Set(["vm", "module", "vm2", "isolated-vm", "worker_threads"]);
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
const JsxParser = acorn.Parser.extend(jsx());
const TS_EXT = /\.(m|c)?tsx?$/i;
const JSX_EXT = /\.(jsx|tsx)$/i;

export type Parsed = { ok: true; ast: N; code: string } | { ok: false; reason: string };

export function parseSource(rel: string, text: string): Parsed {
  let code = text;
  if (TS_EXT.test(rel)) {
    try {
      code = stripTypeScriptTypes(text, { mode: "strip" });
    } catch (err) {
      // Node cannot strip types around JSX (.tsx) and does not do enums/namespaces:
      // a .tsx file gets one more try as plain JSX; anything else is "could not parse".
      if (!JSX_EXT.test(rel)) return { ok: false, reason: `TypeScript: ${firstLine(err)}` };
    }
  }
  const P = JSX_EXT.test(rel) ? JsxParser : acorn.Parser;
  let lastErr = "";
  for (const sourceType of ["module", "script"] as const) {
    try {
      const ast = P.parse(code, { ecmaVersion: "latest", sourceType, locations: true, allowHashBang: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true });
      return { ok: true, ast, code };
    } catch (err) {
      lastErr = firstLine(err);
    }
  }
  return { ok: false, reason: lastErr };
}
const firstLine = (e: unknown): string => String(e instanceof Error ? e.message : e).split("\n")[0]!.slice(0, 200);

// acorn-walk knows no JSX: teach it to descend.
const base: any = {
  ...(walk as any).base,
  JSXElement(n: N, st: N, c: N) {
    c(n.openingElement, st);
    for (const ch of n.children) c(ch, st);
  },
  JSXFragment(n: N, st: N, c: N) {
    for (const ch of n.children) c(ch, st);
  },
  JSXOpeningElement(n: N, st: N, c: N) {
    for (const a of n.attributes) c(a, st);
  },
  JSXAttribute(n: N, st: N, c: N) {
    if (n.value) c(n.value, st);
  },
  JSXSpreadAttribute(n: N, st: N, c: N) {
    c(n.argument, st);
  },
  JSXExpressionContainer(n: N, st: N, c: N) {
    c(n.expression, st);
  },
  JSXSpreadChild(n: N, st: N, c: N) {
    c(n.expression, st);
  },
  JSXEmptyExpression() {},
  JSXText() {},
  JSXIdentifier() {},
};

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
  (walk as any).simple(ast, { VariableDeclarator: (n: N) => decls.push(n) }, base);
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
  if (full.startsWith("@get-bb/plugin-sdk/app")) return { kind: "ui", detail: spec };
  return null;
}

// ---- the analysis -------------------------------------------------------------
export function analyze(rel: string, parsed: { ast: N; code: string }): FileFacts {
  const { ast, code } = parsed;
  const lines = code.split("\n");
  const facts: FileFacts = { findings: [], sites: [], hosts: [], secretPaths: [], rcPaths: [], network: false, childProcess: false, execSink: false, fsWrite: false, parsed: true };
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

  // decode → eval: names assigned from decoders (two passes so chains resolve)
  const tainted = new Set<string>();
  const isDecodeCall = (n: N): boolean => {
    if (n.type !== "CallExpression") return false;
    const c = n.callee;
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
  const propName = (m: N): string | null => (m.computed ? fold(m.property, consts) : m.property.type === "Identifier" ? m.property.name : null);
  const isGlobalObj = (n: N): boolean => n.type === "Identifier" && GLOBAL_OBJECTS.has(n.name);
  const isProcess = (n: N): boolean => (n.type === "Identifier" && n.name === "process") || (n.type === "MemberExpression" && isGlobalObj(n.object) && propName(n) === "process");

  /** The global/property name an expression denotes when used as a callee: `eval`, `globalThis["ev"+"al"]`, `(0, eval)`. */
  const resolveName = (n: N): string | null => {
    if (n.type === "Identifier") return n.name;
    if (n.type === "SequenceExpression") return resolveName(n.expressions.at(-1));
    if (n.type === "ChainExpression") return resolveName(n.expression);
    if (n.type === "MemberExpression" && isGlobalObj(n.object)) return propName(n);
    if (n.type === "MemberExpression" && propName(n) === "require") return "require";
    return null;
  };
  const dottedName = (n: N): string | null => {
    if (n.type === "Identifier") return n.name;
    if (n.type === "MemberExpression") {
      const o = dottedName(n.object);
      const p = propName(n);
      return o && p ? `${o}.${p}` : null;
    }
    return null;
  };

  for (let pass = 0; pass < 2; pass++) {
    (walk as any).simple(ast, { VariableDeclarator: (d: N) => { if (d.id.type === "Identifier" && d.init && decoded(d.init)) tainted.add(d.id.name); } }, base);
  }

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
  };

  const handleEnvUse = (envNode: N, anc: N[]): void => {
    const parent = anc[anc.length - 2];
    const names: string[] = [];
    if (parent?.type === "MemberExpression" && parent.object === envNode) {
      const p = propName(parent);
      if (p === null) {
        names.push("*");
        finding("dynamic-access", "review", parent);
      } else names.push(p);
    } else if ((parent?.type === "VariableDeclarator" && parent.init === envNode && parent.id.type === "ObjectPattern") || (parent?.type === "AssignmentExpression" && parent.right === envNode && parent.left.type === "ObjectPattern")) {
      const pat = parent.type === "VariableDeclarator" ? parent.id : parent.left;
      for (const p of pat.properties) {
        if (p.type === "RestElement") names.push("*");
        else {
          const k = p.computed ? fold(p.key, consts) : p.key.type === "Identifier" ? p.key.name : String(p.key.value);
          names.push(k ?? "*");
        }
      }
    } else {
      names.push("*");
      // Serialising the whole environment: JSON.stringify(process.env), Object.entries({...process.env}) …
      for (let i = anc.length - 2; i >= 0 && i >= anc.length - 6; i--) {
        const a = anc[i];
        if (a.type === "CallExpression") {
          const d = dottedName(a.callee);
          if (d && ENV_SERIALIZERS.has(d)) finding("env-dump", "block", a);
          break;
        }
        if (!["SpreadElement", "ObjectExpression", "Property", "ArrayExpression"].includes(a.type)) break;
      }
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
    if (SECRET_PATH.test(value)) facts.secretPaths.push({ line, text: excerptOf(value, 100) });
    if (RC_PATH.test(value)) facts.rcPaths.push({ line, text: excerptOf(value, 100) });
    if (PIPE_SHELL.test(value)) finding("download-exec", "block", n, excerptOf(value));
    if (BUILTIN_RPC.has(value)) builtinCandidates.push({ n, value });
  };
  const builtinCandidates: Array<{ n: N; value: string }> = [];

  const visitors: Record<string, (n: N, st: unknown, anc: N[]) => void> = {
    Literal(n) {
      if (typeof n.value === "string") stringChecks(n.value, n);
    },
    TemplateLiteral(n, _s, anc) {
      const parent = anc[anc.length - 2];
      if (parent?.type === "TaggedTemplateExpression") return;
      const f = fold(n, consts);
      if (f !== null) stringChecks(f, n);
      else for (const q of n.quasis) if (q.value.cooked) stringChecks(q.value.cooked, n);
    },
    BinaryExpression(n, _s, anc) {
      if (n.operator !== "+" || anc[anc.length - 2]?.type === "BinaryExpression") return;
      const f = fold(n, consts);
      if (f !== null) stringChecks(f, n);
    },
    ImportDeclaration(n) {
      handleSpec(n.source, n, "import");
      if (normalizeModule(String(n.source.value)) === "process") {
        for (const s of n.specifiers) if (s.type === "ImportSpecifier" && s.imported.name === "env") cap("env", "*", n);
      }
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
    Identifier(n, _s, anc) {
      const parent = anc[anc.length - 2];
      if (n.name === "eval") {
        cap("dynamic_code", "eval", n);
        facts.execSink = true;
      }
      if (NETWORK_GLOBALS.has(n.name)) cap("network", n.name, n);
      if (n.name === "require") {
        const isCallee = parent?.type === "CallExpression" && parent.callee === n;
        const benign = (parent?.type === "UnaryExpression" && parent.operator === "typeof") || (parent?.type === "MemberExpression" && parent.object === n && ["resolve", "main", "cache", "extensions"].includes(String(propName(parent))));
        if (!isCallee && !benign) finding("require-alias", "review", n);
      }
    },
    MemberExpression(n, _s, anc) {
      const name = propName(n);
      if (isProcess(n.object)) {
        if (name === "env") handleEnvUse(n, anc);
        else if (name === null) {
          finding("dynamic-access", "review", n);
          cap("env", "*", n);
        } else if (name === "dlopen" || name === "binding") {
          cap("dynamic_code", `process.${name}`, n);
          finding("native-load", "review", n);
        } else if (name === "mainModule") finding("require-alias", "review", n);
      } else if (isGlobalObj(n.object)) {
        if (name === null) {
          finding("dynamic-access", "review", n);
          cap("dynamic_code", "dynamic property access", n);
        } else if (name === "eval") {
          cap("dynamic_code", "eval", n);
          facts.execSink = true;
        } else if (NETWORK_GLOBALS.has(name)) cap("network", name, n);
      }
      if (n.object.type === "Identifier" && n.object.name === "bb") {
        if (name === "hosts") cap("host_artifact", "bb.hosts", n);
        if (name === "experimental_serverAccess") cap("server_access", "bb.experimental_serverAccess", n);
      }
      if (name === "experimental_serverAccess") cap("server_access", "experimental_serverAccess", n);
      if (name !== null && /^(experimental_)?(contentScripts?|composer)$/.test(name)) cap("ui", name, n);
      if (name === "sendBeacon") cap("network", "navigator.sendBeacon", n);
    },
    CallExpression(n) {
      const callee = n.callee;
      const name = resolveName(callee);
      if (name === "eval") markExec(n, "eval");
      else if (name === "Function") markExec(n, "Function");
      if (name === "require" || (callee.type === "MemberExpression" && propName(callee) === "require")) {
        if (n.arguments[0]) handleSpec(n.arguments[0], n, "require");
      }
      if (name === "createRequire") {
        cap("dynamic_code", "createRequire", n);
        finding("require-alias", "review", n);
      }
      if (callee.type === "MemberExpression") {
        const p = propName(callee);
        if (p === "constructor") {
          cap("dynamic_code", ".constructor(…)", n);
          finding("dynamic-constructor", "review", n);
        }
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
        if (p !== null && FS_WRITE.has(p)) facts.fsWrite = true;
        if (p !== null && /rpc|plugin/i.test(p)) rpcCall(n);
      }
      if (callee.type === "Identifier" && FS_WRITE.has(callee.name)) facts.fsWrite = true;
      if (callee.type === "Identifier" && /rpc/i.test(callee.name)) rpcCall(n);
    },
    NewExpression(n) {
      const name = resolveName(n.callee);
      if (name === "Function") markExec(n, "new Function");
      else if (n.callee.type === "MemberExpression" && propName(n.callee) === "Script") markExec(n, "vm.Script");
      else if (name === "Script") markExec(n, "vm.Script");
      else if (name !== null && NETWORK_GLOBALS.has(name)) cap("network", name, n);
    },
  };
  const rpcCall = (call: N): void => {
    for (const a of call.arguments) {
      const v = fold(a, consts);
      if (v !== null && BUILTIN_RPC.has(v)) cap("builtin_rpc", v, call);
    }
  };

  const wrapped: Record<string, any> = {};
  for (const [type, fn] of Object.entries(visitors)) wrapped[type] = (n: N, st: unknown, anc: N[]) => fn(n, st, anc);
  (walk as any).ancestor(ast, wrapped, base);

  // `{ pluginId: "connect" }` style references to built-in plugins
  for (const { n, value } of builtinCandidates) {
    if (anyNode(ast, (x) => x.type === "Property" && x.value === n && !x.computed && /plugin/i.test(String(x.key.name ?? x.key.value)))) cap("builtin_rpc", value, n);
  }

  // download and execute: a network call and an execution sink in one file
  if (facts.network) {
    const exec = facts.sites.find((s) => s.kind === "dynamic_code" && /^(eval|Function|new Function|vm\.)/.test(s.detail));
    if (exec) finding("download-exec", "block", { loc: { start: { line: exec.line } } }, `network call and ${exec.detail} in one file`);
    else if (facts.childProcess && facts.fsWrite) {
      const site = facts.sites.find((s) => s.kind === "child_process")!;
      finding("download-exec", "block", { loc: { start: { line: site.line } } }, "network call, file write and child_process in one file");
    }
  }
  return facts;
}

export const isBadEnvName = (name: string): boolean => BAD_ENV.test(name);
