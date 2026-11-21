// Tree walk and structural checks (spec §5.1 "Структура"): everything that can
// be decided without parsing code.
import { createHash } from "node:crypto";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { parseVersion } from "../deps/semver.ts";
import type { Finding } from "./types.ts";
import { escapeInvisible, excerptOf, isInvisible } from "../text-rules.ts";

export { escapeInvisible, excerptOf };

export const MAX_FILES = 20_000;
export const MAX_FILE_BYTES = 5 * 1024 * 1024;

export interface SourceFile {
  rel: string;
  text: string;
  /** Inside `node_modules`. */
  dep: boolean;
  /** Inside the top-level `dist/` (bb's own build output). */
  dist: boolean;
}

/** A dependency the plugin's own package.json declares. */
export interface DeclaredDep {
  name: string;
  spec: string;
  line: number;
}
/** A package copy found in `node_modules` (name from the directory, as module resolution sees it). */
export interface InstalledPackage {
  name: string;
  /** `version` field of its package.json when it is a valid version; otherwise null. */
  version: string | null;
  file: string;
  /** The package.json names itself differently from its directory. */
  declaredName: string | null;
}

export interface TreeScan {
  findings: Finding[];
  sources: SourceFile[];
  rootPackage: Record<string, unknown> | null;
  declared: DeclaredDep[];
  installed: InstalledPackage[];
  /** Every regular file of the tree (posix paths): the import graph checks existence here. */
  allFiles: Set<string>;
  /** Parsed `package.json` of every package in the tree (posix path → manifest): entry points of dependencies (`main`, `exports`). */
  packageJsons: Map<string, Record<string, unknown>>;
  files: number;
  bytes: number;
}

/** What the integrity stage found out about a package directory (`node_modules/zod`). Only `verified` lifts the scan. */
export type PackageState = "verified" | "modified" | "unverified";

export interface ScanOptions {
  /** Package directories (posix, relative to the root) whose content equals the registry tarball byte for byte. */
  verified?: ReadonlySet<string>;
}

/** `node_modules/@a/b/lib/x.js` → `node_modules/@a/b`; the nearest enclosing package, or null outside `node_modules`. */
export function packageDirOf(relPosix: string): string | null {
  const segs = relPosix.split("/");
  const i = segs.lastIndexOf("node_modules");
  if (i < 0 || i + 1 >= segs.length) return null;
  const take = segs[i + 1]!.startsWith("@") ? 2 : 1;
  if (i + 1 + take > segs.length) return null;
  return segs.slice(0, i + 1 + take).join("/");
}

const CODE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);
export const isCodeFile = (rel: string): boolean => CODE_EXT.has(extname(rel).toLowerCase()) && !/\.d\.[mc]?ts$/i.test(rel);

const NATIVE_EXT = new Set([".node", ".wasm", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".jar"]);
/** Binary formats that are harmless as data. */
const MEDIA_EXT = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".icns", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".mp3", ".mp4", ".wav", ".ogg"]);
const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];
const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const AGENT_DIRS = new Set([".claude", ".cursor", ".vscode", ".windsurf", ".codex", ".gemini"]);
const AGENT_FILES = new Set([".cursorrules", ".windsurfrules", ".mcp.json", "CLAUDE.md", "AGENTS.md", "GEMINI.md"]);
/**
 * Characters that change what code or text means to a person or a model without being seen: direction controls, Unicode Tags,
 * variation selectors, zero-width characters, soft hyphen, line/paragraph separators. Always a block in the plugin's own files.
 */
const HARD_INVISIBLE = /[\u00AD\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060\u2066-\u2069\uFE00-\uFE0F\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/u;

function invisibleFindings(rel: string, text: string): Finding[] {
  const out: Finding[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length && out.length < 5; i++) {
    let line = lines[i]!.replace(/\r$/, "");
    if (i === 0 && line.startsWith("\uFEFF")) line = line.slice(1);
    // U+FE0F right after a pictographic symbol or a keycap base is how an emoji (✔️, ⚠️) is written; anywhere else it stays invisible.
    line = line.replace(/([\p{Extended_Pictographic}0-9#*])\uFE0F/gu, "$1");
    const hidden = [...line].filter(isInvisible);
    if (hidden.length === 0) continue;
    // Anything else invisible (a BOM inside a string, a raw control character in a regex) in code is odd but does not change what the
    // code says to a reader: a warning. In text a reader or a model takes as instructions it stays a block.
    const hard = hidden.some((c) => HARD_INVISIBLE.test(c)) || !isCodeFile(rel);
    out.push({ rule: "invisible-chars", severity: hard ? "block" : "review", file: rel, line: i + 1, excerpt: excerptOf(escapeInvisible(line)) });
  }
  return out;
}

function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

function isExecutableMagic(buf: Buffer): boolean {
  if (buf.length < 4) return false;
  const b = buf.readUInt32BE(0);
  return (
    b === 0x7f454c46 || // ELF
    b === 0xfeedface || b === 0xfeedfacf || b === 0xcefaedfe || b === 0xcffaedfe || // Mach-O
    b === 0xcafebabe || // Mach-O fat / Java class
    buf.readUInt16BE(0) === 0x4d5a || // MZ (PE)
    b === 0x0061736d // wasm
  );
}

const SHORT_ID = /[A-Za-z_$][\w$]*/g;

/**
 * sha256 of the parser files secure-bb vendors (acorn and plugins, vendor/README.md).
 * They are dense by nature (Unicode tables), so a file with exactly these bytes is not
 * called minified. The list is built into the checker on purpose: a checked plugin must
 * not be able to vouch for its own files.
 */
export const KNOWN_VENDORED_SHA256: ReadonlySet<string> = new Set([
  "76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b", // acorn.mjs 8.19.0
  "699f555f7886852da766df6ffe0d8e7787211f1e72acda7a20e76c981dad2e67", // acorn-jsx.mjs 5.3.2 (wrapper)
  "e8e9281a975668bddb679c6cdc266e699cc69ddfeada1e4b3e4dc6def9bbe0e7", // acorn-typescript.mjs 1.0.13 (one import line changed, see vendor/README.md)
]);

/** Quoted strings and template literals on one line hold data (or embedded scripts), not code layout. */
const STRINGS = /`(?:\\.|[^`\\])*`|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g;
const stripStrings = (line: string): string => line.replace(STRINGS, '""');

/** Minified or obfuscated source (heuristics; spec §5.1). Returns a reason or null. */
export function minifiedReason(text: string): string | null {
  if (text.length < 400) return null;
  const lines = text.split("\n").map(stripStrings);
  const code = lines.join("\n");
  let longest = 0;
  let longestIdx = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.length > longest) {
      longest = lines[i]!.length;
      longestIdx = i;
    }
  }
  const shortShare = (s: string): { share: number; count: number } => {
    const ids = s.match(SHORT_ID) ?? [];
    if (ids.length === 0) return { share: 0, count: 0 };
    return { share: ids.filter((x) => x.length <= 2).length / ids.length, count: ids.length };
  };
  const hexIds = text.match(/\b_0x[0-9a-f]{3,}\b/gi) ?? [];
  if (hexIds.length >= 8) return `obfuscated identifiers (_0x…) near line ${longestIdx + 1}`;
  // Escapes are judged by the share of the file they make up, not by count: big files may legitimately hold some.
  const xEsc = (text.match(/\\x[0-9a-fA-F]{2}/g) ?? []).length;
  if (xEsc >= 40 && (xEsc * 4) / text.length > 0.1) return "dense \\x escapes";
  const uEsc = (text.match(/\\u[0-9a-fA-F]{4}/g) ?? []).length;
  if (uEsc >= 80 && (uEsc * 6) / text.length > 0.1) return "dense \\u escapes";
  if (longest > 1000) {
    const s = shortShare(lines[longestIdx]!);
    if (s.count >= 40 && s.share > 0.35) return `line ${longestIdx + 1} is ${longest} characters of code with ${(s.share * 100).toFixed(0)}% 1–2 letter identifiers`;
    if (longest > 5000 && lines.length < 20) return `line ${longestIdx + 1} is ${longest} characters`;
  }
  const whole = shortShare(code);
  if (whole.count >= 300 && whole.share > 0.6) return `${(whole.share * 100).toFixed(0)}% of identifiers are 1–2 letters`;
  return null;
}

/** The host a non-registry dependency spec points at. */
export function specHost(spec: string): string {
  const short = /^(github|gitlab|bitbucket|gist):/i.exec(spec);
  if (short) return { github: "github.com", gitlab: "gitlab.com", bitbucket: "bitbucket.org", gist: "gist.github.com" }[short[1]!.toLowerCase() as "github"];
  if (/^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec)) return "github.com";
  try {
    return new URL(spec.replace(/^git\+/i, "")).hostname || "an unknown host";
  } catch {
    return "an unknown host";
  }
}

export function isUrlSpec(spec: string): boolean {
  return /^(git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|ssh:|file:|link:)/i.test(spec) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec) /* user/repo shorthand */;
}
/** `workspace:` is how bb's own monorepo plugins refer to each other: not a URL, but not a registry version either. */
const isWorkspaceSpec = (spec: string): boolean => /^workspace:/i.test(spec);

const RUNTIME_DEP_FIELDS = ["dependencies", "optionalDependencies"];

function packageFindings(rel: string, raw: string, isRoot: boolean): { findings: Finding[]; pkg: Record<string, unknown> | null; declared: DeclaredDep[] } {
  const findings: Finding[] = [];
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { findings: [{ rule: "bad-package-json", severity: "review", file: rel, line: 0, excerpt: "package.json is not valid JSON" }], pkg: null, declared: [] };
  }
  const lineOf = (needle: string): number => {
    const idx = raw.indexOf(`"${needle}"`);
    return idx < 0 ? 0 : raw.slice(0, idx).split("\n").length;
  };
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? (pkg.scripts as Record<string, unknown>) : {};
  const depName = isRoot ? null : (installedPackageName(rel) ?? (typeof pkg.name === "string" ? pkg.name : rel));
  for (const name of INSTALL_SCRIPTS) {
    if (typeof scripts[name] !== "string") continue;
    // The core installs dependencies with `--ignore-scripts`: a dependency's script never runs. The plugin's own is a red flag as before.
    if (depName !== null) findings.push({ rule: "install-script", severity: "info", file: rel, line: lineOf(name), excerpt: excerptOf(`install script of dependency ${depName} will not run (the core installs with --ignore-scripts): ${name}: ${scripts[name]}`) });
    else findings.push({ rule: "install-script", severity: "block", file: rel, line: lineOf(name), excerpt: excerptOf(`${name}: ${scripts[name]}`) });
  }
  if (pkg.gypfile === true) findings.push({ rule: "native-module", severity: "block", file: rel, line: lineOf("gypfile"), excerpt: "gypfile: true (native build on install)" });
  for (const field of DEP_FIELDS) {
    const deps = pkg[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof spec !== "string") continue;
      if (isUrlSpec(spec.trim())) {
        // Code from a URL or a git host cannot be compared with the registry: one warning. A local path is a block (nothing can vouch for it).
        const local = /^(file:|link:)/i.test(spec.trim());
        findings.push({ rule: "url-dependency", severity: local ? "block" : "review", file: rel, line: lineOf(name), excerpt: excerptOf(`${field}: ${name}@${spec} — dependency ${name} comes from ${local ? "a local path" : specHost(spec.trim())}, not from npm; its content cannot be compared with the registry`) });
      }
      else if (isWorkspaceSpec(spec.trim())) findings.push({ rule: "workspace-dependency", severity: "review", file: rel, line: lineOf(name), excerpt: excerptOf(`${field}: ${name}@${spec}`) });
    }
  }
  const declared: DeclaredDep[] = [];
  if (isRoot) {
    for (const field of RUNTIME_DEP_FIELDS) {
      const deps = pkg[field];
      if (!deps || typeof deps !== "object" || Array.isArray(deps)) continue;
      for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
        if (typeof spec === "string") declared.push({ name, spec: spec.trim(), line: lineOf(name) });
      }
    }
  }
  return { findings, pkg, declared };
}

/** `a/node_modules/@scope/pkg/package.json` → `@scope/pkg`; null when this package.json is not a package's own manifest. */
export function installedPackageName(rel: string): string | null {
  const segs = rel.split(sep);
  if (segs.at(-1) !== "package.json") return null;
  const dir = segs.slice(0, -1);
  const last = dir.at(-1);
  if (last === undefined) return null;
  if (dir.at(-2) === "node_modules") return last;
  if (dir.at(-3) === "node_modules" && dir.at(-2)!.startsWith("@")) return `${dir.at(-2)}/${last}`;
  return null;
}

/** Walks the tree once: structural findings, plus the text of every source file for the AST pass. */
export async function scanTree(root: string, opts: ScanOptions = {}): Promise<TreeScan> {
  const verifiedDirs = opts.verified ?? new Set<string>();
  const allFiles = new Set<string>();
  const packageJsons = new Map<string, Record<string, unknown>>();
  const findings: Finding[] = [];
  const sources: SourceFile[] = [];
  let rootPackage: Record<string, unknown> | null = null;
  let declared: DeclaredDep[] = [];
  const installed: InstalledPackage[] = [];
  let files = 0;
  let bytes = 0;
  let writable = 0;
  let limitHit = false;

  const walkDir = async (rel: string): Promise<void> => {
    const entries = await readdir(join(root, rel), { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const entry of entries) {
      const childRel = rel === "" ? entry.name : join(rel, entry.name);
      if (childRel === ".git") continue;
      if (++files > MAX_FILES) {
        if (!limitHit) {
          limitHit = true;
          findings.push({ rule: "limit-exceeded", severity: "review", file: "", line: 0, excerpt: `more than ${MAX_FILES} entries: the rest of the tree was not scanned` });
        }
        return;
      }
      await visit(childRel, entry.name);
      if (entry.isDirectory() && !entry.isSymbolicLink()) await walkDir(childRel);
    }
  };

  const visit = async (rel: string, name: string): Promise<void> => {
    const full = join(root, rel);
    const st = await lstat(full);
    const segs = rel.split(sep);
    const dep = segs.includes("node_modules");
    const dist = segs[0] === "dist";
    const posixRel = segs.join("/");
    const pkgDir = dep ? packageDirOf(posixRel) : null;
    // The content of a verified package is the npm release itself: it is not read for heuristics (it is still parsed when the import graph reaches it).
    const verified = pkgDir !== null && verifiedDirs.has(pkgDir);

    if (!st.isSymbolicLink() && (st.mode & 0o022) !== 0) {
      writable++;
      if (writable <= 3) findings.push({ rule: "writable-by-others", severity: "block", file: rel, line: 0, excerpt: `mode ${(st.mode & 0o7777).toString(8)}: writable by group/others` });
    }

    if (st.isSymbolicLink()) {
      const target = await readlink(full);
      const resolved = resolve(dirname(full), target);
      const inside = !isAbsolute(target) && (resolved === root || resolved.startsWith(root + sep));
      if (!inside) findings.push({ rule: "escaping-symlink", severity: "block", file: rel, line: 0, excerpt: excerptOf(`-> ${target}`) });
      return;
    }

    if (st.isDirectory()) {
      if (name === "workflows" && segs.at(-2) === ".github") {
        // GitHub's CI: bb does not load it and no agent reads it.
        findings.push({ rule: "ci-config", severity: "info", file: rel, line: 0, excerpt: dep ? ".github/workflows inside a dependency" : "the repository has GitHub CI (.github/workflows); bb does not load it" });
      } else if (AGENT_DIRS.has(name)) {
        // Inside a dependency it is a file of that package's repository, not a configuration anyone loads for this plugin.
        if (dep) findings.push({ rule: "agent-config", severity: "info", file: rel, line: 0, excerpt: `${name}/ inside a dependency (not a configuration of this plugin)` });
        else findings.push({ rule: "agent-config", severity: "review", file: rel, line: 0, excerpt: `${name}/ (agent / IDE configuration inside a plugin)` });
      }
      return;
    }
    if (!st.isFile()) {
      findings.push({ rule: "special-file", severity: "block", file: rel, line: 0, excerpt: "not a regular file" });
      return;
    }

    const ext = extname(name).toLowerCase();
    allFiles.add(posixRel);
    if (verified) {
      // Registry content: only what the graph and the dependency list need is read.
      if (NATIVE_EXT.has(ext)) findings.push({ rule: "binary", severity: "info", file: rel, line: 0, excerpt: `native/binary file (${ext}) in a verified npm package` });
      if (!isCodeFile(rel) && name !== "package.json") return;
    }
    if (!verified) {
      if (AGENT_FILES.has(name)) findings.push({ rule: "agent-config", severity: dep ? "info" : "review", file: rel, line: 0, excerpt: dep ? `${name} inside a dependency (not a configuration of this plugin)` : name });
      if (name === ".npmrc") findings.push({ rule: "npmrc", severity: "block", file: rel, line: 0, excerpt: ".npmrc inside a plugin" });
      if (name === "binding.gyp") findings.push({ rule: "native-module", severity: "block", file: rel, line: 0, excerpt: "binding.gyp (native build)" });
    }

    if (st.size > MAX_FILE_BYTES) {
      findings.push({ rule: "file-too-large", severity: "review", file: rel, line: 0, excerpt: `${st.size} bytes: not scanned` });
      return;
    }
    const buf = await readFile(full);
    bytes += buf.length;

    const exempt = dist; // bb's own build output may contain wasm/minified code
    const executable = isExecutableMagic(buf);
    // A few raw control characters in readable source (a regex written with real bytes) are a warning (invisible-chars), not "binary data".
    const textyCode = isCodeFile(rel) && !executable && !buf.toString("utf8").includes("\uFFFD") && buf.reduce((n, b) => n + (b === 0 ? 1 : 0), 0) <= 16;
    const binary = NATIVE_EXT.has(ext) || executable || (!MEDIA_EXT.has(ext) && looksBinary(buf) && !textyCode);
    if (binary) {
      if (!exempt && !verified) findings.push({ rule: "binary", severity: "block", file: rel, line: 0, excerpt: NATIVE_EXT.has(ext) ? `native/binary file (${ext})` : executable ? "executable binary (by magic bytes)" : "binary data" });
      return;
    }
    if (MEDIA_EXT.has(ext)) return;

    if (!verified && (st.mode & 0o111) !== 0 && !isCodeFile(rel) && ext !== ".sh") {
      findings.push({ rule: "executable-file", severity: "review", file: rel, line: 0, excerpt: `mode ${(st.mode & 0o7777).toString(8)}` });
    }

    const text = buf.toString("utf8");
    if (!verified && text.includes("�") && Buffer.from(text, "utf8").length !== buf.length) {
      findings.push({ rule: "invalid-utf8", severity: "review", file: rel, line: 0, excerpt: "not valid UTF-8: checked as bytes only" });
    }
    if (!verified) findings.push(...invisibleFindings(rel, text));

    if (name === "package.json") {
      const { findings: f, pkg, declared: d } = packageFindings(rel, text, rel === "package.json");
      if (!verified) findings.push(...f);
      else findings.push(...f.filter((x) => x.severity === "info"));
      if (pkg) packageJsons.set(posixRel, pkg);
      if (rel === "package.json") {
        rootPackage = pkg;
        declared = d;
      }
      const dirName = dep ? installedPackageName(rel) : null;
      if (dirName !== null && pkg) {
        const version = typeof pkg.version === "string" && parseVersion(pkg.version) ? pkg.version : null;
        installed.push({ name: dirName, version, file: rel, declaredName: typeof pkg.name === "string" && pkg.name !== dirName ? pkg.name : null });
      }
    }
    if (isCodeFile(rel)) {
      if (!exempt && !verified && !KNOWN_VENDORED_SHA256.has(createHash("sha256").update(buf).digest("hex"))) {
        const why = minifiedReason(text);
        if (why) findings.push({ rule: "minified", severity: "block", file: rel, line: 0, excerpt: why });
      }
      sources.push({ rel, text, dep, dist });
    }
  };

  await walkDir("");
  if (writable > 3) findings.push({ rule: "writable-by-others", severity: "block", file: "", line: 0, excerpt: `${writable - 3} more entries are writable by group/others` });
  return { findings, sources, rootPackage, declared, installed, allFiles, packageJsons, files, bytes };
}
