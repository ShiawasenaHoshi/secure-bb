// Tree walk and structural checks (spec §5.1 "Структура"): everything that can
// be decided without parsing code.
import { createHash } from "node:crypto";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import type { Finding } from "./types.js";

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

export interface TreeScan {
  findings: Finding[];
  sources: SourceFile[];
  rootPackage: Record<string, unknown> | null;
  files: number;
  bytes: number;
}

const CODE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);
export const isCodeFile = (rel: string): boolean => CODE_EXT.has(extname(rel).toLowerCase()) && !/\.d\.[mc]?ts$/i.test(rel);

const NATIVE_EXT = new Set([".node", ".wasm", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".jar"]);
/** Binary formats that are harmless as data. */
const MEDIA_EXT = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".icns", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".mp3", ".mp4", ".wav", ".ogg"]);
const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];
const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const AGENT_DIRS = new Set([".claude", ".cursor", ".vscode", ".windsurf"]);
const AGENT_FILES = new Set([".cursorrules", ".mcp.json"]);

export function excerptOf(text: string, max = 160): string {
  const flat = text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, (c) => `\\u{${c.codePointAt(0)!.toString(16)}}`);
  const t = flat.trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
}

/** Control, format and invisible characters (spec §5.1). TAB, LF, CR and a leading BOM are allowed. */
const INVISIBLE_ONE = /^[\p{Cc}\p{Cf}\u2028\u2029\uFE00-\uFE0F\u{E0100}-\u{E01EF}]$/u;
const isInvisible = (ch: string): boolean => ch !== "\t" && ch !== "\n" && ch !== "\r" && INVISIBLE_ONE.test(ch);

export function escapeInvisible(s: string): string {
  return [...s].map((c) => (isInvisible(c) ? `\\u{${c.codePointAt(0)!.toString(16).toUpperCase()}}` : c)).join("");
}

function invisibleFindings(rel: string, text: string): Finding[] {
  const out: Finding[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length && out.length < 5; i++) {
    let line = lines[i]!.replace(/\r$/, "");
    if (i === 0 && line.startsWith("\uFEFF")) line = line.slice(1);
    if ([...line].some(isInvisible)) out.push({ rule: "invisible-chars", severity: "block", file: rel, line: i + 1, excerpt: excerptOf(escapeInvisible(line)) });
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

function isUrlSpec(spec: string): boolean {
  return /^(git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|ssh:|file:|link:)/i.test(spec) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec) /* user/repo shorthand */;
}
/** `workspace:` is how bb's own monorepo plugins refer to each other: not a URL, but not a registry version either. */
const isWorkspaceSpec = (spec: string): boolean => /^workspace:/i.test(spec);

function packageFindings(rel: string, raw: string, isRoot: boolean): { findings: Finding[]; pkg: Record<string, unknown> | null } {
  const findings: Finding[] = [];
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { findings: [{ rule: "bad-package-json", severity: "review", file: rel, line: 0, excerpt: "package.json is not valid JSON" }], pkg: null };
  }
  const lineOf = (needle: string): number => {
    const idx = raw.indexOf(`"${needle}"`);
    return idx < 0 ? 0 : raw.slice(0, idx).split("\n").length;
  };
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? (pkg.scripts as Record<string, unknown>) : {};
  for (const name of INSTALL_SCRIPTS) {
    if (typeof scripts[name] === "string") findings.push({ rule: "install-script", severity: "block", file: rel, line: lineOf(name), excerpt: excerptOf(`${name}: ${scripts[name]}`) });
  }
  if (pkg.gypfile === true) findings.push({ rule: "native-module", severity: "block", file: rel, line: lineOf("gypfile"), excerpt: "gypfile: true (native build on install)" });
  for (const field of DEP_FIELDS) {
    const deps = pkg[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof spec !== "string") continue;
      if (isUrlSpec(spec.trim())) findings.push({ rule: "url-dependency", severity: "block", file: rel, line: lineOf(name), excerpt: excerptOf(`${field}: ${name}@${spec}`) });
      else if (isWorkspaceSpec(spec.trim())) findings.push({ rule: "workspace-dependency", severity: "review", file: rel, line: lineOf(name), excerpt: excerptOf(`${field}: ${name}@${spec}`) });
    }
  }
  void isRoot;
  return { findings, pkg };
}

/** Walks the tree once: structural findings, plus the text of every source file for the AST pass. */
export async function scanTree(root: string): Promise<TreeScan> {
  const findings: Finding[] = [];
  const sources: SourceFile[] = [];
  let rootPackage: Record<string, unknown> | null = null;
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
      if (AGENT_DIRS.has(name) || (name === "workflows" && segs.at(-2) === ".github")) {
        findings.push({ rule: "agent-config", severity: "block", file: rel, line: 0, excerpt: `${name}/ (agent / IDE / CI configuration inside a plugin)` });
      }
      return;
    }
    if (!st.isFile()) {
      findings.push({ rule: "special-file", severity: "block", file: rel, line: 0, excerpt: "not a regular file" });
      return;
    }

    if (AGENT_FILES.has(name)) findings.push({ rule: "agent-config", severity: "block", file: rel, line: 0, excerpt: name });
    if (name === ".npmrc") findings.push({ rule: "npmrc", severity: "block", file: rel, line: 0, excerpt: ".npmrc inside a plugin" });
    if (name === "binding.gyp") findings.push({ rule: "native-module", severity: "block", file: rel, line: 0, excerpt: "binding.gyp (native build)" });

    const ext = extname(name).toLowerCase();
    if (st.size > MAX_FILE_BYTES) {
      findings.push({ rule: "file-too-large", severity: "review", file: rel, line: 0, excerpt: `${st.size} bytes: not scanned` });
      return;
    }
    const buf = await readFile(full);
    bytes += buf.length;

    const exempt = dist; // bb's own build output may contain wasm/minified code
    const executable = isExecutableMagic(buf);
    const binary = NATIVE_EXT.has(ext) || executable || (!MEDIA_EXT.has(ext) && looksBinary(buf));
    if (binary) {
      if (!exempt) findings.push({ rule: "binary", severity: "block", file: rel, line: 0, excerpt: NATIVE_EXT.has(ext) ? `native/binary file (${ext})` : executable ? "executable binary (by magic bytes)" : "binary data" });
      return;
    }
    if (MEDIA_EXT.has(ext)) return;

    if ((st.mode & 0o111) !== 0 && !isCodeFile(rel) && ext !== ".sh") {
      findings.push({ rule: "executable-file", severity: "review", file: rel, line: 0, excerpt: `mode ${(st.mode & 0o7777).toString(8)}` });
    }

    const text = buf.toString("utf8");
    if (text.includes("�") && Buffer.from(text, "utf8").length !== buf.length) {
      findings.push({ rule: "invalid-utf8", severity: "review", file: rel, line: 0, excerpt: "not valid UTF-8: checked as bytes only" });
    }
    findings.push(...invisibleFindings(rel, text));

    if (name === "package.json") {
      const { findings: f, pkg } = packageFindings(rel, text, rel === "package.json");
      findings.push(...f);
      if (rel === "package.json") rootPackage = pkg;
    }
    if (isCodeFile(rel)) {
      if (!exempt && !KNOWN_VENDORED_SHA256.has(createHash("sha256").update(buf).digest("hex"))) {
        const why = minifiedReason(text);
        if (why) findings.push({ rule: "minified", severity: "block", file: rel, line: 0, excerpt: why });
      }
      sources.push({ rel, text, dep, dist });
    }
  };

  await walkDir("");
  if (writable > 3) findings.push({ rule: "writable-by-others", severity: "block", file: "", line: 0, excerpt: `${writable - 3} more entries are writable by group/others` });
  return { findings, sources, rootPackage, files, bytes };
}
