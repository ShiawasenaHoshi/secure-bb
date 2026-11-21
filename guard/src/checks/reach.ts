// What the core can actually load: the entry points of a plugin and the import graph under them.
// A file nothing reaches (tests, examples, a dependency's docs, its CI configuration) is not code the
// core runs; the checks do not block on it. Pure functions: no file access (the tree scan has read it all).
import { isBuiltin } from "node:module";
import { posix } from "node:path";

export interface GraphContext {
  /** Every regular file of the tree (posix paths). */
  files: ReadonlySet<string>;
  /** Parsed package.json files (posix path → manifest). */
  packageJsons: ReadonlyMap<string, Record<string, unknown>>;
}

const CODE = /\.(m|c)?[jt]sx?$/i;
const EXTS = ["", ".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx"];

/** `./a.js` may be the source `./a.ts`; a directory may hold `index.*`. Returns the files that exist. */
export function fileCandidates(joined: string, ctx: GraphContext): string[] {
  const stem = joined.replace(/\.(m|c)?jsx?$/, "");
  const out = new Set<string>();
  for (const e of EXTS) {
    for (const base of [joined, stem]) if (ctx.files.has(base + e) && CODE.test(base + e)) out.add(base + e);
  }
  for (const e of EXTS.slice(1)) if (ctx.files.has(`${joined}/index${e}`)) out.add(`${joined}/index${e}`);
  return [...out];
}

/** All string leaves of an `exports` / `imports` value (every condition: the graph over-approximates on purpose). */
function leaves(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) leaves(x, out);
  else if (v && typeof v === "object") for (const x of Object.values(v as Record<string, unknown>)) leaves(x, out);
  return out;
}

/** The part of `exports` that answers `subpath` (`.` or `./x`), patterns with one `*` included. */
function exportTargets(exp: unknown, subpath: string): string[] {
  if (exp === undefined || exp === null) return [];
  // `exports` is either a conditions object / string / array for ".", or a map of subpaths.
  const isMap = typeof exp === "object" && !Array.isArray(exp) && Object.keys(exp as object).some((k) => k.startsWith("."));
  if (!isMap) return subpath === "." ? leaves(exp) : [];
  const map = exp as Record<string, unknown>;
  if (map[subpath] !== undefined) return leaves(map[subpath]);
  const out: string[] = [];
  for (const [k, v] of Object.entries(map)) {
    const star = k.indexOf("*");
    if (star < 0) continue;
    const pre = k.slice(0, star);
    const post = k.slice(star + 1);
    if (subpath.startsWith(pre) && subpath.endsWith(post) && subpath.length >= k.length - 1) {
      const mid = subpath.slice(pre.length, subpath.length - post.length);
      for (const t of leaves(v)) out.push(t.replace("*", mid));
    }
  }
  return out;
}

function packageEntry(pkgDir: string, subpath: string, ctx: GraphContext): string[] {
  const pkg = ctx.packageJsons.get(`${pkgDir}/package.json`) ?? {};
  const targets: string[] = [];
  const bySub = exportTargets(pkg.exports, subpath === "" ? "." : `./${subpath}`);
  targets.push(...bySub);
  if (subpath === "") {
    for (const k of ["main", "module", "browser", "jsnext:main"]) if (typeof pkg[k] === "string") targets.push(pkg[k] as string);
    targets.push("index");
  } else if (bySub.length === 0) targets.push(subpath);
  const out = new Set<string>();
  for (const t of targets) {
    const joined = posix.normalize(posix.join(pkgDir, t));
    if (!joined.startsWith(pkgDir + "/") && joined !== pkgDir) continue;
    for (const c of fileCandidates(joined, ctx)) out.add(c);
  }
  return [...out];
}

/** `@scope/name/sub/path` → name and subpath. */
export function splitSpecifier(spec: string): { name: string; subpath: string } | null {
  const parts = spec.split("/");
  const nameParts = spec.startsWith("@") ? 2 : 1;
  if (parts.length < nameParts || parts.slice(0, nameParts).some((p) => p === "" || p === "." || p === "..")) return null;
  return { name: parts.slice(0, nameParts).join("/"), subpath: parts.slice(nameParts).join("/") };
}

/** The files a specifier written in `fromRel` can mean. Empty for built-ins and for packages that are not in the tree (the SDK, the host). */
export function resolveSpecifier(fromRel: string, spec: string, ctx: GraphContext): string[] {
  if (spec === "" || isBuiltin(spec) || spec.startsWith("node:")) return [];
  const dir = posix.dirname(fromRel);
  if (spec.startsWith("./") || spec.startsWith("../") || spec === "." || spec === "..") {
    const joined = posix.normalize(posix.join(dir, spec));
    const out = new Set(fileCandidates(joined, ctx));
    if (ctx.packageJsons.has(`${joined}/package.json`)) for (const c of packageEntry(joined, "", ctx)) out.add(c);
    return [...out];
  }
  if (spec.startsWith("/")) return fileCandidates(posix.normalize(spec.slice(1)), ctx);
  if (spec.startsWith("#")) {
    // The `imports` of the nearest package.json.
    for (let d = dir; ; d = posix.dirname(d)) {
      const pkg = ctx.packageJsons.get(d === "." ? "package.json" : `${d}/package.json`);
      const imp = pkg?.imports as Record<string, unknown> | undefined;
      if (imp && typeof imp === "object") {
        const out = new Set<string>();
        for (const t of exportTargets(imp, spec)) for (const c of fileCandidates(posix.normalize(posix.join(d === "." ? "" : d, t)), ctx)) out.add(c);
        return [...out];
      }
      if (d === "." || d === "/") return [];
    }
  }
  const parts = splitSpecifier(spec);
  if (!parts) return [];
  for (let d = dir; ; d = posix.dirname(d)) {
    const pkgDir = d === "." ? `node_modules/${parts.name}` : `${d}/node_modules/${parts.name}`;
    if (ctx.packageJsons.has(`${pkgDir}/package.json`)) return packageEntry(pkgDir, parts.subpath, ctx);
    if (d === "." || d === "/") return [];
  }
}

/** `bb` of the manifest and `main`/`exports` of the root: every string that names a code file. */
function manifestPaths(pkg: Record<string, unknown>): string[] {
  const out: string[] = [];
  const walk = (v: unknown, depth: number): void => {
    if (depth > 6) return;
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) for (const x of v) walk(x, depth + 1);
    else if (v && typeof v === "object") for (const x of Object.values(v as Record<string, unknown>)) walk(x, depth + 1);
  };
  walk(pkg.bb, 0);
  for (const k of ["main", "module", "bin", "exports"]) walk(pkg[k], 0);
  return out;
}

export interface EntryPoints {
  /** Code files the core loads, as found in the tree. */
  entries: string[];
  /** Files under `dist/` among them. */
  dist: string[];
  /** The `dist/` bundles are built from source entries that exist in this tree: the core rebuilds them on path and git installs. */
  distDerived: boolean;
}

/**
 * Entry points: what `bb.server`, `bb.app`, `bb.host` (and any other code path of the `bb` field, `main`, `exports`) name, and the
 * built `dist/*.js` the core loads in place of the source for managed installs.
 */
export function entryPoints(root: Record<string, unknown> | null, ctx: GraphContext): EntryPoints {
  const entries = new Set<string>();
  const source = new Set<string>();
  if (root) {
    for (const p of manifestPaths(root)) {
      if (!CODE.test(p)) continue;
      const joined = posix.normalize(posix.join(".", p));
      if (joined.startsWith("..") || posix.isAbsolute(joined)) continue;
      for (const c of fileCandidates(joined, ctx)) {
        entries.add(c);
        if (!c.startsWith("dist/")) source.add(c);
      }
    }
  }
  const dist: string[] = [];
  for (const f of ctx.files) {
    if (/^dist\/[^/]+\.(m|c)?js$/.test(f)) {
      dist.push(f);
      entries.add(f);
    }
  }
  // A bundle is derived when the source entry of the same name is in the tree (server → bb.server, app → bb.app, host → bb.host).
  const declared = (root?.bb && typeof root.bb === "object" ? (root.bb as Record<string, unknown>) : {}) as Record<string, unknown>;
  const main = dist.filter((d) => ["server", "app", "host"].includes(posix.basename(d).replace(/\.(m|c)?js$/, "")));
  const derived =
    main.length > 0 &&
    main.every((d) => {
      const decl = declared[posix.basename(d).replace(/\.(m|c)?js$/, "")];
      if (typeof decl !== "string") return false;
      const joined = posix.normalize(posix.join(".", decl));
      return !joined.startsWith("dist/") && fileCandidates(joined, ctx).length > 0;
    });
  return { entries: [...entries].sort(), dist: dist.sort(), distDerived: derived };
}
