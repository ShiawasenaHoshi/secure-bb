// Directory-tree helpers: hashing, snapshot copies, plugin identity.
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { cp, lstat, readdir, readFile, readlink, realpath, rm } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

/** Entries never part of a snapshot: VCS data, and build output (rebuilt on install). */
export function excluded(relPath: string, includeDist = false): boolean {
  const first = relPath.split(sep)[0];
  return first === ".git" || (first === "dist" && !includeDist);
}

async function walk(root: string, rel: string, out: string[], includeDist: boolean): Promise<void> {
  const entries = await readdir(join(root, rel), { withFileTypes: true });
  for (const entry of entries) {
    const childRel = rel === "" ? entry.name : join(rel, entry.name);
    if (excluded(childRel, includeDist)) continue;
    out.push(childRel);
    if (entry.isDirectory()) await walk(root, childRel, out, includeDist);
  }
}

function hashFile(hash: ReturnType<typeof createHash>, path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve());
    stream.on("error", reject);
  });
}

/**
 * sha256 over every path, mode, and byte under `root` (minus `.git`, and minus
 * `dist` unless `includeDist`: bb rebuilds `dist/` itself when it installs).
 */
export async function hashTree(root: string, opts: { includeDist?: boolean } = {}): Promise<string> {
  const paths: string[] = [];
  await walk(root, "", paths, opts.includeDist ?? false);
  paths.sort();
  const hash = createHash("sha256");
  for (const rel of paths) {
    const full = join(root, rel);
    const st = await lstat(full);
    const mode = (st.mode & 0o7777).toString(8);
    if (st.isSymbolicLink()) {
      hash.update(`L\0${rel}\0${await readlink(full)}\0`);
    } else if (st.isDirectory()) {
      hash.update(`D\0${rel}\0${mode}\0`);
    } else if (st.isFile()) {
      hash.update(`F\0${rel}\0${mode}\0${st.size}\0`);
      await hashFile(hash, full);
    } else {
      hash.update(`X\0${rel}\0`); // sockets, devices: recorded, never followed
    }
  }
  return hash.digest("hex");
}

/** Copies `src` to `dest` without `.git`/`dist`; symlinks are kept as links. */
export async function copyTree(src: string, dest: string): Promise<void> {
  await cp(src, dest, {
    recursive: true,
    verbatimSymlinks: true,
    force: false,
    errorOnExist: true,
    filter: (from) => {
      const rel = relative(src, from);
      return rel === "" || !excluded(rel);
    },
  });
}

export async function removeTree(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
}

/** The plugin id bb derives from a package name (see "Plugin id" in the plugin docs). */
export function pluginIdFromPackageName(name: string): string | null {
  const last = name.split("/").pop() ?? "";
  const stripped = last.startsWith("bb-plugin-") ? last.slice("bb-plugin-".length) : last;
  const id = stripped
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return id === "" ? null : id;
}

export interface PackageInfo {
  name: string;
  id: string;
  version: string;
  hasServer: boolean;
}

export async function readPackageInfo(dir: string): Promise<PackageInfo> {
  let raw: string;
  try {
    raw = await readFile(join(dir, "package.json"), "utf8");
  } catch {
    throw new Error(`no package.json in ${dir}`);
  }
  const pkg = JSON.parse(raw) as { name?: unknown; version?: unknown; bb?: { server?: unknown } };
  if (typeof pkg.name !== "string") throw new Error("package.json has no name");
  const id = pluginIdFromPackageName(pkg.name);
  if (id === null) throw new Error(`cannot derive a plugin id from "${pkg.name}"`);
  return {
    name: pkg.name,
    id,
    version: typeof pkg.version === "string" ? pkg.version : "0.0.0",
    hasServer: typeof pkg.bb?.server === "string",
  };
}

export async function realpathOrSelf(p: string): Promise<string> {
  try {
    return await realpath(p);
  } catch {
    return p;
  }
}

/** True when `path` is strictly below `root`. Lexical: resolve symlinks first. */
export function isInside(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel !== "" && rel !== ".." && !rel.startsWith(".." + sep) && !isAbsolute(rel);
}

/**
 * The one definition of "this directory is one of our snapshots": the real
 * path (symlinks resolved) lies strictly inside the real snapshots root.
 * `snapshots-evil/x`, `..` tricks and symlinks that lead out all fail.
 */
export async function isInsideSnapshots(root: string, path: string): Promise<boolean> {
  try {
    return isInside(await realpath(root), await realpath(path));
  } catch {
    return false;
  }
}

/**
 * Symlinks that leave the tree (absolute targets, or relative ones that resolve
 * outside `root`). A snapshot must be self-contained: such a link would make
 * loaded code depend on files nobody reviewed.
 */
export async function findEscapingSymlinks(root: string): Promise<string[]> {
  const paths: string[] = [];
  await walk(root, "", paths, true);
  const bad: string[] = [];
  for (const rel of paths) {
    const full = join(root, rel);
    if (!(await lstat(full)).isSymbolicLink()) continue;
    const target = await readlink(full);
    const resolved = resolve(dirname(full), target);
    if (isAbsolute(target) || !(resolved === root || isInside(root, resolved))) bad.push(rel);
  }
  return bad;
}
