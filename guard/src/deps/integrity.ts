// Which packages in `node_modules` are exactly what the npm registry published. A package whose every file equals the
// file of the registry tarball (the tarball itself checked against the registry's `integrity`) is code published to npm,
// not code the plugin's author wrote: the checks do not run content heuristics on it (invisible characters, minified
// code…), and the judgement of the package itself (age, lookalike names) is the registry stage's job.
//
// Zero dependencies (node:* only): the plugin and the guard share this file. The network is the caller's `fetch`.
import { createHash } from "node:crypto";
import { lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";

export const NPM_REGISTRY = "https://registry.npmjs.org";
const MAX_TARBALL_BYTES = 40 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 200 * 1024 * 1024;
const MAX_ENTRIES = 30_000;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_PACKAGES = 3000;
const NAME = /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export type RegistryFetch = (
  url: string,
  init?: { headers?: Record<string, string>; signal?: AbortSignal; redirect?: "error" | "follow" | "manual" },
) => Promise<{ status: number; ok: boolean; body: ReadableStream<Uint8Array> | null; text(): Promise<string> }>;

/** `file → sha256` of what the registry tarball of `name@version` holds. Kept by the caller (memory or database). */
export interface ManifestCache {
  get(key: string): Record<string, string> | undefined;
  put(key: string, files: Record<string, string>): void;
}
export const memoryManifestCache = (): ManifestCache => {
  const m = new Map<string, Record<string, string>>();
  return { get: (k) => m.get(k), put: (k, v) => void m.set(k, v) };
};

export interface InstalledPackage {
  /** Directory relative to the checked root, posix: `node_modules/@a/b`, `node_modules/x/node_modules/y`. */
  dir: string;
  name: string;
  version: string;
}

export type Integrity =
  | { state: "verified" }
  /** Every file is as published, except these: the copy was changed (or is not the release it claims to be). */
  | { state: "modified"; reason: string }
  /** Could not be established (no network, out of time, no such version, too large). Scanned as if unknown. */
  | { state: "unverified"; reason: string };

const sha256 = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

/** Every `name@version` that sits in a `node_modules` directory of the tree (nested ones included). */
export async function inventoryPackages(root: string): Promise<InstalledPackage[]> {
  const out: InstalledPackage[] = [];
  const readPkg = async (rel: string): Promise<void> => {
    if (out.length >= MAX_PACKAGES) return;
    let doc: unknown;
    try {
      const st = await lstat(join(root, rel, "package.json"));
      if (!st.isFile() || st.size > 2 * 1024 * 1024) return;
      doc = JSON.parse(await readFile(join(root, rel, "package.json"), "utf8"));
    } catch {
      return;
    }
    const d = doc as { name?: unknown; version?: unknown };
    if (typeof d?.name === "string" && typeof d.version === "string" && NAME.test(d.name) && VERSION.test(d.version)) out.push({ dir: rel, name: d.name, version: d.version });
    await nodeModules(`${rel}/node_modules`);
  };
  const nodeModules = async (rel: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(join(root, rel), { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      if (e.name.startsWith(".") || !e.isDirectory()) continue;
      if (e.name.startsWith("@")) {
        let inner;
        try {
          inner = await readdir(join(root, rel, e.name), { withFileTypes: true });
        } catch {
          continue;
        }
        inner.sort((a, b) => (a.name < b.name ? -1 : 1));
        for (const i of inner) if (i.isDirectory() && !i.name.startsWith(".")) await readPkg(`${rel}/${e.name}/${i.name}`);
      } else await readPkg(`${rel}/${e.name}`);
    }
  };
  await nodeModules("node_modules");
  return out;
}

async function readCapped(res: Awaited<ReturnType<RegistryFetch>>, max: number): Promise<Buffer> {
  if (!res.body) throw new Error("no body");
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      throw new Error(`larger than ${Math.round(max / 1024 / 1024)} MB`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

const field = (b: Buffer, off: number, len: number): string => {
  const end = b.indexOf(0, off);
  return b.toString("utf8", off, end >= 0 && end < off + len ? end : off + len);
};

/** `path → sha256` of the regular files of a (gunzipped) tar; the first path component (`package/`) is dropped, as npm does. */
export function tarManifest(tar: Buffer): Record<string, string> {
  const files: Record<string, string> = {};
  let off = 0;
  let longName: string | null = null;
  let paxPath: string | null = null;
  let entries = 0;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (header.every((x) => x === 0)) break;
    if (++entries > MAX_ENTRIES) throw new Error("too many entries");
    const size = parseInt(field(header, 124, 12).trim() || "0", 8);
    if (!Number.isFinite(size) || size < 0) throw new Error("bad tar header");
    const type = String.fromCharCode(header[156] ?? 0);
    const prefix = field(header, 345, 155);
    let name = field(header, 0, 100);
    if (prefix && field(header, 257, 6).startsWith("ustar")) name = `${prefix}/${name}`;
    const body = tar.subarray(off + 512, off + 512 + size);
    if (body.length < size) throw new Error("truncated tar");
    off += 512 + Math.ceil(size / 512) * 512;
    if (type === "L") {
      longName = body.toString("utf8").replace(/\0.*$/s, "");
      continue;
    }
    if (type === "x") {
      const m = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(body.toString("utf8"));
      paxPath = m ? m[1]! : null;
      continue;
    }
    if (type === "g") continue;
    const path = paxPath ?? longName ?? name;
    longName = null;
    paxPath = null;
    if (type !== "0" && type !== "\0") continue; // directories, links: nothing to compare
    const parts = path.split("/").slice(1);
    if (parts.length === 0 || parts.some((p) => p === ".." || p === "" || p === ".")) continue;
    files[parts.join("/")] = sha256(body);
  }
  return files;
}

const registryPath = (name: string): string => (name.startsWith("@") ? name.replace("/", "%2F") : name);

async function fetchManifest(pkg: InstalledPackage, env: IntegrityEnv, signal: AbortSignal): Promise<Record<string, string>> {
  const key = `${pkg.name}@${pkg.version}`;
  const cached = env.cache?.get(key);
  if (cached) return cached;
  const timeout = AbortSignal.timeout(env.requestTimeoutMs ?? 8000);
  const sig = AbortSignal.any([timeout, signal]);
  const metaRes = await env.fetch(`${NPM_REGISTRY}/${registryPath(pkg.name)}/${pkg.version}`, { headers: { accept: "application/json", "user-agent": "secure-bb" }, signal: sig, redirect: "error" });
  if (metaRes.status === 404) throw new Error("the registry has no such version");
  if (!metaRes.ok) throw new Error(`the registry answered HTTP ${metaRes.status}`);
  const meta = JSON.parse((await readCapped(metaRes, 8 * 1024 * 1024)).toString("utf8")) as { dist?: { tarball?: unknown; integrity?: unknown; shasum?: unknown } };
  const tarball = meta.dist?.tarball;
  // The tarball is fetched from the registry's own host only: the document cannot send us elsewhere.
  if (typeof tarball !== "string" || !tarball.startsWith(`${NPM_REGISTRY}/`)) throw new Error("the registry names no tarball on its own host");
  const tgzRes = await env.fetch(tarball, { headers: { "user-agent": "secure-bb" }, signal: sig, redirect: "error" });
  if (!tgzRes.ok) throw new Error(`the tarball answered HTTP ${tgzRes.status}`);
  const tgz = await readCapped(tgzRes, MAX_TARBALL_BYTES);
  if (!sriMatches(tgz, meta.dist?.integrity, meta.dist?.shasum)) throw new Error("the tarball does not match the registry's integrity");
  const files = tarManifest(gunzipSync(tgz, { maxOutputLength: MAX_UNPACKED_BYTES }));
  env.cache?.put(key, files);
  return files;
}

/** Compares a tarball with the `integrity` (SRI, base64) or `shasum` (sha1, hex) the registry published for it. */
export function sriMatches(tgz: Buffer, integrity: unknown, shasum: unknown): boolean {
  if (typeof integrity === "string" && integrity.trim() !== "") {
    const items = integrity.trim().split(/\s+/);
    for (const algo of ["sha512", "sha384", "sha256"]) {
      const want = items.find((x) => x.startsWith(`${algo}-`));
      if (want) return createHash(algo).update(tgz).digest("base64") === want.slice(algo.length + 1);
    }
    return false;
  }
  return typeof shasum === "string" && createHash("sha1").update(tgz).digest("hex") === shasum.toLowerCase();
}

/** Every file of the installed package (not of packages nested in its own `node_modules`) must be a file of the release, byte for byte. */
async function compareInstalled(root: string, pkgDir: string, files: Record<string, string>): Promise<string | null> {
  const walk = async (rel: string): Promise<string | null> => {
    const entries = await readdir(join(root, pkgDir, rel), { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      const r = rel === "" ? e.name : `${rel}/${e.name}`;
      if (e.isSymbolicLink()) return `${r} is a symbolic link`;
      if (e.isDirectory()) {
        if (rel === "" && e.name === "node_modules") continue; // other packages, judged on their own
        const bad = await walk(r);
        if (bad) return bad;
      } else if (e.isFile()) {
        const want = files[r];
        if (want === undefined) return `${r} is not in the published package`;
        const full = join(root, pkgDir, r);
        const st = await lstat(full);
        if (st.size > MAX_FILE_BYTES) return `${r} is too large to compare`;
        if (sha256(await readFile(full)) !== want) return `${r} differs from the published package`;
      } else return `${r} is not a regular file`;
    }
    return null;
  };
  return walk("");
}

export interface IntegrityEnv {
  fetch: RegistryFetch;
  cache?: ManifestCache;
  /** The whole stage. Packages not done by then stay `unverified`. Default 6 s. */
  deadlineMs?: number;
  requestTimeoutMs?: number;
  concurrency?: number;
}

/** Judges every installed package against the registry. Never throws; whatever goes wrong is `unverified` with the reason. */
export async function verifyInstalledPackages(root: string, packages: readonly InstalledPackage[], env: IntegrityEnv): Promise<Map<string, Integrity>> {
  const result = new Map<string, Integrity>();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), env.deadlineMs ?? 6000);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < packages.length) {
      const pkg = packages[next++]!;
      if (controller.signal.aborted) {
        result.set(pkg.dir, { state: "unverified", reason: "out of time" });
        continue;
      }
      let files: Record<string, string>;
      try {
        files = await fetchManifest(pkg, env, controller.signal);
      } catch (err) {
        result.set(pkg.dir, { state: "unverified", reason: (err instanceof Error ? err.message : String(err)).slice(0, 160) });
        continue;
      }
      try {
        const bad = await compareInstalled(root, pkg.dir, files);
        result.set(pkg.dir, bad === null ? { state: "verified" } : { state: "modified", reason: bad.slice(0, 200) });
      } catch (err) {
        result.set(pkg.dir, { state: "unverified", reason: `could not read the copy: ${err instanceof Error ? err.message : String(err)}`.slice(0, 160) });
      }
    }
  };
  try {
    await Promise.all(Array.from({ length: Math.min(env.concurrency ?? 6, packages.length) }, worker));
  } finally {
    clearTimeout(timer);
  }
  return result;
}
