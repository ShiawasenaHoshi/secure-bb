// What the npm registry says about a package: when each version was published and
// which tags exist. Requests are made by the server process (the caller passes `fetch`),
// answers are cached in the plugin's database. Without a cache hit and without network
// the answer is "unknown" — never a guess.
import { isValidName } from "./collect.js";
import { parseVersion } from "./semver.js";

export const REGISTRY_URL = "https://registry.npmjs.org";
/** A cached package that lacks a wanted version is asked about again after this long (a release may be new). */
export const REFRESH_MS = 60 * 60_000;
/** Cached rows older than this are dropped (their release times stay true, but the table must not grow forever). */
export const PRUNE_MS = 60 * 86_400_000;
const MAX_BODY_BYTES = 64 * 1024 * 1024;

export interface RegistryEntry {
  name: string;
  /** `ok`: metadata read; `missing`: the registry answered 404. */
  state: "ok" | "missing";
  fetchedAt: number;
  distTags: Record<string, string>;
  /** version → ISO publish time. */
  times: Record<string, string>;
}

/** Persistent cache; implemented by Store. */
export interface RegistryCache {
  getRegistry(name: string): RegistryEntry | null;
  putRegistry(entry: RegistryEntry): void;
}

export type FetchLike = (url: string, init?: { headers?: Record<string, string>; signal?: AbortSignal; redirect?: "error" | "follow" | "manual" }) => Promise<{
  status: number;
  ok: boolean;
  body: ReadableStream<Uint8Array> | null;
  text(): Promise<string>;
}>;

export type Lookup =
  /** `refreshError`: the cached entry was due for a refresh and the registry could not be asked. */
  | { entry: RegistryEntry; fromCache: boolean; refreshError?: string }
  | { entry: null; reason: string };

export interface RegistryDeps {
  cache: RegistryCache;
  fetch: FetchLike;
  now: () => number;
  /** Per request. Default 5 s. */
  requestTimeoutMs?: number;
  /** Aborts every request still running (the hook may only wait so long). */
  signal?: AbortSignal;
}

const registryPath = (name: string): string => (name.startsWith("@") ? name.replace("/", "%2F") : name);

async function readCapped(res: Awaited<ReturnType<FetchLike>>): Promise<string> {
  if (!res.body) return res.text();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new Error(`answer larger than ${MAX_BODY_BYTES / 1024 / 1024} MB`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Reduces a registry document to what we keep. Throws when it is not a package document. */
export function parsePackument(name: string, text: string, now: number): RegistryEntry {
  const doc = JSON.parse(text) as { "dist-tags"?: unknown; time?: unknown };
  if (typeof doc !== "object" || doc === null || typeof doc.time !== "object" || doc.time === null) throw new Error("the answer has no publish times");
  const times: Record<string, string> = {};
  for (const [version, at] of Object.entries(doc.time as Record<string, unknown>)) {
    if (typeof at === "string" && parseVersion(version) && !Number.isNaN(Date.parse(at))) times[version] = at;
  }
  const distTags: Record<string, string> = {};
  if (doc["dist-tags"] && typeof doc["dist-tags"] === "object") {
    for (const [tag, version] of Object.entries(doc["dist-tags"] as Record<string, unknown>)) if (typeof version === "string") distTags[tag] = version;
  }
  return { name, state: "ok", fetchedAt: now, distTags, times };
}

/**
 * Registry data for a package. `wantVersion` is a version we must find: a cached entry
 * that does not list it is refreshed once it is older than {@link REFRESH_MS}.
 */
export async function lookupPackage(d: RegistryDeps, name: string, wantVersion?: string): Promise<Lookup> {
  if (!isValidName(name)) return { entry: null, reason: "not a valid npm package name" };
  const cached = d.cache.getRegistry(name);
  const now = d.now();
  if (cached) {
    const fresh = now - cached.fetchedAt < REFRESH_MS;
    const satisfied = cached.state === "ok" ? wantVersion === undefined || cached.times[wantVersion] !== undefined : false;
    if (satisfied || fresh) return { entry: cached, fromCache: true };
  }
  const stale = cached && cached.state === "ok" ? cached : null;
  try {
    const timeout = AbortSignal.timeout(d.requestTimeoutMs ?? 5000);
    const signal = d.signal ? AbortSignal.any([timeout, d.signal]) : timeout;
    const res = await d.fetch(`${REGISTRY_URL}/${registryPath(name)}`, { headers: { accept: "application/json", "user-agent": "secure-bb" }, signal, redirect: "error" });
    if (res.status === 404) {
      const entry: RegistryEntry = { name, state: "missing", fetchedAt: now, distTags: {}, times: {} };
      d.cache.putRegistry(entry);
      return { entry, fromCache: false };
    }
    if (!res.ok) return fallback(stale, `the registry answered HTTP ${res.status}`);
    const entry = parsePackument(name, await readCapped(res), now);
    d.cache.putRegistry(entry);
    return { entry, fromCache: false };
  } catch (err) {
    return fallback(stale, `the registry could not be reached (${err instanceof Error ? err.message : String(err)})`.slice(0, 200));
  }
}

/** A failed refresh still has the old answer: usable for versions it lists; for the rest the failure is the answer. */
function fallback(stale: RegistryEntry | null, reason: string): Lookup {
  return stale ? { entry: stale, fromCache: true, refreshError: reason } : { entry: null, reason };
}
