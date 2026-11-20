// The registry stage of the dependency checks (stage 2.3): the version of every
// dependency, when the registry says it was published, and what follows from it.
// Everything that cannot be established is reported as "not verified" (a `review`
// finding), never as fine. Never throws: whatever goes wrong becomes "not verified".
import type { CheckResult, Dependency, DependencyStats, Finding } from "../checks/types.js";
import { excerptOf } from "../checks/files.js";
import { isRegistrySpec, isValidName, MAX_FINDINGS_PER_RULE } from "./collect.js";
import { lookalikeOf } from "./lookalike.js";
import { lookupPackage, type FetchLike, type Lookup, type RegistryCache } from "./registry.js";
import { isExactVersion, maxSatisfying } from "./semver.js";

/** A release younger than this is suspicious (spec §5.1). */
export const YOUNG_RELEASE_MS = 3 * 86_400_000;
const MAX_PACKAGES = 400;
const CONCURRENCY = 6;
/** Entries kept in the stored result besides the declared ones. */
const MAX_FLAGGED = 100;

export interface VerifyEnv {
  cache: RegistryCache;
  fetch: FetchLike;
  now: () => number;
  /** How long the whole stage may take. Default 6 s (the hook gives the checks 8 s in all). */
  deadlineMs?: number;
  requestTimeoutMs?: number;
}

const ageText = (ms: number): string => (ms < 3_600_000 ? `${Math.max(0, Math.round(ms / 60_000))} min` : ms < 2 * 86_400_000 ? `${Math.round(ms / 3_600_000)} h` : `${Math.round(ms / 86_400_000)} days`);

/** `npm:other@^1.0.0` → the real package and range. */
function resolveAlias(d: Dependency): { name: string; spec: string | null } {
  if (d.spec && d.spec.startsWith("npm:")) {
    const rest = d.spec.slice(4);
    const at = rest.lastIndexOf("@");
    return at > 0 ? { name: rest.slice(0, at), spec: rest.slice(at + 1) } : { name: rest, spec: "latest" };
  }
  return { name: d.name, spec: d.spec };
}

interface Judged {
  dep: Dependency;
  findings: Finding[];
}

function judge(dep: Dependency, lookups: Map<string, Lookup | undefined>, now: number): Judged {
  const findings: Finding[] = [];
  const at = (rule: string, excerpt: string): void => void findings.push({ rule, severity: "review", file: dep.file, line: dep.line, excerpt: excerptOf(excerpt) });
  const out: Dependency = { ...dep };
  const unchecked = (why: string): Judged => {
    out.status = "unchecked";
    out.note = why;
    return { dep: out, findings };
  };

  const target = resolveAlias(dep);
  if (dep.installed === null && dep.spec !== null && !isRegistrySpec(dep.spec)) {
    out.status = "skipped";
    out.note = "not a registry dependency";
    return { dep: out, findings };
  }
  if (!isValidName(target.name)) return unchecked("not a valid npm package name");
  const lookup = lookups.get(target.name);
  if (lookup === undefined) return unchecked("not asked: too many packages or out of time");
  if (lookup.entry === null) return unchecked(lookup.reason);
  const entry = lookup.entry;
  const label = `${target.name}${dep.installed ?? target.spec ? "@" + (dep.installed ?? target.spec) : ""}`;

  if (entry.state === "missing") {
    out.status = "not-in-registry";
    at("dep-not-in-registry", `${label}: the npm registry has no package with this name`);
    return { dep: out, findings };
  }

  // Which version is judged: the installed copy, else an exact spec, else what the range/tag resolves to now.
  let version: string | null = dep.installed;
  let how = "installed";
  if (version === null && target.spec !== null) {
    const spec = target.spec.trim();
    try {
      if (isExactVersion(spec)) {
        version = spec.replace(/^[v=\s]+/, "");
        how = "pinned";
      } else if (entry.distTags[spec] !== undefined) {
        version = entry.distTags[spec]!;
        how = `tag ${spec}`;
      } else {
        version = maxSatisfying(Object.keys(entry.times), spec);
        how = `resolves today from ${spec}`;
        if (version === null) return unchecked(`no published version satisfies ${spec}`);
      }
    } catch {
      return unchecked(`version range "${spec}" is not understood`);
    }
  }
  if (version === null) return unchecked("version cannot be determined");
  out.version = version;
  const published = entry.times[version];
  if (published === undefined) {
    if (lookup.refreshError) return unchecked(`${version} is not in the cached metadata and ${lookup.refreshError}`);
    out.status = "unknown-version";
    at("dep-unknown-version", `${target.name}@${version} (${how}): the registry has no such version`);
    return { dep: out, findings };
  }
  out.publishedAt = published;
  const age = now - Date.parse(published);
  if (age < YOUNG_RELEASE_MS) {
    out.status = "young";
    at("dep-young-release", `${target.name}@${version} (${how}) was published ${age < 0 ? "in the future" : ageText(age) + " ago"} (${published}); less than 3 days old`);
  } else out.status = "ok";
  return { dep: out, findings };
}

/** Runs `fn` over `items` with at most `n` at a time, in order of arrival. */
async function pool<T>(items: readonly T[], n: number, fn: (x: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) await fn(items[next++]!);
    }),
  );
}

function capped(rule: string, list: Finding[]): Finding[] {
  const mine = list.filter((f) => f.rule === rule);
  if (mine.length <= MAX_FINDINGS_PER_RULE) return mine;
  return [...mine.slice(0, MAX_FINDINGS_PER_RULE), { rule, severity: "review", file: "", line: 0, excerpt: `and ${mine.length - MAX_FINDINGS_PER_RULE} more` }];
}

/** The registry stage over a finished offline result. Returns a new result; the input is not changed. */
export async function verifyDependencies(result: CheckResult, env: VerifyEnv): Promise<CheckResult> {
  const deps = result.dependencies ?? [];
  const now = env.now();
  const stats: DependencyStats = { total: deps.length, declared: deps.filter((d) => d.declared).length, verified: 0, unchecked: 0, young: 0, lookalikes: result.findings.filter((f) => f.rule === "dep-lookalike" && f.file !== "").length, registry: true };
  if (deps.length === 0) return { ...result, dependencies: [], dependencyStats: stats };

  const lookups = new Map<string, Lookup | undefined>();
  let judged: Judged[];
  try {
    // One request per package name; the versions wanted decide whether a cached answer is enough.
    const wanted = new Map<string, Set<string>>();
    for (const d of deps) {
      const t = resolveAlias(d);
      if (d.installed === null && d.spec !== null && !isRegistrySpec(d.spec)) continue;
      if (!isValidName(t.name)) continue;
      const set = wanted.get(t.name) ?? new Set<string>();
      const exact = d.installed ?? (t.spec !== null && isExactVersion(t.spec) ? t.spec.replace(/^[v=\s]+/, "") : null);
      if (exact) set.add(exact);
      wanted.set(t.name, set);
    }
    const names = [...wanted.keys()].slice(0, MAX_PACKAGES);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), env.deadlineMs ?? 6000);
    try {
      await pool(names, CONCURRENCY, async (name) => {
        if (controller.signal.aborted) return;
        // A package seen in several versions: the cache must list all of them, or be refreshed.
        const versions = [...wanted.get(name)!];
        let res = await lookupPackage({ cache: env.cache, fetch: env.fetch, now: env.now, requestTimeoutMs: env.requestTimeoutMs, signal: controller.signal }, name, versions[0]);
        for (const v of versions.slice(1)) {
          if (res.entry === null || res.entry.state !== "ok" || res.entry.times[v] !== undefined || ("refreshError" in res && res.refreshError)) break;
          res = await lookupPackage({ cache: env.cache, fetch: env.fetch, now: env.now, requestTimeoutMs: env.requestTimeoutMs, signal: controller.signal }, name, v);
        }
        lookups.set(name, res);
      });
    } finally {
      clearTimeout(timer);
    }
    judged = deps.map((d) => judge(d, lookups, now));
  } catch (err) {
    const why = `internal error: ${err instanceof Error ? err.message : String(err)}`.slice(0, 160);
    judged = deps.map((d) => ({ dep: { ...d, status: "unchecked" as const, note: why }, findings: [] }));
  }

  const findings: Finding[] = [...result.findings];
  const flagged: Finding[] = [];
  for (const j of judged) flagged.push(...j.findings);
  for (const rule of ["dep-young-release", "dep-not-in-registry", "dep-unknown-version"]) findings.push(...capped(rule, flagged));

  // "Not verified" is one honest finding per reason, not hundreds of lines.
  const byReason = new Map<string, string[]>();
  for (const j of judged) {
    if (j.dep.status === "unchecked") {
      const list = byReason.get(j.dep.note ?? "unknown reason") ?? [];
      list.push(`${j.dep.name}${j.dep.version ?? j.dep.installed ?? j.dep.spec ? "@" + (j.dep.version ?? j.dep.installed ?? j.dep.spec) : ""}`);
      byReason.set(j.dep.note ?? "unknown reason", list);
    }
  }
  for (const [reason, list] of [...byReason.entries()].slice(0, MAX_FINDINGS_PER_RULE)) {
    findings.push({ rule: "dep-unchecked", severity: "review", file: "package.json", line: 0, excerpt: excerptOf(`not verified: ${list.length} of ${deps.length} dependencies — ${reason}: ${list.slice(0, 5).join(", ")}${list.length > 5 ? ", …" : ""}`, 240) });
  }

  for (const j of judged) {
    if (j.dep.status === "ok" || j.dep.status === "young") stats.verified++;
    if (j.dep.status === "young") stats.young++;
    if (j.dep.status === "unchecked") stats.unchecked++;
  }

  const sorted = dedupeSort(findings);
  // Keep the declared dependencies and whatever was flagged; hundreds of clean node_modules entries stay out of the stored result.
  const isFlagged = (d: Dependency): boolean => (d.status !== "ok" && d.status !== "skipped") || sorted.some((f) => f.rule === "dep-lookalike" && f.file === d.file && f.line === d.line && f.excerpt.startsWith(`"${d.name}"`));
  const kept = judged.map((j) => j.dep).filter((d) => d.declared || isFlagged(d));
  const keptDeps = [...kept.filter((d) => d.declared), ...kept.filter((d) => !d.declared).slice(0, MAX_FLAGGED)];
  return { ...result, findings: sorted, dependencies: keptDeps, dependencyStats: stats };
}

const SEVERITY_ORDER = { block: 0, review: 1, info: 2 } as const;
/** Same ordering and de-duplication as `runChecks`. */
export function dedupeSort(list: Finding[]): Finding[] {
  const uniq = new Map<string, Finding>();
  for (const f of list) uniq.set(`${f.rule}\0${f.file}\0${f.line}\0${f.excerpt}`, f);
  return [...uniq.values()].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line || (a.rule < b.rule ? -1 : 1));
}
