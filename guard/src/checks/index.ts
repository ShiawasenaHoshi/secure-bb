// Deterministic checks of a plugin directory (spec §5.1): no network, no
// model, seconds. Input: a directory (a snapshot). Output: findings and the
// list of capabilities the code can use.
import { posix, sep } from "node:path";
import { analyze, parseSource, type FileFacts, type Site } from "./ast.ts";
import { excerptOf, isCodeFile, isUrlSpec, packageDirOf, scanTree, type SourceFile } from "./files.ts";
import { entryPoints, fileCandidates, resolveSpecifier, type GraphContext } from "./reach.ts";
import { inventoryPackages, verifyInstalledPackages, type Integrity, type IntegrityEnv } from "../deps/integrity.ts";
import { collectDependencies, nameFindings } from "../deps/collect.ts";
import { CAPABILITY_KINDS, UNRESOLVED_HOST, type Capability, type CapabilityKind, type CheckResult, type Finding } from "./types.ts";

export type { Capability, CapabilityKind, CheckResult, Finding, Severity } from "./types.ts";
export { CAPABILITY_KINDS } from "./types.ts";
export type { Integrity, IntegrityEnv, ManifestCache, RegistryFetch } from "../deps/integrity.ts";
export { memoryManifestCache } from "../deps/integrity.ts";

const SITE_CAP = 20;
const MAX_PARSE_BYTES = 40 * 1024 * 1024;
const SEVERITY_ORDER = { block: 0, review: 1, info: 2 } as const;

function addCap(map: Map<CapabilityKind, { detail: Set<string>; sites: Array<{ file: string; line: number }> }>, kind: CapabilityKind, detail: string | null, file: string, line: number): void {
  let c = map.get(kind);
  if (!c) map.set(kind, (c = { detail: new Set(), sites: [] }));
  if (detail !== null) c.detail.add(detail);
  if (c.sites.length < SITE_CAP && !c.sites.some((s) => s.file === file && s.line === line)) c.sites.push({ file, line });
}

/** `./host.js` imported from `src/a.ts` → candidate file names in the tree. */
function importCandidates(fromFile: string, spec: string): string[] {
  const joined = posix.normalize(posix.join(posix.dirname(fromFile.split(sep).join("/")), spec));
  const stem = joined.replace(/\.(m|c)?jsx?$/, "");
  const exts = ["", ".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx"];
  return [joined, ...exts.map((e) => stem + e), ...exts.slice(1).map((e) => `${joined}/index${e}`)];
}

/**
 * Cross-file part of the `env-passed` rule. Handing `process.env` to a function that another file of
 * the same plugin defines, and that only reads named variables from it, is ordinary (`resolveHome(process.env)`):
 * the finding stays in the list as `info`. Everything not resolved this way — packages, re-exports,
 * functions that pass the environment on — remains a `review`.
 */
function resolveEnvPassed(perFile: Array<{ rel: string; facts: FileFacts }>, findings: Finding[]): void {
  const byRel = new Map(perFile.map((f) => [f.rel.split(sep).join("/"), f.facts]));
  for (const { rel, facts } of perFile) {
    for (const call of facts.envCalls) {
      const imp = facts.relImports.get(call.callee);
      if (!imp) continue;
      const target = importCandidates(rel, imp.from).map((c) => byRel.get(c)).find((x) => x !== undefined);
      if (!target || imp.imported === "default") continue;
      if (target.envReaders.get(imp.imported)?.[call.argIndex] !== true) continue;
      const f = findings.find((x) => x.rule === "env-passed" && x.file === rel && x.line === call.line);
      if (f) {
        f.severity = "info";
        f.excerpt = `the whole environment is passed to ${call.callee}(…) from ${imp.from}, which only reads named variables`;
      }
    }
  }
}

export interface CheckOptions {
  /**
   * What the registry stage found out about the packages in `node_modules` (directory → state). A `verified` package is
   * the npm release itself: its content is not judged by heuristics. Without this (offline), every package is scanned.
   */
  integrity?: ReadonlyMap<string, Integrity>;
}

/** Rules of text-level heuristics: they say nothing about a file the core never loads. */
const TEXT_RULES = new Set(["invisible-chars", "minified", "invalid-utf8", "executable-file", "file-too-large", "agent-config"]);

/** Several findings of the same kind collapse into one line (zod's tests alone have dozens). */
function summarize(label: string, list: Finding[], why: string, out: Finding[]): void {
  if (list.length === 0) return;
  const byRule = new Map<string, number>();
  for (const f of list) byRule.set(f.rule, (byRule.get(f.rule) ?? 0) + 1);
  const rules = [...byRule.entries()].map(([r, n]) => `${r} ×${n}`).join(", ");
  out.push({ rule: "ignored-findings", severity: "info", file: label, line: 0, excerpt: excerptOf(`${list.length} finding${list.length === 1 ? "" : "s"} not counted (${why}): ${rules}`, 220) });
}

export async function runChecks(dir: string, opts: CheckOptions = {}): Promise<CheckResult> {
  const t0 = Date.now();
  const verifiedDirs = new Set([...(opts.integrity ?? [])].filter(([, v]) => v.state === "verified").map(([k]) => k));
  const tree = await scanTree(dir, { verified: verifiedDirs });
  const findings: Finding[] = [...tree.findings];
  const caps = new Map<CapabilityKind, { detail: Set<string>; sites: Array<{ file: string; line: number }> }>();
  const perFile: Array<{ rel: string; facts: FileFacts }> = [];

  // package.json: the declared surfaces
  const bbField = tree.rootPackage && typeof tree.rootPackage.bb === "object" && tree.rootPackage.bb ? (tree.rootPackage.bb as Record<string, unknown>) : {};
  if (typeof bbField.app === "string") addCap(caps, "ui", `bb.app: ${bbField.app}`, "package.json", 0);
  for (const key of Object.keys(bbField)) if (/contentScripts?|composer/i.test(key)) addCap(caps, "ui", `bb.${key}`, "package.json", 0);
  if (bbField.host !== undefined) addCap(caps, "host_artifact", `bb.host: ${typeof bbField.host === "string" ? bbField.host : "declared"}`, "package.json", 0);

  // ---- what the core loads: entry points and everything they import ----------------------------------------
  const ctx: GraphContext = { files: tree.allFiles, packageJsons: tree.packageJsons };
  const ep = entryPoints(tree.rootPackage, ctx);
  const posixOf = (rel: string): string => rel.split(sep).join("/");
  const byRel = new Map<string, SourceFile>(tree.sources.map((x) => [posixOf(x.rel), x]));
  const codeFiles = [...byRel.keys()];
  // No entry point found (a tree without a manifest, a headless plugin): everything counts as loaded, as before.
  const everything = ep.entries.length === 0;
  const reached = new Set<string>();
  const queue: string[] = everything ? [...codeFiles] : [...ep.entries];
  const enqueue = (rel: string): void => {
    if (!reached.has(rel) && byRel.has(rel)) {
      reached.add(rel);
      queue.push(rel);
    }
  };
  const seed = queue.splice(0);
  for (const r of seed) enqueue(r);
  const isOwn = (rel: string): boolean => !rel.split("/").includes("node_modules");
  const isVerifiedFile = (rel: string): boolean => {
    const pd = packageDirOf(rel);
    return pd !== null && verifiedDirs.has(pd);
  };
  const allOfPackage = new Set<string>();

  let parseBudget = MAX_PARSE_BYTES;
  let parsed = 0;
  while (queue.length > 0) {
    const rel = queue.shift()!;
    const src = byRel.get(rel)!;
    if (parseBudget < src.text.length) {
      findings.push({ rule: "limit-exceeded", severity: "review", file: src.rel, line: 0, excerpt: "parse budget exhausted: file not analysed" });
      continue;
    }
    parseBudget -= src.text.length;
    const res = parseSource(src.rel, src.text);
    if (!res.ok) {
      findings.push({ rule: "parse-failed", severity: "review", file: src.rel, line: 0, excerpt: `could not parse: ${res.reason}` });
      continue;
    }
    parsed++;
    if (res.note) findings.push({ rule: "parse-note", severity: "info", file: src.rel, line: 0, excerpt: res.note });
    let facts: FileFacts;
    try {
      facts = analyze(src.rel, res);
    } catch (err) {
      findings.push({ rule: "parse-failed", severity: "review", file: src.rel, line: 0, excerpt: `analysis failed: ${excerptOf(String(err instanceof Error ? err.message : err))}` });
      continue;
    }
    perFile.push({ rel: src.rel, facts });
    findings.push(...facts.findings);
    for (const s of facts.sites as Site[]) addCap(caps, s.kind, s.detail, src.rel, s.line);

    // Edges of the import graph. Over-approximate on purpose: what is not followed is not checked.
    for (const spec of facts.specs) {
      if (spec === null) continue;
      for (const t of resolveSpecifier(rel, spec, ctx)) enqueue(t);
    }
    if (!isVerifiedFile(rel)) {
      // A file named by a path-like string may be loaded by other means (Worker, spawn, fork).
      for (const p of facts.pathStrings) {
        const bases = [posix.normalize(posix.join(posix.dirname(rel), p)), posix.normalize(p.replace(/^\.?\//, ""))];
        for (const b of bases) for (const t of fileCandidates(b, ctx)) enqueue(t);
      }
      // A computed module name: any file of the same package (the plugin's own code, or an unverified dependency) may be the one.
      if (facts.specs.includes(null)) {
        const pd = isOwn(rel) ? null : packageDirOf(rel);
        const key = pd ?? "";
        if (!allOfPackage.has(key)) {
          allOfPackage.add(key);
          for (const c of codeFiles) if (isOwn(c) === (pd === null) && (pd === null || packageDirOf(c) === pd) && !isVerifiedFile(c)) enqueue(c);
        }
      }
    }
  }
  const distDerived = (rel: string): boolean => ep.distDerived && rel.startsWith("dist/");

  // Plugin-wide rules: a secret path next to a network capability anywhere is the exfiltration shape.
  const anyNetwork = perFile.some((f) => f.facts.network);
  const anyWriter = perFile.some((f) => f.facts.fsWrite || f.facts.childProcess);
  for (const { rel, facts } of perFile) {
    for (const s of facts.secretPaths.slice(0, 3)) {
      findings.push(
        anyNetwork
          ? { rule: "secret-read-network", severity: "block", file: rel, line: s.line, excerpt: `${s.text} (and the plugin has network access)` }
          : { rule: "secret-path", severity: "review", file: rel, line: s.line, excerpt: s.text },
      );
    }
    if (anyWriter) {
      for (const s of facts.rcPaths.slice(0, 3)) findings.push({ rule: "rc-or-agent-config-write", severity: "block", file: rel, line: s.line, excerpt: `${s.text} (and the plugin can write files / run commands)` });
    }
  }
  // `env-passed` where the callee is a function of another file of this plugin that only reads named variables.
  resolveEnvPassed(perFile, findings);
  // Literal hosts belong to the network capability.
  for (const { rel, facts } of perFile) {
    if (!anyNetwork) break;
    for (const h of facts.hosts) addCap(caps, "network", `host:${h.host}`, rel, h.line);
    for (const line of facts.unresolvedHosts) addCap(caps, "network", UNRESOLVED_HOST, rel, line);
  }
  const programs = [...new Set(perFile.flatMap(({ facts }) => facts.programs))].slice(0, 10);
  const programsUnknown = perFile.some(({ facts }) => facts.programsUnknown);
  const credentials = [...new Set(perFile.flatMap(({ facts }) => facts.credentials.map((c) => c.label)))];

  const fsPaths = [...new Set(perFile.flatMap(({ facts }) => facts.fsPaths))].slice(0, 5);

  // A secret-looking env variable next to any network capability (DNS names are enough to carry it out).
  const envCap = caps.get("env");
  if (caps.has("network") && envCap) {
    const secretish = [...envCap.detail].filter((d) => /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH/i.test(d));
    if (secretish.length > 0) {
      const site = envCap.sites[0]!;
      findings.push({ rule: "env-secret-network", severity: "review", file: site.file, line: site.line, excerpt: `reads ${secretish.join(", ")} and has network access (${[...caps.get("network")!.detail].filter((d) => !d.startsWith("host:")).join(", ")})` });
    }
  }

  // Dependencies: what the plugin uses, and names that look like popular packages (offline; the registry stage is verify.ts).
  const dependencies = collectDependencies(tree.declared, tree.installed);
  findings.push(...nameFindings(dependencies, tree.installed));

  // ---- which findings count ---------------------------------------------------------------------------------
  // Own files keep every finding. A dependency's files count only where the core loads them, and not at all when the package is
  // the registry's own release (the findings were not even produced then). A bundle built from source is judged by the source.
  const pkgReached = new Set<string>();
  for (const r of reached) {
    const pd = packageDirOf(r);
    if (pd) pkgReached.add(pd);
  }
  const STRUCTURAL = new Set(["writable-by-others", "escaping-symlink", "special-file", "limit-exceeded"]);
  // Dependencies that do not come from the npm registry (git, a URL): the registry cannot vouch for them, so their content is scanned,
  // but "looks odd" heuristics (minified, invisible characters) are warnings there. What the code does (reachable) stays as it is.
  const nonRegistry = new Set(tree.declared.filter((d) => isUrlSpec(d.spec) && !/^(file:|link:)/i.test(d.spec)).map((d) => `node_modules/${d.name}`));
  const counted: Finding[] = [];
  const ignored = new Map<string, { list: Finding[]; why: string }>();
  const ignore = (label: string, why: string, f: Finding): void => {
    const e = ignored.get(label) ?? { list: [], why };
    e.list.push(f);
    ignored.set(label, e);
  };
  for (const f of findings) {
    if (f.file === "" || f.severity === "info") {
      counted.push(f);
      continue;
    }
    const fp = posixOf(f.file);
    const pd = packageDirOf(fp);
    if (pd === null) {
      if (distDerived(fp) && !STRUCTURAL.has(f.rule)) ignore("dist", "build output of the plugin's source, which is checked itself", f);
      else counted.push(f);
      continue;
    }
    if (STRUCTURAL.has(f.rule) || f.rule.startsWith("dep-")) counted.push(f); // dep-*: about the package itself, not a file the core loads
    else if (verifiedDirs.has(pd)) ignore(pd, "verified npm release", f);
    else if (nonRegistry.has(pd) && f.severity === "block" && (f.rule === "minified" || f.rule === "invisible-chars") && reached.has(fp)) counted.push({ ...f, severity: "review", excerpt: excerptOf(`(package not from npm) ${f.excerpt}`) });
    else if (reached.has(fp) || (pkgReached.has(pd) && !TEXT_RULES.has(f.rule) && !f.rule.startsWith("parse-"))) counted.push(f);
    else ignore(pd, "not loaded by the plugin", f);
  }
  findings.length = 0;
  findings.push(...counted);
  for (const [label, e] of [...ignored.entries()].slice(0, 30)) summarize(label, e.list, e.why, findings);
  if (ignored.size > 30) findings.push({ rule: "ignored-findings", severity: "info", file: "", line: 0, excerpt: `and findings of ${ignored.size - 30} more places not counted` });

  // What was left out of the analysis, and what the registry said about the copies in node_modules.
  if (!everything) {
    const own = codeFiles.filter((c) => isOwn(c) && !reached.has(c));
    const deps = codeFiles.filter((c) => !isOwn(c) && !reached.has(c) && !isVerifiedFile(c));
    if (own.length + deps.length > 0) {
      const sample = [...new Set(own.map((c) => c.split("/")[0]!))].slice(0, 5).join(", ");
      findings.push({ rule: "unreachable-files", severity: "info", file: "", line: 0, excerpt: `${own.length} code file${own.length === 1 ? "" : "s"} of the plugin${sample ? ` (${sample})` : ""} and ${deps.length} in dependencies are not reachable from the entry points: not analysed` });
    }
  }
  if (opts.integrity) {
    const bad: string[] = [];
    for (const [pdir, st] of opts.integrity) {
      if (nonRegistry.has(pdir)) continue; // url-dependency already says it
      if (st.state === "modified") findings.push({ rule: "dep-modified", severity: "review", file: `${pdir}/package.json`, line: 0, excerpt: excerptOf(`${pdir}: ${st.reason}; the copy is scanned in full`) });
      else if (st.state === "unverified") bad.push(`${pdir.replace(/^.*node_modules\//, "")} (${st.reason})`);
    }
    if (bad.length > 0) findings.push({ rule: "dep-content-unverified", severity: "info", file: "", line: 0, excerpt: excerptOf(`${bad.length} package${bad.length === 1 ? "" : "s"} could not be compared with the npm registry and ${bad.length === 1 ? "is" : "are"} scanned in full: ${bad.slice(0, 3).join("; ")}${bad.length > 3 ? "; …" : ""}`, 240) });
  } else if (tree.installed.length > 0) {
    findings.push({ rule: "dep-content-unverified", severity: "info", file: "", line: 0, excerpt: `${tree.installed.length} packages in node_modules were not compared with the npm registry (offline check): scanned in full` });
  }

  const capabilities: Capability[] = CAPABILITY_KINDS.filter((k) => caps.has(k)).map((kind) => {
    const c = caps.get(kind)!;
    return { kind, detail: [...c.detail].sort(), sites: c.sites };
  });

  // Same rule at the same place only once; most severe first.
  const uniq = new Map<string, Finding>();
  for (const f of findings) uniq.set(`${f.rule}\0${f.file}\0${f.line}\0${f.excerpt}`, f);
  const sorted = [...uniq.values()].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line || (a.rule < b.rule ? -1 : 1),
  );
  return { findings: sorted, capabilities, stats: { files: tree.files, parsed, bytes: tree.bytes, ms: Date.now() - t0 }, dependencies, ...(caps.has("fs") && fsPaths.length > 0 ? { fsPaths } : {}), ...(caps.has("child_process") && (programs.length > 0 || programsUnknown) ? { programs, ...(programsUnknown ? { programsUnknown } : {}) } : {}), ...(credentials.length > 0 ? { credentials } : {}) };
}

/**
 * The checks with the integrity stage in front: the packages in `node_modules` are compared with the registry's tarballs
 * (network through `env.fetch`, a cache of the tarballs' file hashes in `env.cache`). Anything that cannot be compared is
 * scanned as before. Never fails because of the network.
 */
export async function runChecksVerified(dir: string, env: IntegrityEnv): Promise<CheckResult> {
  let integrity: Map<string, Integrity> | undefined;
  try {
    const packages = await inventoryPackages(dir);
    integrity = packages.length === 0 ? new Map() : await verifyInstalledPackages(dir, packages, env);
  } catch {
    integrity = undefined;
  }
  return runChecks(dir, integrity ? { integrity } : {});
}

/** Plain-text report for `bb secure-bb check` and logs. */
export function formatReport(r: CheckResult): string {
  const out: string[] = [];
  const counts = { block: 0, review: 0, info: 0 };
  for (const f of r.findings) counts[f.severity]++;
  out.push(`findings: ${counts.block} block, ${counts.review} review, ${counts.info} info (${r.stats.files} files, ${r.stats.parsed} parsed, ${r.stats.ms} ms)`);
  for (const f of r.findings) out.push(`  [${f.severity}] ${f.rule}  ${f.file}${f.line ? `:${f.line}` : ""}  ${f.excerpt}`);
  out.push(r.capabilities.length === 0 ? "capabilities: none (safe class)" : "capabilities:");
  for (const c of r.capabilities) out.push(`  ${c.kind}${c.detail.length ? `: ${c.detail.join(", ")}` : ""}`);
  const st = r.dependencyStats;
  if (st && st.total > 0) {
    out.push(`dependencies: ${st.total} (${st.declared} declared), ${st.registry ? `${st.verified} verified against the npm registry, ${st.unchecked} not verified, ${st.young} younger than 3 days` : "registry not consulted"}`);
    for (const d of r.dependencies ?? []) {
      const when = d.publishedAt ? `, published ${d.publishedAt.slice(0, 10)}` : "";
      out.push(`  ${d.name}@${d.version ?? d.installed ?? d.spec ?? "?"}${d.declared ? "" : " (node_modules)"}: ${d.status ?? "not looked up"}${when}${d.note ? ` — ${d.note}` : ""}`);
    }
  } else if (r.dependencies && r.dependencies.length > 0) {
    out.push(`dependencies: ${r.dependencies.length}, registry not consulted`);
  }
  return out.join("\n");
}
