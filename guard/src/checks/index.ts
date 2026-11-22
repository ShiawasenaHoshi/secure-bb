// Deterministic checks of a plugin directory (spec §5.1): no network, no
// model, seconds. Input: a directory (a snapshot). Output: findings and the
// list of capabilities the code can use.
import { posix, sep } from "node:path";
import { analyze, parseSource, type FileFacts, type Site } from "./ast.ts";
import { excerptOf, isCodeFile, isUrlSpec, packageDirOf, scanTree, type SourceFile } from "./files.ts";
import { analyzeFlows, type FlowFile } from "./flow.ts";
import type { SourceKind } from "./flow-types.ts";
import { entryPoints, fileCandidates, pluginDirOf, resolveSpecifier, type GraphContext } from "./reach.ts";
import { inventoryPackages, verifyInstalledPackages, type Integrity, type IntegrityEnv } from "../deps/integrity.ts";
import { collectDependencies, nameFindings } from "../deps/collect.ts";
import { FS_HOME, UI_CLICK_ANSWERS, UI_CLICK_GATE, UI_CLICK_NAV, UI_CLICK_OTHER } from "./sdk-rights.ts";
import { CHECKS_VERSION, CAPABILITY_KINDS, UNRESOLVED_HOST, type Capability, type CapabilityKind, type CheckResult, type Finding } from "./types.ts";

export type { Capability, CapabilityKind, CheckResult, Finding, Severity } from "./types.ts";
export { CAPABILITY_KINDS, CHECKS_VERSION } from "./types.ts";
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
  /**
   * The id the core gave the plugin. In a repository of several plugins (`plugins/a`, `plugins/b`, each with its own package.json with a `bb` part) the
   * plugin is the directory of that id: the checks start from ITS entry points, and the code of the neighbours, which it never loads, is not counted.
   */
  pluginId?: string;
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

type Caps = Map<CapabilityKind, { detail: Set<string>; sites: Array<{ file: string; line: number }> }>;
type FileEntry = { rel: string; facts: FileFacts };

/**
 * What one run of the checks builds up. The steps below read it and add to it, in the order `runChecks` calls them: the order is part of the result (the findings are
 * sorted at the end, but where two are alike the earlier one stays, and the sites of a capability are kept in the order they were met).
 */
interface Run {
  opts: CheckOptions;
  t0: number;
  /** The packages of `node_modules` the registry stage vouched for. */
  verifiedDirs: Set<string>;
  tree: Awaited<ReturnType<typeof scanTree>>;
  findings: Finding[];
  caps: Caps;
  perFile: FileEntry[];
  /** The parsed own code the flow analysis reads (the dependencies' code is not: a call into it is «not shown»). */
  flowFiles: FlowFile[];
  /** The plugin's own directory in a repository of several plugins ("" otherwise), its package.json and the surfaces it declares. */
  sub: string;
  rootPackage: Record<string, unknown> | null;
  ctx: GraphContext;
  /** The entry points the core loads (under the plugin's path). */
  ep: { entries: string[]; dist: string[]; distDerived: boolean };
  byRel: Map<string, SourceFile>;
  codeFiles: string[];
  /** No entry point found (a tree without a manifest, a headless plugin): everything counts as loaded, as before. */
  everything: boolean;
  reached: Set<string>;
  /** Code built on the fly that the plugin's OWN files do (a dependency's is not: see where `dynamic` is worked out). */
  ownDynamic: Array<{ file: string; detail: string }>;
  parsed: number;
}

const posixOf = (rel: string): string => rel.split(sep).join("/");
const isOwn = (rel: string): boolean => !rel.split("/").includes("node_modules");
const inSubOf = (sub: string) => (rel: string): boolean => sub === "" || rel === sub || rel.startsWith(`${sub}/`);
const underOf = (sub: string) => (f: string): string => (sub === "" ? f : `${sub}/${f}`);
/** Built from the plugin's own source (`dist/`): its findings are the source's, which is checked itself. */
const isDistDerived = (run: Run, rel: string): boolean => run.ep.distDerived && rel.startsWith(underOf(run.sub)("dist/"));
const isVerifiedFile = (run: Run, rel: string): boolean => {
  const pd = packageDirOf(rel);
  return pd !== null && run.verifiedDirs.has(pd);
};

/** Reads the tree and finds what the core loads: the plugin's own directory, its manifest and its entry points. */
async function startRun(dir: string, opts: CheckOptions): Promise<Run> {
  const t0 = Date.now();
  const verifiedDirs = new Set([...(opts.integrity ?? [])].filter(([, v]) => v.state === "verified").map(([k]) => k));
  const tree = await scanTree(dir, { verified: verifiedDirs });
  // package.json: the declared surfaces
  const sub = pluginDirOf(tree.packageJsons, opts.pluginId);
  const rootPackage = sub === "" ? tree.rootPackage : (tree.packageJsons.get(`${sub}/package.json`) ?? null);
  // ---- what the core loads: entry points and everything they import ----------------------------------------
  const ctx: GraphContext = { files: tree.allFiles, packageJsons: tree.packageJsons };
  // Entry points are read in the plugin's own directory, and put back under its path in the repository.
  const subCtx: GraphContext = sub === "" ? ctx : { files: new Set([...tree.allFiles].filter((f) => f.startsWith(`${sub}/`)).map((f) => f.slice(sub.length + 1))), packageJsons: new Map() };
  const ep0 = entryPoints(rootPackage, subCtx);
  const under = underOf(sub);
  const ep = sub === "" ? ep0 : { entries: ep0.entries.map(under), dist: ep0.dist.map(under), distDerived: ep0.distDerived };
  const byRel = new Map<string, SourceFile>(tree.sources.map((x) => [posixOf(x.rel), x]));
  return { opts, t0, verifiedDirs, tree, findings: [...tree.findings], caps: new Map(), perFile: [], flowFiles: [], sub, rootPackage, ctx, ep, byRel, codeFiles: [...byRel.keys()], everything: ep.entries.length === 0, reached: new Set(), ownDynamic: [], parsed: 0 };
}

/** The surfaces a plugin declares in its package.json: an interface, a composer or content scripts, files put on the machine. */
function packageCaps(run: Run): void {
  const { rootPackage, sub, caps } = run;
  const bbField = rootPackage && typeof rootPackage.bb === "object" && rootPackage.bb ? (rootPackage.bb as Record<string, unknown>) : {};
  if (typeof bbField.app === "string") addCap(caps, "ui", `bb.app: ${bbField.app}`, sub === "" ? "package.json" : `${sub}/package.json`, 0);
  for (const key of Object.keys(bbField)) if (/contentScripts?|composer/i.test(key)) addCap(caps, "ui", `bb.${key}`, "package.json", 0);
  if (bbField.host !== undefined) addCap(caps, "host_artifact", `bb.host: ${typeof bbField.host === "string" ? bbField.host : "declared"}`, "package.json", 0);
}

/** Parses one file inside the budget; null when it was not analysed (a finding says why). */
function parseOne(run: Run, src: SourceFile, budget: { left: number }): FileFacts | null {
  if (budget.left < src.text.length) {
    run.findings.push({ rule: "limit-exceeded", severity: "review", file: src.rel, line: 0, excerpt: "parse budget exhausted: file not analysed" });
    return null;
  }
  budget.left -= src.text.length;
  const res = parseSource(src.rel, src.text);
  if (!res.ok) {
    run.findings.push({ rule: "parse-failed", severity: "review", file: src.rel, line: 0, excerpt: `could not parse: ${res.reason}` });
    return null;
  }
  run.parsed++;
  run.flowFiles.push({ rel: src.rel, ast: res.ast, code: res.code });
  if (res.note) run.findings.push({ rule: "parse-note", severity: "info", file: src.rel, line: 0, excerpt: res.note });
  try {
    return analyze(src.rel, res);
  } catch (err) {
    run.findings.push({ rule: "parse-failed", severity: "review", file: src.rel, line: 0, excerpt: `analysis failed: ${excerptOf(String(err instanceof Error ? err.message : err))}` });
    return null;
  }
}

/** What a parsed file adds to the run: its findings, its capability sites, the code it builds on the fly. */
function takeFacts(run: Run, src: SourceFile, facts: FileFacts): void {
  run.perFile.push({ rel: src.rel, facts });
  run.findings.push(...facts.findings);
  const rel = posixOf(src.rel);
  for (const s of facts.sites as Site[]) {
    addCap(run.caps, s.kind, s.detail, src.rel, s.line);
    if (s.kind === "dynamic_code" && !/\(literal\)$/.test(s.detail) && isOwn(rel) && inSubOf(run.sub)(rel)) run.ownDynamic.push({ file: rel, detail: s.detail });
  }
}

/** The files that may be loaded though no import names them: a path-like string (Worker, spawn, fork), and the files of a package for a computed module name. */
function loadedByOtherMeans(run: Run, rel: string, facts: FileFacts, allOfPackage: Set<string>, enqueue: (rel: string) => void): void {
  // A file named by a path-like string may be loaded by other means (Worker, spawn, fork).
  for (const p of facts.pathStrings) {
    const bases = [posix.normalize(posix.join(posix.dirname(rel), p)), posix.normalize(p.replace(/^\.?\//, ""))];
    for (const b of bases) for (const t of fileCandidates(b, run.ctx)) enqueue(t);
  }
  // A computed module name: any file of the same package (the plugin's own code, or an unverified dependency) may be the one.
  if (!facts.specs.includes(null)) return;
  const pd = isOwn(rel) ? null : packageDirOf(rel);
  const key = pd ?? "";
  if (allOfPackage.has(key)) return;
  allOfPackage.add(key);
  const inSub = inSubOf(run.sub);
  for (const c of run.codeFiles) if (isOwn(c) === (pd === null) && (pd === null ? inSub(c) : packageDirOf(c) === pd) && !isVerifiedFile(run, c)) enqueue(c);
}

/** Walks the import graph from the entry points, parses what the core loads and collects what each file says. */
function analyzeReachable(run: Run): void {
  const inSub = inSubOf(run.sub);
  const queue: string[] = run.everything ? run.codeFiles.filter(inSub) : [...run.ep.entries];
  const enqueue = (rel: string): void => {
    if (!run.reached.has(rel) && run.byRel.has(rel)) {
      run.reached.add(rel);
      queue.push(rel);
    }
  };
  const seed = queue.splice(0);
  for (const r of seed) enqueue(r);
  const allOfPackage = new Set<string>();
  const budget = { left: MAX_PARSE_BYTES };
  while (queue.length > 0) {
    const rel = queue.shift()!;
    const src = run.byRel.get(rel)!;
    const facts = parseOne(run, src, budget);
    if (facts === null) continue;
    takeFacts(run, src, facts);
    // Edges of the import graph. Over-approximate on purpose: what is not followed is not checked.
    for (const spec of facts.specs) {
      if (spec === null) continue;
      for (const t of resolveSpecifier(rel, spec, run.ctx)) enqueue(t);
    }
    if (!isVerifiedFile(run, rel)) loadedByOtherMeans(run, rel, facts, allOfPackage, enqueue);
  }
}

/** A secret path next to a network capability anywhere is the exfiltration shape; so is a shell file written by a plugin that can write or run. */
function pluginWideRules(run: Run): { anyNetwork: boolean } {
  const { perFile, findings } = run;
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
  return { anyNetwork };
}

/** Pressing buttons of bb's page: an element looked up that the plugin did not draw, and a press on an element, anywhere in the plugin. */
function pressCaps(run: Run): void {
  const { perFile, caps } = run;
  if (!perFile.some((f) => f.facts.domLookups.length > 0)) return;
  for (const { rel, facts } of perFile) for (const p of facts.domPresses) addCap(caps, "ui_click", p.detail, rel, p.line);
  if (!caps.has("ui_click")) return;
  // Where it presses: by the selectors it looks elements up with, and the labels it knows. A target the code does not show is the worse one when it speaks of approving.
  const targets = new Set(perFile.flatMap((f) => f.facts.domLookups.map((l) => l.target)));
  if (perFile.some((f) => f.facts.answerText)) targets.add("answers");
  if (targets.delete("unknown")) targets.add(perFile.some((f) => f.facts.approveText) ? "gate" : "other");
  const detailOf = { answers: UI_CLICK_ANSWERS, nav: UI_CLICK_NAV, gate: UI_CLICK_GATE, other: UI_CLICK_OTHER } as const;
  const site = caps.get("ui_click")!.sites[0]!;
  for (const t of targets) if (t !== "unknown") addCap(caps, "ui_click", detailOf[t], site.file, site.line);
}

/** Files: «your documents» are said only when the code reaches the person's own folders (home directory, Documents…); otherwise the files are not known. */
function homeFilesCap(run: Run): void {
  const { caps, perFile } = run;
  if (caps.has("fs") && (perFile.some((f) => f.facts.homeRef) || [...(caps.get("env")?.detail ?? [])].some((d) => /^(env:)?(HOME|USERPROFILE|HOMEPATH)$/i.test(d)))) {
    const site = caps.get("fs")!.sites[0]!;
    addCap(caps, "fs", FS_HOME, site.file, site.line);
  }
}

/** Literal hosts belong to the network capability. */
function hostCaps(run: Run, anyNetwork: boolean): void {
  for (const { rel, facts } of run.perFile) {
    if (!anyNetwork) break;
    for (const h of facts.hosts) addCap(run.caps, "network", `host:${h.host}`, rel, h.line);
    for (const line of facts.unresolvedHosts) addCap(run.caps, "network", UNRESOLVED_HOST, rel, line);
  }
}

/** The plugin-wide facts the result reports: the programs it starts, the logins of other programs it reads, the paths it gives to file calls. */
function derivedFacts(run: Run) {
  const { perFile } = run;
  return {
    programs: [...new Set(perFile.flatMap(({ facts }) => facts.programs))].slice(0, 10),
    programsUnknown: perFile.some(({ facts }) => facts.programsUnknown),
    credentials: [...new Set(perFile.flatMap(({ facts }) => facts.credentials.map((c) => c.label)))],
    fsPaths: [...new Set(perFile.flatMap(({ facts }) => facts.fsPaths))].slice(0, 5),
  };
}

/** A secret-looking env variable next to any network capability (DNS names are enough to carry it out). */
function envSecretNetwork(run: Run): void {
  const { caps, findings } = run;
  const envCap = caps.get("env");
  if (!caps.has("network") || !envCap) return;
  const secretish = [...envCap.detail].filter((d) => /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH/i.test(d));
  if (secretish.length === 0) return;
  const site = envCap.sites[0]!;
  findings.push({ rule: "env-secret-network", severity: "review", file: site.file, line: site.line, excerpt: `reads ${secretish.join(", ")} and has network access (${[...caps.get("network")!.detail].filter((d) => !d.startsWith("host:")).join(", ")})` });
}

/** What the plugin's own code says about itself across files, before the findings are folded: the rules that need the whole plugin. */
function wholePluginRules(run: Run): ReturnType<typeof derivedFacts> {
  const { anyNetwork } = pluginWideRules(run);
  // `env-passed` where the callee is a function of another file of this plugin that only reads named variables.
  resolveEnvPassed(run.perFile, run.findings);
  pressCaps(run);
  homeFilesCap(run);
  hostCaps(run, anyNetwork);
  const facts = derivedFacts(run);
  envSecretNetwork(run);
  return facts;
}

type Folded = { counted: Finding[]; ignored: Map<string, { list: Finding[]; why: string }> };

const STRUCTURAL = new Set(["writable-by-others", "escaping-symlink", "special-file", "limit-exceeded"]);

const setAside = (out: Folded, f: Finding, label: string, why: string): void => {
  const e = out.ignored.get(label) ?? { list: [], why };
  e.list.push(f);
  out.ignored.set(label, e);
};

/** A finding in a file of the plugin's own repository (not in `node_modules`). */
function placeOwn(run: Run, f: Finding, fp: string, out: Folded): void {
  // Another plugin of the same repository: its code is not loaded by this one, so it says nothing about this one.
  if (!inSubOf(run.sub)(fp) && !run.reached.has(fp) && !STRUCTURAL.has(f.rule)) setAside(out, f, "other plugins of the repository", "not part of this plugin");
  else if (isDistDerived(run, fp) && !STRUCTURAL.has(f.rule)) setAside(out, f, "dist", "build output of the plugin's source, which is checked itself");
  else out.counted.push(f);
}

/** A finding in the files of a package of `node_modules`: counted only where the core loads it, and not at all for the registry's own release. */
function placeInPackage(run: Run, f: Finding, fp: string, pd: string, pkgReached: Set<string>, nonRegistry: Set<string>, out: Folded): void {
  if (STRUCTURAL.has(f.rule) || f.rule.startsWith("dep-")) out.counted.push(f); // dep-*: about the package itself, not a file the core loads
  else if (run.verifiedDirs.has(pd)) setAside(out, f, pd, "verified npm release");
  else if (nonRegistry.has(pd) && f.severity === "block" && (f.rule === "minified" || f.rule === "invisible-chars") && run.reached.has(fp)) out.counted.push({ ...f, severity: "review", excerpt: excerptOf(`(package not from npm) ${f.excerpt}`) });
  else if (run.reached.has(fp) || (pkgReached.has(pd) && !TEXT_RULES.has(f.rule) && !f.rule.startsWith("parse-"))) out.counted.push(f);
  else setAside(out, f, pd, "not loaded by the plugin");
}

/** Where a finding stands: counted, or set aside with a reason (another plugin of the repository, build output, a verified npm release, a file the core never loads). */
function placeFinding(run: Run, f: Finding, pkgReached: Set<string>, nonRegistry: Set<string>, out: Folded): void {
  if (f.file === "" || f.severity === "info") {
    out.counted.push(f);
    return;
  }
  const fp = posixOf(f.file);
  const pd = packageDirOf(fp);
  if (pd === null) placeOwn(run, f, fp, out);
  else placeInPackage(run, f, fp, pd, pkgReached, nonRegistry, out);
}

/** What was left out of the analysis: code files the entry points do not reach. */
function unreachableNote(run: Run): void {
  if (run.everything) return;
  const inSub = inSubOf(run.sub);
  const own = run.codeFiles.filter((c) => isOwn(c) && inSub(c) && !run.reached.has(c));
  const deps = run.codeFiles.filter((c) => !isOwn(c) && !run.reached.has(c) && !isVerifiedFile(run, c));
  if (own.length + deps.length === 0) return;
  const sample = [...new Set(own.map((c) => c.split("/")[0]!))].slice(0, 5).join(", ");
  run.findings.push({ rule: "unreachable-files", severity: "info", file: "", line: 0, excerpt: `${own.length} code file${own.length === 1 ? "" : "s"} of the plugin${sample ? ` (${sample})` : ""} and ${deps.length} in dependencies are not reachable from the entry points: not analysed` });
}

/** The packages whose copy differs from the registry's, or could not be compared: a finding each, and one line for those that could not be. */
function integrityFindings(findings: Finding[], integrity: ReadonlyMap<string, Integrity>, nonRegistry: Set<string>): void {
  const bad: string[] = [];
  for (const [pdir, st] of integrity) {
    if (nonRegistry.has(pdir)) continue; // url-dependency already says it
    if (st.state === "modified") findings.push({ rule: "dep-modified", severity: "review", file: `${pdir}/package.json`, line: 0, excerpt: excerptOf(`${pdir}: ${st.reason}; the copy is scanned in full`) });
    else if (st.state === "unverified") bad.push(`${pdir.replace(/^.*node_modules\//, "")} (${st.reason})`);
  }
  if (bad.length > 0) findings.push({ rule: "dep-content-unverified", severity: "info", file: "", line: 0, excerpt: excerptOf(`${bad.length} package${bad.length === 1 ? "" : "s"} could not be compared with the npm registry and ${bad.length === 1 ? "is" : "are"} scanned in full: ${bad.slice(0, 3).join("; ")}${bad.length > 3 ? "; …" : ""}`, 240) });
}

/** What the registry said about the copies in node_modules (or that it was not asked). */
function integrityNotes(run: Run, nonRegistry: Set<string>): void {
  const { opts, tree, findings } = run;
  if (opts.integrity) integrityFindings(findings, opts.integrity, nonRegistry);
  else if (tree.installed.length > 0) findings.push({ rule: "dep-content-unverified", severity: "info", file: "", line: 0, excerpt: `${tree.installed.length} packages in node_modules were not compared with the npm registry (offline check): scanned in full` });
}

/**
 * Which findings count. Own files keep every finding. A dependency's files count only where the core loads them, and not at all when the package is
 * the registry's own release (the findings were not even produced then). A bundle built from source is judged by the source.
 * Those set aside are said once per place, in a line of their own.
 */
function foldFindings(run: Run): void {
  const { tree, findings } = run;
  const pkgReached = new Set<string>();
  for (const r of run.reached) {
    const pd = packageDirOf(r);
    if (pd) pkgReached.add(pd);
  }
  // Dependencies that do not come from the npm registry (git, a URL): the registry cannot vouch for them, so their content is scanned,
  // but "looks odd" heuristics (minified, invisible characters) are warnings there. What the code does (reachable) stays as it is.
  const nonRegistry = new Set(tree.declared.filter((d) => isUrlSpec(d.spec) && !/^(file:|link:)/i.test(d.spec)).map((d) => `node_modules/${d.name}`));
  const folded: Folded = { counted: [], ignored: new Map() };
  for (const f of findings) placeFinding(run, f, pkgReached, nonRegistry, folded);
  findings.length = 0;
  findings.push(...folded.counted);
  for (const [label, e] of [...folded.ignored.entries()].slice(0, 30)) summarize(label, e.list, e.why, findings);
  if (folded.ignored.size > 30) findings.push({ rule: "ignored-findings", severity: "info", file: "", line: 0, excerpt: `and findings of ${folded.ignored.size - 30} more places not counted` });
  // What was left out of the analysis, and what the registry said about the copies in node_modules.
  unreachableNote(run);
  integrityNotes(run, nonRegistry);
}

/** The kinds of what is read that the plugin can reach, so that the flow analysis knows what to follow. */
function flowExpectations(run: Run, credentials: string[]): { expect: Set<SourceKind>; watch: boolean } {
  const { caps } = run;
  const has = (k: CapabilityKind): boolean => caps.has(k);
  const expect = new Set<SourceKind>();
  if (has("sdk_read")) expect.add("threads");
  if (has("sdk_questions")) expect.add("questions");
  const envNames = [...(caps.get("env")?.detail ?? [])];
  if (envNames.some((d) => d === "*" || !/^(env:)?(HOME|USER|LOGNAME|PATH|SHELL|LANG|LC_\w+|TZ|PWD|TMPDIR|TERM|NODE_ENV|NO_COLOR|FORCE_COLOR|CI|DEBUG|PLATFORM)$/.test(d))) expect.add("env");
  if (credentials.length > 0) expect.add("credentials");
  return { expect, watch: expect.size > 0 || has("sdk_meta") || has("ui_click") || has("fs") };
}

const DYNAMIC_RULES = new Set(["dynamic-access", "require-alias", "module-load", "dynamic-constructor", "global-proxy", "native-load", "webassembly", "dynamic-import", "dynamic-require", "url-import"]);

/** Whether the plugin runs code that is not what the analysis read (built on the fly, a worker, a vm, a computed module). Only the plugin's own code counts. */
function runsDynamicCode(run: Run): boolean {
  const ownFile = (rel: string): boolean => isOwn(posixOf(rel)) && inSubOf(run.sub)(posixOf(rel)) && !isDistDerived(run, posixOf(rel));
  // Code built on the fly, a worker, a vm, a computed module: what runs there is not what the analysis read (a plain `Function("return this")` is only text).
  // Only in the plugin's own code. A dependency that does it (zod tests `new Function("")`) is code that data goes into only through a call the analysis already
  // counts as «не видно» (a package it has not read); what is inside it does not change where what is not handed to it goes.
  return (
    run.ownDynamic.some((d) => !isDistDerived(run, d.file)) ||
    run.perFile.some((f) => ownFile(f.rel) && (f.facts.execSink || f.facts.specs.includes(null))) ||
    run.findings.some((f) => DYNAMIC_RULES.has(f.rule) && ownFile(f.file))
  );
}

/** Where what it reads goes (data flow over the plugin's own code); null when nothing worth following was found. */
function attachFlows(run: Run, credentials: string[]): ReturnType<typeof analyzeFlows> | null {
  const { expect, watch } = flowExpectations(run, credentials);
  if (!watch) return null;
  const own = run.flowFiles.filter((f) => isOwn(f.rel) && inSubOf(run.sub)(f.rel) && !isDistDerived(run, f.rel));
  const dynamic = runsDynamicCode(run);
  const incomplete = run.findings.some((f) => (f.rule === "parse-failed" || f.rule === "limit-exceeded") && isOwn(f.file) && !isDistDerived(run, f.file));
  const navClick = [...(run.caps.get("ui_click")?.detail ?? [])].includes(UI_CLICK_NAV);
  return analyzeFlows({ files: own, graph: run.ctx, expect, dynamic, incomplete, navClick, entries: new Set(run.ep.entries) });
}

/** Same rule at the same place only once; most severe first. */
function sortedFindings(findings: Finding[]): Finding[] {
  const uniq = new Map<string, Finding>();
  for (const f of findings) uniq.set(`${f.rule}\0${f.file}\0${f.line}\0${f.excerpt}`, f);
  return [...uniq.values()].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line || (a.rule < b.rule ? -1 : 1));
}

/** The result: the findings, the capabilities with their sites, and what the facts of the run add (programs, paths, logins, flows). */
function assemble(run: Run, d: ReturnType<typeof derivedFacts>, dependencies: CheckResult["dependencies"], flowResult: ReturnType<typeof analyzeFlows> | null): CheckResult {
  const { caps, tree } = run;
  const capabilities: Capability[] = CAPABILITY_KINDS.filter((k) => caps.has(k)).map((kind) => {
    const c = caps.get(kind)!;
    return { kind, detail: [...c.detail].sort(), sites: c.sites };
  });
  const { programs, programsUnknown, credentials, fsPaths } = d;
  return { v: CHECKS_VERSION, findings: sortedFindings(run.findings), capabilities, stats: { files: tree.files, parsed: run.parsed, bytes: tree.bytes, ms: Date.now() - run.t0 }, dependencies, ...(caps.has("fs") && fsPaths.length > 0 ? { fsPaths } : {}), ...(caps.has("child_process") && (programs.length > 0 || programsUnknown) ? { programs, ...(programsUnknown ? { programsUnknown } : {}) } : {}), ...(credentials.length > 0 ? { credentials } : {}), ...(flowResult?.timedOut ? { flowsTimedOut: true as const } : {}), ...(flowResult && !flowResult.timedOut ? { flows: flowResult.summaries, ...(flowResult.purposes.length > 0 ? { purposes: flowResult.purposes } : {}) } : {}) };
}

export async function runChecks(dir: string, opts: CheckOptions = {}): Promise<CheckResult> {
  const run = await startRun(dir, opts);
  packageCaps(run);
  analyzeReachable(run);
  const facts = wholePluginRules(run);
  // Dependencies: what the plugin uses, and names that look like popular packages (offline; the registry stage is verify.ts).
  const dependencies = collectDependencies(run.tree.declared, run.tree.installed);
  run.findings.push(...nameFindings(dependencies, run.tree.installed));
  foldFindings(run);
  const flowResult = attachFlows(run, facts.credentials);
  return assemble(run, facts, dependencies, flowResult);
}

/**
 * The checks with the integrity stage in front: the packages in `node_modules` are compared with the registry's tarballs
 * (network through `env.fetch`, a cache of the tarballs' file hashes in `env.cache`). Anything that cannot be compared is
 * scanned as before. Never fails because of the network.
 */
export async function runChecksVerified(dir: string, env: IntegrityEnv, pluginId?: string): Promise<CheckResult> {
  let integrity: Map<string, Integrity> | undefined;
  try {
    const packages = await inventoryPackages(dir);
    integrity = packages.length === 0 ? new Map() : await verifyInstalledPackages(dir, packages, env);
  } catch {
    integrity = undefined;
  }
  return runChecks(dir, { ...(integrity ? { integrity } : {}), ...(pluginId ? { pluginId } : {}) });
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
  if (r.flows && r.flows.length > 0) {
    out.push("where what it reads goes:");
    for (const f of r.flows) out.push(`  ${f.source}${f.detail.length ? ` (${f.detail.join(", ")})` : ""}: ${f.verdict}${f.sinks.length ? ` → ${f.sinks.map((s) => `${s.kind}${s.target ? `:${s.target}` : ""} ${s.file}:${s.line}`).join(", ")}` : ""}${f.why ? ` — ${f.why}` : ""}`);
  }
  for (const p of r.purposes ?? []) out.push(`  purpose (${p.on.join("/")}): ${p.text} [${p.pair}]`);
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
