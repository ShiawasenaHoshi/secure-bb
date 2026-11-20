// Offline part of the dependency checks (stage 2.3): which packages the plugin
// uses, and which names look like popular ones. No network here: `runChecks`
// stays deterministic. What the registry says about them is added by verify.ts.
import type { DeclaredDep, InstalledPackage } from "../checks/files.js";
import { excerptOf } from "../checks/files.js";
import type { Dependency, Finding } from "../checks/types.js";
import { lookalikeOf } from "./lookalike.js";

export const MAX_FINDINGS_PER_RULE = 20;

/** A name the registry could be asked about without it escaping the URL path. */
export const VALID_NAME = /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;
export const isValidName = (name: string): boolean => name.length <= 214 && VALID_NAME.test(name);

/** Specs that are not a registry range: other rules (url-dependency, workspace-dependency) cover them. */
export const isRegistrySpec = (spec: string): boolean => !/^(git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|ssh:|file:|link:|workspace:|portal:|patch:)/i.test(spec) && !/^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec);

/**
 * Distinct `name@version` of everything the plugin declares or ships in `node_modules`.
 * A declared dependency with a top-level installed copy is one entry (its `installed`
 * version is the one that runs).
 */
export function collectDependencies(declared: readonly DeclaredDep[], installed: readonly InstalledPackage[]): Dependency[] {
  const out = new Map<string, Dependency>();
  const topLevel = new Map<string, Dependency>();
  for (const p of [...installed].sort((a, b) => (a.file < b.file ? -1 : 1))) {
    const key = `${p.name}@${p.version ?? "?"}`;
    let dep = out.get(key);
    if (!dep) {
      dep = { name: p.name, spec: null, installed: p.version, file: p.file, line: 0, declared: false };
      out.set(key, dep);
    }
    if (p.file === `node_modules/${p.name}/package.json` || p.file === `node_modules\\${p.name.replace("/", "\\")}\\package.json`) topLevel.set(p.name, dep);
  }
  for (const d of declared) {
    const hit = topLevel.get(d.name);
    if (hit && !hit.declared) {
      hit.declared = true;
      hit.spec = d.spec;
      hit.file = "package.json";
      hit.line = d.line;
      continue;
    }
    out.set(`${d.name}@spec:${d.spec}`, { name: d.name, spec: d.spec, installed: null, file: "package.json", line: d.line, declared: true });
  }
  return [...out.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : (a.installed ?? a.spec ?? "") < (b.installed ?? b.spec ?? "") ? -1 : 1));
}

/** `dep-lookalike` for names within the allowed edit distance of a popular package, and name mismatches inside `node_modules`. */
export function nameFindings(deps: readonly Dependency[], installed: readonly InstalledPackage[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  let more = 0;
  for (const d of deps) {
    if (seen.has(d.name)) continue;
    seen.add(d.name);
    if (!isValidName(d.name)) continue; // reported by the registry stage as not verified
    const hit = lookalikeOf(d.name);
    if (!hit) continue;
    if (findings.length >= MAX_FINDINGS_PER_RULE) {
      more++;
      continue;
    }
    findings.push({
      rule: "dep-lookalike",
      severity: "review",
      file: d.file,
      line: d.line,
      excerpt: excerptOf(`"${d.name}" is ${hit.distance} edit${hit.distance === 1 ? "" : "s"} away from the popular package "${hit.popular}"`),
    });
  }
  if (more > 0) findings.push({ rule: "dep-lookalike", severity: "review", file: "", line: 0, excerpt: `and ${more} more names that look like popular packages` });
  for (const p of installed.filter((x) => x.declaredName !== null).slice(0, MAX_FINDINGS_PER_RULE)) {
    findings.push({ rule: "dep-name-mismatch", severity: "review", file: p.file, line: 0, excerpt: excerptOf(`directory "${p.name}" holds a package that calls itself "${p.declaredName}"`) });
  }
  return findings;
}
