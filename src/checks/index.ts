// Deterministic checks of a plugin directory (spec §5.1): no network, no
// model, seconds. Input: a directory (a snapshot). Output: findings and the
// list of capabilities the code can use.
import { analyze, parseSource, type FileFacts, type Site } from "./ast.js";
import { excerptOf, scanTree } from "./files.js";
import { CAPABILITY_KINDS, type Capability, type CapabilityKind, type CheckResult, type Finding } from "./types.js";

export type { Capability, CapabilityKind, CheckResult, Finding, Severity } from "./types.js";
export { CAPABILITY_KINDS } from "./types.js";

const SITE_CAP = 20;
const MAX_PARSE_BYTES = 40 * 1024 * 1024;
const SEVERITY_ORDER = { block: 0, review: 1, info: 2 } as const;

function addCap(map: Map<CapabilityKind, { detail: Set<string>; sites: Array<{ file: string; line: number }> }>, kind: CapabilityKind, detail: string | null, file: string, line: number): void {
  let c = map.get(kind);
  if (!c) map.set(kind, (c = { detail: new Set(), sites: [] }));
  if (detail !== null) c.detail.add(detail);
  if (c.sites.length < SITE_CAP && !c.sites.some((s) => s.file === file && s.line === line)) c.sites.push({ file, line });
}

export async function runChecks(dir: string): Promise<CheckResult> {
  const t0 = Date.now();
  const tree = await scanTree(dir);
  const findings: Finding[] = [...tree.findings];
  const caps = new Map<CapabilityKind, { detail: Set<string>; sites: Array<{ file: string; line: number }> }>();
  const perFile: Array<{ rel: string; facts: FileFacts }> = [];

  // package.json: the declared surfaces
  const bbField = tree.rootPackage && typeof tree.rootPackage.bb === "object" && tree.rootPackage.bb ? (tree.rootPackage.bb as Record<string, unknown>) : {};
  if (typeof bbField.app === "string") addCap(caps, "ui", `bb.app: ${bbField.app}`, "package.json", 0);
  for (const key of Object.keys(bbField)) if (/contentScripts?|composer/i.test(key)) addCap(caps, "ui", `bb.${key}`, "package.json", 0);
  if (bbField.host !== undefined) addCap(caps, "host_artifact", `bb.host: ${typeof bbField.host === "string" ? bbField.host : "declared"}`, "package.json", 0);

  let parseBudget = MAX_PARSE_BYTES;
  let parsed = 0;
  for (const src of tree.sources) {
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
  }

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
  // Literal hosts belong to the network capability.
  for (const { rel, facts } of perFile) {
    if (!anyNetwork) break;
    for (const h of facts.hosts) addCap(caps, "network", `host:${h.host}`, rel, h.line);
  }

  // A secret-looking env variable next to any network capability (DNS names are enough to carry it out).
  const envCap = caps.get("env");
  if (caps.has("network") && envCap) {
    const secretish = [...envCap.detail].filter((d) => /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH/i.test(d));
    if (secretish.length > 0) {
      const site = envCap.sites[0]!;
      findings.push({ rule: "env-secret-network", severity: "review", file: site.file, line: site.line, excerpt: `reads ${secretish.join(", ")} and has network access (${[...caps.get("network")!.detail].filter((d) => !d.startsWith("host:")).join(", ")})` });
    }
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
  return { findings: sorted, capabilities, stats: { files: tree.files, parsed, bytes: tree.bytes, ms: Date.now() - t0 } };
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
  return out.join("\n");
}
