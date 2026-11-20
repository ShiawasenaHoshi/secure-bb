// Result shapes of the deterministic plugin checks (spec §5.1).

export type Severity = "block" | "review" | "info";

export interface Finding {
  /** Stable rule id, e.g. `invisible-chars`, `decode-eval`. */
  rule: string;
  severity: Severity;
  /** Path relative to the checked directory (`""` for the tree as a whole). */
  file: string;
  /** 1-based line, `0` when the finding is about the whole file or tree. */
  line: number;
  /** The offending text (shortened, control characters escaped). */
  excerpt: string;
}

export type CapabilityKind =
  | "network"
  | "child_process"
  | "env"
  | "fs"
  | "dynamic_code"
  | "ui"
  | "http_routes"
  | "contribute_env"
  | "host_artifact"
  | "builtin_rpc"
  | "server_access";

export const CAPABILITY_KINDS: readonly CapabilityKind[] = [
  "network",
  "child_process",
  "env",
  "fs",
  "dynamic_code",
  "ui",
  "http_routes",
  "contribute_env",
  "host_artifact",
  "builtin_rpc",
  "server_access",
];

export interface Capability {
  kind: CapabilityKind;
  /** What exactly: module names, literal hosts, env variable names, routes… Sorted, unique. */
  detail: string[];
  /** Where it was seen (capped). */
  sites: Array<{ file: string; line: number }>;
}

/** What the registry stage concluded about one dependency (stage 2.3). */
export type DependencyStatus =
  /** Registry metadata read, release is old enough, name is not a lookalike. */
  | "ok"
  /** Released less than 3 days ago. */
  | "young"
  /** Not looked at (no metadata: no network, no cache, version cannot be determined…). The reason is in `note`. */
  | "unchecked"
  /** The name is not on the npm registry. */
  | "not-in-registry"
  /** The registry has no such version. */
  | "unknown-version"
  /** A git / URL / file / workspace dependency: the registry says nothing about it (other rules cover these). */
  | "skipped";

export interface Dependency {
  name: string;
  /** Declared range, tag or exact version; null for a package found only in `node_modules`. */
  spec: string | null;
  /** Version of the copy in `node_modules`, if there is one. */
  installed: string | null;
  /** Where it was seen: `package.json` or the `node_modules/<name>/package.json` path. */
  file: string;
  line: number;
  /** Listed in the plugin's own `dependencies` / `optionalDependencies`. */
  declared: boolean;
  /** Set by the registry stage. */
  status?: DependencyStatus;
  /** The version that was judged (installed, exact, or what the range resolves to today). */
  version?: string | null;
  /** ISO time the registry says that version was published. */
  publishedAt?: string | null;
  note?: string;
}

export interface DependencyStats {
  /** Distinct `name@version` found (declared and in `node_modules`). */
  total: number;
  declared: number;
  /** Judged against registry metadata (status ok or young). */
  verified: number;
  unchecked: number;
  young: number;
  lookalikes: number;
  /** Whether the registry stage ran at all (false: `bb secure-bb check` without a registry client, tests). */
  registry: boolean;
}

export interface CheckResult {
  findings: Finding[];
  capabilities: Capability[];
  stats: { files: number; parsed: number; bytes: number; ms: number };
  /** Stage 2.3. Absent in results stored by earlier versions. */
  dependencies?: Dependency[];
  dependencyStats?: DependencyStats;
}
