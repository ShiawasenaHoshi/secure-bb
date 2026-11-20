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

export interface CheckResult {
  findings: Finding[];
  capabilities: Capability[];
  stats: { files: number; parsed: number; bytes: number; ms: number };
}
