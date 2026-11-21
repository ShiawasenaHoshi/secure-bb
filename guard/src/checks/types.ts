// Result shapes of the deterministic plugin checks (spec §5.1).

import type { Finding, Severity } from "../text-rules.ts";
import type { FlowSummary, Purpose } from "./flow.ts";
export type { Finding, Severity };

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
  | "server_access"
  /** `bb.storage.database()` / `node:sqlite`: a database handle in the gate's own process and uid can reach other databases (ATTACH, extensions). */
  | "database"
  /** `sdk.threads.timeline/output/search`, message and turn events: reads what is written in the person's conversations. */
  | "sdk_read"
  /** `sdk.threads.get/list`, `bb.events.on("thread.idle")`: titles and states of threads (when agents start and finish), not what is written in them. */
  | "sdk_meta"
  /** `sdk.threads.interactions.list/get`: sees which questions and permission requests the agents raise. */
  | "sdk_questions"
  /** `sdk.threads.spawn/stop/archive/fork/delete…`: starts, stops and removes agents. */
  | "sdk_agents"
  /** `sdk.threads.send/message/editMessage…`: writes into conversations as the person. */
  | "sdk_send"
  /** `sdk.threads.interactions.respond/resolve/cancel`: answers an agent's questions and permission requests. */
  | "sdk_answer"
  /** `sdk.system/plugins/providers/skills/projects/environments/hosts` setters: changes how bb is set up (installs and enables plugins, sets machine variables). */
  | "sdk_settings"
  /** Presses buttons of bb's page that the plugin did not draw (`document.querySelector(…).click()`, `dispatchEvent`, `requestSubmit`): the channel by which a plugin can press the gate's buttons too. */
  | "ui_click";

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
  "database",
  "sdk_read",
  "sdk_meta",
  "sdk_questions",
  "sdk_agents",
  "sdk_send",
  "sdk_answer",
  "sdk_settings",
  "ui_click",
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

/**
 * The version of the analysis a result was made by. Results are stored by the content hash and shown for as long as the version lives, so a change of
 * what the checks count (which directory of a repository, which calls are which right) must make the stored ones be made again: they carry this number.
 */
export const CHECKS_VERSION = 5;

export interface CheckResult {
  /** `CHECKS_VERSION` at the time; absent on results of the first checks. */
  v?: number;
  findings: Finding[];
  capabilities: Capability[];
  stats: { files: number; parsed: number; bytes: number; ms: number };
  /** Stage 2.3. Absent in results stored by earlier versions. */
  dependencies?: Dependency[];
  dependencyStats?: DependencyStats;
  /** Literal paths the plugin hands to file-system calls (a few). Only for the person to read; no decision uses them. */
  fsPaths?: string[];
  /** Programs the plugin starts by name (`afplay`, `osascript`), and whether it also starts one the code does not name. For the person to read; no decision uses them. */
  programs?: string[];
  programsUnknown?: boolean;
  /** Whose credential files the plugin's file or process calls reach («Google (Gemini)», «SSH-ключи»). For the person to read; no decision uses them. */
  credentials?: string[];
  /** Where what the plugin reads goes («Зачем»): one summary per source it has. Absent when the code was not analysed for flows. For the person to read, and the guard's rights say the dangerous ones. */
  flows?: FlowSummary[];
  /** «Зачем» by the pair access → sink: short sentences with the capability kinds whose lines they belong to. */
  purposes?: Purpose[];
  /** The clock stopped the flow analysis: this result is not finished. It is not kept, it counts for no right, and the check is made again later. */
  flowsTimedOut?: true;
}
/** The detail of a `network` capability: a network call whose address the code does not show. */
export const UNRESOLVED_HOST = "unresolved-host";
