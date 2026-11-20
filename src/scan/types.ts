// Shapes of the optional AI scan (spec §8). Nothing here touches a process or the network.

/** Which model produced an outcome. */
export type ModelId = "claude" | "cursor";

/**
 * What one model run came to.
 * `clean` and `flag` are answers; `refusal`, `invalid`, `timeout` and `error` are failures that count as suspicion;
 * `unavailable` means the model could not be asked at all (no binary, no login): nothing was learned either way.
 */
export type ModelStatus = "clean" | "flag" | "refusal" | "invalid" | "timeout" | "error" | "unavailable";

export interface ReportCapability {
  kind: string;
  detail: string;
  file: string;
  line: number;
}
export interface ReportFlow {
  from: string;
  to: string;
  file: string;
  line: number;
  note: string;
}
export interface ReportConcern {
  severity: "low" | "medium" | "high";
  what: string;
  file: string;
  line: number;
}
/** The JSON a model must answer with. */
export interface ScanReport {
  summary: string;
  matchesDescription: boolean;
  descriptionNote: string;
  capabilities: ReportCapability[];
  dataFlows: ReportFlow[];
  concerns: ReportConcern[];
  verdict: "clean" | "suspicious";
}

export interface ModelOutcome {
  model: ModelId;
  /** `claude`, or `cursor-agent (<model name>)`. */
  label: string;
  status: ModelStatus;
  /** Short human text: why a failure, or the one-line summary of an answer. Never contains a token. */
  detail: string;
  report: ScanReport | null;
  ms: number;
}

/** `running` until the models are done; `suspect` = any flag, refusal, bad answer, timeout, or code that did not fit. */
export type ScanStatus = "running" | "clean" | "suspect" | "unavailable";
export type ScanTrigger = "manual" | "freeze" | "external" | "cli";

export interface ScanResult {
  status: Exclude<ScanStatus, "running">;
  models: ModelOutcome[];
  /** Files whose code was sent (comments removed). */
  files: number;
  chars: number;
  /** Why the scan did not cover everything (each entry makes the scan suspect). */
  incomplete: string[];
  /** Files of the tree that were not sent by design (not code: docs, images, data), names only. */
  skipped: string[];
  note: string | null;
}

export interface ScanRow {
  id: number;
  pluginId: string;
  version: string;
  /** Hash of the source tree (without dist/) that was scanned. */
  localHash: string;
  /** The core's hash, when the scan was started for a version the hook has seen. */
  contentHash: string | null;
  trigger: ScanTrigger;
  status: ScanStatus;
  startedAt: number;
  finishedAt: number | null;
  result: ScanResult | null;
}

export interface AiSettings {
  /** The whole module. Off by default. */
  enabled: boolean;
  /** Scan the pinned version when a trust window freezes. */
  autoFreeze: boolean;
  /** Scan every version of an external plugin before it is decided. */
  autoExternal: boolean;
  /** Ask a second model (cursor-agent, another vendor). */
  second: boolean;
  /** Name of the second model; must not be an Anthropic model. */
  secondModel: string;
  /** Plugins whose freeze is scanned even when `autoFreeze` is off. */
  freezePlugins: string[];
}
export const DEFAULT_AI: AiSettings = { enabled: false, autoFreeze: false, autoExternal: false, second: false, secondModel: "", freezePlugins: [] };
