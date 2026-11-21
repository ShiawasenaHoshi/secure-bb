// Skills module (stage 6): shared types. Everything here is plain data.
import type { Finding } from "../checks/types.js";

/** Scopes bb can delete a skill from (`deleteSkillRequestSchema` + `editableSkillScopeSchema` in bb). */
export const REMOVABLE_SCOPES: readonly string[] = ["bb-user", "bb-project", "provider-user", "provider-project"];

/** One installed skill as bb lists it. */
export interface SkillRef {
  /** Same key the watchdog uses for the skill, so a drift and a verdict line up. */
  key: string;
  /** bb's id (`skill_<sha256>`): where the file lives. */
  id: string;
  /** The project through which the skill was read (and through which it is removed). */
  projectId: string;
  name: string;
  scope: string;
  pluginId: string | null;
  /** bb says this skill can be deleted/edited. */
  manageable: boolean;
  /** `github.com/owner/repo/skill`: where bb installed it from, if it did. A claim written next to the skill, not a proof. */
  registrySkillId: string | null;
}

export interface SkillFileData {
  path: string;
  /** sha256 of the file's bytes as bb reports it; `unreadable` when the file could not be read. */
  revision: string;
  /** Text as bb returns it (UTF-8 decoded). Null when unreadable. */
  content: string | null;
  error?: string;
}

/** The whole content of one skill at one moment. */
export interface SkillSnapshot {
  /** sha256 over every (path, revision) pair: any other byte, file, or a missing file changes it. */
  hash: string;
  files: SkillFileData[];
  /** bb's listing was cut (more files than it shows): the rest is not seen. */
  truncated: boolean;
  bytes: number;
}

/** What the module needs from bb. Implemented over `bb.sdk.skills` in server.ts and faked in tests. */
export interface SkillFileSource {
  listFiles(ref: SkillRef): Promise<{ files: string[]; truncated: boolean }>;
  readFile(ref: SkillRef, path: string): Promise<{ content: string; revision: string }>;
  /** Deletes the skill. Throws when bb refuses. */
  remove(ref: SkillRef): Promise<void>;
}

/** Capabilities of a skill's scripts. The plugin kinds plus `script` (a script is there, nothing more is known). */
export interface SkillCapability {
  kind: string;
  detail: string[];
}

export interface SkillCheck {
  findings: Finding[];
  capabilities: SkillCapability[];
  stats: { files: number; bytes: number; scripts: number; ms: number };
}

export type SkillDecision = "clean" | "review" | "block";

export type SkillState = "held" | "removed" | "alarm" | "approved" | "gone";

export interface SkillQueueRow {
  id: number;
  key: string;
  skillId: string;
  name: string;
  scope: string;
  projectId: string;
  hash: string;
  decision: "review" | "block";
  state: SkillState;
  /** Why it is in the queue, one line (page only). */
  reason: string;
  check: SkillCheck | null;
  source: string | null;
  /** Existed before the module's first scan: never removed automatically. */
  preexisting: boolean;
  firstSeen: number;
  lastSeen: number;
  resolvedAt: number | null;
  via: string | null;
  /** What was removed (state `removed`): files and text as they were. */
  removedFiles: Array<{ path: string; content: string | null }> | null;
  note: string | null;
  /** Version of the skill rules that decided this entry (see SKILL_RULES_VERSION). */
  rulesVersion: number;
}

export interface SkillPinRow {
  key: string;
  skillId: string;
  name: string;
  scope: string;
  projectId: string;
  hash: string;
  /** builtin: bb's own, only pinned; baseline: present before the module; approved: accepted after the checks. */
  kind: "builtin" | "baseline" | "approved";
  via: string;
  approvedAt: number;
  files: number;
}

export type Verdict = "ok" | "approved" | "builtin" | "held" | "removed" | "alarm" | "unchecked";
