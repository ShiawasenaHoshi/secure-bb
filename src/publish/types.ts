// Stage 4 (spec §14): publishing a frozen version of our own plugin to the plugins monorepo.

/** Settings live in secure-bb's database. The token is NOT here and never will be: it is a file named by an environment variable. */
export interface PublishSettings {
  enabled: boolean;
  /** `https://host/owner/repo.git`. No credentials in it, ever. */
  repoUrl: string;
  branch: string;
  /** Also publish a version when a human approves it with a code (not only when a window freezes). */
  onApprove: boolean;
}
export const DEFAULT_PUBLISH: PublishSettings = { enabled: false, repoUrl: "", branch: "main", onApprove: false };

export const PUBLISH_TOKEN_FILE_ENV = "BB_SECURE_BB_PUBLISH_TOKEN_FILE";

export type PublishStatus = "running" | "published" | "unchanged" | "failed" | "skipped";
export type PublishTrigger = "freeze" | "approve" | "manual";

export interface PublishRow {
  id: number;
  pluginId: string;
  version: string;
  localHash: string;
  trigger: PublishTrigger;
  status: PublishStatus;
  repoUrl: string;
  branch: string;
  startedAt: number;
  finishedAt: number | null;
  commit: string | null;
  tag: string | null;
  /** What happened, in words for the human (git's message with the token and credentials removed). */
  detail: string | null;
}

/** Why publishing cannot run right now (null: it can). */
export type PublishState = "off" | "not-configured" | "no-address" | "ready";
