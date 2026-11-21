// Migration into the guard: the approvals this plugin holds, written to a file that `sbb-guard import <file>` reads.
// The file is made by code inside bb, so the guard treats it as a claim: whoever runs the import sees every line first and may pin
// the file's sha256 (shown on the page when the file is made).
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import type { ApprovalRow } from "./store.js";

/** The same string as in guard/src/cli.ts (a test compares them). */
export const EXPORT_FORMAT = "secure-bb-approvals/1";

export interface ExportResult {
  text: string;
  digest: string;
  count: number;
}

export function buildExport(approvals: ApprovalRow[], now: number): ExportResult {
  const active = approvals.filter((a) => a.revokedAt === null);
  const text = `${JSON.stringify(
    {
      format: EXPORT_FORMAT,
      exportedAt: now,
      approvals: active.map((a) => ({
        contentHash: a.contentHash,
        pluginId: a.pluginId,
        version: a.version,
        source: a.source,
        sourceKind: a.sourceKind,
        gitCommit: a.gitCommit,
        npmIntegrity: a.npmIntegrity,
        approvedAt: a.approvedAt,
      })),
    },
    null,
    2,
  )}\n`;
  return { text, digest: createHash("sha256").update(text).digest("hex"), count: active.length };
}

/** `<dataDir>/exports/approvals-<time>.json`, readable by the plugin's user only. */
export function writeExport(dataDir: string, result: ExportResult, now: number): string {
  const dir = join(dataDir, "exports");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, `approvals-${new Date(now).toISOString().replace(/[:.]/g, "-")}.json`);
  writeFileSync(path, result.text, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}
