import { createHash } from "node:crypto";

/** One hash for the whole skill: every file's path and bb-reported revision, sorted; plus whether the listing was complete. */
export function hashSkillFiles(files: ReadonlyArray<{ path: string; revision: string }>, truncated: boolean): string {
  const h = createHash("sha256");
  h.update(`secure-bb skill v1\n${truncated ? "truncated" : "complete"}\n`);
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  for (const f of sorted) h.update(`${JSON.stringify(f.path)} ${f.revision}\n`);
  return h.digest("hex");
}
