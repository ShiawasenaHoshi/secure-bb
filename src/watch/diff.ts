// Pure comparison of the approved snapshot with a fresh observation.
import type { DriftKind, Item, Observation, SnapshotRow } from "./model.js";

export interface Difference {
  key: string;
  category: Item["category"];
  source: string;
  kind: DriftKind;
  label: string;
  before: string | null;
  after: string | null;
  /** The current item (absent for "removed"). */
  item: Item | null;
}

/**
 * A key whose source could not be read is skipped: failing to look is not a
 * change (and not an all-clear either; the page lists unobserved sources).
 */
export function diffSnapshot(snapshot: SnapshotRow[], obs: Observation): Difference[] {
  // A failed source covers its sub-sources too: "env:project" covers "env:project:proj_x".
  const failedSources = obs.failed.map((f) => f.source);
  const isFailed = (source: string): boolean => failedSources.some((f) => source === f || source.startsWith(`${f}:`));
  const now = new Map(obs.items.map((i) => [i.key, i]));
  const before = new Map(snapshot.map((r) => [r.key, r]));
  const out: Difference[] = [];
  for (const item of obs.items) {
    const was = before.get(item.key);
    if (!was) out.push({ key: item.key, category: item.category, source: item.source, kind: "added", label: item.label, before: null, after: item.value, item });
    else if (was.value !== item.value) out.push({ key: item.key, category: item.category, source: item.source, kind: "changed", label: item.label, before: was.value, after: item.value, item });
  }
  for (const row of snapshot) {
    if (now.has(row.key) || isFailed(row.source)) continue;
    out.push({ key: row.key, category: row.category, source: row.source, kind: "removed", label: row.label, before: row.value, after: null, item: null });
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}
