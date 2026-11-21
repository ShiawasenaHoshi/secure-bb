// Names that look like a popular package (typosquatting), offline: the list is
// vendored (vendor/popular-packages.mjs, source and date in vendor/README.md).
import { POPULAR_PACKAGES } from "../../vendor/popular-packages.mjs";

/** Edit distance between `a` and `b`, or `max + 1` as soon as it is certain to exceed `max`. */
export function levenshtein(a: string, b: string, max = Infinity): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const v = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
      cur.push(v);
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length]!;
}

/** The brief's bound: distance ≤ 2. */
export const MAX_DISTANCE = 2;

/**
 * How many edits still count as "a lookalike" for a name of this length. Distance 2 on a
 * two-letter name matches half the registry (`ms`, `mz`, `ws`…), so short names get a
 * tighter bound: one edit per three characters, at most {@link MAX_DISTANCE}.
 */
export const allowedDistance = (name: string): number => Math.min(MAX_DISTANCE, Math.floor(name.length / 3));

export interface Lookalike {
  /** The popular package this name resembles. */
  popular: string;
  distance: number;
}

const byLength = new Map<number, string[]>();
const popularSet = new Set<string>();
for (const raw of POPULAR_PACKAGES) {
  const n = raw.toLowerCase();
  popularSet.add(n);
  let bucket = byLength.get(n.length);
  if (!bucket) byLength.set(n.length, (bucket = []));
  bucket.push(n);
}

export const isPopular = (name: string): boolean => popularSet.has(name.toLowerCase());

/**
 * The closest popular package within the allowed distance, or null. A name that *is*
 * a popular package (exact, case-insensitive) is the real thing, not a lookalike;
 * so is any name on the list, even if it sits near another listed name.
 */
export function lookalikeOf(name: string, popular: ReadonlySet<string> = popularSet, buckets: ReadonlyMap<number, string[]> = byLength): Lookalike | null {
  const n = name.toLowerCase();
  if (popular.has(n)) return null;
  const max = allowedDistance(n);
  if (max === 0) return null;
  let best: Lookalike | null = null;
  for (let len = n.length - max; len <= n.length + max; len++) {
    for (const p of buckets.get(len) ?? []) {
      // Only an equal or closer match can replace the best one; ties go to the alphabetically first name (stable output).
      const bound = best ? best.distance : max;
      const d = levenshtein(n, p, bound);
      if (d <= bound && (best === null || d < best.distance || p < best.popular)) best = { popular: p, distance: d };
    }
  }
  return best;
}
