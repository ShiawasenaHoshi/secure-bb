// Canonical JSON for HASHING and comparing: sorted keys, no spaces, the same text for the same data (the id of a part of a settings file is a hash of it;
// `sbb-restore` compares array elements with it). Not for reading: `prettyStableJson` in agents-scan.ts is the one for a diff.
// Its own file so that `json-parts.ts` and `restore.ts` (which import each other's neighbours) can both stand on it without a cycle.
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (isPlain(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
}
