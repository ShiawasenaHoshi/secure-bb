// The part of npm's semver that dependency checks need: which registry version a
// range such as `^1.2.0` resolves to. Zero dependencies. Anything not understood
// throws, and the caller reports the dependency as not verified (never guesses).

export interface Version {
  major: number;
  minor: number;
  patch: number;
  pre: string[];
}

const VERSION = /^[v=\s]*(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseVersion(s: string): Version | null {
  const m = VERSION.exec(s.trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), pre: m[4] ? m[4].split(".") : [] };
}

export const isExactVersion = (s: string): boolean => parseVersion(s) !== null;

function comparePre(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1; // a release is above its pre-releases
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    } else if (nx !== ny) return nx ? -1 : 1;
    else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export function compareVersions(a: Version, b: Version): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch || comparePre(a.pre, b.pre);
}

type Op = "<" | "<=" | ">" | ">=" | "=";
interface Comparator {
  op: Op;
  v: Version;
}

const v = (major: number, minor = 0, patch = 0): Version => ({ major, minor, patch, pre: [] });

/** `1`, `1.2`, `1.2.x`, `*` → numbers or null for a wildcard position. */
function parsePartial(s: string): { major: number | null; minor: number | null; patch: number | null } {
  const m = /^[v=\s]*(?:(\d+|[xX*])(?:\.(\d+|[xX*])(?:\.(\d+|[xX*])(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)?)?)?$/.exec(s.trim());
  if (!m || m[1] === undefined) {
    if (s.trim() === "") return { major: null, minor: null, patch: null };
    throw new Error(`unsupported version "${s}"`);
  }
  const num = (x: string | undefined): number | null => (x === undefined || /^[xX*]$/.test(x) ? null : Number(x));
  const major = num(m[1]);
  const minor = major === null ? null : num(m[2]);
  const patch = minor === null ? null : num(m[3]);
  return { major, minor, patch };
}

function desugar(op: string, raw: string): Comparator[] {
  const { major, minor, patch } = parsePartial(raw);
  const lo = (): Comparator[] => (major === null ? [] : [{ op: ">=", v: v(major, minor ?? 0, patch ?? 0) }]);
  const upExclusive = (): Version | null => (major === null ? null : minor === null ? v(major + 1) : patch === null ? v(major, minor + 1) : null);
  switch (op) {
    case "^": {
      if (major === null) return [];
      let hi: Version;
      if (major > 0 || minor === null) hi = v(major + 1);
      else if (minor > 0 || patch === null) hi = v(0, minor + 1);
      else hi = v(0, 0, patch + 1);
      return [...lo(), { op: "<", v: hi }];
    }
    case "~": {
      if (major === null) return [];
      return [...lo(), { op: "<", v: minor === null ? v(major + 1) : v(major, minor + 1) }];
    }
    case ">":
      if (major === null) return [{ op: "<", v: v(0) }]; // nothing is above "any"
      return upExclusive() ? [{ op: ">=", v: upExclusive()! }] : [{ op: ">", v: v(major, minor!, patch!) }];
    case ">=":
      return lo();
    case "<":
      return major === null ? [{ op: "<", v: v(0) }] : [{ op: "<", v: v(major, minor ?? 0, patch ?? 0) }];
    case "<=": {
      if (major === null) return [];
      const hi = upExclusive();
      return hi ? [{ op: "<", v: hi }] : [{ op: "<=", v: v(major, minor!, patch!) }];
    }
    default: {
      // "" or "=": a partial version is an x-range
      if (major === null) return [];
      const hi = upExclusive();
      return hi ? [...lo(), { op: "<", v: hi }] : [{ op: "=", v: v(major, minor!, patch!) }];
    }
  }
}

function parseSet(set: string): Comparator[] {
  let s = set.trim();
  const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(s);
  if (hyphen) {
    const from = parsePartial(hyphen[1]!);
    const out: Comparator[] = from.major === null ? [] : [{ op: ">=", v: v(from.major, from.minor ?? 0, from.patch ?? 0) }];
    return [...out, ...desugar("<=", hyphen[2]!)];
  }
  s = s.replace(/(\^|~>?|<=|>=|<|>|=)\s+/g, "$1"); // "^ 1.2.3" → "^1.2.3"
  const out: Comparator[] = [];
  for (const tok of s.split(/\s+/).filter(Boolean)) {
    const m = /^(\^|~>?|<=|>=|<|>|=)?(.*)$/.exec(tok)!;
    out.push(...desugar(m[1] === "~>" ? "~" : (m[1] ?? ""), m[2]!));
  }
  return out;
}

const holds = (c: Comparator, x: Version): boolean => {
  const d = compareVersions(x, c.v);
  return c.op === "<" ? d < 0 : c.op === "<=" ? d <= 0 : c.op === ">" ? d > 0 : c.op === ">=" ? d >= 0 : d === 0;
};

/** Parses a range into alternatives (`||`), each a list of comparators that must all hold. Throws on what it does not understand. */
export function parseRange(range: string): Comparator[][] {
  return range.split("||").map(parseSet);
}

export const satisfies = (version: Version, range: Comparator[][]): boolean => range.some((set) => set.every((c) => holds(c, version)));

/**
 * The version npm would pick for `range` among `versions`: the highest release
 * (no pre-releases). Null when nothing matches; throws when the range is not understood.
 */
export function maxSatisfying(versions: readonly string[], range: string): string | null {
  const parsed = parseRange(range);
  let best: { text: string; v: Version } | null = null;
  for (const text of versions) {
    const x = parseVersion(text);
    if (!x || x.pre.length > 0 || !satisfies(x, parsed)) continue;
    if (best === null || compareVersions(x, best.v) > 0) best = { text, v: x };
  }
  return best?.text ?? null;
}
