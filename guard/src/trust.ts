// Trust by source and rights (UX v1, PR 1). Pure functions: no I/O, no clock. The guard decides with them; the plugin shows the result.
//
// A source is judged from what the core sent (`source`, `sourceKind`), never from what a plugin says about itself.
//   own     — the repository or the directory is in the owner's list ("my sources")
//   known   — it is in the list the guard was started with for the official catalog (`--known-source`)
//   unknown — everything else
// The rights of a version are computed by the guard from the plugin's directory (the checks module of this directory tree), and a
// version passes by itself only if they did not grow compared to an approved version from the same source.
import { posix } from "node:path";
import type { CheckResult, Finding } from "./checks/index.ts";
import { flowTokens } from "./checks/flow.ts";

export type Level = "own" | "known" | "unknown";
export type TrustMode = "simple" | "detailed" | "strict";
export const TRUST_MODES: readonly TrustMode[] = ["simple", "detailed", "strict"];
/** How strict a mode is: a lower rank is a weaker mode (letting it in needs a touch). */
export const MODE_RANK: Record<TrustMode, number> = { simple: 0, detailed: 1, strict: 2 };
export const DEFAULT_TRUST_MODE: TrustMode = "simple";
export const MAX_SOURCES = 100;

// ---- sources ------------------------------------------------------------------------------------------------------------
const OWNER = /^[a-z0-9](?:[a-z0-9-]{0,38})$/;
const REPO = /^[a-z0-9._-]{1,100}$/;

/**
 * An entry of the list: `github:owner/name`, `github:owner/*` or `path:/absolute/dir`. Returns the normalized form, or null.
 * A path entry is a directory: it covers itself and everything below it (never `..`, never relative, never the root itself).
 */
export function normalizeEntry(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const t = input.trim();
  // eslint-disable-next-line no-control-regex
  if (t === "" || t.length > 1024 || /[\u0000-\u001f\u007f]/.test(t)) return null;
  if (/^path:/i.test(t)) return normalizePath(t.slice(5));
  const gh = t.replace(/^github:/i, "").replace(/^https?:\/\/github\.com\//i, "").replace(/\.git$/i, "").replace(/\/$/, "").toLowerCase();
  const m = /^([^/]+)\/([^/]+)$/.exec(gh);
  if (!m || !OWNER.test(m[1]!)) return null;
  if (m[2] === "*") return `github:${m[1]}/*`;
  return REPO.test(m[2]!) && m[2] !== "." && m[2] !== ".." ? `github:${m[1]}/${m[2]}` : null;
}
function normalizePath(p: string): string | null {
  if (!p.startsWith("/") || p.split("/").includes("..")) return null;
  const n = posix.normalize(p).replace(/\/+$/, "");
  return n === "" ? null : `path:${n}`;
}

export interface SourceIdentity {
  kind: "git" | "path";
  /** The exact source: `github:owner/name` or `path:/dir`. Two versions are "from the same source" when this is equal. */
  id: string;
}

/**
 * The ONE reading of a github.com address as `owner/name` (lower case); the plugin's pollution tracker (`src/taint/repos.ts`) calls it too.
 * `https://github.com/o/r.git`, `git@github.com:o/r`, `ssh://git@github.com/o/r`: the host must be exactly github.com.
 * `@ref` is the syntax of bb's PLUGIN SOURCES (`git@github.com:o/r@v1`): only with `allowRef` is it cut off. Anywhere else (an address in a shell command) a name with
 * `@` is not a repository of GitHub, so it is not one here: the choice that never trusts more (a repo is not «the same» because a suffix was ignored).
 */
export function githubRepo(address: string, opts: { allowRef?: boolean } = {}): string | null {
  let host: string;
  let path: string;
  const scp = /^[\w.-]+@([\w.-]+):(.+)$/.exec(address);
  if (scp) {
    host = scp[1]!;
    path = scp[2]!;
  } else {
    try {
      const u = new URL(address);
      if (!["https:", "http:", "ssh:", "git:"].includes(u.protocol)) return null;
      host = u.hostname;
      path = u.pathname;
    } catch {
      return null;
    }
  }
  if (host.toLowerCase() !== "github.com") return null;
  const parts = path.split(/[?#]/)[0]!.replace(/^\/+/, "").split("/");
  if (parts.length < 2) return null;
  const owner = parts[0]!.toLowerCase();
  const rawName = parts[1]!;
  if (!opts.allowRef && rawName.includes("@")) return null;
  const name = rawName.split("@")[0]!.replace(/\.git$/i, "").toLowerCase();
  return OWNER.test(owner) && REPO.test(name) && name !== "." && name !== ".." ? `${owner}/${name}` : null;
}

/** What the core's `source` says it is. Null: not a source the lists can name (npm, a marketplace over https, anything odd). */
export function identityOf(sourceKind: string, source: string): SourceIdentity | null {
  if (sourceKind === "path") {
    if (!source.startsWith("path:")) return null;
    const n = normalizePath(source.slice(5));
    return n === null ? null : { kind: "path", id: n };
  }
  if (sourceKind === "git") {
    if (!source.startsWith("git:")) return null;
    const repo = githubRepo(source.slice(4).replace(/#.*$/, "").replace(/\s.*$/, ""), { allowRef: true });
    return repo === null ? null : { kind: "git", id: `github:${repo}` };
  }
  return null;
}

/** Does the entry of a list name this source? */
export function entryCovers(entry: string, ident: SourceIdentity): boolean {
  if (entry.startsWith("path:")) return ident.kind === "path" && (ident.id === entry || ident.id.startsWith(`${entry}/`));
  if (ident.kind !== "git") return false;
  return entry.endsWith("/*") ? ident.id.startsWith(entry.slice(0, -1)) : entry === ident.id;
}

export function levelOf(ident: SourceIdentity | null, mine: readonly string[], known: readonly string[]): { level: Level; entry: string | null } {
  if (ident === null) return { level: "unknown", entry: null };
  const own = mine.find((e) => entryCovers(e, ident));
  if (own !== undefined) return { level: "own", entry: own };
  const k = known.find((e) => entryCovers(e, ident));
  return k !== undefined ? { level: "known", entry: k } : { level: "unknown", entry: null };
}

// ---- rights --------------------------------------------------------------------------------------------------------------
export interface Rights {
  /** `kind` and `kind:detail` of every capability the checks found. Sorted, unique. */
  tokens: string[];
  /** Rules of the findings that need a look (`review`): a version may not bring a rule its approved ancestor did not have. */
  review: string[];
}
const MAX_TOKENS = 400;

export function capabilityTokens(r: Pick<CheckResult, "capabilities" | "flows">): string[] {
  const out = new Set<string>();
  for (const c of r.capabilities) {
    out.add(c.kind);
    for (const d of c.detail) out.add(`${c.kind}:${d}`);
  }
  // Where what the plugin reads goes (the guard counts it itself, with the same module): a new way out is a new right.
  for (const t of flowTokens(r.flows)) out.add(t);
  return [...out].sort();
}

export const rightsOf = (r: CheckResult): Rights => ({
  tokens: capabilityTokens(r).slice(0, MAX_TOKENS),
  review: [...new Set(r.findings.filter((f) => f.severity === "review").map((f) => f.rule))].sort(),
});

export function parseRights(raw: unknown): Rights | null {
  if (typeof raw !== "string") return null;
  try {
    const j = JSON.parse(raw) as Partial<Rights>;
    return Array.isArray(j.tokens) && Array.isArray(j.review) && j.tokens.every((t) => typeof t === "string") && j.review.every((t) => typeof t === "string") ? { tokens: j.tokens, review: j.review } : null;
  } catch {
    return null;
  }
}

/** What a version has that its approved ancestor did not. */
export function grown(base: Rights, now: Rights): { tokens: string[]; review: string[] } {
  const t = new Set(base.tokens);
  const r = new Set(base.review);
  return { tokens: now.tokens.filter((x) => !t.has(x)), review: now.review.filter((x) => !r.has(x)) };
}

export const hardFlags = (r: CheckResult): Finding[] => r.findings.filter((f) => f.severity === "block");

/** What an open window says about a version's rights (`windowAllows`). */
export interface WindowVerdict {
  /** The window lets the version in as far as its rights go: no new right and nothing for review. */
  allowed: boolean;
  /** Tokens the version has and the baseline lacks (`grown`): a new capability. */
  newTokens: string[];
  /** Rules of the findings that need a look. ANY of them holds the version in a window, not only a new one: a window waves through what was already seen, not what needs eyes. */
  reviews: string[];
}
/**
 * THE rule of what an open window lets in, by rights. The guard calls it (`windowRefuses`) and so does the plugin's hook without a guard (`decideUnsafe`); the hook
 * in guard mode adds only what the guard cannot see (the thread, a damaged snapshot, a polluted tree, the AI scan's flag) and does not compare rights at all.
 * `baseline`: the rights of the last approved version, and of the version the window was opened from; each caller names its own, the comparison is this.
 */
export function windowAllows(baseline: Rights, rights: Rights): WindowVerdict {
  const newTokens = grown(baseline, rights).tokens;
  const reviews = rights.review;
  return { allowed: newTokens.length === 0 && reviews.length === 0, newTokens, reviews };
}

/** `rule file:line` of the first few findings, for a line in a queue entry. */
export function brief(items: string[], max = 4): string {
  return items.slice(0, max).join(", ") + (items.length > max ? ` и ещё ${items.length - max}` : "");
}

// ---- what may lift a held version: the guard's facts, not a note's words ------------------------------------------------------------
/** Why a version is held (the guard's own reading). `mismatch`: the directory's hash is not the request's; `block`: a hard flag; `growth`: a new right. */
export const REASON_KINDS = ["mismatch", "block", "growth", "unknown-source", "strict", "first", "other"] as const;
export type ReasonKind = (typeof REASON_KINDS)[number];
export const isReasonKind = (x: unknown): x is ReasonKind => typeof x === "string" && (REASON_KINDS as readonly string[]).includes(x);

export interface LiftInput {
  /** Absent (an entry older than the column, or from a guard that predates it): unknown. */
  reasonKind?: string | null;
  /** The hard flags the guard's own `evaluate` found. `null` or absent: the guard did not read the version, so a block may be there. */
  blocks?: string[] | null;
}
export interface Lift {
  /** Never: the directory is not what the request says (reinstall). */
  never: boolean;
  /** A hard flag is there, or may be (not read): approving takes `acknowledgeBlock` AND a fresh touch; a session never covers it. */
  needsAck: boolean;
  /** Why `needsAck`: `block` (flags found) or `unread` (nothing was read). */
  why: "mismatch" | "block" | "unread" | null;
  /** Strict mode lets no block be lifted. */
  refusedByMode: boolean;
}
/**
 * The ONE rule of lifting a stop, used by the guard (`approve`, batch, «Вернуть», «доверять источнику») and by the page (the buttons it shows).
 * It reads facts: `reasonKind === "mismatch"`, a non-empty `blocks`, or `blocks` not read at all. A note's text is never looked at.
 */
export function liftBlock(e: LiftInput, mode: TrustMode | null): Lift {
  const kind = e.reasonKind ?? null;
  if (kind === "mismatch") return { never: true, needsAck: true, why: "mismatch", refusedByMode: false };
  const unread = e.blocks === null || e.blocks === undefined;
  const found = !unread && (e.blocks as string[]).length > 0;
  const needsAck = unread || found || kind === "block";
  return { never: false, needsAck, why: !needsAck ? null : found || kind === "block" ? "block" : "unread", refusedByMode: needsAck && mode === "strict" };
}

// ---- the same rule for an entry that has only words -----------------------------------------------------------------------------
// An entry the PLUGIN keeps itself (no guard) has no facts the guard read, only the words its gate wrote in `reason`. Those words are turned into facts HERE, and
// then the one rule above decides: the page does not decide anything about a block by itself.
export interface EntryLiftInput extends LiftInput {
  reason: string | null;
}
/** «the directory's files did not match the hash of the request»: the words of the gate's own reason for a mismatch. */
export const isMismatchWords = (reason: string | null): boolean => /не совпал с хешем/.test(reason ?? "");
const BLOCKED_WORDS = /заблокирован(о)? проверками|жёсткий флаг/;
/** The facts an entry kept by the plugin states in words. A block in the words is a flag found; no such words means nothing was found (the plugin's own gate has read it). */
export function factsOfReasonWords(reason: string | null): { reasonKind: string | null; blocks: string[] } {
  return { reasonKind: isMismatchWords(reason) ? "mismatch" : null, blocks: BLOCKED_WORDS.test(reason ?? "") ? ["words"] : [] };
}
/** The entry comes from the guard and carries its facts: then no word of `reason` decides anything. */
const carriesFacts = (e: LiftInput): boolean => e.reasonKind !== undefined || e.blocks !== undefined;
/** `liftBlock` for an entry as the page holds it: by the guard's facts when it has them, else by the facts read from the gate's words. */
export function liftOfEntry(e: EntryLiftInput, mode: TrustMode | null): Lift {
  return liftBlock(carriesFacts(e) ? { reasonKind: e.reasonKind ?? null, blocks: e.blocks ?? null } : factsOfReasonWords(e.reason), mode);
}
/** «Всё равно разрешить…» exists on a red card only if the mode allows it (Strict does not) AND the stop is not a mismatch (an approval would be written for the hash of a suspect request). */
export function bypassOffered(e: EntryLiftInput, mode: TrustMode | null): boolean {
  return mode !== "strict" && !liftOfEntry(e, mode).never;
}
