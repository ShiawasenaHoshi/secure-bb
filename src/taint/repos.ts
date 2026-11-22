// Repositories that do not taint a thread («trusted» in the names of the functions below): patterns `owner/name` and `owner/*` (github.com only). A `git clone` of, or a `gh` call on,
// such a repository is the user's own work and does not taint a thread; anything else with an address does.

import { githubRepo } from "../../guard/src/trust.ts";

export const REPO_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,38})\/(?:\*|[a-z0-9._-]{1,100})$/;

/** Normalised pattern, or null when it is not `owner/name` / `owner/*`. */
export function normalizePattern(input: string): string | null {
  const p = input.trim().toLowerCase().replace(/^https?:\/\/github\.com\//, "").replace(/\.git$/, "").replace(/\/$/, "");
  return REPO_PATTERN.test(p) ? p : null;
}

export function isTrustedRepo(slug: string, patterns: readonly string[]): boolean {
  const s = slug.toLowerCase();
  const owner = s.split("/")[0]!;
  return patterns.some((p) => p === s || (p.endsWith("/*") && p.slice(0, -2) === owner));
}

const ADDRESS = /\b(?:https?|ssh|git|ftp):\/\/[^\s"']+|\bgit@[\w.-]+:[^\s"']+/gi;

/**
 * `owner/name` of a github.com address; null for other hosts or unparsable ones. One reading for the guard and the tracker: `githubRepo` in guard/src/trust.ts
 * (the host is exactly `github.com`; `github.com` in the path, in a longer host name or in the user part is not GitHub: threat model F10).
 * A `@ref` is no ref in a shell command: such a name is not a repository, so it does not count as a trusted one.
 */
export function githubSlug(address: string): string | null {
  return githubRepo(address);
}

/** True when the segment has addresses and every one is a trusted github.com repository. */
export function gitAddressesTrusted(segment: string, patterns: readonly string[]): boolean {
  const addresses = segment.match(ADDRESS) ?? [];
  if (addresses.length === 0) return false;
  return addresses.every((a) => {
    const slug = githubSlug(a);
    return slug !== null && isTrustedRepo(slug, patterns);
  });
}

/** Repositories a `gh` segment names explicitly (--repo/-R, github.com addresses, `repos/o/n` api paths, `gh repo clone o/n`). Null entries: named but not a github.com repository. */
export function ghRepos(segment: string): Array<string | null> {
  const out: Array<string | null> = [];
  for (const m of segment.matchAll(/(?:^|\s)(?:-R|--repo)(?:=|\s+)(\S+)/g)) {
    const v = m[1]!.replace(/^["']|["']$/g, "");
    out.push(/^[\w.-]+\/[\w.-]+$/.test(v) ? v.toLowerCase() : githubSlug(v));
  }
  for (const a of segment.match(ADDRESS) ?? []) out.push(githubSlug(a));
  for (const m of segment.matchAll(/\brepos\/([\w.-]+)\/([\w.-]+)/g)) out.push(`${m[1]}/${m[2]}`.toLowerCase());
  const pos = /\bgh\s+repo\s+(?:clone|fork|view|sync)\s+(?:-\S+\s+)*([\w.-]+\/[\w.-]+)(?=\s|$)/i.exec(segment);
  if (pos) out.push(pos[1]!.toLowerCase());
  return out;
}

export function ghTrusted(segment: string, patterns: readonly string[]): boolean {
  const repos = ghRepos(segment);
  return repos.length > 0 && repos.every((r) => r !== null && isTrustedRepo(r, patterns));
}

/** Shell command split into simple commands: `a && b; c | d`. */
export const segments = (cmd: string): string[] => cmd.split(/&&|\|\||[;|\n]/).map((s) => s.trim()).filter(Boolean);
