// Who can write to a directory a plugin would be installed or approved from?
//
// A directory is trustworthy as a source only if nobody but the bb server's own
// OS user (and root, who can do anything anyway) can change it: not the
// directory, not anything inside it, and not any parent on the way to "/" (a
// parent that others can write lets them swap the whole directory). Our own
// snapshots are exempt: they are verified by hash at every load instead.
import { lstat, readdir, realpath } from "node:fs/promises";
import { dirname, join } from "node:path";

export type PermWhy = "owner" | "group-write" | "other-write" | "too-large";
export interface PermIssue {
  path: string;
  why: PermWhy;
  /** Part of the chain above the directory, or something inside it. */
  where: "dir" | "parent" | "inside";
}

export interface PermOptions {
  /** The server's uid. */
  uid: number;
  /** The server's primary gid; a group-writable entry in a private group (gid = uid) is the user's own. */
  gid?: number;
  /** Stops after this many entries inside the tree. */
  maxEntries?: number;
}

export const MAX_TREE_ENTRIES = 20_000;
const STICKY = 0o1000;

/** The current process's uid/gid, or null where the OS has none (Windows: the check cannot run). */
export function serverIds(): { uid: number; gid: number } | null {
  if (typeof process.getuid !== "function") return null;
  return { uid: process.getuid(), gid: process.getgid?.() ?? process.getuid() };
}

function judge(st: { uid: number; gid: number; mode: number; isDirectory(): boolean }, o: PermOptions, where: PermIssue["where"]): PermWhy | null {
  if (st.uid !== o.uid && st.uid !== 0) return "owner";
  const sticky = where === "parent" && st.isDirectory() && (st.mode & STICKY) !== 0;
  // A sticky parent (like /tmp) lets others add entries but not replace ours.
  if (sticky) return null;
  if ((st.mode & 0o002) !== 0) return "other-write";
  if ((st.mode & 0o020) !== 0) {
    const privateGroup = o.gid !== undefined && st.gid === o.gid && st.gid === o.uid;
    if (!privateGroup) return "group-write";
  }
  return null;
}

/**
 * Everything that makes `dir` writable by someone other than the server user:
 * the directory itself and every entry inside it, and every parent up to "/".
 * Symlinks are not followed (a link's own mode is irrelevant); the path is
 * resolved first, so a link in the chain is judged by where it really leads.
 * An empty list means: nobody else can write there (as far as modes and owners say;
 * ACLs and mounted-volume rules are not read).
 */
export async function writableByOthers(dir: string, o: PermOptions): Promise<PermIssue[]> {
  const issues: PermIssue[] = [];
  const real = await realpath(dir);

  let cur = real;
  for (let first = true; ; first = false) {
    const st = await lstat(cur);
    const why = judge(st, o, first ? "dir" : "parent");
    if (why) issues.push({ path: cur, why, where: first ? "dir" : "parent" });
    const up = dirname(cur);
    if (up === cur) break;
    cur = up;
  }

  const limit = o.maxEntries ?? MAX_TREE_ENTRIES;
  let seen = 0;
  const walk = async (d: string): Promise<void> => {
    for (const entry of await readdir(d, { withFileTypes: true })) {
      if (++seen > limit) return;
      const full = join(d, entry.name);
      const st = await lstat(full);
      if (st.isSymbolicLink()) continue;
      const why = judge(st, o, "inside");
      if (why) issues.push({ path: full, why, where: "inside" });
      if (st.isDirectory()) await walk(full);
    }
  };
  await walk(real);
  if (seen > limit) issues.push({ path: real, why: "too-large", where: "inside" }); // not fully checkable: treated as unsafe
  return issues;
}

/** A short human line for the page (never sent to agents). */
export function describeIssues(issues: PermIssue[], max = 3): string {
  const label: Record<PermWhy, string> = { owner: "чужой владелец", "group-write": "запись для группы", "other-write": "запись для всех", "too-large": "слишком много файлов для проверки" };
  const shown = issues.slice(0, max).map((i) => `${i.path} (${label[i.why]}${i.where === "parent" ? ", родитель" : ""})`);
  return shown.join("; ") + (issues.length > max ? ` и ещё ${issues.length - max}` : "");
}
