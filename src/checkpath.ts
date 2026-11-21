// `bb secure-bb check <path>` runs as the server's user, so with no limit it reads what the caller cannot and returns names,
// modes and excerpts of lines: an oracle (threat model F9). It is allowed only for directories that are not bb's own data
// and not private to the server's user.
import { realpathSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, sep } from "node:path";
import type { CheckResult } from "./checks/types.js";

export interface CheckPathContext {
  /** bb's data directory (everything inside is refused). Null: unknown. */
  dataDir: string | null;
  /** uid of the server process; null where there are no uids (Windows: only the data-directory rule applies). */
  serverUid: number | null;
}

const real = (p: string): string | null => {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
};
const within = (child: string, parent: string): boolean => child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);

/** A directory owned by the server's user that nobody else can enter (mode 700 or tighter). */
function privateToServer(path: string, uid: number): boolean {
  try {
    const st = statSync(path);
    return st.isDirectory() && st.uid === uid && (st.mode & 0o077) === 0;
  } catch {
    return false;
  }
}

/**
 * Null: this directory may be checked. Otherwise the reason (for the log, not for the caller).
 * Refused: bb's data directory and anything under it; a directory, or a parent of it, that is owned by the server's user
 * with mode 700. The walk up stops at the home and temp directories: those are private by nature and say nothing about
 * what lies under them. A path that does not exist is not refused here (the check itself reports it).
 */
export function checkPathRefusal(path: string, ctx: CheckPathContext): string | null {
  const target = real(path);
  if (target === null) return null;
  const data = ctx.dataDir ? real(ctx.dataDir) : null;
  if (data !== null && within(target, data)) return "inside the bb data directory";
  if (ctx.serverUid === null) return null;
  const stops = new Set([home(), real(tmpdir())].filter((x): x is string => x !== null));
  for (let dir = target; ; dir = dirname(dir)) {
    if (stops.has(dir)) return null;
    if (privateToServer(dir, ctx.serverUid)) return `private to the server user: ${dir}`;
    if (dirname(dir) === dir) return null;
  }
}
const home = (): string | null => real(homedir());

/** What an agent may be told about a check: a verdict and counts. No rule names, files, lines, excerpts, hosts or variable names. */
export function checkSummary(r: CheckResult): string {
  const n = { block: 0, review: 0, info: 0 };
  for (const f of r.findings) n[f.severity]++;
  const verdict = n.block > 0 ? "stopped" : n.review > 0 || r.capabilities.length > 0 ? "needs a human review" : "clean";
  return `check: ${verdict}; ${n.block} block, ${n.review} review, ${r.capabilities.length} capabilities; details are for the person on the secure-bb page`;
}
