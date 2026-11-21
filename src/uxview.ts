// What the page needs to explain a held version in plain words (UX v1, PR 2): the author's own "why", where it came from
// (thread → subthread), and how far the source is trusted. Display only: nothing here approves or holds anything.
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";
import { identityOf, levelOf } from "../guard/src/trust.ts";
import type { GuardTrust } from "./guardlink.js";
import { cleanWhy, sourceLabel, type Level } from "./ux.js";

export interface ThreadRef {
  id: string;
  /** The thread's title when bb gave one (short). */
  title: string | null;
}
export interface QueueUx {
  /** `secureBb.why` of the plugin's package.json: what the AUTHOR says. Not checked; the page says so. */
  why: string | null;
  /** Root thread first, the thread the version came from last. Empty when no thread is known. */
  chain: ThreadRef[];
  level: Level;
  /** The entry «мои источники» would take for this source (`github:owner/name` or `path:/dir`); null: the source cannot be named. */
  entry: string | null;
  /** Readable origin. */
  sourceLabel: string;
}

const MAX_MANIFEST = 256 * 1024;
/** `secureBb.why` from the package.json of a plugin directory. A symlink, a non-file or a big file gives nothing: the text is only a convenience. */
export async function readWhy(rootDir: string | null): Promise<string | null> {
  if (!rootDir) return null;
  const file = join(rootDir, "package.json");
  try {
    const st = await lstat(file);
    if (!st.isFile() || st.size > MAX_MANIFEST) return null;
    const fh = await open(file, "r");
    try {
      const j = JSON.parse(await fh.readFile("utf8")) as { secureBb?: { why?: unknown } } | null;
      return cleanWhy(j?.secureBb?.why);
    } finally {
      await fh.close();
    }
  } catch {
    return null;
  }
}

export interface QueueUxDeps {
  /** The thread's ancestors, parent first, root last (as bb gives them). */
  ancestors?: (threadId: string) => Promise<string[]>;
  threadTitle?: (threadId: string) => Promise<string | null>;
}

export async function queueUx(d: QueueUxDeps, q: { rootDir: string | null; source: string; sourceKind: string; threadId: string | null }, trust: GuardTrust | null): Promise<QueueUx> {
  const ident = identityOf(q.sourceKind, q.source);
  const { level } = levelOf(ident, trust?.mySources ?? [], trust?.known ?? []);
  let chain: ThreadRef[] = [];
  if (q.threadId) {
    let ids = [q.threadId];
    try {
      const up = d.ancestors ? await d.ancestors(q.threadId) : [];
      ids = [...up.slice(0, 8).reverse(), q.threadId];
    } catch {
      /* the thread alone */
    }
    chain = await Promise.all(
      ids.map(async (id) => {
        let title: string | null = null;
        try {
          title = d.threadTitle ? await d.threadTitle(id) : null;
        } catch {
          title = null;
        }
        return { id, title: title ? title.slice(0, 60) : null };
      }),
    );
  }
  return { why: await readWhy(q.rootDir), chain, level, entry: ident?.id ?? null, sourceLabel: sourceLabel(q.sourceKind, q.source) };
}
