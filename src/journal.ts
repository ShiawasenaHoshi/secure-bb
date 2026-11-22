// The decision journal is a hash chain: every record carries the hash of the previous one,
// so a changed, removed, inserted or reordered record breaks the chain at that place.
//
// What the chain can and cannot show (said plainly on the page and in the README):
//  - it shows edits and deletions made without rewriting everything after them;
//  - the head (last id + hash) is also written to a file next to the database, so a database
//    rolled back to an older copy, or cut at the tail, no longer matches that file;
//  - whoever can write both the database and that file (the same OS user, before stage 3) can
//    rewrite the whole chain consistently. The chain is evidence, not a lock.
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { entryHash, GENESIS, scanChain, type ChainRow, type JournalHead } from "../guard/src/journal-chain.ts";
import type { Db } from "./store.js";

export { entryHash, GENESIS, type JournalHead };

/** Where the head is kept outside the database (a file next to it). */
export interface JournalAnchor {
  read(): JournalHead | null;
  write(head: JournalHead): void;
}

export type ProblemKind =
  | "hash-mismatch" // a record's content no longer matches its hash
  | "prev-mismatch" // a record does not continue the one before it (rows removed, inserted or reordered)
  | "missing-hash" // a record without a hash after the chain began
  | "tail-removed" // ids were handed out that no longer exist
  | "anchor-ahead" // the head file knows a newer record than the database
  | "anchor-mismatch" // the head file names a record that is different in the database
  | "orphan-approval"; // an approval with no approval record in the journal

export interface JournalProblem {
  kind: ProblemKind;
  /** The journal record the problem was found at (null: not tied to one). */
  id: number | null;
  /** For the page only. */
  detail: string;
}
export interface JournalReport {
  ok: boolean;
  entries: number;
  head: JournalHead | null;
  problems: JournalProblem[];
  checkedAt: number;
}

type RawRow = ChainRow;

export function lastHead(db: Db): JournalHead | null {
  const r = db.prepare(`SELECT id, hash FROM log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1`).get() as { id: number; hash: string } | undefined;
  return r ? { id: r.id, hash: r.hash } : null;
}

/** Appends one record to the chain. Synchronous: nothing can interleave between reading the head and writing. */
export function appendRecord(db: Db, ts: number, kind: string, pluginId: string | null, contentHash: string | null, detail: string | null): JournalHead {
  const prev = lastHead(db)?.hash ?? GENESIS;
  const hash = entryHash(prev, ts, kind, pluginId, contentHash, detail);
  const info = db.prepare(`INSERT INTO log (ts, kind, plugin_id, content_hash, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(ts, kind, pluginId, contentHash, detail, prev, hash);
  return { id: Number(info.lastInsertRowid), hash };
}

/**
 * One-time: records that existed before the chain was introduced are chained in id order.
 * Their integrity before this moment cannot be proven, and the page says so.
 */
export function sealLegacy(db: Db): number {
  const rows = db.prepare(`SELECT id, ts, kind, plugin_id, content_hash, detail FROM log WHERE hash IS NULL ORDER BY id`).all() as RawRow[];
  const update = db.prepare(`UPDATE log SET prev_hash = ?, hash = ? WHERE id = ?`);
  let prev = lastHead(db)?.hash ?? GENESIS;
  for (const r of rows) {
    const hash = entryHash(prev, r.ts, r.kind, r.plugin_id, r.content_hash, r.detail);
    update.run(prev, hash, r.id);
    prev = hash;
  }
  return rows.length;
}

export function verifyChain(db: Db, now: number, anchor?: JournalAnchor | null): JournalReport {
  const problems: JournalProblem[] = [];
  const add = (kind: ProblemKind, id: number | null, detail: string) => problems.push({ kind, id, detail });
  const scan = scanChain(db.prepare(`SELECT id, ts, kind, plugin_id, content_hash, detail, prev_hash, hash FROM log ORDER BY id`).iterate() as Iterable<RawRow>);
  for (const b of scan.breaks) {
    if (b.kind === "missing-hash") add("missing-hash", b.id, `запись #${b.id} (${b.recordKind}) без хеша`);
    else if (b.kind === "prev-mismatch") add("prev-mismatch", b.id, `запись #${b.id} не продолжает предыдущую: между ними что-то удалено, вставлено или переставлено`);
    else add("hash-mismatch", b.id, `запись #${b.id} (${b.recordKind}) изменена после записи`);
  }
  const { entries, head, maxId } = scan;

  const seq = db.prepare(`SELECT seq FROM sqlite_sequence WHERE name = 'log'`).get() as { seq: number } | undefined;
  if (seq && seq.seq > maxId) add("tail-removed", null, `выдано записей до #${seq.seq}, последняя сейчас #${maxId}: хвост журнала удалён`);

  const pinned = anchor?.read() ?? null;
  if (pinned) {
    if (head === null || head.id < pinned.id) add("anchor-ahead", pinned.id, `файл головы журнала знает запись #${pinned.id}, а в базе последняя ${head ? `#${head.id}` : "— пусто"}: база откатана или обрезана`);
    else {
      const at = db.prepare(`SELECT hash FROM log WHERE id = ?`).get(pinned.id) as { hash: string | null } | undefined;
      if (!at || at.hash !== pinned.hash) add("anchor-mismatch", pinned.id, `запись #${pinned.id} в базе отличается от той, что запомнил файл головы журнала`);
    }
  }

  // An approval nobody journaled was written to the database directly.
  const orphans = db
    .prepare(
      `SELECT a.id AS id, a.plugin_id AS plugin_id FROM approvals a
       WHERE NOT EXISTS (SELECT 1 FROM log l WHERE l.content_hash = a.content_hash AND l.kind LIKE 'approved.%')`,
    )
    .all() as Array<{ id: number; plugin_id: string }>;
  for (const o of orphans) add("orphan-approval", null, `одобрение #${o.id} плагина ${o.plugin_id} без записи об одобрении в журнале`);

  return { ok: problems.length === 0, entries, head, problems, checkedAt: now };
}

/** The line shown to agents: no record numbers, no kinds of problems. */
export function agentLine(r: JournalReport): string {
  return r.ok ? `journal: ok (${r.entries} entries, head ${r.head ? r.head.hash.slice(0, 12) : "-"})` : `journal: BROKEN (${r.problems.length} problem${r.problems.length === 1 ? "" : "s"}); a human must look at the secure-bb page`;
}

/** The head file: `<id> <hash>`, rewritten atomically after every record. */
export function fileAnchor(path: string): JournalAnchor {
  return {
    read() {
      try {
        const m = /^(\d+) ([0-9a-f]{64})\s*$/.exec(readFileSync(path, "utf8"));
        return m ? { id: Number(m[1]), hash: m[2]! } : null;
      } catch {
        return null;
      }
    },
    write(head) {
      const tmp = `${path}.tmp`;
      writeFileSync(tmp, `${head.id} ${head.hash}\n`, { mode: 0o600 });
      renameSync(tmp, path);
    },
  };
}
