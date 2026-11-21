// The guard's journal: a hash chain. Every record carries the hash of the one before it, so a changed,
// removed, inserted or reordered record breaks the chain at that place. The head (last id + hash) is also
// kept in a separate file: a database rolled back to an older copy, or cut at the tail, no longer matches it.
//
// What this proves and what it does not: it shows edits and deletions made without rewriting everything
// after them. Whoever can write both files (the guard's own user, or root) can rewrite the whole chain.
// It is evidence for the owner, not a lock; the lock is that the files belong to a user bb does not run as.
import { createHash } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import type { DatabaseSync } from "node:sqlite";

export const GENESIS = "0".repeat(64);

export function entryHash(prev: string, ts: number, kind: string, pluginId: string | null, contentHash: string | null, detail: string | null): string {
  return createHash("sha256").update(JSON.stringify([prev, ts, kind, pluginId, contentHash, detail])).digest("hex");
}

export interface JournalHead {
  id: number;
  hash: string;
}

export type ProblemKind =
  | "hash-mismatch" // a record no longer matches its hash
  | "prev-mismatch" // a record does not continue the one before it
  | "tail-removed" // ids were handed out that no longer exist
  | "anchor-missing" // the database has records but the head file is gone
  | "anchor-ahead" // the head file knows a newer record than the database
  | "anchor-mismatch" // the head file names a record that is different in the database
  | "orphan-approval"; // an approval with no approval record in the journal

export interface JournalProblem {
  kind: ProblemKind;
  id: number | null;
  detail: string;
}
export interface JournalReport {
  ok: boolean;
  entries: number;
  head: JournalHead | null;
  problems: JournalProblem[];
}

interface Row {
  id: number;
  ts: number;
  kind: string;
  plugin_id: string | null;
  content_hash: string | null;
  detail: string | null;
  prev_hash: string;
  hash: string;
}

export function readHead(db: DatabaseSync): JournalHead | null {
  const r = db.prepare(`SELECT id, hash FROM journal ORDER BY id DESC LIMIT 1`).get() as { id: number; hash: string } | undefined;
  return r ? { id: r.id, hash: r.hash } : null;
}

/** Appends one record. Synchronous, and the caller holds the transaction: nothing interleaves between reading the head and writing. */
export function append(db: DatabaseSync, ts: number, kind: string, pluginId: string | null, contentHash: string | null, detail: Record<string, unknown> | null): JournalHead {
  const prev = readHead(db)?.hash ?? GENESIS;
  const text = detail === null ? null : JSON.stringify(detail);
  const hash = entryHash(prev, ts, kind, pluginId, contentHash, text);
  const info = db.prepare(`INSERT INTO journal (ts, kind, plugin_id, content_hash, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(ts, kind, pluginId, contentHash, text, prev, hash);
  return { id: Number(info.lastInsertRowid), hash };
}

/** `<id> <hash>`, rewritten atomically. */
export class HeadFile {
  readonly path: string;
  constructor(path: string) {
    this.path = path;
  }
  read(): JournalHead | null {
    try {
      const m = /^(\d+) ([0-9a-f]{64})\s*$/.exec(readFileSync(this.path, "utf8"));
      return m ? { id: Number(m[1]), hash: m[2]! } : null;
    } catch {
      return null;
    }
  }
  write(head: JournalHead): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, `${head.id} ${head.hash}\n`, { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}

export function verify(db: DatabaseSync, anchor: HeadFile): JournalReport {
  const problems: JournalProblem[] = [];
  const add = (kind: ProblemKind, id: number | null, detail: string) => problems.push({ kind, id, detail });
  let entries = 0;
  let prev = GENESIS;
  let head: JournalHead | null = null;
  let maxId = 0;
  for (const r of db.prepare(`SELECT id, ts, kind, plugin_id, content_hash, detail, prev_hash, hash FROM journal ORDER BY id`).iterate() as Iterable<unknown> as Iterable<Row>) {
    entries++;
    maxId = r.id;
    if (r.prev_hash !== prev) add("prev-mismatch", r.id, `record #${r.id} does not continue the one before it: something was removed, inserted or reordered`);
    if (entryHash(r.prev_hash, r.ts, r.kind, r.plugin_id, r.content_hash, r.detail) !== r.hash) add("hash-mismatch", r.id, `record #${r.id} (${r.kind}) was changed after it was written`);
    prev = r.hash; // continue from what is stored: one edit is reported once, not for every record after it
    head = { id: r.id, hash: r.hash };
  }
  const seq = db.prepare(`SELECT seq FROM sqlite_sequence WHERE name = 'journal'`).get() as { seq: number } | undefined;
  if (seq && seq.seq > maxId) add("tail-removed", null, `records were issued up to #${seq.seq}, the last one now is #${maxId}: the tail was removed`);

  const pinned = anchor.read();
  if (pinned === null) {
    if (head !== null) add("anchor-missing", null, "the head file is missing or unreadable although the journal has records");
  } else if (head === null || head.id < pinned.id) {
    add("anchor-ahead", pinned.id, `the head file knows record #${pinned.id}, the database ends at ${head ? `#${head.id}` : "nothing"}: the database was rolled back or cut`);
  } else {
    const at = db.prepare(`SELECT hash FROM journal WHERE id = ?`).get(pinned.id) as { hash: string } | undefined;
    if (!at || at.hash !== pinned.hash) add("anchor-mismatch", pinned.id, `record #${pinned.id} in the database differs from the one the head file remembers`);
  }

  // An approval nobody journaled was written to the database directly.
  const orphans = db
    .prepare(
      `SELECT a.id AS id, a.plugin_id AS plugin_id FROM approvals a
       WHERE NOT EXISTS (SELECT 1 FROM journal j WHERE j.content_hash = a.content_hash AND j.kind LIKE 'approved.%')`,
    )
    .all() as Array<{ id: number; plugin_id: string }>;
  for (const o of orphans) add("orphan-approval", null, `approval #${o.id} of ${o.plugin_id} has no approval record in the journal`);

  return { ok: problems.length === 0, entries, head, problems };
}
