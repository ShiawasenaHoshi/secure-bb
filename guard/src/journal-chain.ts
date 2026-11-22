// The pure part of the decision journal's hash chain, the same for the guard's journal and the plugin's: how a record is hashed, and how rows that were already
// read are walked to find where the chain is broken. No database, no file, no words for the person: each journal keeps its own storage, its own anchor (the head
// file), its own extra checks and its own messages, and turns what this finds into them.
import { createHash } from "node:crypto";

export const GENESIS = "0".repeat(64);

export function entryHash(prev: string, ts: number, kind: string, pluginId: string | null, contentHash: string | null, detail: string | null): string {
  return createHash("sha256").update(JSON.stringify([prev, ts, kind, pluginId, contentHash, detail])).digest("hex");
}

export interface JournalHead {
  id: number;
  hash: string;
}

/** A row as the databases hold it. The hashes are null only in the plugin's journal, for records from before the chain began. */
export interface ChainRow {
  id: number;
  ts: number;
  kind: string;
  plugin_id: string | null;
  content_hash: string | null;
  detail: string | null;
  prev_hash: string | null;
  hash: string | null;
}

export interface ChainBreak {
  /** `missing-hash`: no hash after the chain began; `prev-mismatch`: the row does not continue the one before it; `hash-mismatch`: the row was changed after it was written. */
  kind: "missing-hash" | "prev-mismatch" | "hash-mismatch";
  id: number;
  /** The record's own kind (for the message). */
  recordKind: string;
}

export interface ChainScan {
  entries: number;
  /** The largest id seen (0: no rows). */
  maxId: number;
  /** The last row that has a hash. */
  head: JournalHead | null;
  breaks: ChainBreak[];
}

/** Walks the rows in id order. One edit is reported once, not for every row after it: the walk continues from what is stored. */
export function scanChain(rows: Iterable<ChainRow>): ChainScan {
  const breaks: ChainBreak[] = [];
  let entries = 0;
  let prev = GENESIS;
  let head: JournalHead | null = null;
  let maxId = 0;
  for (const r of rows) {
    entries++;
    maxId = r.id;
    if (r.hash === null || r.prev_hash === null) {
      breaks.push({ kind: "missing-hash", id: r.id, recordKind: r.kind });
      continue; // the chain cannot continue through it: the next record will report a break too
    }
    if (r.prev_hash !== prev) breaks.push({ kind: "prev-mismatch", id: r.id, recordKind: r.kind });
    if (entryHash(r.prev_hash, r.ts, r.kind, r.plugin_id, r.content_hash, r.detail) !== r.hash) breaks.push({ kind: "hash-mismatch", id: r.id, recordKind: r.kind });
    prev = r.hash;
    head = { id: r.id, hash: r.hash };
  }
  return { entries, maxId, head, breaks };
}
