// The guard's own SQLite, through node:sqlite (built into Node: no native module, no dependency).
// Why a database and not a JSON file: an approval, its queue entry and its journal record must
// change together or not at all, and a crash in the middle of a JSON rewrite would lose or tear them.
// SQLite gives that with one transaction; the amounts are small, so the cost is nothing.
import { chmodSync, mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

/** Append-only: never edit a shipped statement, only push new ones. */
export const MIGRATIONS: string[] = [
  `CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE attempts (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     ts INTEGER NOT NULL,
     ok INTEGER NOT NULL,
     purpose TEXT NOT NULL)`,
  `CREATE TABLE approvals (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     content_hash TEXT NOT NULL,
     plugin_id TEXT NOT NULL,
     version TEXT NOT NULL,
     source TEXT NOT NULL,
     source_kind TEXT NOT NULL,
     git_commit TEXT,
     npm_integrity TEXT,
     via TEXT NOT NULL,
     window_id INTEGER,
     approved_at INTEGER NOT NULL,
     revoked_at INTEGER)`,
  `CREATE INDEX approvals_hash ON approvals (content_hash)`,
  `CREATE TABLE queue (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     content_hash TEXT NOT NULL,
     plugin_id TEXT NOT NULL,
     version TEXT NOT NULL,
     source TEXT NOT NULL,
     source_kind TEXT NOT NULL,
     root_dir TEXT NOT NULL,
     trigger TEXT NOT NULL,
     status TEXT NOT NULL,
     first_seen INTEGER NOT NULL,
     last_seen INTEGER NOT NULL,
     seen_count INTEGER NOT NULL DEFAULT 1)`,
  `CREATE INDEX queue_hash ON queue (content_hash)`,
  `CREATE TABLE annotations (
     content_hash TEXT PRIMARY KEY,
     ts INTEGER NOT NULL,
     findings TEXT NOT NULL)`,
  `CREATE TABLE windows (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     plugin_id TEXT NOT NULL,
     size_sec INTEGER NOT NULL,
     cap_sec INTEGER NOT NULL,
     mode TEXT NOT NULL,
     opened_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     hard_expires_at INTEGER NOT NULL,
     closed_at INTEGER,
     closed_reason TEXT,
     uses INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE journal (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     ts INTEGER NOT NULL,
     kind TEXT NOT NULL,
     plugin_id TEXT,
     content_hash TEXT,
     detail TEXT,
     prev_hash TEXT NOT NULL,
     hash TEXT NOT NULL)`,
  // A hold that a window does not lift: the plugin's hook stopped this version for its own reasons (a new capability, a tainted tree).
  `ALTER TABLE queue ADD COLUMN stop INTEGER NOT NULL DEFAULT 0`,
];

export function openDb(path: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA synchronous = FULL");
  db.exec("PRAGMA busy_timeout = 5000");
  const row = db.prepare("PRAGMA user_version").get() as { user_version: number };
  for (let v = row.user_version; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.exec(`PRAGMA user_version = ${v + 1}`);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      chmodSync(path + suffix, 0o600);
    } catch {
      /* the side files exist only while the database is in use */
    }
  }
  return db;
}

/** Creates a directory only its owner can enter. */
export function privateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}
