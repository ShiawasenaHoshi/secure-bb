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
  // Passkeys. A key is 'pending' from the moment the page registers it until the person at the console confirms it (then 'active'); 'removed' stays for the record.
  `CREATE TABLE passkeys (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     credential_id TEXT NOT NULL UNIQUE,
     public_key TEXT NOT NULL,
     label TEXT NOT NULL,
     aaguid TEXT NOT NULL,
     fingerprint TEXT NOT NULL,
     sign_count INTEGER NOT NULL DEFAULT 0,
     state TEXT NOT NULL,
     enrollment_id INTEGER,
     created_at INTEGER NOT NULL,
     confirmed_at INTEGER,
     last_used_at INTEGER,
     removed_at INTEGER)`,
  // The registration window the console opens: one at a time, a one-time token (only its digest is kept), five wrong tokens close it.
  `CREATE TABLE enrollments (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     token_digest TEXT NOT NULL,
     label TEXT NOT NULL,
     user_handle TEXT NOT NULL,
     opened_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     fails INTEGER NOT NULL DEFAULT 0,
     state TEXT NOT NULL)`,
  // A challenge is bound to what it was issued for: an action (its normalized JSON) or an enrollment. Used once, valid for two minutes.
  `CREATE TABLE challenges (
     nonce TEXT PRIMARY KEY,
     kind TEXT NOT NULL,
     action_json TEXT,
     enrollment_id INTEGER,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     used INTEGER NOT NULL DEFAULT 0)`,
  // Agent watch: the accepted baseline (what a human took as it should be) and the differences from it. A difference is tied to the exact
  // content it was found with (new_sha): when the file changes again, that difference is superseded by a new one, so a touch is always
  // for what the person saw. The content is kept for the diff and for accepting; only the guard reads it (answers carry a masked diff).
  `CREATE TABLE agent_baseline (
     path TEXT PRIMARY KEY,
     root TEXT NOT NULL,
     rel TEXT NOT NULL,
     kind TEXT NOT NULL,
     sha256 TEXT NOT NULL,
     size INTEGER NOT NULL,
     content TEXT,
     accepted_at INTEGER NOT NULL)`,
  `CREATE TABLE agent_drifts (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     path TEXT NOT NULL,
     root TEXT NOT NULL,
     root_kind TEXT NOT NULL,
     rel TEXT NOT NULL,
     kind TEXT NOT NULL,
     change TEXT NOT NULL,
     class TEXT NOT NULL,
     reasons TEXT NOT NULL,
     findings TEXT NOT NULL,
     old_sha TEXT,
     new_sha TEXT,
     new_size INTEGER,
     new_mtime INTEGER,
     diff TEXT NOT NULL,
     new_content TEXT,
     initial INTEGER NOT NULL DEFAULT 0,
     status TEXT NOT NULL,
     first_seen INTEGER NOT NULL,
     last_seen INTEGER NOT NULL,
     resolved_at INTEGER)`,
  `CREATE INDEX agent_drifts_status ON agent_drifts (status, path)`,
  // Trust by source and rights (UX v1, PR 1). `rights`: what the guard itself found in the version's directory (JSON: capability tokens and review rules),
  // kept with the approval as the baseline a later version of the same source is compared with; `source_id`: the source the approval is from
  // (`github:owner/name` or `path:/dir`; null for sources the lists cannot name). `note` in the queue: why a version did not pass by itself.
  `ALTER TABLE approvals ADD COLUMN rights TEXT`,
  `ALTER TABLE approvals ADD COLUMN source_id TEXT`,
  `ALTER TABLE queue ADD COLUMN rights TEXT`,
  `ALTER TABLE queue ADD COLUMN note TEXT`,
  `CREATE INDEX approvals_baseline ON approvals (plugin_id, source_id)`,
  // UX v1, PR 3. Wrong codes and wrong signatures are counted apart (a signature cannot be guessed, so a process that spams wrong ones must not
  // be able to take the owner's codes, and the other way round): `kind` is 'code' (codes and session tokens) or 'passkey'.
  `ALTER TABLE attempts ADD COLUMN kind TEXT NOT NULL DEFAULT 'code'`,
  // Approval sessions: one touch opens one; only the SHA-256 of its token is kept here (the token lives in the memory of the page).
  `CREATE TABLE sessions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     token_hash TEXT NOT NULL UNIQUE,
     opened_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     hard_expires_at INTEGER NOT NULL,
     closed_at INTEGER,
     closed_reason TEXT,
     uses INTEGER NOT NULL DEFAULT 0)`,
  // A list for one touch, fixed here BEFORE the touch: the touch names only the list's id and hash, never its items.
  `CREATE TABLE batches (
     id TEXT PRIMARY KEY,
     set_hash TEXT NOT NULL,
     items TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     used_at INTEGER)`,
  // Pilot round 2: «Это не я — отклонить». A rejected difference stays open (the alarm and the pollution stay until the file is fixed) and never goes into the baseline.
  `ALTER TABLE agent_drifts ADD COLUMN rejected_at INTEGER`,
  // Why a version was let in, in the guard's own words (the version history shows it: «прошла сама: свой источник, права те же» / «касанием: новое право …»).
  `ALTER TABLE approvals ADD COLUMN why TEXT`,
  // Parts of settings files the owner kept («Оставить»): the list of exceptions shows them and takes each back («Отозвать») without a code (tightening).
  `CREATE TABLE agent_kept (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     path TEXT NOT NULL,
     rel TEXT NOT NULL,
     part TEXT NOT NULL,
     danger TEXT,
     kept_at INTEGER NOT NULL,
     revoked_at INTEGER)`,
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
