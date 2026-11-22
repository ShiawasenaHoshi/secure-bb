// The handle of the plugin's SQLite database. A leaf module: the store and the modules that keep their own tables (journal, skills, sentinel) all name it,
// and none of them has to import the store for that.
import type BetterSqlite3 from "better-sqlite3";

export type Db = BetterSqlite3.Database;
