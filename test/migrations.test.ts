// Released migrations are never changed, reordered or inserted into: a database made by an older release records each migration by its
// index and the SHA-256 of its text, and bb's core refuses to load the plugin when an index no longer matches
// («migration N does not match the recorded statement»). Docker test beds start from an empty database and cannot catch this.
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterEach, describe, expect, it } from "vitest";
import { MIGRATIONS as GUARD_MIGRATIONS, openDb } from "../guard/src/db.js";
import { MIGRATIONS as PLUGIN_MIGRATIONS, Store } from "../src/store.js";

const fixture = <T>(name: string): T => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8")) as T;
const PINNED = fixture<{ plugin: string[]; guard: string[] }>("migration-hashes.json");
/** The texts the plugin and the guard had at afe6479: a database made then must still open. */
const AFE6479 = fixture<{ plugin: string[]; guard: string[] }>("migrations-afe6479.json");
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const RULE = "миграции только дописываются в конец";

function prefixCheck(name: string, current: string[], pinned: string[]): void {
  const got = current.map(sha);
  for (let i = 0; i < pinned.length; i++) {
    if (got[i] !== pinned[i]) throw new Error(`${RULE}: ${name} migration ${i} differs from the released one (changed, inserted before it, or removed)`);
  }
}

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("released migrations are append-only", () => {
  it("plugin MIGRATIONS start with the pinned hashes, byte for byte", () => {
    expect(() => prefixCheck("plugin", PLUGIN_MIGRATIONS, PINNED.plugin)).not.toThrow();
    expect(PLUGIN_MIGRATIONS.length).toBeGreaterThanOrEqual(PINNED.plugin.length);
  });
  it("guard MIGRATIONS start with the pinned hashes, byte for byte", () => {
    expect(() => prefixCheck("guard", GUARD_MIGRATIONS, PINNED.guard)).not.toThrow();
    expect(GUARD_MIGRATIONS.length).toBeGreaterThanOrEqual(PINNED.guard.length);
  });
  it("what afe6479 shipped is part of the pinned prefix", () => {
    expect(AFE6479.plugin.map(sha)).toEqual(PINNED.plugin.slice(0, AFE6479.plugin.length));
    expect(AFE6479.guard.map(sha)).toEqual(PINNED.guard.slice(0, AFE6479.guard.length));
  });
  it("the check fails on an edit, an insertion in the middle and a removal, with the rule in the message", () => {
    const edited = PLUGIN_MIGRATIONS.slice();
    edited[3] = edited[3] + " ";
    expect(() => prefixCheck("plugin", edited, PINNED.plugin)).toThrow(RULE);
    const inserted = PLUGIN_MIGRATIONS.slice();
    inserted.splice(19, 0, "CREATE TABLE IF NOT EXISTS x (a)");
    expect(() => prefixCheck("plugin", inserted, PINNED.plugin)).toThrow(RULE);
    expect(() => prefixCheck("guard", GUARD_MIGRATIONS.slice(1), PINNED.guard)).toThrow(RULE);
  });
  it("appending to the end is allowed", () => {
    expect(() => prefixCheck("plugin", [...PLUGIN_MIGRATIONS, "CREATE TABLE IF NOT EXISTS later (a)"], PINNED.plugin)).not.toThrow();
  });
});

describe("a database made by afe6479 opens with the current code", () => {
  it("plugin: bb's own storage.migrate accepts the recorded statements and applies the missing ones", () => {
    const { bb } = createFakePluginHost();
    const db = bb.storage.database();
    bb.storage.migrate(db, AFE6479.plugin); // what the stand's database looks like
    expect(db.prepare("SELECT name FROM sqlite_master WHERE name = 'integrity_cache'").get()).toBeUndefined();
    expect(() => bb.storage.migrate(db, PLUGIN_MIGRATIONS)).not.toThrow();
    expect(db.prepare("SELECT name FROM sqlite_master WHERE name = 'integrity_cache'").get()).toBeTruthy();
    const store = new Store(db as never, () => 1);
    store.putManifest("pkg@1", { "index.js": "abc" });
    expect(store.getManifest("pkg@1")).toEqual({ "index.js": "abc" });
  });
  it("plugin: the order that broke the stand (integrity_cache before scans) is refused by the core check", () => {
    const { bb } = createFakePluginHost();
    const db = bb.storage.database();
    bb.storage.migrate(db, AFE6479.plugin);
    const broken = PLUGIN_MIGRATIONS.slice();
    const at = broken.findIndex((s) => s.includes("integrity_cache"));
    const [integrity] = broken.splice(at, 1);
    broken.splice(19, 0, integrity!);
    expect(() => bb.storage.migrate(db, broken)).toThrow(/migration 19 does not match the recorded statement/);
  });
  it("guard: a database at the afe6479 version opens and gets the missing migrations", () => {
    const dir = mkdtempSync(join(tmpdir(), "sbb-mig-"));
    dirs.push(dir);
    const path = join(dir, "guard.db");
    const old = new DatabaseSync(path);
    AFE6479.guard.forEach((s) => old.exec(s));
    old.exec(`PRAGMA user_version = ${AFE6479.guard.length}`);
    old.close();
    const db = openDb(path);
    expect((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version).toBe(GUARD_MIGRATIONS.length);
    expect(db.prepare("SELECT name FROM sqlite_master WHERE name = 'agent_kept'").get()).toBeTruthy();
    db.close();
  });
  it("guard: the text recorded for every old index equals the current one (the equivalent of the core check)", () => {
    AFE6479.guard.forEach((s, i) => expect(GUARD_MIGRATIONS[i], `guard migration ${i}`).toBe(s));
  });
});
