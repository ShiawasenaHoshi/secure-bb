import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { beforeEach, describe, expect, it } from "vitest";
import { Gate, type HookCtx, UNSAFE_DIR_REASON } from "../src/gate.js";
import { GateError } from "../src/errors.js";
import { agentLine, fileAnchor, GENESIS, entryHash } from "../src/journal.js";
import { agentStatusDetail } from "../src/propose.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { base32Decode, hotp, stepAt } from "../guard/src/totp.ts";
import { writableByOthers, serverIds, type PermIssue } from "../src/perms.js";
import { NETWORKED, CLEAN, withFindings } from "./support/checks.js";

class H {
  t = 1_800_000_000_000;
  root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-s5-")));
  snaps = join(this.root, "snapshots");
  db = new Database(":memory:");
  store: Store;
  gate: Gate;
  unsafe: PermIssue[] = [];
  asked: string[] = [];
  next = NETWORKED;
  code!: () => string;
  constructor() {
    mkdirSync(this.snaps);
    for (const stmt of MIGRATIONS) this.db.exec(stmt);
    this.store = new Store(this.db, () => this.t);
    this.gate = new Gate({
      store: this.store,
      now: () => this.t,
      threads: { ancestors: async () => [], descendants: async () => [] },
      thirdPartyRunning: async () => [],
      externalTotpFile: null,
      snapshotsRoot: this.snaps,
      runChecks: async () => this.next,
      unsafeDirs: async (dir) => (this.asked.push(dir), this.unsafe),
    });
  }
  async register(): Promise<void> {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    this.code = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(this.code());
    this.t += 31_000;
  }
  fresh(): string {
    this.t += 31_000;
    return this.code();
  }
}
const ctx = (over: Partial<HookCtx> = {}): HookCtx => ({ pluginId: "demo", version: "1.0.0", source: "path:/dev/demo", sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: "/dev/demo", contentHash: "sha256:aaa", trigger: "install", ...over });

// ---- (1) refuse to install/approve from directories others can write to ---------------------------
describe("directories that someone other than the server's user can write to", () => {
  let h: H;
  beforeEach(async () => {
    h = new H();
    await h.register();
  });

  it("an unsafe directory is held, and no code approves it; the entry says why (for the page only)", async () => {
    h.unsafe = [{ path: "/dev", why: "group-write", where: "parent" }];
    const d = await h.gate.decide(ctx());
    expect(d).toEqual({ action: "wait", reason: "held by secure-bb: review #1" }); // nothing about directories
    const q = h.store.getQueue(1)!;
    expect(q.reason).toContain(UNSAFE_DIR_REASON);
    expect(q.reason).toContain("/dev");
    expect(() => h.gate.approveQueue(1, h.fresh())).toThrow(GateError);
    expect(() => h.gate.approveQueue(1, h.fresh())).toThrow(/others can write/);
    expect(h.store.listApprovals(10)).toHaveLength(0);
    expect(await h.gate.decide(ctx())).toMatchObject({ action: "wait" });
  });

  it("the refusal does not burn a code (the directory is checked before the touch)", async () => {
    h.unsafe = [{ path: "/dev/demo", why: "other-write", where: "dir" }];
    await h.gate.decide(ctx());
    expect(() => h.gate.approveQueue(1, "000000")).toThrow(/others can write/);
    expect(h.store.failuresSince(0)).toBe(0);
  });

  it("once the directory is fixed the same version is looked at again and can be approved", async () => {
    h.unsafe = [{ path: "/dev/demo", why: "group-write", where: "dir" }];
    await h.gate.decide(ctx());
    h.unsafe = [];
    await h.gate.decide(ctx()); // recheck after the fix: the reason is replaced
    expect(h.store.getQueue(1)!.reason ?? "").not.toContain(UNSAFE_DIR_REASON);
    h.gate.approveQueue(1, h.fresh());
    expect(await h.gate.decide(ctx())).toEqual({ action: "proceed" });
  });

  it("our own snapshots are exempt: they are checked by hash, the file system is not asked", async () => {
    h.unsafe = [{ path: "/x", why: "other-write", where: "parent" }];
    const dir = join(h.snaps, "demo", "h1");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), "{}");
    await h.gate.decide(ctx({ rootDir: dir }));
    expect(h.asked).toEqual([]);
  });

  it("afterfact entries (a plugin already loaded) are refused the same way", async () => {
    h.unsafe = [{ path: "/p", why: "owner", where: "dir" }];
    await h.gate.decide(ctx({ trigger: "afterfact" }));
    expect(h.store.getQueue(1)).toMatchObject({ kind: "afterfact", status: "held" });
    expect(() => h.gate.approveQueue(1, h.fresh())).toThrow(/others can write/);
  });

  it("the real check says yes to an owner-only directory and no to a writable one", async () => {
    const ids = serverIds()!;
    const dir = join(h.root, "plug");
    mkdirSync(dir);
    chmodSync(dir, 0o755);
    expect(await writableByOthers(dir, ids)).toEqual([]);
    chmodSync(dir, 0o777);
    expect((await writableByOthers(dir, ids)).map((i) => i.why)).toEqual(["other-write"]);
  });
});

// ---- (2) generic status for agents ------------------------------------------------------------
describe("what an agent is told", () => {
  it("hold, reject and error carry no rule, file or path; reasons are only in the queue and the log for the page", async () => {
    const h = new H();
    h.next = withFindings([{ rule: "decode-eval", severity: "block", file: "src/secret-path.ts", line: 9, excerpt: "eval(atob(x))" }]);
    const dir = join(h.snaps, "demo", "h1");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), "{}");
    const rejected = await h.gate.decide(ctx({ rootDir: dir }));
    expect(rejected).toEqual({ action: "reject", message: "rejected by secure-bb: review #1" });
    expect(JSON.stringify(rejected)).not.toMatch(/decode|secret-path|eval|заблокировано/);
    h.next = NETWORKED;
    const held = await h.gate.decide(ctx({ contentHash: "sha256:bbb", rootDir: dir }));
    expect(held).toEqual({ action: "wait", reason: expect.stringMatching(/^held by secure-bb: review #\d+$/) });
    // ...and the human has the details
    expect(h.store.getQueue(1)!.reason).toContain("decode-eval src/secret-path.ts:9");
  });

  it("an internal error is just 'held by secure-bb'", async () => {
    const h = new H();
    h.store.activeApproval = () => {
      throw new Error("db at /private/path exploded");
    };
    const d = await h.gate.decide(ctx());
    expect(d).toEqual({ action: "wait", reason: "held by secure-bb" });
  });

  it("whatever the core's statusDetail says, the agent sees at most 'held/rejected by secure-bb: review #N'", () => {
    expect(agentStatusDetail('waiting for activation guard "secure-bb"')).toBe("held by secure-bb");
    expect(agentStatusDetail("held by secure-bb: review #4")).toBe("held by secure-bb: review #4");
    expect(agentStatusDetail("rejected by secure-bb: review #7 because of /etc/passwd")).toBe("rejected by secure-bb: review #7");
    expect(agentStatusDetail("held by secure-bb: каталог доступен на запись другим: /Users/x (review #3)")).toBe("held by secure-bb: review #3");
    expect(agentStatusDetail("Build failed")).toBeNull();
    expect(agentStatusDetail(null)).toBeNull();
  });
});

// ---- (4) the journal is a hash chain ------------------------------------------------------------
describe("the decision journal is a hash chain", () => {
  let h: H;
  beforeEach(() => {
    h = new H();
    for (let i = 0; i < 5; i++) h.store.log(`k${i}`, "demo", `sha256:${i}`, { n: i });
  });
  const ids = () => (h.db.prepare(`SELECT id FROM log ORDER BY id`).all() as Array<{ id: number }>).map((r) => r.id);

  it("each record holds the hash of the previous; an untouched journal verifies", () => {
    const rows = h.db.prepare(`SELECT * FROM log ORDER BY id`).all() as Array<{ prev_hash: string; hash: string; ts: number; kind: string; plugin_id: string; content_hash: string; detail: string }>;
    expect(rows[0]!.prev_hash).toBe(GENESIS);
    for (let i = 1; i < rows.length; i++) expect(rows[i]!.prev_hash).toBe(rows[i - 1]!.hash);
    expect(rows[2]!.hash).toBe(entryHash(rows[2]!.prev_hash, rows[2]!.ts, rows[2]!.kind, rows[2]!.plugin_id, rows[2]!.content_hash, rows[2]!.detail));
    const r = h.store.verifyJournal();
    expect(r).toMatchObject({ ok: true, entries: 5, problems: [] });
    expect(agentLine(r)).toMatch(/^journal: ok \(5 entries, head [0-9a-f]{12}\)$/);
  });

  it("an edited record breaks the chain at that record", () => {
    h.db.prepare(`UPDATE log SET detail = '{"n":99}' WHERE id = ?`).run(ids()[2]);
    const r = h.store.verifyJournal();
    expect(r.ok).toBe(false);
    expect(r.problems).toEqual([expect.objectContaining({ kind: "hash-mismatch", id: ids()[2] })]);
    expect(agentLine(r)).toBe("journal: BROKEN (1 problem); a human must look at the secure-bb page");
    expect(agentLine(r)).not.toMatch(/hash-mismatch|#\d/); // no oracle for agents
  });

  it("a removed record from the middle breaks the chain where it was", () => {
    h.db.prepare(`DELETE FROM log WHERE id = ?`).run(ids()[2]);
    const r = h.store.verifyJournal();
    expect(r.ok).toBe(false);
    expect(r.problems.map((p) => p.kind)).toEqual(["prev-mismatch"]);
    expect(r.problems[0]!.id).toBe(ids()[2]); // the record after the gap no longer continues its predecessor
  });

  it("removed records at the head, a reordered pair, and an inserted forgery are all caught", () => {
    h.db.prepare(`DELETE FROM log WHERE id = ?`).run(ids()[0]);
    expect(h.store.verifyJournal().problems.map((p) => p.kind)).toContain("prev-mismatch");

    const g = new H();
    for (let i = 0; i < 3; i++) g.store.log(`k${i}`, null, null);
    g.db.prepare(`INSERT INTO log (ts, kind, plugin_id, content_hash, detail, prev_hash, hash) VALUES (1, 'approved.touch', 'evil', 'sha256:evil', NULL, ?, ?)`).run("f".repeat(64), "e".repeat(64));
    expect(g.store.verifyJournal().ok).toBe(false);
    const n = new H();
    n.store.log("a", null, null);
    n.db.prepare(`INSERT INTO log (ts, kind) VALUES (1, 'approved.touch')`).run(); // no hash at all
    expect(n.store.verifyJournal().problems.map((p) => p.kind)).toContain("missing-hash");
  });

  it("a removed tail is caught by the id counter, even with nothing after it to disagree", () => {
    h.db.prepare(`DELETE FROM log WHERE id = ?`).run(ids()[4]);
    expect(h.store.verifyJournal().problems.map((p) => p.kind)).toEqual(["tail-removed"]);
  });

  it("an approval written straight into the database, with no journal record, is an alarm", () => {
    h.store.addApproval({ contentHash: "sha256:sneaky", pluginId: "evil", version: "1", source: "x", sourceKind: "path", gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, threadId: null });
    const r = h.store.verifyJournal();
    expect(r.ok).toBe(false);
    expect(r.problems).toEqual([expect.objectContaining({ kind: "orphan-approval" })]);
    h.store.log("approved.touch", "evil", "sha256:sneaky", {}); // a real approval is journaled by the gate
    expect(h.store.verifyJournal().ok).toBe(true);
  });

  it("the head file notices a database rolled back to an older copy", () => {
    const file = join(h.root, "journal.head");
    const anchored = new Store(h.db, () => h.t, fileAnchor(file));
    anchored.log("after-anchor", null, null);
    const head = readFileSync(file, "utf8").trim().split(" ");
    expect(Number(head[0])).toBe(ids().at(-1));
    expect(anchored.verifyJournal().ok).toBe(true);
    // roll the database back by two records (and keep the counter consistent, as a restored backup would)
    h.db.prepare(`DELETE FROM log WHERE id > ?`).run(ids().at(-3)!);
    h.db.prepare(`UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM log) WHERE name = 'log'`).run();
    const r = anchored.verifyJournal();
    expect(r.ok).toBe(false);
    expect(r.problems.map((p) => p.kind)).toEqual(["anchor-ahead"]);
  });

  it("the head file also catches a record rewritten consistently (the whole chain recomputed)", () => {
    const file = join(h.root, "journal.head");
    const anchored = new Store(h.db, () => h.t, fileAnchor(file));
    anchored.log("last", null, null);
    // rewrite record #2 and recompute every hash after it: the chain is internally consistent again...
    const rows = h.db.prepare(`SELECT * FROM log ORDER BY id`).all() as Array<{ id: number; ts: number; kind: string; plugin_id: string | null; content_hash: string | null; detail: string | null }>;
    let prev = GENESIS;
    for (const r of rows) {
      const detail = r.id === 2 ? '{"forged":true}' : r.detail;
      const hash = entryHash(prev, r.ts, r.kind, r.plugin_id, r.content_hash, detail);
      h.db.prepare(`UPDATE log SET detail = ?, prev_hash = ?, hash = ? WHERE id = ?`).run(detail, prev, hash, r.id);
      prev = hash;
    }
    const r = anchored.verifyJournal();
    // ...but the head the file remembered is no longer what the database holds
    expect(r.problems.map((p) => p.kind)).toEqual(["anchor-mismatch"]);
  });

  it("records that existed before the chain are sealed once, and a record added behind the back is not", () => {
    const db = new Database(":memory:");
    for (const stmt of MIGRATIONS) db.exec(stmt);
    for (let i = 0; i < 3; i++) db.prepare(`INSERT INTO log (ts, kind, plugin_id, content_hash, detail) VALUES (?, 'old', NULL, NULL, NULL)`).run(i);
    const s = new Store(db, () => 1);
    expect(s.journalSealedLegacy()).toBe(3);
    expect(s.verifyJournal()).toMatchObject({ ok: true, entries: 3 });
    // a restart does not seal again: a record inserted without a hash stays a problem
    db.prepare(`INSERT INTO log (ts, kind) VALUES (9, 'planted')`).run();
    const again = new Store(db, () => 2);
    expect(again.verifyJournal().problems.map((p) => p.kind)).toContain("missing-hash");
  });

  it("the gate's own decisions are what is chained (approve → journal → verifies)", async () => {
    const g = new H();
    await g.register();
    await g.gate.decide(ctx());
    g.gate.approveQueue(1, g.fresh());
    expect(g.store.verifyJournal()).toMatchObject({ ok: true });
    expect(g.store.listLog(20).some((l) => l.kind === "approved.touch")).toBe(true);
    void CLEAN;
  });
});
