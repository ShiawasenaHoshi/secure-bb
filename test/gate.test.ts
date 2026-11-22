import { mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { beforeEach, describe, expect, it } from "vitest";
import { Gate, type HookCtx } from "../src/gate.js";
import { GateError } from "../src/errors.js";
import type { ThreadTree } from "../src/thread-tree.js";
import { NETWORKED } from "./support/checks.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { base32Decode, base32Encode, hotp, stepAt, verifyTotp } from "../guard/src/totp.ts";
import { findEscapingSymlinks, hashTree, isInside, isInsideSnapshots } from "../src/tree.js";

class Harness {
  t = 1_800_000_000_000;
  store: Store;
  gate: Gate;
  running: string[] = [];
  /** child thread -> parent thread */
  parents = new Map<string, string>();
  root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-gate-")));
  snaps = join(this.root, "snapshots");
  externalFile: string | null = null;
  constructor() {
    mkdirSync(this.snaps);
    const db = new Database(":memory:");
    for (const stmt of MIGRATIONS) db.exec(stmt);
    this.store = new Store(db, () => this.t);
    const threads: ThreadTree = {
      ancestors: async (id) => {
        const out: string[] = [];
        for (let cur = this.parents.get(id); cur; cur = this.parents.get(cur)) out.push(cur);
        return out;
      },
      descendants: async (id) => [...this.parents.keys()].filter((c) => this.parents.get(c) === id),
    };
    this.gate = new Gate({
      store: this.store,
      now: () => this.t,
      threads,
      thirdPartyRunning: async () => this.running,
      externalTotpFile: this.externalFile,
      snapshotsRoot: this.snaps, unsafeDirs: async () => [],
      runChecks: async () => NETWORKED,
    });
  }
  /** Registers a TOTP secret (from the page) and returns a code generator. */
  async register(): Promise<() => string> {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    const code = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(code());
    this.t += 31_000; // next step so the next code is fresh
    return code;
  }
  next(): void {
    this.t += 31_000;
  }
  /** A real snapshot directory plus its proposal row, as `propose` would leave them. */
  async snapshot(n: number, thread: string | null, files: Record<string, string> = {}) {
    const dir = join(this.snaps, "demo", `h${n}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: `1.0.${n}` }));
    writeFileSync(join(dir, "server.ts"), `export default () => ${n};\n`);
    for (const [f, body] of Object.entries(files)) {
      mkdirSync(join(dir, f, ".."), { recursive: true });
      writeFileSync(join(dir, f), body);
    }
    const w = await this.gate.windowCovering("demo", thread);
    const proposal = this.store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: thread, windowId: w?.id ?? null });
    return { dir, proposal };
  }
}

const ctx = (over: Partial<HookCtx> = {}): HookCtx => ({
  pluginId: "demo",
  version: "1.0.0",
  source: "path:/x",
  sourceKind: "path",
  gitCommit: null,
  npmIntegrity: null,
  rootDir: "/elsewhere/demo",
  contentHash: "sha256:aaa",
  trigger: "install",
  ...over,
});
const snapCtx = (dir: string, n: number, core = `sha256:v${n}`): HookCtx => ctx({ rootDir: dir, contentHash: core, version: `1.0.${n}` });

describe("totp", () => {
  it("matches RFC 6238 test vectors (SHA-1, 6 digits)", () => {
    const secret = Buffer.from("12345678901234567890");
    expect(hotp(secret, Math.floor(59 / 30))).toBe("287082");
    expect(hotp(secret, Math.floor(1111111109 / 30))).toBe("081804");
    expect(hotp(secret, Math.floor(20000000000 / 30))).toBe("353130");
  });
  it("round-trips base32", () => {
    const bytes = Buffer.from("hello secure bb!");
    expect(base32Decode(base32Encode(bytes)).equals(bytes)).toBe(true);
  });
  it("accepts ±1 step, rejects ±2 and replays", () => {
    const secretB32 = base32Encode(Buffer.from("12345678901234567890"));
    const now = 1_800_000_000_000;
    const step = stepAt(now);
    const secret = base32Decode(secretB32);
    expect(verifyTotp(secretB32, hotp(secret, step - 1), now, 0).ok).toBe(true);
    expect(verifyTotp(secretB32, hotp(secret, step + 1), now, 0).ok).toBe(true);
    expect(verifyTotp(secretB32, hotp(secret, step + 2), now, 0).ok).toBe(false);
    expect(verifyTotp(secretB32, hotp(secret, step - 2), now, 0).ok).toBe(false);
    expect(verifyTotp(secretB32, hotp(secret, step), now, step).ok).toBe(false);
    expect(verifyTotp(secretB32, "12345", now, 0).ok).toBe(false);
  });
});

describe("hook decisions", () => {
  let h: Harness;
  beforeEach(() => {
    h = new Harness();
  });

  it("holds an unknown hash with a short, reason-free status and queues it once", async () => {
    const a = await h.gate.decide(ctx());
    const b = await h.gate.decide(ctx());
    expect(a).toEqual({ action: "wait", reason: "held by secure-bb: review #1" });
    expect(b).toEqual(a);
    expect(h.store.listQueue()).toHaveLength(1);
  });

  it("proceeds immediately for an approved hash", async () => {
    const code = await h.register();
    await h.gate.decide(ctx());
    h.gate.approveQueue(1, code());
    expect(await h.gate.decide(ctx())).toEqual({ action: "proceed" });
    expect(h.store.listQueue()[0]!.status).toBe("approved");
  });

  it("holds again when a single byte (the hash) changes", async () => {
    const code = await h.register();
    await h.gate.decide(ctx());
    h.gate.approveQueue(1, code());
    expect((await h.gate.decide(ctx({ contentHash: "sha256:bbb" }))).action).toBe("wait");
  });

  it("holds after the approval is revoked", async () => {
    const code = await h.register();
    await h.gate.decide(ctx());
    h.gate.approveQueue(1, code());
    h.next();
    h.gate.revoke(h.store.listApprovals()[0]!.id);
    expect((await h.gate.decide(ctx())).action).toBe("wait");
  });

  it("fails closed on an internal error", async () => {
    h.store.db.exec("DROP TABLE queue");
    expect((await h.gate.decide(ctx())).action).toBe("wait");
  });
});

describe("touch", () => {
  let h: Harness;
  beforeEach(() => {
    h = new Harness();
  });

  it("refuses everything until a second factor is registered", async () => {
    await h.gate.decide(ctx());
    expect(() => h.gate.approveQueue(1, "123456")).toThrow(/no second factor/);
  });

  it("rejects a wrong code and a reused code", async () => {
    const code = await h.register();
    await h.gate.decide(ctx());
    await h.gate.decide(ctx({ contentHash: "sha256:bbb" }));
    expect(() => h.gate.approveQueue(1, "000000")).toThrow(GateError);
    const good = code();
    h.gate.approveQueue(1, good);
    expect(() => h.gate.approveQueue(2, good)).toThrow(/invalid or already used/);
    h.next();
    h.gate.approveQueue(2, code());
  });

  it("blocks approvals for an hour after 5 wrong codes", async () => {
    const code = await h.register();
    await h.gate.decide(ctx());
    for (let i = 0; i < 5; i++) expect(() => h.gate.approveQueue(1, "000000")).toThrow(/invalid/);
    h.next();
    expect(() => h.gate.approveQueue(1, code())).toThrow(/blocked/);
    h.t += 3_600_000;
    h.gate.approveQueue(1, code());
  });

  it("locks the secret after the first valid code and never offers it again", async () => {
    await h.register();
    expect(h.gate.totpState()).toBe("locked");
    await expect(h.gate.beginRegistration({ attended: true, caller: "t" })).rejects.toThrow(/cannot be shown again/);
  });

  it("refuses to register while a third-party plugin is running", async () => {
    h.running = ["somebody"];
    await expect(h.gate.beginRegistration({ attended: true, caller: "t" })).rejects.toMatchObject({ code: "conflict", extra: { plugins: ["somebody"] } });
  });

  it("does not accept a wrong first code and stays pending", async () => {
    await h.gate.beginRegistration({ attended: true, caller: "t" });
    expect(() => h.gate.confirmRegistration("000000")).toThrow(/invalid/);
    expect(h.gate.totpState()).toBe("pending");
  });

  it("a registration started without the page open cannot be confirmed until restarted from the page", async () => {
    const { secret } = await h.gate.beginRegistration({ attended: false, caller: "client" });
    expect(h.gate.pendingUnattended()).toBe(true);
    expect(() => h.gate.confirmRegistration(hotp(base32Decode(secret), stepAt(h.t)))).toThrow(/not started from the secure-bb page/);
    expect(h.gate.totpState()).toBe("pending");
    const begin = h.store.listLog().find((l) => l.kind === "totp.begin")!;
    expect(begin.detail).toMatchObject({ attended: false, caller: "client" });

    const again = await h.gate.beginRegistration({ attended: true, caller: "client" });
    expect(again.secret).not.toBe(secret);
    expect(h.gate.pendingUnattended()).toBe(false);
    h.gate.confirmRegistration(hotp(base32Decode(again.secret), stepAt(h.t)));
    expect(h.gate.totpState()).toBe("locked");
  });

  it("uses an external secret file when configured, and never the internal one", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sbb-"));
    const file = join(dir, "totp");
    const secret = base32Encode(Buffer.from("12345678901234567890"));
    writeFileSync(file, `${secret}\n`);
    const g = new Gate({
      store: h.store,
      now: () => h.t,
      threads: { ancestors: async () => [], descendants: async () => [] },
      thirdPartyRunning: async () => [],
      externalTotpFile: file,
      snapshotsRoot: h.snaps, unsafeDirs: async () => [],
    });
    expect(g.totpState()).toBe("external");
    await g.decide(ctx());
    g.approveQueue(1, hotp(base32Decode(secret), stepAt(h.t)));
  });
});

describe("trust windows", () => {
  let h: Harness;
  let code: () => string;

  beforeEach(async () => {
    h = new Harness();
    code = await h.register();
  });

  const openFor = (thread: string, scope?: "tree" | "thread") => {
    h.store.putCheck("sha256:opening", "demo", NETWORKED); // what the human saw when opening the window
    const q = h.store.upsertQueue({
      kind: "proposal", contentHash: "sha256:opening", pluginId: "demo", version: "1.0.0", source: "path:/x", sourceKind: "path",
      rootDir: null, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: thread, proposalId: null, reason: null,
    });
    return h.gate.openWindow(q.id, code(), scope);
  };

  it("lets versions from the opening thread through, sliding the window on each", async () => {
    const w = openFor("T1");
    const firstExpiry = w.expiresAt;
    const s1 = await h.snapshot(1, "T1");
    h.t += 10 * 60_000;
    expect(await h.gate.decide(snapCtx(s1.dir, 1))).toEqual({ action: "proceed" });
    expect(h.store.getWindow(w.id)!.expiresAt).toBe(h.t + 30 * 60_000);
    expect(h.store.getWindow(w.id)!.expiresAt).toBeGreaterThan(firstExpiry);
    expect(h.store.activeApproval("sha256:v1")).toMatchObject({ via: "window", localHash: s1.proposal.localHash });
    expect(h.store.listLog().some((l) => l.kind === "approved.window")).toBe(true);
  });

  it("covers sub-threads and forks by default, but not unrelated threads", async () => {
    h.parents.set("T2", "T1");
    h.parents.set("T3", "T2");
    openFor("T1");
    expect((await h.gate.windowCovering("demo", "T3"))?.threadId).toBe("T1");
    expect(await h.gate.windowCovering("demo", "OTHER")).toBeNull();
    expect(await h.gate.windowCovering("demo", null)).toBeNull();
    expect(await h.gate.windowCovering("another-plugin", "T1")).toBeNull();
  });

  it("'only this thread' excludes the sub-threads", async () => {
    h.parents.set("T2", "T1");
    openFor("T1", "thread");
    expect(await h.gate.windowCovering("demo", "T1")).not.toBeNull();
    expect(await h.gate.windowCovering("demo", "T2")).toBeNull();
  });

  it("never exceeds the hard ceiling while sliding, then holds", async () => {
    h.gate.setPolicy({ windowMin: 30, capMin: 45 }, code());
    h.next();
    const w = openFor("T1");
    const snaps = [await h.snapshot(1, "T1"), await h.snapshot(2, "T1"), await h.snapshot(3, "T1")];
    for (let n = 1; n <= 3; n++) {
      h.t += 20 * 60_000;
      if (n < 3) expect((await h.gate.decide(snapCtx(snaps[n - 1]!.dir, n))).action).toBe("proceed");
    }
    expect(h.store.getWindow(w.id)!.expiresAt).toBeLessThanOrEqual(w.hardExpiresAt);
    expect((await h.gate.decide(snapCtx(snaps[2]!.dir, 3))).action).toBe("wait"); // 60 min > 45 min ceiling
  });

  it("freezes after expiry: the last version stays pinned and is named in the log; a new one is held", async () => {
    const w = openFor("T1");
    const s1 = await h.snapshot(1, "T1");
    expect((await h.gate.decide(snapCtx(s1.dir, 1))).action).toBe("proceed");
    h.t += 31 * 60_000;
    expect(h.gate.sweep()).toBe(1);
    expect(h.store.getWindow(w.id)!.closedReason).toBe("expired");
    const freeze = h.store.listLog().find((l) => l.kind === "window.freeze")!;
    expect(freeze.detail).toMatchObject({ pinnedVersion: "1.0.1" });
    expect((await h.gate.decide(snapCtx(s1.dir, 1))).action).toBe("proceed"); // pinned
    const s2 = await h.snapshot(2, "T1"); // window closed -> not covered
    expect((await h.gate.decide(snapCtx(s2.dir, 2))).action).toBe("wait");
  });

  it("fixed windows do not slide", async () => {
    h.gate.setPolicy({ mode: "fixed" }, code());
    h.next();
    const w = openFor("T1");
    const s1 = await h.snapshot(1, "T1");
    h.t += 5 * 60_000;
    await h.gate.decide(snapCtx(s1.dir, 1));
    expect(h.store.getWindow(w.id)!.expiresAt).toBe(w.expiresAt);
  });

  it("closing a window needs no code (it only tightens) and ends it immediately", async () => {
    const w = openFor("T1");
    h.gate.closeWindow(w.id);
    expect(h.gate.openWindows()).toHaveLength(0);
    const s1 = await h.snapshot(1, "T1");
    expect((await h.gate.decide(snapCtx(s1.dir, 1))).action).toBe("wait");
  });

  it("does not honour a window for a different plugin id or a path outside snapshots", async () => {
    openFor("T1");
    const s1 = await h.snapshot(1, "T1");
    expect((await h.gate.decide({ ...snapCtx(s1.dir, 1), pluginId: "other" })).action).toBe("wait");
    expect((await h.gate.decide(ctx({ rootDir: "/tmp/elsewhere/h1", contentHash: "sha256:zzz" }))).action).toBe("wait");
  });

  it("widening the policy needs a code, narrowing does not", () => {
    expect(() => h.gate.setPolicy({ windowMin: 60 }, undefined)).toThrow(/needs a code/);
    h.gate.setPolicy({ windowMin: 10 }, undefined);
    expect(h.store.policy().windowMin).toBe(10);
    expect(() => h.gate.setPolicy({ windowMin: 500 }, undefined)).toThrow(GateError);
  });

  it("`flow.downgrade` (a card is less red when the checks found no way out) is off by default; turning it on loosens, so it needs a code, turning it off does not", () => {
    expect(h.store.policy().flowDowngrade).toBe(false);
    expect(() => h.gate.setPolicy({ flowDowngrade: true }, undefined)).toThrow(/needs a code/);
    expect(h.store.policy().flowDowngrade).toBe(false);
    h.gate.setPolicy({ flowDowngrade: true }, code());
    expect(h.store.policy().flowDowngrade).toBe(true);
    h.gate.setPolicy({ flowDowngrade: false }, undefined);
    expect(h.store.policy().flowDowngrade).toBe(false);
  });

  it("reopening replaces the previous window of the same plugin", () => {
    const a = openFor("T1");
    h.next();
    openFor("T9");
    expect(h.store.getWindow(a.id)!.closedReason).toBe("reopened");
    expect(h.gate.openWindows()).toHaveLength(1);
  });
});

describe("a snapshot is only trusted if its bytes match what was proposed (review 1–2)", () => {
  let h: Harness;
  let code: () => string;
  beforeEach(async () => {
    h = new Harness();
    code = await h.register();
  });

  const queueFor = (proposalId: number, dir: string) =>
    h.store.upsertQueue({
      kind: "proposal", contentHash: null, pluginId: "demo", version: "1.0.1", source: `path:${dir}`, sourceKind: "path",
      rootDir: dir, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: "T1", proposalId, reason: "window closed",
    });

  it("approving a proposal installs it, and the later hook lets it through", async () => {
    const s = await h.snapshot(1, "T1");
    const q = queueFor(s.proposal.id, s.dir);
    const res = h.gate.approveQueue(q.id, code());
    expect(res.installDir).toBe(s.dir);
    expect(await h.gate.decide(snapCtx(s.dir, 1, "sha256:core1"))).toEqual({ action: "proceed" });
    expect(h.store.activeApproval("sha256:core1")).toMatchObject({ via: "touch", localHash: s.proposal.localHash });
  });

  it("holds a touch-approved snapshot that was edited before it loaded", async () => {
    const s = await h.snapshot(1, "T1");
    h.gate.approveQueue(queueFor(s.proposal.id, s.dir).id, code());
    writeFileSync(join(s.dir, "server.ts"), "export default () => 'evil';\n");
    expect((await h.gate.decide(snapCtx(s.dir, 1, "sha256:core-evil"))).action).toBe("wait");
    expect(h.store.activeApproval("sha256:core-evil")).toBeNull();
    const hold = h.store.listLog().find((l) => l.kind === "hold")!;
    expect(hold.detail).toMatchObject({ reason: "снимок изменён после предложения" });
  });

  it("logs the load of a touch-approved snapshot as approved.load, not a second approved.touch", async () => {
    const s = await h.snapshot(1, "T1");
    h.gate.approveQueue(queueFor(s.proposal.id, s.dir).id, code());
    await h.gate.decide(snapCtx(s.dir, 1, "sha256:core1"));
    const kinds = h.store.listLog().map((l) => l.kind);
    expect(kinds.filter((k) => k === "approved.touch")).toHaveLength(1);
    expect(kinds).toContain("approved.load");
  });

  it("marks the held 'snapshot changed' entry stale once the original loads again", async () => {
    const s = await h.snapshot(1, "T1");
    h.gate.approveQueue(queueFor(s.proposal.id, s.dir).id, code());
    const orig = readFileSync(join(s.dir, "server.ts"), "utf8");
    writeFileSync(join(s.dir, "server.ts"), "export default () => 'evil';\n");
    expect((await h.gate.decide(snapCtx(s.dir, 1, "sha256:core-evil"))).action).toBe("wait");
    const held = h.store.listQueue().find((q) => q.contentHash === "sha256:core-evil")!;
    expect(held.status).toBe("held");
    writeFileSync(join(s.dir, "server.ts"), orig);
    expect((await h.gate.decide(snapCtx(s.dir, 1, "sha256:core1"))).action).toBe("proceed");
    expect(h.store.listQueue().find((q) => q.id === held.id)!.status).toBe("stale");
  });

  it("holds a window-approved snapshot that was edited, or gained a file, after proposing", async () => {
    const w = (() => {
      h.store.putCheck("sha256:opening", "demo", NETWORKED);
      const q = h.store.upsertQueue({ kind: "proposal", contentHash: "sha256:opening", pluginId: "demo", version: "1", source: "x", sourceKind: "path", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: "T1", proposalId: null, reason: null });
      return h.gate.openWindow(q.id, code());
    })();
    expect(w.pluginId).toBe("demo");
    const s = await h.snapshot(1, "T1");
    writeFileSync(join(s.dir, "extra.js"), "steal()");
    expect((await h.gate.decide(snapCtx(s.dir, 1))).action).toBe("wait");
  });

  it("pins the built tree: later loads need the dist/ bb built, and a changed dist/ is held", async () => {
    const s = await h.snapshot(1, "T1");
    h.gate.approveQueue(queueFor(s.proposal.id, s.dir).id, code());
    // first load: no dist yet
    expect((await h.gate.decide(snapCtx(s.dir, 1, "sha256:pre-build"))).action).toBe("proceed");
    // bb builds, the server records what was built
    mkdirSync(join(s.dir, "dist"));
    writeFileSync(join(s.dir, "dist", "server.js"), "built();");
    await h.gate.recordBuilt(s.dir);
    // restart: the core hash now covers dist, so it is new, but the pin accepts the same bytes
    expect(await h.gate.decide(snapCtx(s.dir, 1, "sha256:post-build"))).toEqual({ action: "proceed" });
    expect(h.store.activeApproval("sha256:post-build")!.via).toBe("pin");
    // someone edits the built output
    writeFileSync(join(s.dir, "dist", "server.js"), "stolen();");
    expect((await h.gate.decide(snapCtx(s.dir, 1, "sha256:tampered"))).action).toBe("wait");
    expect(h.store.listLog().find((l) => l.kind === "hold")!.detail).toMatchObject({ reason: "собранный dist/ изменён после установки" });
  });

  it("holds a dist/ the gate never saw being built", async () => {
    const s = await h.snapshot(1, "T1", { "dist/server.js": "planted();" });
    h.gate.approveQueue(queueFor(s.proposal.id, s.dir).id, code());
    expect((await h.gate.decide(snapCtx(s.dir, 1))).action).toBe("wait");
  });

  it("recordBuilt refuses to bless a tree whose source changed", async () => {
    const s = await h.snapshot(1, "T1");
    writeFileSync(join(s.dir, "server.ts"), "changed();");
    await h.gate.recordBuilt(s.dir);
    expect(h.store.getProposal(s.proposal.id)!.builtHash).toBeNull();
  });

  it("revoking an approval also ends the pin of that snapshot", async () => {
    const s = await h.snapshot(1, "T1");
    h.gate.approveQueue(queueFor(s.proposal.id, s.dir).id, code());
    await h.gate.decide(snapCtx(s.dir, 1, "sha256:core1"));
    h.next();
    h.gate.revoke(h.store.activeApproval("sha256:core1")!.id);
    expect((await h.gate.decide(snapCtx(s.dir, 1, "sha256:core1"))).action).toBe("wait");
    expect((await h.gate.decide(snapCtx(s.dir, 1, "sha256:core2"))).action).toBe("wait");
  });
});

describe("one definition of 'inside the snapshots directory' (review 3)", () => {
  it("rejects look-alike siblings, parents, the root itself and escaping symlinks", async () => {
    const h = new Harness();
    const inside = join(h.snaps, "demo", "h1");
    mkdirSync(inside, { recursive: true });
    const evil = join(h.root, "snapshots-evil", "demo");
    mkdirSync(evil, { recursive: true });
    const outside = join(h.root, "outside");
    mkdirSync(outside);
    symlinkSync(outside, join(h.snaps, "demo", "link"));

    expect(await isInsideSnapshots(h.snaps, inside)).toBe(true);
    expect(await isInsideSnapshots(h.snaps, evil)).toBe(false);
    expect(await isInsideSnapshots(h.snaps, h.snaps)).toBe(false);
    expect(await isInsideSnapshots(h.snaps, h.root)).toBe(false);
    expect(await isInsideSnapshots(h.snaps, join(h.snaps, "demo", "link"))).toBe(false);
    expect(await isInsideSnapshots(h.snaps, join(h.snaps, "demo", "..", "..", "outside"))).toBe(false);
    expect(await isInsideSnapshots(h.snaps, join(h.snaps, "missing"))).toBe(false);
    expect(isInside("/a/snapshots", "/a/snapshots-evil/x")).toBe(false);
    expect(isInside("/a/snapshots", "/a/snapshots/x")).toBe(true);
  });

  it("the hook does not treat a path outside the snapshots as a snapshot, even with a matching proposal", async () => {
    const h = new Harness();
    const code = await h.register();
    const evil = join(h.root, "snapshots-evil", "demo", "h1");
    mkdirSync(evil, { recursive: true });
    writeFileSync(join(evil, "server.ts"), "x");
    const p = h.store.addProposal({ pluginId: "demo", localHash: await hashTree(evil), snapshotDir: evil, threadId: "T1", windowId: null });
    h.store.approveProposal(p.id);
    expect((await h.gate.decide(ctx({ rootDir: evil, contentHash: "sha256:e" }))).action).toBe("wait");
    void code;
  });

  it("finds absolute symlinks and relative ones that leave the tree, but allows internal ones", async () => {
    const h = new Harness();
    const dir = join(h.root, "pl");
    mkdirSync(join(dir, "node_modules", ".bin"), { recursive: true });
    mkdirSync(join(dir, "lib"));
    writeFileSync(join(dir, "lib", "a.js"), "1");
    symlinkSync("../../lib/a.js", join(dir, "node_modules", ".bin", "ok"));
    symlinkSync("/etc/passwd", join(dir, "abs"));
    symlinkSync("../../outside", join(dir, "lib", "up"));
    expect((await findEscapingSymlinks(dir)).sort()).toEqual(["abs", join("lib", "up")]);
  });
});
