// The scenario of the design doc ("Сквозные проверки"): a harmful plugin that was approved once now runs INSIDE the bb process, the same
// OS user as the plugin and the core. It can reach the guard's socket (same group), the plugin's own database and RPC, and the files of the
// bb user. It tries to approve without a code, open a window without a code, read the second factor's secret. Everything must be refused,
// and the guard's journal must stay sound.
//
// What these tests cannot show (and the README says): that the files of the guard are unreadable for the bb user. That is the OS user and the
// modes the installer sets; here the test process IS the guard's user. What is checked is the modes the guard itself sets (0600/0700).
import { readFileSync, readdirSync, statSync } from "node:fs";
import net from "node:net";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GuardLink } from "../../src/guardlink.js";
import { bootPlugin, core, hookCtx, plugDir, startGuardOnDate, type Booted, type TestGuard } from "./support.ts";

let g: TestGuard;
let h: Booted;
let evil: GuardLink; // what a plugin in the bb process has: the socket
beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  g = await startGuardOnDate();
  h = await bootPlugin(g.paths.socket);
  evil = new GuardLink(g.paths.socket);
});
afterEach(async () => {
  vi.useRealTimers();
  await g.close();
});
const tick = (ms = 31_000) => vi.setSystemTime(Date.now() + ms);
const fresh = (): string => (tick(), g.code());
const refused = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (err) {
    return (err as { code?: string }).code ?? "error";
  }
  throw new Error("expected a refusal, got an answer");
};

/** A version somebody proposed: the guard knows it only as a hash. */
const victim = (name = "victim") => hookCtx(name, plugDir(name), `sha256:${name}`);

describe("a harmful plugin inside the bb process", () => {
  it("approve without a code, with an empty or wrong code: refused, nothing approved", async () => {
    const ctx = victim();
    await core(g, h, ctx);
    expect(await refused(evil.call({ op: "approve", requestId: 1 }))).toBe("invalid_code");
    expect(await refused(evil.approve(1, ""))).toBe("invalid_code");
    expect(await refused(evil.approve(1, "123456"))).toBe("invalid_code");
    expect(await refused(evil.call({ op: "approve", requestId: 1, code: null }))).toBe("invalid_code");
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0);
    expect(await core(g, h, ctx)).toBe("held");
  });

  it("rejects a version stopped by the plugin's hook, then tries to load it through the window: still held, the window is closed", async () => {
    // the owner's window is open; the hook stopped a new capability; the harmful plugin dismisses the entry (no code needed) and asks again
    expect((await g.send({ op: "open-window", pluginId: "victim", minutes: 30, code: fresh() })).ok).toBe(true);
    const ctx = victim();
    await evil.call({ op: "hold", pluginId: ctx.pluginId, version: ctx.version, contentHash: ctx.contentHash, rootDir: ctx.rootDir, source: ctx.source, sourceKind: ctx.sourceKind, trigger: ctx.trigger, stop: true });
    const entry = (await g.send({ op: "state" })).queue.find((q: any) => q.status === "held");
    await evil.dismiss(entry.id); // allowed: tightening
    expect(await core(g, h, ctx)).toBe("rejected");
    expect(await core(g, h, ctx, "hooks-first")).toBe("rejected");
    expect(await g.send({ op: "decide", pluginId: ctx.pluginId, version: ctx.version, contentHash: ctx.contentHash, rootDir: ctx.rootDir, source: ctx.source, sourceKind: ctx.sourceKind, trigger: ctx.trigger })).toMatchObject({ action: "reject" });
    const s = await g.send({ op: "state" });
    expect(s.approvals).toHaveLength(0);
    expect(s.windows).toHaveLength(0); // the dismissal closed it
  });

  it("open-window without a code, with a wrong one, or with a huge size: refused, no window", async () => {
    expect(await refused(evil.call({ op: "open-window", pluginId: "victim", minutes: 60 }))).toBe("invalid_code");
    expect(await refused(evil.openWindow("victim", 60, "000000"))).toBe("invalid_code");
    expect(await refused(evil.openWindow("victim", 100_000, "000000"))).toBe("invalid");
    expect((await g.send({ op: "state" })).windows).toHaveLength(0);
    expect(await core(g, h, victim())).toBe("held");
  });

  it("widening the guard's policy, or touching for its own purposes, needs a code too", async () => {
    expect(await refused(evil.policy({ capMin: 1440 }))).toBe("invalid_code");
    expect(await refused(evil.policy({ mode: "sliding", windowMin: 1000, capMin: 1440 }, "999999"))).toBe("invalid_code");
    expect(await refused(evil.touch("anything", "000000"))).toBe("invalid_code");
    expect((await evil.policy()).capMin).toBe(240);
  });

  it("cannot read the secret: no op returns it, nothing in the plugin's database, pages or journal holds it; the guard's own files are private", async () => {
    const ctx = victim();
    await core(g, h, ctx);
    await h.rpc("queue.approve", { id: 1, code: fresh() });
    const seen: string[] = [];
    for (const op of ["state", "ping", "policy", "journal-verify", "secret", "totp", "totp-secret", "export", "dump", "get", "read", "debug", "config", "keys", "register", "totp-register"]) {
      try {
        seen.push(JSON.stringify(await evil.call({ op })));
      } catch (e) {
        seen.push(String((e as Error).message));
      }
    }
    seen.push(JSON.stringify(await evil.state()), JSON.stringify(await evil.verifyJournal()), JSON.stringify(await evil.lookup("victim", ctx.contentHash)));
    seen.push(JSON.stringify(await h.rpc("overview")));
    for (const text of seen) {
      expect(text).not.toContain(g.secret);
      expect(text).not.toContain(Buffer.from(g.secret).toString("base64"));
    }
    // the plugin's own database (which a harmful plugin reads freely: F2) has no secret, and no key of any kind
    const db = h.bb.storage.database();
    for (const { name } of db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as Array<{ name: string }>) {
      expect(JSON.stringify(db.prepare(`SELECT * FROM "${name}"`).all())).not.toContain(g.secret);
    }
    expect((db.prepare(`SELECT COUNT(*) AS n FROM totp`).get() as { n: number }).n).toBe(0);
    // no registration can be started through bb, so no other secret can be planted either
    expect(await refused(h.rpc("totp.begin"))).toBeTruthy();
    expect(await refused(h.rpc("totp.confirm", { code: "123456" }))).toBeTruthy();
    // the files the guard made: private to its own user
    expect(statSync(g.paths.secret).mode & 0o777).toBe(0o600);
    expect(statSync(g.paths.stateDir).mode & 0o777).toBe(0o700);
    expect(readFileSync(g.paths.secret, "utf8").trim()).toBe(g.secret); // (the test process is the guard's user)
    // and the bb plugin's own data directory has no copy of it
    const walk = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
    for (const f of walk(h.dataDir)) expect(readFileSync(f).toString("latin1")).not.toContain(g.secret);
  });

  it("the plugin's own RPC does not approve, open a window, export or change settings without a code the guard accepts", async () => {
    const ctx = victim();
    await core(g, h, ctx);
    await expect(h.rpc("queue.approve", { id: 1 })).rejects.toThrow();
    await expect(h.rpc("queue.approve", { id: 1, code: "000000" })).rejects.toThrow();
    await expect(h.rpc("window.open", { queueId: 1 })).rejects.toThrow();
    await expect(h.rpc("window.open", { queueId: 1, code: "000000", scope: "tree" })).rejects.toThrow();
    await expect(h.rpc("approvals.export", { code: "000000" })).rejects.toThrow();
    await expect(h.rpc("policy.set", { windowMin: 240, capMin: 1440, mode: "sliding", scope: "tree", cfgWindowMin: 240, cfgCapMin: 1440, cfgMode: "sliding", autoSafe: true })).rejects.toThrow();
    await expect(h.rpc("session.open", { code: "000000" })).rejects.toThrow();
    await expect(h.rpc("queue.approve", { id: 1, session: "invented-token" })).rejects.toThrow();
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0);
    expect((await g.send({ op: "state" })).windows).toHaveLength(0);
    expect(await core(g, h, ctx)).toBe("held");
  });

  it("cannot get unapproved code loaded: not by deciding, annotating, holding, looking up, writing its own approvals, or its own window rows", async () => {
    const ctx = victim("loot");
    await core(g, h, ctx);
    expect((await evil.call({ op: "decide", ...ctx })).action).toBe("wait");
    await evil.annotate({ contentHash: ctx.contentHash }, { reason: "all clean", findings: [], verified: true, approved: true });
    await evil.hold({ pluginId: "loot", version: "1.0.0", contentHash: ctx.contentHash, rootDir: ctx.rootDir, source: ctx.source, sourceKind: "path", trigger: "install" }, false);
    expect((await evil.lookup("loot", ctx.contentHash)).approved).toBe(false);
    // F2: it writes "approved" and a window straight into the plugin's own database
    const db = h.bb.storage.database();
    db.prepare(`INSERT INTO approvals (content_hash, plugin_id, version, source, source_kind, via, approved_at) VALUES (?, 'loot', '1.0.0', 's', 'path', 'touch', 1)`).run(ctx.contentHash);
    db.prepare(`INSERT INTO windows (plugin_id, thread_id, scope, mode, size_sec, cap_sec, opened_at, expires_at, hard_expires_at, caps, guard_window_id) VALUES ('loot', 'T1', 'tree', 'sliding', 1800, 14400, 1, 9999999999999, 9999999999999, '[]', 1)`).run();
    expect(await core(g, h, ctx)).toBe("held");
    expect(await core(g, h, ctx, "hooks-first")).toBe("held");
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0);
  });

  it("cannot switch the guard off: unknown ops, junk, endless lines and a crowd of connections change nothing", async () => {
    for (const op of ["stop", "shutdown", "exit", "kill", "disable", "reload", "restart"]) expect(await refused(evil.call({ op }))).toBe("unknown_op");
    expect(await refused(evil.call({ op: "decide", pluginId: "../../etc", contentHash: "x" }))).toBe("invalid");
    const crowd = await Promise.all(
      Array.from({ length: 100 }, () => new Promise<void>((resolve) => {
        const c = net.connect(g.paths.socket, () => c.write("x".repeat(600 * 1024)));
        c.on("close", () => resolve());
        c.on("error", () => resolve());
      })),
    );
    expect(crowd).toHaveLength(100);
    expect((await evil.call({ op: "ping" })).protocol).toBe(1);
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0);
  });

  it("after all this the guard's journal is sound and records the failed attempts", async () => {
    await core(g, h, victim());
    for (let i = 0; i < 3; i++) await refused(evil.approve(1, "000000"));
    await refused(evil.openWindow("victim", 5, "000000"));
    const report = await evil.verifyJournal();
    expect(report).toMatchObject({ valid: true, problems: [] });
    const kinds = ((await g.send({ op: "state" })).journal.recent as Array<{ kind: string }>).map((j) => j.kind);
    expect(kinds.filter((k) => k === "totp.fail").length).toBe(4);
    expect(kinds).not.toContain("approved.touch");
    expect(kinds).not.toContain("approved.window");
  });

  it("five wrong codes block approvals for an hour (the limit), but the human can still close windows and revoke", async () => {
    await g.send({ op: "open-window", pluginId: "victim", minutes: 20, code: fresh() });
    await core(g, h, victim());
    for (let i = 0; i < 5; i++) await refused(evil.approve(1, "000000"));
    expect(await refused(h.rpc("queue.approve", { id: 1, code: fresh() }))).toBeTruthy(); // the human's right code is refused too: the block
    expect((await g.send({ op: "state" })).totp.blockedUntil).toBeGreaterThan(Date.now());
    // tightening is never blocked
    await h.rpc("window.close", { windowId: 1 });
    expect((await g.send({ op: "state" })).windows).toHaveLength(0);
    tick(3_600_001);
    expect((await g.send({ op: "state" })).totp.blockedUntil).toBe(0);
    await g.send({ op: "open-window", pluginId: "victim", minutes: 5, code: fresh() });
  });

  // The residual risk the design doc names ("Остаточный риск TOTP"): a code typed on the page passes through the bb process. This test says plainly
  // what a plugin that intercepts it can and cannot do, so nobody reads the guard as more than it is. Passkey (a signature over the action) is the fix.
  it("KNOWN LIMIT: a code intercepted from the page can be spent once, first, on the plugin's own action; the journal then says exactly what was approved", async () => {
    const ctx = victim("wanted");
    const other = victim("loot");
    await core(g, h, ctx);
    await core(g, h, other);
    const intercepted = fresh(); // the human typed this on the page for "wanted"; the plugin saw it first
    const stolen = await evil.approve(2, intercepted); // ...and spends it on "loot"
    expect(stolen.approval).toMatchObject({ pluginId: "loot", via: "touch" });
    expect(await refused(h.rpc("queue.approve", { id: 1, code: intercepted }))).toBeTruthy(); // the human's click now fails: a replay
    const rec = ((await g.send({ op: "state" })).journal.recent as Array<{ kind: string; pluginId: string; detail: { version: string; source: string } }>).find((j) => j.kind === "approved.touch");
    expect(rec).toMatchObject({ pluginId: "loot", detail: { version: "1.0.0" } }); // visible after the fact; "wanted" stays held
    expect(await core(g, h, ctx)).toBe("held");
    // it still cannot do more than one thing per code, and cannot use it again
    expect(await refused(evil.openWindow("loot", 60, intercepted))).toBe("invalid_code");
  });
});
