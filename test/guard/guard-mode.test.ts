// The plugin in guard mode (BB_SECURE_BB_GUARD_SOCKET): a real guard on a temporary socket, the plugin over the fake bb host,
// and a test that plays the core of patch 0003 (asks the guard, runs the hooks, any "no" wins).
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EXPORT_FORMAT as GUARD_EXPORT_FORMAT, importCmd, type Io } from "../../guard/src/cli.ts";
import { EXPORT_FORMAT } from "../../src/export.js";
import { base32Decode, hotp, stepAt } from "../../guard/src/totp.ts";
import { bootPlugin, core, hookCtx, plugDir, startGuardOnDate, type Booted, type TestGuard } from "./support.ts";

let g: TestGuard | null = null;
beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
afterEach(async () => {
  vi.useRealTimers();
  await g?.close();
  g = null;
});
const tick = (ms = 31_000) => vi.setSystemTime(Date.now() + ms);
/** A code of a step nobody used yet (the clock is faked: move it one step). */
const fresh = (gd: TestGuard): string => (tick(), gd.code());

const snapshotDir = (h: Booted, id: string): string => {
  const root = join(dirname(h.bb.storage.database().name), "snapshots", id);
  const all = readdirSync(root).map((d) => join(root, d));
  return all.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0]!;
};
const ov = (h: Booted) => h.rpc<any>("overview");

/** Proposes a plugin from a thread and returns the context the core would ask about (the snapshot's directory). */
async function proposed(h: Booted, name: string, body?: string, threadId = "T1") {
  const dir = plugDir(name, body);
  const res = await h.harness.behavior.runCli(["propose", dir], { threadId });
  const snap = snapshotDir(h, name);
  return { res, ctx: hookCtx(name, snap, `sha256:${name}:${snap.slice(-8)}`), dir };
}

describe("guard mode: approvals are the guard's, the hook only holds", () => {
  it("holds an unapproved version, shows the guard's queue on the page, approves with a code checked by the guard, and records nothing locally", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const { res, ctx } = await proposed(h, "demo");
    expect(res.exitCode).toBe(0); // installed: the guard, not propose, holds it
    expect(h.installs).toHaveLength(1);

    expect(await core(g, h, ctx)).toBe("held");
    const page = await ov(h);
    expect(page.guard).toMatchObject({ connected: true });
    expect(page.totp.state).toBe("external"); // the secret is outside bb
    expect(page.queue).toHaveLength(1);
    expect(page.queue[0]).toMatchObject({ id: 1, pluginId: "demo", status: "held", contentHash: ctx.contentHash });
    expect(page.queueChecks[1]).toBeDefined(); // the checks of the snapshot are on the guard's entry
    expect(page.queue[0].threadId).toBe("T1");

    // a wrong code is refused at the guard, and so is a replay
    await expect(h.rpc("queue.approve", { id: 1, code: "000000" })).rejects.toThrow();
    const code = fresh(g);
    expect(await h.rpc("queue.approve", { id: 1, code })).toMatchObject({ ok: true });
    expect(await core(g, h, ctx)).toBe("load");
    expect((await ov(h)).queue[0].status).toBe("approved");
    const other = await proposed(h, "second", "fetch('https://y.example');\n");
    await core(g, h, other.ctx);
    await expect(h.rpc("queue.approve", { id: 2, code })).rejects.toThrow(); // the same code twice
    await h.rpc("queue.approve", { id: 2, code: fresh(g) });

    // nothing was written to this plugin's own approvals
    const db = h.bb.storage.database();
    expect((db.prepare(`SELECT COUNT(*) AS n FROM approvals`).get() as { n: number }).n).toBe(0);
    // the guard's journal says what was approved
    const rec = (await g.send({ op: "state" })).journal.recent.find((j: any) => j.kind === "approved.touch");
    expect(rec).toMatchObject({ pluginId: "second", detail: { version: "1.0.0" } });
  });

  it("holds what the guard has not approved even if this plugin's own database says approved", async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const { ctx } = await proposed(h, "demo");
    // what a harmful plugin with access to this database (F2) would do: write "approved" itself
    h.bb.storage.database().prepare(`INSERT INTO approvals (content_hash, plugin_id, version, source, source_kind, via, approved_at, local_hash) VALUES (?, 'demo', '1.0.0', 's', 'path', 'touch', 1, NULL)`).run(ctx.contentHash);
    expect(await h.hook(ctx)).toMatchObject({ action: "wait" });
    expect(await core(g, h, ctx)).toBe("held");
  });

  it("rejects hard findings, and a clean unapproved version still waits for the guard", async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const bad = await proposed(h, "evil", "eval(atob('YWxlcnQoMSk='));\n");
    // `propose` itself stops hard findings before installing
    expect(bad.res.exitCode).toBe(3);
    const clean = await proposed(h, "quiet", "export default () => {};\n");
    expect(await core(g, h, clean.ctx)).toBe("held"); // safe class, but no auto-pass in guard mode: a human decides
  });

  it("if the guard is not there, everything is held and the page says so", async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const { ctx } = await proposed(h, "demo");
    await g.close();
    expect(await h.hook(ctx)).toMatchObject({ action: "wait" });
    const page = await ov(h);
    expect(page.guard.connected).toBe(false);
    expect(page.queue).toEqual([]);
    expect(page.totp.state).toBe("none");
    await expect(h.rpc("queue.approve", { id: 1, code: "123456" })).rejects.toThrow();
  });

  it("without the socket the plugin is what it was: no guard section, its own TOTP", async () => {
    const h = await bootPlugin(null);
    const page = await ov(h);
    expect(page.guard).toBeUndefined();
    expect(page.totp.state).toBe("none");
    await h.rpc("page.ping");
    expect(await h.rpc("totp.begin")).toHaveProperty("secret");
  });

  it("registration and the safe-class auto-pass do not exist here (sessions do: the guard issues them)", async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    await expect(h.rpc("totp.begin")).rejects.toThrow(/консол|console/i);
    await expect(h.rpc("totp.confirm", { code: "123456" })).rejects.toThrow(/консол|console/i);
    await expect(h.rpc("policy.set", { autoSafe: true, code: fresh(g) })).rejects.toThrow();
    // the same code was not wasted on the refusals above
    expect((await g.send({ op: "touch", purpose: "t", code: g.code() })).ok).toBe(true);
  });
});

describe("guard mode: what is approved is the guard's entry for the core's hash", () => {
  const coreHash = (dir: string) => `sha256:core-${dir.slice(-10)}`; // not the snapshot's own hash, as in the real core
  const coreCtx = (name: string, dir: string) => hookCtx(name, dir, coreHash(dir));

  it("propose → the install makes the core ask → approve by code → the plugin loads", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    let h!: Booted;
    h = await bootPlugin(g.paths.socket, { onInstall: async (src) => void (await core(g!, h, coreCtx("demo", src))) });
    const { res } = await proposed(h, "demo");
    expect(res.exitCode).toBe(0);
    const page = await ov(h);
    expect(page.queue).toHaveLength(1);
    expect(page.queue[0].contentHash).toMatch(/^sha256:core-/); // never a local: key
    await h.rpc("queue.approve", { id: page.queue[0].id, code: fresh(g) });
    expect(await core(g, h, coreCtx("demo", h.installs[0]!))).toBe("load");
    const st = await g.send({ op: "state" });
    expect(st.approvals.map((a: any) => a.contentHash)).toEqual([coreHash(h.installs[0]!)]);
  });

  it("a proposal the core never asked about is installed first, the guard's entry awaited, and that entry approved", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    let h!: Booted;
    h = await bootPlugin(g.paths.socket, { onInstall: async (src) => void (await core(g!, h, coreCtx("evil", src))) });
    const { res } = await proposed(h, "evil", "eval(atob('YWxlcnQoMSk='));\n"); // stopped by the checks before install
    expect(res.exitCode).toBe(3);
    expect(h.installs).toHaveLength(0);
    const page = await ov(h);
    expect(page.queue).toHaveLength(1);
    expect(page.queue[0].id).toBeLessThan(0);
    expect(page.queue[0].reason).toMatch(/^не установлен: заблокирован проверками secure-bb: /);
    await expect(h.rpc("queue.approve", { id: page.queue[0].id, code: g.code() })).rejects.toThrow(); // block needs the risk acknowledged
    expect((await g.send({ op: "touch", purpose: "x", code: fresh(g) })).ok).toBe(true); // ...and that refusal did not spend a code
    await h.rpc("queue.approve", { id: page.queue[0].id, code: fresh(g), acknowledgeBlock: true });
    expect(h.installs).toHaveLength(1);
    const st = await g.send({ op: "state" });
    expect(st.approvals).toHaveLength(1);
    expect(st.approvals[0].contentHash).toBe(coreHash(h.installs[0]!));
    expect((await ov(h)).queue.every((q: any) => q.id > 0)).toBe(true);
  });
});

describe("guard mode: rejecting needs no code", () => {
  it("a guard entry is dismissed at the guard without a code, also while wrong codes block approvals", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    let h!: Booted;
    h = await bootPlugin(g.paths.socket);
    const { ctx } = await proposed(h, "demo");
    expect(await core(g, h, ctx)).toBe("held");
    const page = await ov(h);
    const id = page.queue[0].id;
    expect(id).toBeGreaterThan(0);
    for (let i = 0; i < 5; i++) await expect(h.rpc("queue.approve", { id, code: "000000" })).rejects.toThrow();
    await expect(h.rpc("queue.approve", { id, code: fresh(g) })).rejects.toThrow(/blocked|too many/);
    await h.rpc("queue.dismiss", { id }); // no code
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0);
    expect((await g.send({ op: "state" })).queue.filter((q: any) => q.status === "held")).toHaveLength(0);
    expect(((await g.send({ op: "state" })).journal.recent as any[]).some((j) => j.kind === "dismissed")).toBe(true);
    expect(await core(g, h, ctx)).toBe("rejected"); // still not approved: and told "no", not asked about again
    // asked again and again: still no new entry at the guard (the core asks at every start)
    for (let i = 0; i < 4; i++) expect(await core(g, h, ctx)).toBe("rejected");
    expect((await g.send({ op: "state" })).queue).toHaveLength(1);
    expect(((await g.send({ op: "state" })).journal.recent as any[]).filter((j) => j.kind === "reject.repeat")).toHaveLength(1);
  });

  it("a local proposal (negative id) is only marked dismissed, without a code and without touching the guard", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    let h!: Booted;
    h = await bootPlugin(g.paths.socket, { onInstall: async (src) => void (await core(g!, h, hookCtx("evil", src, `sha256:core-${src.slice(-10)}`))) });
    await proposed(h, "evil", "eval(atob('YWxlcnQoMSk='));\n");
    const page = await ov(h);
    expect(page.queue[0].id).toBeLessThan(0);
    const before = await g.send({ op: "state" });
    await h.rpc("queue.dismiss", { id: page.queue[0].id }); // no code
    expect((await ov(h)).queue.filter((q: any) => q.status === "held")).toHaveLength(0);
    expect((await g.send({ op: "state" })).journal.head).toEqual(before.journal.head); // the guard was not touched
    expect(h.installs).toHaveLength(0);
  });
});

describe("guard mode: windows", () => {
  it("the guard opens and slides the window; the plugin keeps the thread and the capabilities, and can only hold more", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const first = await proposed(h, "demo");
    expect(await core(g, h, first.ctx)).toBe("held");
    await h.rpc("window.open", { queueId: 1, code: fresh(g) });
    const page = await ov(h);
    expect(page.windows).toHaveLength(1);
    expect(page.windows[0]).toMatchObject({ pluginId: "demo", threadId: "T1" });
    expect((await g.send({ op: "state" })).windows).toHaveLength(1);

    // a new version from the same thread, nothing new: the guard approves it by the window
    const v2 = await proposed(h, "demo", "fetch('https://x.example');\n// v2\n");
    expect(await core(g, h, v2.ctx)).toBe("load");
    const rec = (await g.send({ op: "state" })).journal.recent.find((j: any) => j.kind === "approved.window");
    expect(rec).toMatchObject({ pluginId: "demo" });

    // A new capability is no longer this plugin's to compare: the guard holds it itself by the one rule (`windowAllows`), and the hook lets the version through
    // to it. That needs the guard to read the version for real, which this harness (made-up core hashes) cannot give; it is tested in window-rule.test.ts
    // (the guard and the hook decide alike) and window-checks.test.ts (the guard holds a new right with a stop).
    expect((await ov(h)).windows).toHaveLength(1);

    // closing needs no code
    await h.rpc("window.close", { windowId: (await ov(h)).windows[0].id });
    expect((await g.send({ op: "state" })).windows).toHaveLength(0);
    const v4 = await proposed(h, "demo", "fetch('https://x.example');\n// v4\n");
    expect(await core(g, h, v4.ctx)).toBe("held");
  });

  it("a version that did not come from the window's thread is held even though the guard has a window", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const first = await proposed(h, "demo", undefined, "T1");
    await core(g, h, first.ctx);
    await h.rpc("window.open", { queueId: 1, code: fresh(g) });
    const elsewhere = await proposed(h, "demo", "fetch('https://x.example');\n// other thread\n", "T9");
    expect(await h.hook(elsewhere.ctx)).toMatchObject({ action: "wait" });
    expect(await core(g, h, elsewhere.ctx)).toBe("held");
    expect((await g.send({ op: "lookup", pluginId: "demo", contentHash: elsewhere.ctx.contentHash })).approved).toBe(false);
  });

  it("a window opened at the guard from elsewhere (no thread known here) holds the plugin's versions", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: fresh(g) });
    const v = await proposed(h, "demo");
    expect(await h.hook(v.ctx)).toMatchObject({ action: "wait" });
    const page = await ov(h);
    expect(page.windows).toHaveLength(1); // still visible, with an unknown thread
    expect(page.windows[0].threadId).toBe("неизвестен");
  });

  it("policy: the guard's window settings change through the page, widening only with a code", async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const base = { autoSafe: false, scope: "tree" as const, cfgWindowMin: 10, cfgCapMin: 240, cfgMode: "sliding" as const };
    await h.rpc("policy.set", { ...base, windowMin: 20, capMin: 60, mode: "sliding" });
    expect((await g.send({ op: "policy" })).policy).toMatchObject({ windowMin: 20, capMin: 60 });
    await expect(h.rpc("policy.set", { ...base, windowMin: 20, capMin: 120, mode: "sliding" })).rejects.toThrow();
    await h.rpc("policy.set", { ...base, windowMin: 20, capMin: 120, mode: "sliding", code: fresh(g) });
    expect((await g.send({ op: "policy" })).policy.capMin).toBe(120);
    expect((await ov(h)).policy).toMatchObject({ windowMin: 20, capMin: 120, autoSafe: false });
  });
});

describe("guard mode: every code the plugin takes is checked by the guard", () => {
  it("another RPC that needs a code (trusted repositories) goes through the guard once, and a replay is refused", async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const code = fresh(g);
    expect(await h.rpc("trusted.set", { add: "octo/repo", code })).toMatchObject({ ok: true, repos: ["octo/repo"] });
    await expect(h.rpc("trusted.set", { add: "octo/other", code })).rejects.toThrow();
    await expect(h.rpc("trusted.set", { add: "octo/other", code: "000000" })).rejects.toThrow();
    const kinds = (await g.send({ op: "state" })).journal.recent.map((j: any) => j.kind);
    expect(kinds).toContain("touch");
    expect(kinds).toContain("totp.fail");
  });

  it("the guard's journal is checked on the page and can be verified on demand", async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    expect((await ov(h)).guard.journal).toMatchObject({ valid: true });
    expect(await h.rpc("guard.verify")).toMatchObject({ valid: true });
  });
});

describe("migration: the plugin exports, the guard imports", () => {
  const quiet: Io = { out: () => {}, err: () => {}, ask: async () => null };

  it("exports the active approvals with a code, to a private file; `sbb-guard import` makes them the guard's", { timeout: 30_000 }, async () => {
    // a plugin with its own approvals (the way it was before the guard)
    const h = await bootPlugin(null);
    await h.rpc("page.ping");
    const begin = await h.rpc<{ secret: string }>("totp.begin");
    const gen = () => hotp(base32Decode(begin.secret), stepAt(Date.now()));
    await h.rpc("totp.confirm", { code: gen() });
    const dir = plugDir("demo");
    const ctx = hookCtx("demo", dir);
    expect(await h.hook(ctx)).toMatchObject({ action: "wait" });
    const id = ((await ov(h)).queue as Array<{ id: number }>)[0]!.id;
    tick();
    await h.rpc("queue.approve", { id, code: gen() });
    expect(await h.hook(ctx)).toEqual({ action: "proceed" });

    await expect(h.rpc("approvals.export", { code: "000000" })).rejects.toThrow();
    tick();
    const out = await h.rpc<{ path: string; digest: string; count: number }>("approvals.export", { code: gen() });
    expect(out.count).toBe(1);
    expect(statSync(out.path).mode & 0o777).toBe(0o600);
    const body = JSON.parse(readFileSync(out.path, "utf8"));
    expect(body.format).toBe(EXPORT_FORMAT);
    expect(body.approvals[0]).toMatchObject({ pluginId: "demo", contentHash: ctx.contentHash });
    expect(EXPORT_FORMAT).toBe(GUARD_EXPORT_FORMAT);

    // now the console: a guard, and the import
    g = await startGuardOnDate();
    expect(await importCmd(g.paths, quiet, out.path, { yes: true, digest: out.digest }, () => Date.now())).toBe(0);
    expect(await g.send({ op: "decide", pluginId: "demo", version: "1.0.0", contentHash: ctx.contentHash, rootDir: dir, source: ctx.source, sourceKind: "path", trigger: "install" })).toMatchObject({ action: "proceed" });
    expect(g.guard.verifyJournal().ok).toBe(true);
  });

  it("in guard mode the export too needs a code, checked by the guard", async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    await expect(h.rpc("approvals.export", { code: "000000" })).rejects.toThrow();
    expect((await h.rpc<{ count: number }>("approvals.export", { code: fresh(g) })).count).toBe(0);
  });
});
