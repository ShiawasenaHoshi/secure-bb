// UX v1, PR 3 through the plugin in guard mode: the approval session the guard issues, one touch for a fixed list, Strict mode and a hash mismatch,
// «вернуть и доверять» as one operation, troubleshooting mode on the page and in the hook. A real guard on a temporary socket, the plugin over the fake bb host.
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Gate } from "../../src/gate.js";
import { GuardLink } from "../../src/guardlink.js";
import { SoftAuthenticator } from "./authenticator.ts";
import { bootPlugin, core, hookCtx, plugDir, startGuardOnDate, type Booted, type TestGuard } from "./support.ts";

let g: TestGuard;
let h: Booted;
beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
afterEach(async () => {
  vi.useRealTimers();
  await g?.close();
});
const tick = (ms = 31_000) => vi.setSystemTime(Date.now() + ms);
const fresh = (): string => (tick(), g.code());
const ov = () => h.rpc<any>("overview");
const gstate = () => g.send({ op: "state" });
const kinds = async (kind: string) => ((await gstate()).journal.recent as Array<{ kind: string; detail: any }>).filter((r) => r.kind === kind);
const sha = (t: string): string => createHash("sha256").update(t, "utf8").digest("hex");

/** A version somebody proposed: the guard knows it only as a hash. */
const version = (name: string) => hookCtx(name, plugDir(name), `sha256:${name}`);
async function setup(n = 2): Promise<ReturnType<typeof version>[]> {
  g = await startGuardOnDate();
  h = await bootPlugin(g.paths.socket);
  const ctxs = Array.from({ length: n }, (_, i) => version(`p${i + 1}`));
  for (const c of ctxs) expect(await core(g, h, c)).toBe("held");
  return ctxs;
}
const openSession = async (): Promise<string> => (await h.rpc<{ token: string }>("session.open", { code: fresh() })).token;

/** Every table of the plugin's database as text: where a token could hide. */
function dumpPluginDb(): string {
  const db = h.bb.storage.database() as unknown as { prepare(sql: string): { all(): Array<Record<string, unknown>> } };
  const tables = db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all().map((r) => String(r.name));
  return JSON.stringify(tables.map((t) => db.prepare(`SELECT * FROM "${t}"`).all()));
}

describe("approval session in guard mode", () => {
  it("one touch opens it at the guard; routine approvals then need no code; the token is only in the answer", { timeout: 30_000 }, async () => {
    await setup(2);
    const opened = await h.rpc<{ token: string; idleMs: number; capMs: number }>("session.open", { code: fresh() });
    expect(opened).toMatchObject({ idleMs: 15 * 60_000, capMs: 60 * 60_000 });
    const { token } = opened;
    // routine: approve versions — no code (a window by session is covered at the guard's own tests: it needs a thread here)
    expect(await h.rpc("queue.approve", { id: 1, session: token })).toMatchObject({ ok: true });
    expect(await h.rpc("queue.approve", { id: 2, session: token })).toMatchObject({ ok: true });
    expect((await gstate()).approvals.map((a: any) => a.pluginId)).toEqual(["p2", "p1"]);
    expect((await kinds("approved.touch"))[0]!.detail).toMatchObject({ via: "session" });
    // the token is nowhere: not in the guard's state or journal, not in the plugin's database, not on the page's overview
    const everywhere = JSON.stringify([await gstate(), g.guard.state(), dumpPluginDb(), await ov()]);
    expect(everywhere).not.toContain(token);
    expect(everywhere).not.toContain(sha(token));
    expect((await gstate()).sessions).toHaveLength(1);
    // locking closes it at the guard
    await h.rpc("session.close");
    expect((await gstate()).sessions).toEqual([]);
    await expect(h.rpc("queue.approve", { id: 1, session: token })).rejects.toThrow(/invalid or expired session|already/);
  });

  it("opens with a passkey touch too, and the guard says what it is for", { timeout: 30_000 }, async () => {
    await setup(1);
    const auth = new SoftAuthenticator();
    const e = g.guard.enrollStart("laptop");
    const first = await h.rpc<{ options: any }>("passkey.register", { token: e.token });
    await h.rpc("passkey.register", { token: e.token, ...auth.create(first.options) });
    g.guard.confirmEnrollment(e.id);
    const c = await h.rpc<any>("passkey.challenge", { kind: "session.open" });
    expect(c).toMatchObject({ needed: true, description: expect.stringContaining("сессию подтверждения") });
    const { token } = await h.rpc<{ token: string }>("session.open", { passkey: auth.get(c.challenge) });
    expect(await h.rpc("queue.approve", { id: 1, session: token })).toMatchObject({ ok: true });
    expect((await kinds("session.open"))[0]!.detail).toMatchObject({ via: "passkey" });
  });

  it("the dangerous kind always takes a fresh touch: a session is refused, and it is not counted as a wrong code", { timeout: 30_000 }, async () => {
    await setup(1);
    const token = await openSession();
    // lifting a block, and a window on the whole tree when the policy says "this thread only"
    await expect(h.rpc("queue.approve", { id: 1, session: token, acknowledgeBlock: true })).rejects.toThrow(/fresh|touch/);
    await h.rpc("policy.set", { scope: "thread" } as never).catch(() => undefined);
    await expect(h.rpc("window.open", { queueId: 1, session: token, scope: "tree" })).rejects.toThrow(/fresh|touch/);
    // RPCs whose schema takes no session at all: policy, trusting a source, the return-and-trust operation, weakening the mode
    for (const [name, args] of [
      ["policy.set", { windowMin: 600, capMin: 900 }],
      ["trust.add", { entries: ["github:me/x"] }],
      ["trust.mode", { mode: "simple" }],
      ["queue.approveTrust", { id: 1 }],
      ["session.open", {}],
    ] as const)
      await expect(h.rpc(name, { ...args, session: token } as never), name).rejects.toThrow();
    expect((await gstate()).totp.blockedUntil).toBe(0);
    expect((await gstate()).approvals).toEqual([]);
    expect((await gstate()).trust.mySources).toEqual([]);
    // the same session still works for what it covers
    expect(await h.rpc("queue.approve", { id: 1, session: token })).toMatchObject({ ok: true });
  });

  it("is not opened while a third-party plugin runs (the code is not spent), and is closed at the guard when one starts", { timeout: 30_000 }, async () => {
    await setup(1);
    h.setPlugins([{ id: "nosy", provenance: "direct", enabled: true, status: "running", version: "1.0.0", source: "path:/x", rootDir: "/x" }]);
    const code = fresh();
    await expect(h.rpc("session.open", { code })).rejects.toThrow(/nosy/);
    h.setPlugins([]);
    const { token } = await h.rpc<{ token: string }>("session.open", { code }); // the same code: it was not consumed
    // a third-party plugin starts while the session is open: the plugin's watch over sessions closes it AT THE GUARD (no touch: it only tightens)
    const logged: string[] = [];
    const gate = new Gate({ store: { log: (k: string) => void logged.push(k) } as never, guard: new GuardLink(g.paths.socket), thirdPartyRunning: async () => ["nosy"], now: () => Date.now() } as never);
    expect((await gstate()).sessions).toHaveLength(1);
    expect(await gate.closeSessionsForThirdParty()).toEqual(["nosy"]);
    expect((await gstate()).sessions).toEqual([]);
    await expect(h.rpc("queue.approve", { id: 1, session: token })).rejects.toThrow();
  });

  it("a harmful plugin in the process without the token gets nothing: no proof, a wrong token, the token's hash", { timeout: 30_000 }, async () => {
    await setup(1);
    const token = await openSession();
    const evil = new GuardLink(g.paths.socket);
    const code = async (p: Promise<unknown>): Promise<string> => p.then(() => "answered", (e) => (e as { code?: string }).code ?? "error");
    expect(await code(evil.call({ op: "approve", requestId: 1 }))).toBe("invalid_code");
    expect(await code(evil.approve(1, { session: "q".repeat(43) }))).toBe("invalid_code");
    expect(await code(evil.approve(1, { session: sha(token) }))).toBe("invalid_code");
    expect(await code(evil.batchPrepare([{ kind: "queue", id: 1 }]).then((b) => evil.batchApprove(b.batchId, b.setHash, { session: "z".repeat(43) })))).toBe("invalid_code");
    expect(await code(evil.openWindow("p1", 60, { session: "z".repeat(43) }))).toBe("invalid_code");
    expect((await gstate()).approvals).toEqual([]);
    expect((await gstate()).windows).toEqual([]);
  });
});

describe("batch in guard mode: the list is the guard's, one touch", () => {
  it("shows the list, approves all of it with one code (or the session), and leaves out what a batch must not hold", { timeout: 30_000 }, async () => {
    await setup(3);
    const prep = await h.rpc<any>("batch.prepare", { items: [{ kind: "queue", id: 1 }, { kind: "queue", id: 2 }] });
    expect(prep.items.map((i: any) => i.label)).toEqual(["p1@1.0.0", "p2@1.0.0"]);
    // the list is at the guard, before any touch
    expect((g.guard as any).db.prepare("SELECT COUNT(*) AS n FROM batches").get().n).toBe(1);
    const r = await h.rpc<any>("batch.approve", { batchId: prep.batchId, setHash: prep.setHash, code: fresh() });
    expect(r.results.map((x: any) => x.ok)).toEqual([true, true]);
    expect((await gstate()).approvals.map((a: any) => a.pluginId).sort()).toEqual(["p1", "p2"]);
    expect(await kinds("batch.approve")).toHaveLength(1);
    expect(await kinds("approved.touch")).toHaveLength(2);
    // again: spent
    await expect(h.rpc("batch.approve", { batchId: prep.batchId, setHash: prep.setHash, code: fresh() })).rejects.toThrow(/already approved/);
    // by session
    const token = await openSession();
    const third = await h.rpc<any>("batch.prepare", { items: [{ kind: "queue", id: 3 }] });
    expect(await h.rpc<any>("batch.approve", { batchId: third.batchId, setHash: third.setHash, session: token })).toMatchObject({ ok: true });
    expect((await gstate()).approvals).toHaveLength(3);
  });

  it("a list swapped between the showing and the touch is refused (another hash, another list, a changed version)", { timeout: 30_000 }, async () => {
    await setup(3);
    const a = await h.rpc<any>("batch.prepare", { items: [{ kind: "queue", id: 1 }] });
    const b = await h.rpc<any>("batch.prepare", { items: [{ kind: "queue", id: 1 }, { kind: "queue", id: 2 }, { kind: "queue", id: 3 }] });
    await expect(h.rpc("batch.approve", { batchId: b.batchId, setHash: a.setHash, code: fresh() })).rejects.toThrow(/does not match/);
    await expect(h.rpc("batch.approve", { batchId: a.batchId, setHash: b.setHash, code: fresh() })).rejects.toThrow(/does not match/);
    expect((await gstate()).approvals).toEqual([]);
    // the same through the guard's own socket: the id and the hash must be a pair
    const evil = new GuardLink(g.paths.socket);
    await expect(evil.batchApprove(b.batchId, a.setHash, fresh())).rejects.toThrow(/does not match/);
    // what the person saw is list A; a version that changed since is reported and not approved, while the list's own hash holds
    const c = await h.rpc<any>("batch.prepare", { items: [{ kind: "queue", id: 2 }, { kind: "queue", id: 3 }] });
    await g.send({ op: "decide", pluginId: "p2", version: "9.9.9", contentHash: "sha256:p2", rootDir: version("p2").rootDir, source: version("p2").source, sourceKind: "path", trigger: "install" });
    const r = await h.rpc<any>("batch.approve", { batchId: c.batchId, setHash: c.setHash, code: fresh() });
    expect(r.results.map((x: any) => [x.id, x.ok])).toEqual([[2, false], [3, true]]);
    expect((await gstate()).approvals.map((x: any) => x.pluginId)).toEqual(["p3"]);
  });

  it("a signature for one list is for that list only", { timeout: 30_000 }, async () => {
    await setup(2);
    const auth = new SoftAuthenticator();
    const e = g.guard.enrollStart("laptop");
    const first = await h.rpc<{ options: any }>("passkey.register", { token: e.token });
    await h.rpc("passkey.register", { token: e.token, ...auth.create(first.options) });
    g.guard.confirmEnrollment(e.id);
    const a = await h.rpc<any>("batch.prepare", { items: [{ kind: "queue", id: 1 }] });
    const b = await h.rpc<any>("batch.prepare", { items: [{ kind: "queue", id: 2 }] });
    const c = await h.rpc<any>("passkey.challenge", { kind: "batch.approve", batchId: a.batchId, setHash: a.setHash });
    expect(c.description).toContain("p1@1.0.0");
    const sig = auth.get(c.challenge);
    await expect(h.rpc("batch.approve", { batchId: b.batchId, setHash: b.setHash, passkey: sig })).rejects.toThrow();
    expect((await gstate()).approvals).toEqual([]);
    expect(await h.rpc("batch.approve", { batchId: a.batchId, setHash: a.setHash, passkey: sig })).toMatchObject({ ok: true });
  });
});

describe("Strict mode and a hash mismatch: no bypass, at the guard", () => {
  it("Strict: approve with acknowledgeBlock is refused by the guard, with a code and with a signature; weakening brings it back", { timeout: 40_000 }, async () => {
    g = await startGuardOnDate();
    let hh!: Booted;
    hh = await bootPlugin(g.paths.socket, { onInstall: async (src) => void (await core(g, hh, hookCtx("evil", src, `sha256:core-${src.slice(-10)}`))) });
    h = hh;
    await h.harness.behavior.runCli(["propose", plugDir("evil", "eval(atob('YWxlcnQoMSk='));\n")], { threadId: "T1" });
    const pending = (await ov()).queue[0];
    expect(pending.id).toBeLessThan(0);
    expect(await h.rpc("trust.mode", { mode: "strict" })).toMatchObject({ ok: true });
    await expect(h.rpc("queue.approve", { id: pending.id, code: fresh(), acknowledgeBlock: true })).rejects.toThrow(/Строгий/);
    expect((await gstate()).approvals).toEqual([]);
    expect((await gstate()).totp.blockedUntil).toBe(0);
    expect(await h.rpc("trust.mode", { mode: "detailed", code: fresh() })).toMatchObject({ ok: true });
    await h.rpc("queue.approve", { id: pending.id, code: fresh(), acknowledgeBlock: true });
    expect((await gstate()).approvals).toHaveLength(1);
  });

  it("a hash that did not match is never approved through acknowledgeBlock (any mode)", { timeout: 40_000 }, async () => {
    const ctx = version("demo");
    g = await startGuardOnDate({ trust: {} });
    h = await bootPlugin(g.paths.socket);
    await h.rpc("trust.add", { entries: [`path:${ctx.rootDir}`], code: fresh() }); // an own source: the guard reads the directory itself
    expect(await core(g, h, ctx)).toBe("held"); // the request's hash is not the directory's
    const q = (await ov()).queue[0];
    expect(q.reason).toMatch(/не совпал с хешем/);
    for (const mode of ["simple", "strict"] as const) {
      if (mode === "strict") await h.rpc("trust.mode", { mode });
      await expect(h.rpc("queue.approve", { id: q.id, code: fresh(), acknowledgeBlock: true }), mode).rejects.toThrow(/hash did not match/);
    }
    await expect(h.rpc("queue.approve", { id: q.id, code: fresh() })).rejects.toThrow(/hash did not match/);
    await expect(h.rpc("queue.approveTrust", { id: q.id, code: fresh() })).rejects.toThrow(/hash did not match/);
    expect((await gstate()).approvals).toEqual([]);
    expect((await gstate()).totp.blockedUntil).toBe(0);
  });
});

describe("«Вернуть и доверять источнику»: one operation", () => {
  it("one code, one operation at the guard, one journal record; the description names both parts", { timeout: 30_000 }, async () => {
    const [c] = await setup(1);
    const auth = new SoftAuthenticator();
    const e = g.guard.enrollStart("laptop");
    const first = await h.rpc<{ options: any }>("passkey.register", { token: e.token });
    await h.rpc("passkey.register", { token: e.token, ...auth.create(first.options) });
    g.guard.confirmEnrollment(e.id);
    const ch = await h.rpc<any>("passkey.challenge", { kind: "approve.trust", queueId: 1 });
    expect(ch.description).toContain("Одобрить версию");
    expect(ch.description).toContain(`path:${c!.rootDir}`);
    expect(ch.description).toContain("«мои источники»");
    const before = (await gstate()).journal.recent.length;
    const r = await h.rpc<any>("queue.approveTrust", { id: 1, passkey: auth.get(ch.challenge) });
    expect(r).toMatchObject({ ok: true, entry: `path:${c!.rootDir}` });
    const st = await gstate();
    expect(st.approvals.map((a: any) => a.pluginId)).toEqual(["p1"]);
    expect(st.trust.mySources).toEqual([`path:${c!.rootDir}`]);
    expect(await kinds("approved.trust")).toHaveLength(1);
    expect(await kinds("approved.touch")).toHaveLength(0);
    expect(await kinds("sources.add")).toHaveLength(0);
    expect(st.journal.recent.length - before).toBe(1); // one record for the whole operation
    // a version that is already approved cannot be approved again
    await expect(h.rpc("queue.approveTrust", { id: 1, code: fresh() })).rejects.toThrow();
  });

  it("with a code or a touch, never with a session, and not for a version that is not an entry of the guard", { timeout: 30_000 }, async () => {
    await setup(1);
    const token = await openSession();
    await expect(h.rpc("queue.approveTrust", { id: 1, session: token } as never)).rejects.toThrow();
    await expect(h.rpc("queue.approveTrust", { id: 1 })).rejects.toThrow(/code|touch/);
    await expect(h.rpc("queue.approveTrust", { id: -1, code: fresh() })).rejects.toThrow(); // a proposal the core has not asked about: no such entry yet
    expect(await h.rpc("queue.approveTrust", { id: 1, code: fresh() })).toMatchObject({ ok: true });
    expect((await gstate()).trust.mySources).toHaveLength(1);
  });
});

describe("troubleshooting mode on the page and in the hook", () => {
  it("everything loads, the page says so (red bar data), the hook stands aside; it returns by itself and the journal has each decision", { timeout: 30_000 }, async () => {
    await setup(1);
    const stranger = version("stranger");
    expect(await core(g, h, stranger)).toBe("held");
    const until = g.guard.troubleshootStart(30, fresh()).until;
    expect((await ov()).guard.troubleshootUntil).toBe(until);
    expect(await core(g, h, stranger)).toBe("load");
    expect(await core(g, h, version("other"), "hooks-first")).toBe("load");
    const passes = await kinds("troubleshoot.pass");
    expect(passes.length).toBeGreaterThanOrEqual(2);
    expect(passes.every((p) => typeof p.detail.wouldHave === "string")).toBe(true);
    // a stop of the plugin's own (hard flag) is passed as well: "everything"
    const evil = hookCtx("evil", plugDir("evil", "eval(atob('YWxlcnQoMSk='));\n"), "sha256:evil");
    expect(await core(g, h, evil)).toBe("load");
    // time passes: it is over by itself, and what was held before is held again
    tick(31 * 60_000);
    expect(await core(g, h, stranger)).toBe("held");
    expect((await ov()).guard.troubleshootUntil).toBe(0);
    expect((await kinds("troubleshoot.end"))[0]!.detail).toMatchObject({ reason: "expired" });
    expect((await gstate()).troubleshoot).toBeNull();
  });
});
