// UX v1, PR 3 at the guard: approval sessions, one touch for a fixed list, wrong signatures apart from wrong codes, troubleshooting mode,
// no bypass in Strict mode or on a hash mismatch, and «вернуть и доверять» as ONE operation.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main, type Io } from "../../guard/src/cli.ts";
import { MAX_TROUBLESHOOT_MIN, SESSION_CAP_MS, SESSION_IDLE_MS, type TrustConfig } from "../../guard/src/guard.ts";
import { coreHash, decideReq, enrollKey, SoftAuthenticator, startGuard, startGuardOnDate, touchFor, type TestGuard } from "./support.ts";

let g: TestGuard;
const cleanup: string[] = [];
afterEach(async () => {
  await g?.close();
  for (const d of cleanup.splice(0)) rmSync(d, { recursive: true, force: true });
});

const H = (c: string): string => c.repeat(64);
const kinds = (): Array<{ kind: string; detail: any }> => (g.guard.state().journal as { recent: Array<{ kind: string; detail: any }> }).recent;
const ofKind = (k: string) => kinds().filter((r) => r.kind === k);
const state = async () => g.send({ op: "state" });
const sha = (t: string): string => createHash("sha256").update(t, "utf8").digest("hex");

/** A guard with `n` held versions of different plugins (#1…#n). */
async function held(n: number, opts: Parameters<typeof startGuard>[0] = {}): Promise<void> {
  g = await startGuard(opts);
  for (let i = 1; i <= n; i++) await g.send(decideReq({ pluginId: `p${i}`, contentHash: H(String(i)), rootDir: `/tmp/p${i}`, source: `path:/tmp/p${i}` }));
}
const openSession = async (): Promise<string> => {
  const r = await g.send({ op: "session-open", code: g.nextCode() });
  expect(r).toMatchObject({ ok: true, idleMs: SESSION_IDLE_MS, capMs: SESSION_CAP_MS });
  return r.token as string;
};

// --------------------------------------------------------------------------------------------------------- sessions
describe("approval session at the guard", () => {
  it("one touch opens it; routine actions then pass without a code, and the journal says so", async () => {
    await held(3);
    const token = await openSession();
    expect(await g.send({ op: "approve", requestId: 1, session: token })).toMatchObject({ ok: true });
    expect(await g.send({ op: "open-window", pluginId: "p2", minutes: 10, session: token })).toMatchObject({ ok: true });
    expect(await g.send({ op: "touch", purpose: "watch.accept", session: token })).toMatchObject({ ok: true });
    expect(await g.send({ op: "touch", purpose: "skills.approve", session: token })).toMatchObject({ ok: true });
    const ap = ofKind("approved.touch")[0]!;
    expect(ap.detail).toMatchObject({ via: "session" });
    expect(ofKind("session.open")).toHaveLength(1);
    expect(ofKind("session.open")[0]!.detail).toMatchObject({ via: "totp" });
  });

  it("«на час»: the end is the ceiling from the start, a use does not shorten it, and it never goes past the ceiling", async () => {
    await held(2);
    const r = await g.send({ op: "session-open", hour: true, code: g.nextCode() });
    expect(r).toMatchObject({ ok: true, idleMs: SESSION_CAP_MS, capMs: SESSION_CAP_MS });
    const before = (await state()).sessions[0];
    expect(before.expiresAt - before.openedAt).toBe(SESSION_CAP_MS);
    expect(await g.send({ op: "approve", requestId: 1, session: r.token as string })).toMatchObject({ ok: true });
    const after = (await state()).sessions[0];
    expect(after.expiresAt).toBe(before.expiresAt);
    expect(after.expiresAt).toBeLessThanOrEqual(after.hardExpiresAt);
    expect(ofKind("session.open")[0]!.detail).toMatchObject({ hour: true });
    // the 15-minute session is unchanged: it ends 15 minutes after the open
    const r2 = await g.send({ op: "session-open", code: g.nextCode() });
    expect(r2).toMatchObject({ idleMs: SESSION_IDLE_MS });
  });

  it("the token is not in the state, the journal, or any answer but the first; the guard keeps a hash", async () => {
    await held(2);
    const token = await openSession();
    await g.send({ op: "approve", requestId: 1, session: token });
    const all = JSON.stringify([await state(), g.guard.state(), kinds()]);
    expect(all).not.toContain(token);
    expect(all).not.toContain(sha(token));
    // a record of the session (without its secret) is visible to the page
    expect((await state()).sessions).toHaveLength(1);
    expect(Object.keys((await state()).sessions[0]).sort()).toEqual(["expiresAt", "hardExpiresAt", "id", "openedAt", "uses"]);
    const row = (g.guard as any).db.prepare("SELECT token_hash FROM sessions").get() as { token_hash: string };
    expect(row.token_hash).toBe(sha(token));
  });

  it("dangerous actions always need a fresh touch: a session does not cover them, and being refused does not count as a wrong code", async () => {
    await held(2);
    expect(await g.send({ op: "trust-mode", mode: "strict", code: g.nextCode() })).toMatchObject({ ok: true }); // tightening needs no touch, but a code is welcome
    const token = await openSession();
    const dangerous: Array<Record<string, unknown>> = [
      { op: "approve", requestId: 1, acknowledgeBlock: true },
      { op: "approve-trust", requestId: 1 },
      { op: "trust-mode", mode: "simple" },
      { op: "sources-add", entries: ["github:octo/demo"] },
      { op: "policy", patch: { windowMin: 600, capMin: 900 } },
      { op: "touch", purpose: "policy.set" },
      { op: "touch", purpose: "agents.accept" },
      { op: "agents-accept", ids: [1] },
      { op: "session-open" },
    ];
    for (let round = 0; round < 3; round++) for (const a of dangerous) expect(await g.send({ ...a, session: token }), JSON.stringify(a)).toMatchObject({ ok: false, error: { code: expect.stringMatching(/invalid_code|invalid|not_found|conflict/) } });
    // nothing was changed, and the page's wrong guesses did not block anything
    expect((await state()).approvals).toEqual([]);
    expect((await state()).totp.blockedUntil).toBe(0);
    expect((await state()).policy).toMatchObject({ windowMin: 30, capMin: 240 });
    expect((await state()).trust).toMatchObject({ mode: "strict", mySources: [] });
    // the same actions with a fresh code do work (the policy widening here)
    expect(await g.send({ op: "policy", patch: { windowMin: 60 }, code: g.nextCode() })).toMatchObject({ ok: true });
  });

  it("a harmful plugin without the token gets nothing: no proof, a wrong token, the hash of the token, a closed session", async () => {
    await held(2);
    const token = await openSession();
    expect(await g.send({ op: "approve", requestId: 1 })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    expect(await g.send({ op: "approve", requestId: 1, session: "x".repeat(43) })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    expect(await g.send({ op: "approve", requestId: 1, session: sha(token) })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    expect(await g.send({ op: "open-window", pluginId: "p1", minutes: 5, session: 1 })).toMatchObject({ ok: false });
    expect((await state()).approvals).toEqual([]);
    // wrong tokens are wrong codes: the same counter and the same hour of blocking
    expect(ofKind("totp.fail").length).toBeGreaterThanOrEqual(2);
    await g.send({ op: "session-close" });
    expect(await g.send({ op: "approve", requestId: 1, session: token })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    expect((await state()).sessions).toEqual([]);
  });

  it("idle 15 minutes (sliding), ceiling 1 hour, and closing is free", async () => {
    await held(4);
    const token = await openSession();
    g.clock.advance(SESSION_IDLE_MS - 1000);
    expect((await g.send({ op: "approve", requestId: 1, session: token })).ok).toBe(true); // slides
    g.clock.advance(SESSION_IDLE_MS - 1000);
    expect((await g.send({ op: "approve", requestId: 2, session: token })).ok).toBe(true);
    // never past the ceiling, however busy
    for (let i = 0; i < 4; i++) g.clock.advance(SESSION_IDLE_MS - 1000), await g.send({ op: "touch", purpose: "watch.accept", session: token });
    g.clock.advance(SESSION_CAP_MS);
    expect(await g.send({ op: "approve", requestId: 3, session: token })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    expect(ofKind("session.expire").length).toBeGreaterThan(0);
    // a new one: closing needs no touch and no code
    const t2 = await openSession();
    expect(await g.send({ op: "session-close" })).toMatchObject({ ok: true, closed: 1 });
    expect(await g.send({ op: "approve", requestId: 3, session: t2 })).toMatchObject({ ok: false });
    // opening a new one closes the old one: there is one
    const a = await openSession();
    const b = await openSession();
    expect(await g.send({ op: "approve", requestId: 3, session: a })).toMatchObject({ ok: false });
    expect(await g.send({ op: "approve", requestId: 3, session: b })).toMatchObject({ ok: true });
  });

  it("a passkey touch opens a session too, bound to the action; a session cannot open a session", async () => {
    await held(1);
    const auth = new SoftAuthenticator();
    await enrollKey(g, auth);
    const t = await touchFor(g, auth, { op: "session-open" });
    expect(t.challenge.description).toContain("сессию");
    const r = await g.send({ op: "session-open", passkey: t.passkey });
    expect(r).toMatchObject({ ok: true });
    expect(ofKind("session.open")[0]!.detail).toMatchObject({ via: "passkey" });
    expect(await g.send({ op: "session-open", session: r.token })).toMatchObject({ ok: false });
    // a signature made for another action cannot open a session
    const other = await touchFor(g, auth, { op: "approve", requestId: 1 });
    expect(await g.send({ op: "session-open", passkey: other.passkey })).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });
  });
});

// ----------------------------------------------------------------------------------------------------------- batch
describe("batch: the list is fixed at the guard, one touch for all of it", () => {
  it("one code approves the whole list, and is spent once", async () => {
    await held(3);
    const p = await g.send({ op: "batch-prepare", items: [{ kind: "queue", id: 1 }, { kind: "queue", id: 2 }] });
    expect(p).toMatchObject({ ok: true });
    expect(p.items.map((i: any) => i.label)).toEqual(["p1@1.0.0", "p2@1.0.0"]);
    const code = g.nextCode();
    const r = await g.send({ op: "batch-approve", batchId: p.batchId, setHash: p.setHash, code });
    expect(r.results.map((x: any) => x.ok)).toEqual([true, true]);
    expect((await state()).approvals.map((a: any) => a.pluginId).sort()).toEqual(["p1", "p2"]);
    expect(ofKind("approved.touch")).toHaveLength(2);
    expect(ofKind("batch.approve")).toHaveLength(1);
    // the list and the code are spent: the same list again, or another entry with the same code, does nothing
    expect(await g.send({ op: "batch-approve", batchId: p.batchId, setHash: p.setHash, code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(await g.send({ op: "approve", requestId: 3, code })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
  });

  it("a swapped list between the showing and the touch is refused: another list's hash, another list's id, a signature for another list", async () => {
    await held(3);
    const auth = new SoftAuthenticator();
    await enrollKey(g, auth);
    const a = await g.send({ op: "batch-prepare", items: [{ kind: "queue", id: 1 }] });
    const b = await g.send({ op: "batch-prepare", items: [{ kind: "queue", id: 1 }, { kind: "queue", id: 2 }, { kind: "queue", id: 3 }] });
    expect(a.setHash).not.toBe(b.setHash);
    // what the person saw is A (its hash); the request names B's items — the touch can only name an id and a hash, and they must be a pair
    expect(await g.send({ op: "batch-approve", batchId: b.batchId, setHash: a.setHash, code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(await g.send({ op: "batch-approve", batchId: a.batchId, setHash: b.setHash, code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(await g.send({ op: "batch-approve", batchId: "f".repeat(24), setHash: a.setHash, code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "not_found" } });
    // a signature for list A is for A only
    const sig = await touchFor(g, auth, { op: "batch-approve", batchId: a.batchId, setHash: a.setHash });
    expect(sig.challenge.description).toContain("p1@1.0.0");
    expect(await g.send({ op: "batch-approve", batchId: b.batchId, setHash: b.setHash, passkey: sig.passkey })).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });
    expect((await state()).approvals).toEqual([]);
    expect(await g.send({ op: "batch-approve", batchId: a.batchId, setHash: a.setHash, passkey: sig.passkey })).toMatchObject({ ok: true });
    expect((await state()).approvals.map((x: any) => x.pluginId)).toEqual(["p1"]);
  });

  it("an item that changed after it was shown is not approved; the rest are", async () => {
    await held(2);
    const p = await g.send({ op: "batch-prepare", items: [{ kind: "queue", id: 1 }, { kind: "queue", id: 2 }] });
    // #1 is asked about again with another version while the list waits
    await g.send(decideReq({ pluginId: "p1", contentHash: H("1"), rootDir: "/tmp/p1", source: "path:/tmp/p1", version: "9.9.9" }));
    const r = await g.send({ op: "batch-approve", batchId: p.batchId, setHash: p.setHash, code: g.nextCode() });
    expect(r.results.map((x: any) => [x.id, x.ok])).toEqual([[1, false], [2, true]]);
    expect(r.results[0].note).toContain("изменилось");
    expect((await state()).approvals.map((a: any) => a.pluginId)).toEqual(["p2"]);
  });

  it("a session covers a batch; a list expires; blocks and mismatches do not go into a list", async () => {
    await held(2);
    const token = await openSession();
    const p = await g.send({ op: "batch-prepare", items: [{ kind: "queue", id: 1 }, { kind: "queue", id: 2 }] });
    expect(await g.send({ op: "batch-approve", batchId: p.batchId, setHash: p.setHash, session: token })).toMatchObject({ ok: true });
    expect(ofKind("approved.touch")[0]!.detail).toMatchObject({ via: "session", batch: p.batchId });
    await g.send(decideReq({ pluginId: "p3", contentHash: H("3"), rootDir: "/tmp/p3", source: "path:/tmp/p3" }));
    const q = await g.send({ op: "batch-prepare", items: [{ kind: "queue", id: 3 }] });
    g.clock.advance(11 * 60_000);
    expect(await g.send({ op: "batch-approve", batchId: q.batchId, setHash: q.setHash, code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "conflict" } });
    // nothing to put in: refused with the reasons
    expect(await g.send({ op: "batch-prepare", items: [{ kind: "queue", id: 1 }] })).toMatchObject({ ok: false, error: { message: expect.stringContaining("nothing in the list") } });
  });
});

// ------------------------------------------------------------------------------- Strict, mismatch, block lifting
describe("no bypass at the guard: Strict mode and a hash mismatch", () => {
  const tmp = (): string => {
    const d = realpathSync(mkdtempSync(join(tmpdir(), "sbb-pr3-")));
    cleanup.push(d);
    return d;
  };
  const plugin = (dir: string, name: string, server: string): string => {
    const d = join(dir, name);
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "package.json"), JSON.stringify({ name, version: "1.0.0", bb: { name, server: "./server.ts" } }));
    writeFileSync(join(d, "server.ts"), server);
    return d;
  };
  const BASE = `export default function plugin(bb) {\n  bb.log.info("hello");\n}\n`;
  const EVAL = `const code = atob("YWxlcnQoMSk=");\neval(code);\n`;
  const decideOf = (rootDir: string, over: Record<string, unknown> = {}) => decideReq({ pluginId: "demo", rootDir, source: `path:${rootDir}`, contentHash: coreHash(rootDir), ...over });
  const trustCfg: TrustConfig = {};

  /** A version of an own source with a hard flag (waits, with the guard's own note about it). */
  async function flagged(): Promise<number> {
    g = await startGuard({ trust: trustCfg });
    const dir = tmp();
    const d = plugin(dir, "demo", BASE);
    await g.send({ op: "sources-add", entries: [`path:${dir}`], code: g.nextCode() });
    const first = await g.send(decideOf(d));
    await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() });
    writeFileSync(join(d, "server.ts"), EVAL);
    const second = await g.send(decideOf(d, { version: "1.0.1" }));
    expect(second).toMatchObject({ action: "wait" });
    expect((await state()).queue.find((q: any) => q.id === second.requestId).note).toContain("жёсткий флаг");
    return second.requestId as number;
  }
  /** A version whose request carries a hash other than the one of the directory: the guard's note says it did not match. */
  async function mismatched(): Promise<number> {
    g = await startGuard({ trust: trustCfg });
    const dir = tmp();
    const d = plugin(dir, "demo", BASE);
    await g.send({ op: "sources-add", entries: [`path:${dir}`], code: g.nextCode() });
    const first = await g.send(decideOf(d));
    await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() });
    const r = await g.send(decideOf(d, { version: "1.0.1", contentHash: `sha256:${"d".repeat(64)}` }));
    expect(r).toMatchObject({ action: "wait" });
    expect((await state()).queue.find((q: any) => q.id === r.requestId).note).toMatch(/не совпал с хешем/);
    return r.requestId as number;
  }

  it("a hard flag is lifted only with acknowledgeBlock and a fresh touch — never by a session or a plain approve", async () => {
    const id = await flagged();
    const token = await openSession();
    expect(await g.send({ op: "approve", requestId: id, session: token })).toMatchObject({ ok: false });
    expect(await g.send({ op: "approve", requestId: id, code: g.nextCode() })).toMatchObject({ ok: false, error: { message: expect.stringContaining("acknowledgeBlock") } });
    expect(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, session: token })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    expect(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, code: g.nextCode() })).toMatchObject({ ok: true });
    expect(ofKind("approved.touch")[0]!.detail).toMatchObject({ acknowledgeBlock: true, via: "totp" });
  });

  it("in Strict mode approve with acknowledgeBlock is refused by the guard, with a code and with a signature", async () => {
    const id = await flagged();
    const auth = new SoftAuthenticator();
    await enrollKey(g, auth);
    expect(await g.send({ op: "trust-mode", mode: "strict", code: g.nextCode() })).toMatchObject({ ok: true });
    const code = g.nextCode();
    expect(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, code })).toMatchObject({ ok: false, error: { message: expect.stringContaining("Строгий") } });
    const sig = await touchFor(g, auth, { op: "approve", requestId: id, acknowledgeBlock: true });
    expect(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, passkey: sig.passkey })).toMatchObject({ ok: false, error: { message: expect.stringContaining("Строгий") } });
    // the refusal did not spend the code and did not count as a wrong one
    expect((await state()).totp.blockedUntil).toBe(0);
    expect((await state()).approvals.map((a: any) => a.version)).toEqual(["1.0.0"]);
    // weakening the mode (a touch) brings the bypass back
    expect(await g.send({ op: "trust-mode", mode: "detailed", code: g.nextCode() })).toMatchObject({ ok: true });
    expect(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, code: g.nextCode() })).toMatchObject({ ok: true });
  });

  it("a hash mismatch is never approved through acknowledgeBlock — in any mode, by a code or a signature", async () => {
    const id = await mismatched();
    const auth = new SoftAuthenticator();
    await enrollKey(g, auth);
    for (const mode of ["simple", "detailed", "strict"] as const) {
      if (mode !== "simple") await g.send({ op: "trust-mode", mode, code: g.nextCode() });
      expect(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, code: g.nextCode() }), mode).toMatchObject({ ok: false, error: { message: expect.stringContaining("hash did not match") } });
      const sig = await touchFor(g, auth, { op: "approve", requestId: id, acknowledgeBlock: true });
      expect(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, passkey: sig.passkey }), mode).toMatchObject({ ok: false });
    }
    expect(await g.send({ op: "approve", requestId: id, code: g.nextCode() })).toMatchObject({ ok: false });
    expect(await g.send({ op: "approve-trust", requestId: id, code: g.nextCode() })).toMatchObject({ ok: false });
    expect(await g.send({ op: "batch-prepare", items: [{ kind: "queue", id }] })).toMatchObject({ ok: false });
    expect((await state()).approvals.map((a: any) => a.version)).toEqual(["1.0.0"]);
    expect((await state()).totp.blockedUntil).toBe(0);
  });
});

// ------------------------------------------------------------------------------- «вернуть и доверять источнику»
describe("«Вернуть и доверять источнику»: one touch, one operation, one record", () => {
  it("approves the version and adds its source, names both in the description, writes one record", async () => {
    await held(1);
    const auth = new SoftAuthenticator();
    await enrollKey(g, auth);
    const before = kinds().length;
    const t = await touchFor(g, auth, { op: "approve-trust", requestId: 1 });
    expect(t.challenge.description).toContain("Одобрить версию");
    expect(t.challenge.description).toContain("path:/tmp/p1");
    expect(t.challenge.description).toContain("«мои источники»");
    const r = await g.send({ op: "approve-trust", requestId: 1, passkey: t.passkey });
    expect(r).toMatchObject({ ok: true, entry: "path:/tmp/p1", mySources: ["path:/tmp/p1"] });
    expect((await state()).approvals.map((a: any) => a.pluginId)).toEqual(["p1"]);
    expect((await state()).trust.mySources).toEqual(["path:/tmp/p1"]);
    // ONE journal record for the whole operation (the plain `approved.touch` and `sources.add` are not written)
    const fresh = kinds().slice(0, kinds().length - before).filter((k) => !k.kind.startsWith("passkey."));
    expect(fresh.map((k) => k.kind).filter((k) => k !== "hold")).toEqual(["approved.trust"]);
    expect(ofKind("approved.touch")).toHaveLength(0);
    expect(ofKind("sources.add")).toHaveLength(0);
    expect(ofKind("approved.trust")[0]!.detail).toMatchObject({ trustedSource: "path:/tmp/p1", version: "1.0.0", via: "passkey" });
  });

  it("a code does it too; a signature made for the plain approve does not; the source is the guard's reading of the entry, not the caller's", async () => {
    await held(2);
    const auth = new SoftAuthenticator();
    await enrollKey(g, auth);
    const plain = await touchFor(g, auth, { op: "approve", requestId: 1 });
    expect(await g.send({ op: "approve-trust", requestId: 1, passkey: plain.passkey })).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });
    // a caller cannot name another source: the entry comes from the queue (an `entry` in the request is ignored)
    const r = await g.send({ op: "approve-trust", requestId: 2, entry: "github:evil/evil", code: g.nextCode() });
    expect(r).toMatchObject({ ok: true, entry: "path:/tmp/p2" });
    expect((await state()).trust.mySources).toEqual(["path:/tmp/p2"]);
  });

  it("a source that cannot be named is refused before anything is spent", async () => {
    g = await startGuard();
    await g.send(decideReq({ source: "npm:demo@1.0.0", sourceKind: "npm" }));
    const code = g.nextCode();
    expect(await g.send({ op: "approve-trust", requestId: 1, code })).toMatchObject({ ok: false, error: { code: "invalid" } });
    expect((await state()).approvals).toEqual([]);
    expect(await g.send({ op: "approve", requestId: 1, code })).toMatchObject({ ok: true }); // the code was not spent
  });
});

// ------------------------------------------------------------------------------------------ troubleshooting mode
describe("troubleshooting mode: the console and a code, passes everything, writes everything, returns by itself", () => {
  it("there is no op for it on the socket, and no off switch of the guard", async () => {
    await held(1);
    for (const op of ["troubleshoot", "troubleshoot-start", "troubleshoot-stop", "debug", "disable", "off", "stop", "pause"]) expect(await g.send({ op, minutes: 30, code: g.nextCode() }), op).toMatchObject({ ok: false, error: { code: "unknown_op" } });
    expect((await state()).troubleshoot).toBeNull();
  });

  it("starts from the console with a code, passes everything, journals each decision with what it would have been", async () => {
    await held(1);
    expect(() => g.guard.troubleshootStart(30, "000000")).toThrow(/invalid or already used code/);
    expect(() => g.guard.troubleshootStart(0, g.nextCode())).toThrow();
    expect(() => g.guard.troubleshootStart(MAX_TROUBLESHOOT_MIN + 1, g.nextCode())).toThrow();
    expect(g.guard.troubleshootUntil()).toBe(0);
    const until = g.guard.troubleshootStart(30, g.nextCode()).until;
    expect(until).toBe(g.clock.t + 30 * 60_000);
    expect((await state()).troubleshoot).toEqual({ until });
    // an unknown plugin passes (and nothing is queued or approved for it)
    const d = await g.send(decideReq({ pluginId: "stranger", contentHash: H("e"), rootDir: "/tmp/s", source: "path:/tmp/s" }));
    expect(d).toMatchObject({ ok: true, action: "proceed", via: "troubleshoot" });
    expect((await state()).queue.some((q: any) => q.pluginId === "stranger")).toBe(false);
    expect((await state()).approvals).toEqual([]);
    // an approved one and one with an open window pass too; each is its own record, with what the normal decision would have been
    await g.send({ op: "approve", requestId: 1, code: g.nextCode() });
    await g.send({ op: "open-window", pluginId: "w", minutes: 5, code: g.nextCode() });
    await g.send(decideReq({ pluginId: "p1", contentHash: H("1"), rootDir: "/tmp/p1", source: "path:/tmp/p1" }));
    await g.send(decideReq({ pluginId: "w", contentHash: H("w"), rootDir: "/tmp/w", source: "path:/tmp/w" }));
    await g.send(decideReq({ pluginId: "stranger", contentHash: H("e"), rootDir: "/tmp/s", source: "path:/tmp/s", version: "2.0.0" }));
    const passes = ofKind("troubleshoot.pass");
    expect(passes.map((p) => p.detail.wouldHave).sort()).toEqual(["approval", "wait", "wait", "window"]);
    expect(passes.every((p) => typeof p.detail.version === "string" && typeof p.detail.source === "string" && typeof p.detail.rootDir === "string")).toBe(true);
    expect(ofKind("troubleshoot.start")).toHaveLength(1);
    // lookup says so (the plugin's own hook passes and says so too)
    expect(await g.send({ op: "lookup", pluginId: "x", contentHash: H("f") })).toMatchObject({ ok: true, troubleshootUntil: until });
  });

  it("returns by itself: after the time the guard holds again and the end is in the journal", async () => {
    await held(1);
    g.guard.troubleshootStart(5, g.nextCode());
    expect(await g.send(decideReq({ pluginId: "s", contentHash: H("e"), rootDir: "/tmp/s", source: "path:/tmp/s" }))).toMatchObject({ action: "proceed" });
    g.clock.advance(5 * 60_000 + 1);
    const d = await g.send(decideReq({ pluginId: "s", contentHash: H("e"), rootDir: "/tmp/s", source: "path:/tmp/s" }));
    expect(d).toMatchObject({ action: "wait" });
    expect(ofKind("troubleshoot.end")[0]!.detail).toMatchObject({ reason: "expired" });
    expect((await state()).troubleshoot).toBeNull();
    // the background pass also ends it, with nobody asking
    g.guard.troubleshootStart(5, g.nextCode());
    g.clock.advance(5 * 60_000 + 1);
    g.guard.sweep();
    expect(ofKind("troubleshoot.end")).toHaveLength(2);
    // and the console can end it early, without a code
    g.guard.troubleshootStart(5, g.nextCode());
    expect(g.guard.troubleshootStop()).toBe(true);
    expect(g.guard.troubleshootStop()).toBe(false);
    expect(await g.send(decideReq({ pluginId: "s", contentHash: H("e"), rootDir: "/tmp/s", source: "path:/tmp/s" }))).toMatchObject({ action: "wait" });
  });

});

describe("`sbb-guard troubleshoot` on the console", () => {
  const out: string[] = [];
  const io = (answer: string | null): Io => ({ out: (t) => void out.push(t), err: () => undefined, ask: async () => answer });
  afterEach(() => vi.useRealTimers());
  it("asks for a code, refuses nonsense, and is not an off switch", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    g = await startGuardOnDate();
    const tick = (): string => (vi.setSystemTime(Date.now() + 31_000), g.code());
    const cli = (args: string[], answer: string | null = null) => main(["--data", g.paths.dataDir, ...args], io(answer));
    expect(await cli(["troubleshoot", "abc"])).toBe(64);
    expect(await cli(["troubleshoot"])).toBe(64);
    expect(await cli(["troubleshoot", "30"], null)).toBe(1); // no terminal, no code
    expect(await cli(["troubleshoot", "30m"], "000000")).toBe(1); // a wrong code
    expect(g.guard.troubleshootUntil()).toBe(0);
    expect(await cli(["troubleshoot", "30m"], tick())).toBe(0);
    expect(out.join("\n")).toContain("Troubleshooting mode until");
    expect(g.guard.troubleshootUntil()).toBeGreaterThan(Date.now());
    // the guard still answers and still holds what it is not asked to pass: approvals need their touch as before
    expect(await g.send({ op: "approve", requestId: 1 })).toMatchObject({ ok: false });
    expect(await cli(["troubleshoot", "off"], null)).toBe(0);
    expect(g.guard.troubleshootUntil()).toBe(0);
  });
});
