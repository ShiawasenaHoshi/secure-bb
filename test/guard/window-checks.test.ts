// An open window at the guard lets a version in only if the same stands as when the plugin runs: no hard sign, no right the approved version did not have,
// and a thread-bound window only while the plugin calls the guard («beat»). What the guard cannot read, it does not let in without the plugin.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PLUGIN_ALIVE_MS, WINDOW_PAUSED_NOTE } from "../../guard/src/guard.ts";
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
const NET = `export default function plugin(bb) {\n  bb.log.info("hello");\n  fetch("https://api.example/x");\n}\n`;
function write(dir: string, name: string, server: string): string {
  const d = join(dir, name);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "package.json"), JSON.stringify({ name, version: "1.0.0", bb: { name, server: "./server.ts" } }));
  writeFileSync(join(d, "server.ts"), server);
  return d;
}
const decideOf = (rootDir: string, pluginId: string, version = "1.0.0") => ({ op: "decide", pluginId, version, contentHash: coreHash(rootDir), rootDir, source: `path:${rootDir}`, sourceKind: "path", provenance: "direct", trigger: "update" });

async function setup() {
  const plugins = tmp("sbb-wc-");
  const g: TestGuard = await startGuard({ trust: {}, pluginAlive: false });
  cleanup.push(() => g.close());
  const dir = write(plugins, "p", QUIET);
  const first = await g.send(decideOf(dir, "p"));
  await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() });
  const noteOf = async (requestId: number): Promise<string> => (((await g.send({ op: "state" })).queue as any[]).find((q) => q.id === requestId)?.note ?? "") as string;
  const set = (server: string) => writeFileSync(join(dir, "server.ts"), server);
  return { g, dir, set, noteOf };
}

describe("a window at the guard, without the plugin", () => {
  it("a window over everything: eval(atob) + fetch is held, the reason is the hard sign, and the window does not lift it later", async () => {
    const { g, dir, set, noteOf } = await setup();
    g.guard.openWindow({ pluginId: "p", minutes: 30, code: g.nextCode() });
    set(LOUD);
    const r = await g.send(decideOf(dir, "p", "1.0.1"));
    expect(r.action).toBe("wait");
    expect(await noteOf(r.requestId)).toMatch(/жёсткий флаг/);
    // asked again: still held (a stop), not let in by the window
    expect((await g.send(decideOf(dir, "p", "1.0.1"))).action).toBe("wait");
  });

  it("a window over everything: a new right is held", async () => {
    const { g, dir, set, noteOf } = await setup();
    g.guard.openWindow({ pluginId: "p", minutes: 30, code: g.nextCode() });
    set(NET);
    const r = await g.send(decideOf(dir, "p", "1.0.1"));
    expect(r.action).toBe("wait");
    expect(await noteOf(r.requestId)).toMatch(/новое право: .*net/);
    // a human's code lets it in, and the right is then the baseline: the next version with the same right passes
    await g.send({ op: "approve", requestId: r.requestId, code: g.nextCode() });
    set(`${NET}// again\n`);
    expect(await g.send(decideOf(dir, "p", "1.0.2"))).toMatchObject({ action: "proceed", via: "window" });
  });

  it("a window over everything: a clean version of the same source with no new rights passes", async () => {
    const { g, dir, set } = await setup();
    g.guard.openWindow({ pluginId: "p", minutes: 30, code: g.nextCode() });
    set(`${QUIET}// a comment\n`);
    expect(await g.send(decideOf(dir, "p", "1.0.1"))).toMatchObject({ action: "proceed", via: "window" });
  });

  it("a window bound to a thread or tree: held with the reason, even a clean version", async () => {
    for (const scope of ["tree", "thread"]) {
      const { g, dir, set, noteOf } = await setup();
      g.guard.openWindow({ pluginId: "p", minutes: 30, scope, code: g.nextCode() });
      set(`${QUIET}// a comment\n`);
      const r = await g.send(decideOf(dir, "p", "1.0.1"));
      expect(r.action, scope).toBe("wait");
      expect(await noteOf(r.requestId)).toBe(WINDOW_PAUSED_NOTE);
    }
  });

  it("a window bound to a thread: the plugin's pulse lifts the pause, and silence for too long brings it back", async () => {
    const { g, dir, set } = await setup();
    g.guard.openWindow({ pluginId: "p", minutes: 30, scope: "tree", code: g.nextCode() });
    set(`${QUIET}// one\n`);
    expect(await g.send({ op: "beat" })).toMatchObject({ ok: true });
    // alive: as before (the plugin's hook vets it and withdraws a window approval it does not like)
    expect(await g.send(decideOf(dir, "p", "1.0.1"))).toMatchObject({ action: "proceed", via: "window" });
    g.clock.advance(PLUGIN_ALIVE_MS + 1000);
    set(`${QUIET}// two\n`);
    expect((await g.send(decideOf(dir, "p", "1.0.2"))).action).toBe("wait");
    await g.send({ op: "beat" });
    set(`${QUIET}// three\n`);
    expect((await g.send(decideOf(dir, "p", "1.0.3"))).action).toBe("proceed");
  });

  it("a window opened before the scope was recorded counts as bound to a thread", async () => {
    const { g, dir, set, noteOf } = await setup();
    const w = g.guard.openWindow({ pluginId: "p", minutes: 30, code: g.nextCode() });
    (g.guard as any).db.prepare(`UPDATE windows SET scope = NULL WHERE id = ?`).run(w.id);
    set(`${QUIET}// c\n`);
    const r = await g.send(decideOf(dir, "p", "1.0.1"));
    expect(r.action).toBe("wait");
    expect(await noteOf(r.requestId)).toBe(WINDOW_PAUSED_NOTE);
  });

  it("a version the guard cannot read is not let in by a window without the plugin", async () => {
    const { g, dir, set, noteOf } = await setup();
    g.guard.openWindow({ pluginId: "p", minutes: 30, code: g.nextCode() });
    set(QUIET);
    const r = await g.send({ ...decideOf(dir, "p", "1.0.1"), contentHash: "sha256:" + "0".repeat(64) });
    expect(r.action).toBe("wait");
    expect(await noteOf(r.requestId)).toMatch(/^окно: /);
  });
});
