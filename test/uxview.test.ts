// UX v1, PR 2: what the page learns about a held version (the author's why, the thread chain, how far the source is trusted).
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { queueUx, readWhy } from "../src/uxview.ts";

const dirs: string[] = [];
const dir = (): string => {
  const d = mkdtempSync(join(tmpdir(), "sbb-uxview-"));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const plugin = (pkg: unknown): string => {
  const d = dir();
  writeFileSync(join(d, "package.json"), typeof pkg === "string" ? pkg : JSON.stringify(pkg));
  return d;
};

describe("secureBb.why", () => {
  it("is read from package.json and cleaned", async () => {
    expect(await readWhy(plugin({ name: "p", secureBb: { why: "загружаю превью макетов" } }))).toBe("загружаю превью макетов");
    expect(await readWhy(plugin({ secureBb: { why: "a‮b\nc" } }))).toBe("a b c");
  });
  it("is nothing when absent, not a string, invalid JSON, missing, a directory or too big", async () => {
    expect(await readWhy(plugin({ name: "p" }))).toBeNull();
    expect(await readWhy(plugin({ secureBb: { why: { x: 1 } } }))).toBeNull();
    expect(await readWhy(plugin("{nope"))).toBeNull();
    expect(await readWhy(dir())).toBeNull();
    expect(await readWhy(null)).toBeNull();
    const big = dir();
    writeFileSync(join(big, "package.json"), JSON.stringify({ secureBb: { why: "x" }, pad: "y".repeat(300 * 1024) }));
    expect(await readWhy(big)).toBeNull();
    const d = dir();
    mkdirSync(join(d, "package.json"));
    expect(await readWhy(d)).toBeNull();
  });
  it("is not read through a link: the file may be somewhere the plugin does not own", async () => {
    const real = plugin({ secureBb: { why: "secret place" } });
    const d = dir();
    symlinkSync(join(real, "package.json"), join(d, "package.json"));
    expect(await readWhy(d)).toBeNull();
  });
});

describe("where from, and how far the source is trusted", () => {
  const trust = { mode: "simple" as const, mySources: ["github:me/*"], known: ["github:getbb/plugins"], pluginsRoots: 1 };
  const q = (over: Partial<{ source: string; sourceKind: string; threadId: string | null }> = {}) => ({ rootDir: null, source: "git:https://github.com/me/p.git@main", sourceKind: "git", threadId: null, ...over });
  it("own, known and unknown sources", async () => {
    expect((await queueUx({}, q(), trust)).level).toBe("own");
    expect((await queueUx({}, q({ source: "git:https://github.com/getbb/plugins" }), trust)).level).toBe("known");
    const u = await queueUx({}, q({ source: "git:https://github.com/evil/p" }), trust);
    expect(u).toMatchObject({ level: "unknown", entry: "github:evil/p", sourceLabel: "github.com/evil/p" });
  });
  it("a source that cannot be named is unknown and has no entry to add", async () => {
    expect(await queueUx({}, q({ source: "npm:left-pad", sourceKind: "npm" }), trust)).toMatchObject({ level: "unknown", entry: null });
  });
  it("a guard that does not know trust: everything is unknown", async () => {
    expect((await queueUx({}, q(), null)).level).toBe("unknown");
  });
  it("the thread chain runs from the root to the thread, with titles", async () => {
    const titles: Record<string, string> = { r: "Экспорт", m: "Фигма", t: "Плагин" };
    const ux = await queueUx({ ancestors: async () => ["m", "r"], threadTitle: async (id) => titles[id] ?? null }, q({ threadId: "t" }), trust);
    expect(ux.chain).toEqual([{ id: "r", title: "Экспорт" }, { id: "m", title: "Фигма" }, { id: "t", title: "Плагин" }]);
  });
  it("no thread: an empty chain; failures of bb's API do not break the card", async () => {
    expect((await queueUx({}, q(), trust)).chain).toEqual([]);
    const ux = await queueUx({ ancestors: async () => { throw new Error("x"); }, threadTitle: async () => { throw new Error("y"); } }, q({ threadId: "t" }), trust);
    expect(ux.chain).toEqual([{ id: "t", title: null }]);
  });
  it("long titles are cut", async () => {
    const ux = await queueUx({ threadTitle: async () => "я".repeat(200) }, q({ threadId: "t" }), trust);
    expect(ux.chain[0]!.title!.length).toBe(60);
  });
});
