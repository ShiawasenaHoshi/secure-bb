// The plugin's minimal UI side of trust by source (UX v1, PR 1): the page shows the guard's mode and "my sources"; every change goes to the guard,
// which checks the touch itself. The plugin cannot weaken or add anything by itself.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { bootPlugin, startGuardOnDate, type TestGuard } from "./support.ts";

let g: TestGuard | null = null;
beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
afterEach(async () => {
  vi.useRealTimers();
  await g?.close();
  g = null;
});
const fresh = (gd: TestGuard): string => (vi.setSystemTime(Date.now() + 31_000), gd.code());

describe("guard mode: the mode and my sources on the page", () => {
  it("shows the guard's state; adding takes a touch checked at the guard; removing does not", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    expect((await h.rpc<any>("overview")).guard.trust).toMatchObject({ mode: "simple", mySources: [], known: [] });
    await expect(h.rpc("trust.add", { entries: ["me/*"] })).rejects.toThrow();
    await expect(h.rpc("trust.add", { entries: ["me/*"], code: "000000" })).rejects.toThrow();
    expect(await h.rpc("trust.add", { entries: ["github:me/*"], code: fresh(g) })).toMatchObject({ ok: true, mySources: ["github:me/*"] });
    expect((await h.rpc<any>("overview")).guard.trust.mySources).toEqual(["github:me/*"]);
    expect(await h.rpc("trust.remove", { entry: "github:me/*" })).toMatchObject({ ok: true, mySources: [] });
  });

  it("strengthening the mode needs no touch, weakening does", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    expect(await h.rpc("trust.mode", { mode: "strict" })).toMatchObject({ ok: true, mode: "strict" });
    await expect(h.rpc("trust.mode", { mode: "simple" })).rejects.toThrow();
    expect((await h.rpc<any>("overview")).guard.trust.mode).toBe("strict");
    expect(await h.rpc("trust.mode", { mode: "detailed", code: fresh(g) })).toMatchObject({ ok: true, mode: "detailed" });
    // the page's "do I need a touch" question is answered from the guard's state
    expect(await h.rpc("passkey.challenge", { kind: "trust.mode", trustMode: "strict" })).toEqual({ needed: false });
  });

  it("moves the old list of trusted repositories into my sources by a touch", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    await expect(h.rpc("trust.migrate", {})).rejects.toThrow(); // nothing to move
    await h.rpc("trusted.set", { add: "me/demo", code: fresh(g) });
    await h.rpc("trusted.set", { add: "other/*", code: fresh(g) });
    await expect(h.rpc("trust.migrate", {})).rejects.toThrow(); // no touch
    expect(await h.rpc("trust.migrate", { code: fresh(g) })).toMatchObject({ ok: true, moved: ["github:me/demo", "github:other/*"], mySources: ["github:me/demo", "github:other/*"] });
    const recent = (await h.rpc<any>("overview")).guard.recent as Array<{ kind: string; detail: { migrated?: string } | null }>;
    expect(recent.find((r) => r.kind === "sources.add")?.detail?.migrated).toBeTruthy();
    // the old list stays as it is (the pollution tracker still reads it)
    expect((await h.rpc<any>("overview")).trustedRepos).toEqual(["me/demo", "other/*"]);
  });
});

describe("guard mode: the core runs the hook before it asks the guard, and an own source still gets in", () => {
  it("a version of an own source with the same rights loads in both orders; a new right is held by the guard", { timeout: 30_000 }, async () => {
    const { core, coreHash, hookCtx, plugDir } = await import("./support.ts");
    const { writeFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { dirname } = await import("node:path");
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const dir = plugDir("mine", "export default function plugin() {}\n");
    await h.rpc("trust.add", { entries: [`path:${dirname(dir)}`], code: fresh(g) });
    const ctx1 = hookCtx("mine", dir, coreHash(dir));
    expect(await core(g, h, ctx1)).toBe("held"); // the first version: nobody approved anything from this source yet
    const first = (await h.rpc<any>("overview")).queue[0];
    expect(await h.rpc("queue.approve", { id: first.id, code: fresh(g) })).toMatchObject({ ok: true });
    for (const [i, order] of (["guard-first", "hooks-first"] as const).entries()) {
      writeFileSync(join(dir, "server.ts"), `export default function plugin() {}\n// v${i + 2}\n`);
      expect(await core(g, h, hookCtx("mine", dir, coreHash(dir)), order)).toBe("load");
    }
    writeFileSync(join(dir, "server.ts"), "export default async function plugin() { await fetch('https://new.example/'); }\n");
    expect(await core(g, h, hookCtx("mine", dir, coreHash(dir)), "hooks-first")).toBe("held");
    const q = (await h.rpc<any>("overview")).queue.find((x: any) => x.contentHash === coreHash(dir));
    expect(q.reason).toMatch(/новое право/);
  });
});
