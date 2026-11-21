// Item 11: a bb without the plugin.activate hook. The scanner "after the fact" must notice a new third-party plugin and
// disable it within seconds, and the hook must be detected by its effect, not only by `on()` not throwing.
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterEach, describe, expect, it, vi } from "vitest";
import plugin from "../server.js";

type Installed = Record<string, unknown>;
const dirOf = (name: string): string => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-af-")));
  chmodSync(root, 0o755);
  const dir = join(root, name);
  mkdirSync(dir, { mode: 0o755 });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `bb-plugin-${name}`, version: "1.0.0" }));
  writeFileSync(join(dir, "server.ts"), `export default () => "${name}";\n`);
  return dir;
};
const lite = (id: string, rootDir: string): Installed => ({ id, provenance: "direct", enabled: true, status: "running", version: "1.0.0", source: `path:${rootDir}`, rootDir, statusDetail: null });

/** A bb that accepts `on("plugin.activate")` without complaint and never calls the hook (what a bb without the patch could do). */
async function boot(initial: Installed[], hook: "missing-throws" | "silent" | "working") {
  let plugins = initial;
  const disabled: string[] = [];
  const { bb, harness } = createFakePluginHost({
    pluginId: "secure-bb",
    sdk: {
      plugins: {
        list: async () => ({ plugins }),
        disable: async (a: { pluginId: string }) => {
          disabled.push(a.pluginId);
          plugins = plugins.map((p) => (p.id === a.pluginId ? { ...p, enabled: false, status: "disabled" } : p));
          return {};
        },
        enable: async () => ({}),
        install: async () => ({}),
      },
      system: { config: async () => ({ generalSettings: { telemetryEnabled: false }, primaryHostId: null }) },
      threads: { experimental_listAncestors: async () => ({ threads: [] }), experimental_listDescendants: async () => ({ threads: [] }), get: async () => ({ environmentId: null }) },
    } as never,
  } as never);
  let onCalls = 0;
  let handler: ((ctx: unknown) => Promise<unknown>) | null = null;
  (bb as unknown as { experimental_hooks: unknown }).experimental_hooks = {
    on(_name: string, h: (ctx: unknown) => Promise<unknown>) {
      onCalls++;
      handler = h;
      if (hook === "missing-throws") throw new Error('a "plugin.activate" hook handler is already registered by this plugin');
    },
    recheck: async () => undefined,
  };
  await plugin(bb);
  return { bb, harness, disabled, add: (p: Installed) => (plugins = [...plugins, p]), onCalls: () => onCalls, ask: (ctx: unknown) => handler!(ctx) };
}

// Fake time with real I/O between the steps is slow on a loaded machine: the default 5 s was the flake.
vi.setConfig({ testTimeout: 60_000 });
afterEach(() => vi.useRealTimers());
/** Fake time advances in small steps with real I/O in between (the scan reads files, which fake timers do not wait for). */
async function settle(ms: number): Promise<void> {
  for (let t = 0; t < ms; t += 500) {
    await vi.advanceTimersByTimeAsync(500);
    // Real I/O needs real time, and under a loaded machine a fixed number of event-loop turns is not enough:
    // yield until a slice of REAL time has passed (performance.now is not faked).
    const until = performance.now() + 10;
    do await new Promise((r) => setImmediate(r));
    while (performance.now() < until);
  }
}

describe("after the fact (a bb without the hook)", () => {
  for (const hook of ["missing-throws", "silent"] as const) {
    it(`${hook}: a third-party plugin installed after secure-bb is disabled within seconds, and the journal says so`, async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
      const env = await boot([lite("old", dirOf("old"))], hook);
      const svc = env.harness.runService("watch");
      await settle(3_000); // the baseline pass: what was there before is not touched
      expect(env.disabled).toEqual([]);

      env.add(lite("stock-evil", dirOf("stock-evil"))); // installed later; no event reaches us (the worst case)
      await settle(12_000);
      expect(env.disabled).toEqual(["stock-evil"]);
      const log = (await env.harness.behavior.runCli(["log", "--limit", "50"])).stdout;
      expect(log).toContain("afterfact.baseline");
      expect(log).toContain("afterfact.disable stock-evil");
      svc.controller.abort();
      await vi.advanceTimersByTimeAsync(20_000);
      await svc.done;
    });
  }

  it("the hook is registered once; on `silent` it is found dead because the core never asked about a running plugin, and the page says after the fact", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
    const env = await boot([], "silent");
    expect(env.onCalls()).toBe(1);
    const svc = env.harness.runService("watch");
    env.add(lite("late", dirOf("late")));
    await settle(60_000);
    const ov = (await env.harness.behavior.callRpc("overview", null)) as { hookRegistered: boolean; assessment: { afterTheFact: boolean } };
    expect(ov.hookRegistered).toBe(false);
    expect(ov.assessment.afterTheFact).toBe(true);
    expect((await env.harness.behavior.runCli(["status"])).stdout).toContain("no (after the fact)");
    svc.controller.abort();
    await vi.advanceTimersByTimeAsync(20_000);
    await svc.done;
  });

  it("silent: the journal records that the hook was found dead", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
    const env = await boot([], "silent");
    const svc = env.harness.runService("watch");
    await settle(2_000);
    env.add(lite("sneaky", dirOf("sneaky")));
    await settle(10_000);
    expect(env.disabled).toEqual(["sneaky"]);
    expect((await env.harness.behavior.runCli(["log", "--limit", "50"])).stdout).toContain("hook.dead");
    svc.controller.abort();
    await vi.advanceTimersByTimeAsync(20_000);
    await svc.done;
  });

  it("a working hook: a plugin the core asked about is not touched by the scanner, and the hook is not declared dead", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
    const env = await boot([], "working");
    const svc = env.harness.runService("watch");
    await settle(2_000);
    const dir = dirOf("vetted");
    await env.ask({ pluginId: "vetted", version: "1.0.0", source: `path:${dir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: dir, contentHash: "sha256:v", trigger: "install" });
    env.add(lite("vetted", dir)); // it runs now, as if the gate had let it through
    await settle(15_000);
    expect(env.disabled).toEqual([]);
    const ov = (await env.harness.behavior.callRpc("overview", null)) as { hookRegistered: boolean };
    expect(ov.hookRegistered).toBe(true);
    svc.controller.abort();
    await vi.advanceTimersByTimeAsync(20_000);
    await svc.done;
  });
});
