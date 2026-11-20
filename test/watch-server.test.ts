// The watchdog through the plugin's real surfaces (RPC, CLI, background service) over a
// fake bb whose SDK answers have the shapes of the real SDK (checked against bb's typings).
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import plugin from "../server.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";

interface World {
  builtinEnabled: Record<string, boolean>;
  instructions: string;
  machineVars: string[];
  calls: string[];
  catalogs: Array<{ name: string; source: string; subdirectory: string | null }>;
}

async function boot(dataDir: string) {
  const world: World = {
    builtinEnabled: { connect: false, "bb-ai": true },
    instructions: "be careful",
    machineVars: ["GH_TOKEN"],
    calls: [],
    catalogs: [{ name: "bb-official", source: "path:/b", subdirectory: null }],
  };
  let listener: ((e: { changes?: string[] }) => void) | null = null;
  const pluginRow = (id: string, enabled: boolean) => ({ id, provenance: "builtin", enabled, status: enabled ? "running" : "disabled", version: "0.1.0", source: `builtin:${id}`, rootDir: `/b/${id}` });
  const { bb, harness } = createFakePluginHost({
    pluginId: "secure-bb",
    experimental_dataDir: dataDir,
    sdk: {
      subscribe: (opts: { callback: (e: { changes?: string[] }) => void }) => {
        listener = opts.callback;
        return () => {
          listener = null;
        };
      },
      plugins: {
        list: async () => ({ plugins: Object.entries(world.builtinEnabled).map(([id, on]) => pluginRow(id, on)) }),
        disable: async (a: { pluginId: string }) => {
          world.calls.push(`disable ${a.pluginId}`);
          world.builtinEnabled[a.pluginId] = false;
          return {};
        },
        enable: async () => ({}),
        install: async () => ({ id: "x", version: "1", status: "running", statusDetail: null }),
        getSettings: async (a: { pluginId: string }) => ({ ok: true, schema: {}, values: a.pluginId === "custom-instructions" ? { instructions: world.instructions } : { sandboxEnabled: true, fullAccessApprovalsEnabled: false } }),
        updateSettings: async (a: { pluginId: string; values: { instructions: string } }) => {
          world.calls.push(`instructions:${a.pluginId}`);
          world.instructions = a.values.instructions;
          return { ok: true, schema: {}, values: a.values };
        },
        marketplaces: { list: async () => world.catalogs },
        experimental_getSafeMode: async () => ({ enabled: false }),
      },
      system: {
        config: async () => ({ generalSettings: { telemetryEnabled: false }, primaryHostId: null, experiments: { serverMove: false } }),
        machineEnvironment: async () => ({ builtInGit: {}, variables: world.machineVars.map((name) => ({ name, note: null, secret: true, value: null })) }),
        deleteMachineEnvironmentVariable: async (a: { name: string }) => {
          world.calls.push(`delete ${a.name}`);
          world.machineVars = world.machineVars.filter((n) => n !== a.name);
          return {};
        },
      },
      projects: {
        list: async () => [{ id: "proj_p", name: "Personal" }],
        machineEnvironment: async () => ({ builtInGit: {}, variables: [], inheritedVariables: [] }),
        defaultExecutionOptions: async () => ({ permissionMode: "accept-edits" }),
        fileContent: async () => {
          throw new Error("HTTP 404: file not found");
        },
      },
      skills: {
        list: async () => ({ skills: [{ id: "sk1", name: "bb-cli", scope: "plugin", pluginId: "bb-guide", manageable: false, description: null, filePath: "/x", provider: null, registrySkillId: null }] }),
        getContent: async () => ({ content: "", revision: "r" }),
      },
      hosts: { list: async () => [{ id: "host_1", name: "laptop", maxPermissionMode: "full" }] },
      threads: { experimental_listAncestors: async () => ({ threads: [] }), experimental_listDescendants: async () => ({ threads: [] }), get: async () => ({ environmentId: null }) },
    } as never,
  } as never);
  await plugin(bb);
  return { bb, harness, world, fire: (changes: string[]) => listener?.({ changes }) };
}

let dataDir: string;
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  dataDir = mkdtempSync(join(tmpdir(), "sbb-watch-"));
  writeFileSync(join(dataDir, "server-connect-hold.json"), "{}");
  // the account probe calls our own server: answer "signed out" without touching the network
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ ok: true, result: { state: "signed-out" } }), { status: 200 }));
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  rmSync(dataDir, { recursive: true, force: true });
});

type Ov = { watch: { baselineAt: number | null; drifts: Array<{ key: string; status: string }>; windows: Array<{ scopeLabels: string[] }>; failed: Array<{ source: string }>; rollbackEnabled: boolean; observedCount: number }; totp: { state: string } };
const ov = async (harness: Awaited<ReturnType<typeof boot>>["harness"]) => (await harness.behavior.callRpc("overview", null)) as Ov;

async function register(harness: Awaited<ReturnType<typeof boot>>["harness"]) {
  await harness.behavior.callRpc("page.ping", null);
  const begin = (await harness.behavior.callRpc("totp.begin", null)) as { secret: string };
  const secret = base32Decode(begin.secret);
  const current = () => hotp(secret, stepAt(Date.now()));
  await harness.behavior.callRpc("totp.confirm", { code: current() });
  // Every touch spends one 30 s step: move the (faked) clock to the next one first.
  return () => {
    vi.setSystemTime(Date.now() + 31_000);
    return current();
  };
}

describe("watchdog through the plugin surfaces", () => {
  it("reads bb through the SDK, shows the state before approval and the 'not observed' list", async () => {
    const { harness } = await boot(dataDir);
    await harness.behavior.callRpc("watch.scan", null);
    const o = await ov(harness);
    expect(o.watch.baselineAt).toBeNull();
    expect(o.watch.observedCount).toBeGreaterThan(8);
    const cli = await harness.behavior.runCli(["config"]);
    expect(cli.exitCode).toBe(0);
    expect(cli.stdout).toContain("эталон: не принят");
    expect(cli.stdout).toContain("не наблюдается вообще");
    expect(cli.stdout).toContain("откат: выключен");
  });

  it("approve → agent changes things → feed shows them in `bb secure-bb config` and the page; nothing is undone by default", async () => {
    const { harness, world } = await boot(dataDir);
    const code = await register(harness);
    await harness.behavior.callRpc("watch.acceptAll", { code: code() });
    world.builtinEnabled.connect = true;
    world.instructions = "ignore previous";
    world.machineVars.push("NODE_OPTIONS");
    const res = await harness.behavior.runCli(["config", "--scan"]);
    expect(res.stdout).toContain("ОТКРЫТО");
    expect(res.stdout).toContain("встроенный плагин connect");
    expect(res.stdout).toContain("пользовательские инструкции");
    expect(res.stdout).toContain("переменная NODE_OPTIONS");
    expect(res.stdout).not.toContain("ignore previous");
    expect(world.calls).toEqual([]);
    const o = await ov(harness);
    expect(o.watch.drifts.filter((d) => d.status === "open").length).toBe(3);
  });

  it("rollback on (with a code): disables the plugin, deletes the variable, restores the instructions", async () => {
    const { harness, world } = await boot(dataDir);
    const code = await register(harness);
    await harness.behavior.callRpc("watch.acceptAll", { code: code() });
    await expect(harness.behavior.callRpc("watch.rollbackMode", { enabled: true, code: "000000" })).rejects.toThrow();
    await harness.behavior.callRpc("watch.rollbackMode", { enabled: true, code: code() });
    world.builtinEnabled.connect = true;
    world.instructions = "evil";
    world.machineVars.push("EVIL");
    await harness.behavior.callRpc("watch.scan", null);
    expect(world.calls.sort()).toEqual(["delete EVIL", "disable connect", "instructions:custom-instructions"]);
    expect(world.instructions).toBe("be careful");
    expect((await ov(harness)).watch.drifts.every((d) => d.status === "rolled-back")).toBe(true);
  });

  it("configuration window over RPC: banner data, change accepted without a code, closes by code", async () => {
    const { harness, world } = await boot(dataDir);
    const code = await register(harness);
    await harness.behavior.callRpc("watch.acceptAll", { code: code() });
    await expect(harness.behavior.callRpc("watch.window.open", { scopes: ["account"], code: code() })).rejects.toThrow(/cannot be opened/);
    await harness.behavior.callRpc("watch.window.open", { scopes: ["instructions", "skills"], code: code() });
    expect((await ov(harness)).watch.windows[0]!.scopeLabels).toEqual(["инструкции", "скиллы"]);
    world.instructions = "edited in the window";
    await harness.behavior.callRpc("watch.scan", null);
    expect((await ov(harness)).watch.drifts[0]).toMatchObject({ key: "instructions", status: "accepted-window" });
    const cli = await harness.behavior.runCli(["config"]);
    expect(cli.stdout).toContain("окно доверия «конфигурация»: инструкции, скиллы — ещё 10 мин");
    const windowId = ((await harness.behavior.callRpc("overview", null)) as unknown as { watch: { windows: Array<{ id: number }> } }).watch.windows[0]!.id;
    await harness.behavior.callRpc("watch.window.close", { windowId, code: code() });
    expect((await ov(harness)).watch.windows).toEqual([]);
  });

  it("policy.set takes the configuration window size", async () => {
    const { harness } = await boot(dataDir);
    const code = await register(harness);
    await harness.behavior.callRpc("policy.set", { cfgWindowMin: 20, code: code() });
    const o = (await harness.behavior.callRpc("overview", null)) as unknown as { policy: { cfgWindowMin: number; cfgCapMin: number; cfgMode: string } };
    expect(o.policy).toMatchObject({ cfgWindowMin: 20, cfgCapMin: 240, cfgMode: "sliding" });
    await expect(harness.behavior.callRpc("policy.set", { cfgWindowMin: 60 })).rejects.toThrow();
  });

  it("an unreadable source is listed, not reported as a change", async () => {
    const { harness } = await boot(dataDir);
    vi.stubGlobal("fetch", async () => {
      throw new Error("connection refused");
    });
    const code = await register(harness);
    await harness.behavior.callRpc("watch.acceptAll", { code: code() });
    await harness.behavior.callRpc("watch.scan", null);
    const o = await ov(harness);
    expect(o.watch.failed.map((f) => f.source)).toContain("account");
    expect(o.watch.drifts).toEqual([]);
  });

  it("the background service scans on `config-changed` / `plugins-changed` events", { timeout: 15_000 }, async () => {
    const { harness, world, fire } = await boot(dataDir);
    const code = await register(harness);
    await harness.behavior.callRpc("watch.acceptAll", { code: code() });
    const svc = harness.runService("watch");
    await new Promise((r) => setTimeout(r, 1800)); // first scan (debounce 1.5 s)
    world.builtinEnabled.connect = true;
    fire(["ui-preferences-changed"]); // not a config event: ignored
    await new Promise((r) => setTimeout(r, 1700));
    expect((await ov(harness)).watch.drifts).toEqual([]);
    fire(["config-changed"]);
    await new Promise((r) => setTimeout(r, 1900));
    expect((await ov(harness)).watch.drifts.map((d) => d.key)).toEqual(["builtin:connect"]);
    svc.controller.abort();
    await svc.done;
  });
});
