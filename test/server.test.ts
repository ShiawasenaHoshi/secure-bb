import { chmodSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { describe, expect, it } from "vitest";
import plugin from "../server.js";
import { base32Decode, hotp, stepAt } from "../guard/src/totp.ts";

type Installed = Record<string, unknown>;

function installedPlugin(over: Installed): Installed {
  return {
    id: "demo",
    provenance: "direct",
    enabled: true,
    status: "running",
    version: "1.0.0",
    source: "path:/x",
    rootDir: "/x",
    statusDetail: null,
    ...over,
  };
}

async function boot(opts: { plugins?: Installed[]; hook?: boolean } = {}) {
  const calls: Array<[string, unknown]> = [];
  let plugins = opts.plugins ?? [];
  const { bb, harness } = createFakePluginHost({
    pluginId: "secure-bb",
    sdk: {
      plugins: {
        list: async () => ({ plugins }),
        disable: async (a: { pluginId: string }) => {
          calls.push(["disable", a.pluginId]);
          plugins = plugins.map((p) => (p.id === a.pluginId ? { ...p, enabled: false, status: "disabled" } : p));
          return {};
        },
        enable: async (a: { pluginId: string }) => {
          calls.push(["enable", a.pluginId]);
          return {};
        },
        install: async (a: { source: string }) => {
          calls.push(["install", a.source]);
          return { id: "demo", version: "1.0.0", status: "disabled", statusDetail: "held by secure-bb: review #1" };
        },
      },
      system: { config: async () => ({ generalSettings: { telemetryEnabled: true }, primaryHostId: null }) },
      threads: {
        experimental_listAncestors: async () => ({ threads: [] }),
        experimental_listDescendants: async () => ({ threads: [] }),
        get: async () => ({ environmentId: null }),
      },
    } as never,
  } as never);
  if (opts.hook === false) {
    (bb as unknown as { experimental_hooks: unknown }).experimental_hooks = {
      on() {
        throw new Error("unknown hook plugin.activate");
      },
      recheck: async () => undefined,
    };
  }
  await plugin(bb);
  return { bb, harness, calls, setPlugins: (p: Installed[]) => (plugins = p) };
}

describe("secure-bb server", () => {
  it("reports the stage honestly and registers the CLI + RPC surfaces", async () => {
    const { harness } = await boot();
    const ov = (await harness.behavior.callRpc("overview", null)) as {
      assessment: { stage: number; checks: Array<{ id: string }> };
      totp: { state: string };
      hookRegistered: boolean;
    };
    expect(ov.totp.state).toBe("none");
    expect(typeof ov.hookRegistered).toBe("boolean");
    expect(ov.assessment.checks.map((c) => c.id)).toEqual(
      expect.arrayContaining(["hook", "guard", "uid", "account", "builtins", "connect-hold", "bind", "telemetry", "marketplace", "api-auth", "third-party"]),
    );
    const status = await harness.behavior.runCli(["status"]);
    expect(status.exitCode).toBe(0);
    expect(status.stdout).toContain("gate before load:");
    expect(status.stdout).toContain("trust window for this thread: closed");
    expect(status.stdout).not.toMatch(/second factor|ступень|stage/i);
  });

  it("registers TOTP end to end over RPC and never returns the secret afterwards", async () => {
    const { harness } = await boot();
    await harness.behavior.callRpc("page.ping", null);
    const begin = (await harness.behavior.callRpc("totp.begin", null)) as { secret: string; uri: string; matrix: boolean[][] };
    expect(begin.uri).toContain(begin.secret);
    expect(begin.matrix.length).toBeGreaterThan(20);
    const code = hotp(base32Decode(begin.secret), stepAt(Date.now()));
    await harness.behavior.callRpc("totp.confirm", { code });
    await expect(harness.behavior.callRpc("totp.begin", null)).rejects.toThrow();
    const ov = JSON.stringify(await harness.behavior.callRpc("overview", null));
    expect(ov).not.toContain(begin.secret);
    expect(JSON.parse(ov).totp.state).toBe("locked");
  });

  it("a registration started without the page open cannot be confirmed", async () => {
    const { harness } = await boot();
    const begin = (await harness.behavior.callRpc("totp.begin", null)) as { secret: string };
    const code = hotp(base32Decode(begin.secret), stepAt(Date.now()));
    await expect(harness.behavior.callRpc("totp.confirm", { code })).rejects.toThrow(/not started from the secure-bb page/);
    const ov = (await harness.behavior.callRpc("overview", null)) as { totp: { state: string; pendingUnattended: boolean } };
    expect(ov.totp).toMatchObject({ state: "pending", pendingUnattended: true });
  });

  it("refuses registration while a third-party plugin runs and names it", async () => {
    const { harness } = await boot({ plugins: [installedPlugin({ id: "nosy" })] });
    await expect(harness.behavior.callRpc("totp.begin", null)).rejects.toThrow(/third-party plugins/);
  });

  it("`check <path>` runs the checks without installing anything", async () => {
    const { harness, calls } = await boot();
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-cli-")));
    chmodSync(dir, 0o755);
    mkdirSync(join(dir, "p"), { mode: 0o755 });
    writeFileSync(join(dir, "p", "index.js"), "export const s = JSON.stringify(process.env);\nfetch('https://x.example');\n", { mode: 0o644 });
    const res = await harness.behavior.runCli(["check", join(dir, "p")]);
    expect(res.exitCode).toBe(0);
    // only a summary: no rule, file, line, excerpt or host (threat model F9)
    expect(res.stdout).toContain("check: stopped; 1 block");
    expect(res.stdout).not.toMatch(/env-dump|index\.js|x\.example|JSON\.stringify/);
    expect(calls.filter(([k]) => k === "install")).toEqual([]);
    const missing = await harness.behavior.runCli(["check", join(dir, "missing")]);
    expect(missing.exitCode).toBe(1);
    expect(missing.stderr).toMatch(/cannot check/);
  });
});
