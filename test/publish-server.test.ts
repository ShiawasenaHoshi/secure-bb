// Stage 4 through the real server entry (fake bb host): the settings door, the environment variable, the CLI.
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterEach, describe, expect, it } from "vitest";
import plugin from "../server.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";

const ENV = "BB_SECURE_BB_PUBLISH_TOKEN_FILE";
const saved = process.env[ENV];
afterEach(() => {
  if (saved === undefined) delete process.env[ENV];
  else process.env[ENV] = saved;
});

type Ov = { publish: { settings: { enabled: boolean; repoUrl: string; branch: string; onApprove: boolean }; state: string; recent: unknown[] } };

async function boot() {
  const { bb, harness } = createFakePluginHost({
    pluginId: "secure-bb",
    sdk: {
      plugins: { list: async () => ({ plugins: [] }), disable: async () => ({}), enable: async () => ({}), install: async () => ({}) },
      system: { config: async () => ({ generalSettings: { telemetryEnabled: true }, primaryHostId: null }) },
      threads: { experimental_listAncestors: async () => ({ threads: [] }), experimental_listDescendants: async () => ({ threads: [] }), get: async () => ({ environmentId: null }) },
    } as never,
  } as never);
  await plugin(bb);
  await harness.behavior.callRpc("page.ping", null);
  const begin = (await harness.behavior.callRpc("totp.begin", null)) as { secret: string };
  let ahead = 0;
  const code = () => hotp(base32Decode(begin.secret), stepAt(Date.now()) + ahead++);
  await harness.behavior.callRpc("totp.confirm", { code: code() });
  return { harness, code };
}

describe("publishing through the server entry", () => {
  it("is off by default and says 'not configured' once enabled without the token variable", async () => {
    delete process.env[ENV];
    const { harness, code } = await boot();
    const off = (await harness.behavior.callRpc("overview", null)) as Ov;
    expect(off.publish).toMatchObject({ state: "off", settings: { enabled: false, repoUrl: "", branch: "main", onApprove: false }, recent: [] });
    await expect(harness.behavior.callRpc("publish.settings", { repoUrl: "https://example.com/o/bb-plugins.git" })).rejects.toThrow(/кода/);
    await harness.behavior.callRpc("publish.settings", { repoUrl: "https://example.com/o/bb-plugins.git", enabled: true, code: code() });
    const on = (await harness.behavior.callRpc("overview", null)) as Ov;
    expect(on.publish.state).toBe("not-configured");
    const cli = await harness.behavior.runCli(["publish"]);
    expect(cli.exitCode).toBe(0);
    expect(cli.stdout).toContain("on, not configured on the server");
    expect(cli.stdout).not.toContain("example.com"); // agents are not told the address
  });

  it("with the variable set the state is ready; the token file's path and text are not in the overview", async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-pubsrv-")));
    const tokenFile = join(dir, "token");
    writeFileSync(tokenFile, "ghp_SERVER0123456789abcdefghijklmnopqr\n", { mode: 0o600 });
    process.env[ENV] = tokenFile;
    const { harness, code } = await boot();
    await harness.behavior.callRpc("publish.settings", { repoUrl: "https://example.com/o/bb-plugins.git", branch: "frozen", enabled: true, code: code() });
    const ov = (await harness.behavior.callRpc("overview", null)) as Ov;
    expect(ov.publish.state).toBe("ready");
    expect(ov.publish.settings).toMatchObject({ enabled: true, branch: "frozen" });
    const text = JSON.stringify(ov);
    expect(text).not.toContain("ghp_SERVER");
    expect(text).not.toContain(tokenFile);
  });

  it("bad addresses are refused even with a valid code", async () => {
    const { harness, code } = await boot();
    // The address is validated before the code is spent, so one code is enough for all.
    const c = code();
    for (const repoUrl of ["http://example.com/o/r.git", "https://u:p@example.com/o/r.git", "file:///tmp/r.git", "--upload-pack=x"]) {
      await expect(harness.behavior.callRpc("publish.settings", { repoUrl, code: c })).rejects.toThrow(/https|адрес|логина/);
    }
  });

  it("a manual publish of a plugin that is not ours does nothing", async () => {
    const { harness } = await boot();
    const r = (await harness.behavior.callRpc("publish.run", { pluginId: "foreign" })) as { status: string; note: string };
    expect(r.status).toBe("skipped");
    expect(r.note).toMatch(/нет закреплённой версии|выключена/);
  });
});
