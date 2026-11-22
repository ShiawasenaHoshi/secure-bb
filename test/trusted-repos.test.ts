import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Gate } from "../src/gate.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { classifyItem } from "../src/taint/classify.js";
import { isTrustedRepo, normalizePattern } from "../src/taint/repos.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import plugin from "../server.js";

const cmd = (command: string, trusted: string[] = []) => classifyItem({ type: "commandExecution", command, status: "completed" }, trusted);
const MINE = ["me/my-plugin", "myorg/*"];

describe("trusted repositories: own work does not taint", () => {
  it("patterns: owner/name and owner/*, github.com only, normalised", () => {
    expect(normalizePattern(" Me/My-Plugin ")).toBe("me/my-plugin");
    expect(normalizePattern("https://github.com/me/my-plugin.git")).toBe("me/my-plugin");
    expect(normalizePattern("myorg/*")).toBe("myorg/*");
    for (const bad of ["", "me", "*/x", "me/a/b", "gitlab.com/me/x", "me/ x", "*/*"]) expect(normalizePattern(bad)).toBeNull();
    expect(isTrustedRepo("MyOrg/anything", MINE)).toBe(true);
    expect(isTrustedRepo("me/other", MINE)).toBe(false);
    expect(isTrustedRepo("evilorg/my-plugin", MINE)).toBe(false);
  });

  it("git clone/fetch/pull/ls-remote by the address of a trusted repository do not taint; any other address does", () => {
    for (const c of [
      "git clone https://github.com/me/my-plugin.git",
      "git clone git@github.com:me/my-plugin.git /tmp/x",
      "git -C /w fetch https://github.com/myorg/tool main",
      "git pull ssh://git@github.com/myorg/tool",
      "git ls-remote https://github.com/ME/My-Plugin",
    ])
      expect(cmd(c, MINE), c).toBeNull();
    for (const c of [
      "git clone https://github.com/me/other.git",
      "git clone https://github.com/evil/my-plugin",
      "git clone https://gitlab.com/me/my-plugin",
      "git clone https://github.com.evil.test/me/my-plugin",
      "git clone https://github.com/me/my-plugin && git clone https://github.com/evil/x", // one trusted does not excuse the next
      "git fetch https://github.com/me/my-plugin https://github.com/evil/x",
    ])
      expect(cmd(c, MINE)?.kind, c).toBe("repo");
    expect(cmd("git clone https://github.com/me/my-plugin.git", [])?.kind).toBe("repo"); // empty list: as before
  });

  it("gh with an explicit trusted repository does not taint; without one it does", () => {
    for (const c of ["gh repo clone me/my-plugin", "gh release download v1 --repo=me/my-plugin", "gh api repos/me/my-plugin/contents/README.md", "gh repo view me/my-plugin"])
      expect(cmd(c, MINE), c).toBeNull();
    for (const c of ["gh pr checkout 5", "gh api user", "gh repo clone evil/x", "gh pr diff 5 --repo evil/x", "gh repo clone me/my-plugin && gh pr diff 6"])
      expect(cmd(c, MINE)?.kind, c).toBe("repo");
    expect(cmd("gh repo clone me/my-plugin", [])?.kind).toBe("repo");
  });

  it("non-repository kinds are unaffected by the list", () => {
    expect(cmd("curl -sL https://github.com/me/my-plugin/raw/main/a.sh", MINE)?.kind).toBe("web");
    expect(cmd("bb skill install me/skill", MINE)?.kind).toBe("skill");
  });
});

describe("the list is changed only with a code", () => {
  function gate() {
    let t = 1_800_000_000_000;
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    const store = new Store(db, () => t);
    const g = new Gate({ store, now: () => t, threads: { ancestors: async () => [], descendants: async () => [] }, thirdPartyRunning: async () => [], externalTotpFile: null, snapshotsRoot: "/nonexistent" });
    return { g, store, tick: () => (t += 31_000), at: () => t };
  }
  it("empty by default; add and remove need a valid, unused code; both are journaled", async () => {
    const { g, store, tick, at } = gate();
    expect(store.trustedRepos()).toEqual([]);
    const { secret } = await g.beginRegistration({ attended: true, caller: "t" });
    const code = () => hotp(base32Decode(secret), stepAt(at()));
    g.confirmRegistration(code());
    expect(() => g.setTrustedRepo({ add: "me/x" }, "000000")).toThrow(/invalid/);
    expect(store.trustedRepos()).toEqual([]);
    tick();
    expect(g.setTrustedRepo({ add: "Me/X" }, code())).toEqual(["me/x"]);
    expect(() => g.setTrustedRepo({ add: "me/y" }, code())).toThrow(/invalid|already used/); // the same step is not accepted twice
    tick();
    expect(() => g.setTrustedRepo({ add: "not a repo" }, code())).toThrow(/owner\/name/);
    expect(() => g.setTrustedRepo({ remove: "me/x" }, "000000")).toThrow(/invalid/);
    expect(store.trustedRepos()).toEqual(["me/x"]);
    expect(g.setTrustedRepo({ remove: "me/x" }, code())).toEqual([]);
    expect(store.listLog(20).filter((l) => l.kind.startsWith("trusted.")).map((l) => l.kind)).toEqual(["trusted.remove", "trusted.add"]);
    expect(store.verifyJournal().ok).toBe(true);
  });
});

describe("through the plugin surfaces", () => {
  afterEach(() => vi.useRealTimers());
  it("status prints the count, the page overview lists the patterns, and the RPC refuses without a valid code", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { bb, harness } = createFakePluginHost({
      pluginId: "secure-bb",
      sdk: { plugins: { list: async () => ({ plugins: [] }) }, system: { config: async () => ({}) }, threads: {} } as never,
    } as never);
    await plugin(bb);
    expect((await harness.behavior.runCli(["status"])).stdout).toContain("repositories that do not taint a thread: 0");
    await harness.behavior.callRpc("page.ping", null);
    const begin = (await harness.behavior.callRpc("totp.begin", null)) as { secret: string };
    const gen = () => hotp(base32Decode(begin.secret), stepAt(Date.now()));
    await harness.behavior.callRpc("totp.confirm", { code: gen() });
    await expect(harness.behavior.callRpc("trusted.set", { add: "me/x", code: "000000" })).rejects.toThrow();
    vi.setSystemTime(Date.now() + 31_000); // next TOTP step
    await harness.behavior.callRpc("trusted.set", { add: "me/x", code: gen() });
    expect((await harness.behavior.runCli(["status"])).stdout).toContain("repositories that do not taint a thread: 1");
    const ov = (await harness.behavior.callRpc("overview", null)) as { trustedRepos: string[] };
    expect(ov.trustedRepos).toEqual(["me/x"]);
  });
});
