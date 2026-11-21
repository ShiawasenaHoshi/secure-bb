import { existsSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { beforeEach, describe, expect, it } from "vitest";
import { AfterFactScanner } from "../src/afterfact.js";
import { Gate } from "../src/gate.js";
import type { InstalledPluginLite } from "../src/probe.js";
import { propose } from "../src/propose.js";
import { CHECKS_VERSION, type CheckResult } from "../src/checks/index.js";
import { CLEAN, NETWORKED, withFindings } from "./support/checks.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";
import { hashTree, pluginIdFromPackageName } from "../src/tree.js";

class Env {
  t = 1_800_000_000_000;
  store: Store;
  gate: Gate;
  root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-flow-")));
  snapshots = join(this.root, "snapshots");
  code!: () => string;
  /** What the checks answer for every directory. */
  result: CheckResult = NETWORKED;
  constructor() {
    mkdirSync(this.snapshots);
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    this.store = new Store(db, () => this.t);
    this.gate = new Gate({
      store: this.store,
      now: () => this.t,
      threads: { ancestors: async () => [], descendants: async () => [] },
      thirdPartyRunning: async () => [],
      externalTotpFile: null,
      snapshotsRoot: this.snapshots, unsafeDirs: async () => [],
      runChecks: async () => this.result,
    });
  }
  async register(): Promise<void> {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    this.code = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(this.code());
    this.t += 31_000;
  }
  plugin(name: string, files: Record<string, string> = {}): string {
    const dir = join(this.root, "src", name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `bb-plugin-${name}`, version: "1.0.0", bb: { server: "./server.ts" } }));
    writeFileSync(join(dir, "server.ts"), "export default () => {};\n");
    for (const [f, body] of Object.entries(files)) {
      mkdirSync(join(dir, f, ".."), { recursive: true });
      writeFileSync(join(dir, f), body);
    }
    return dir;
  }
}

describe("propose", () => {
  let e: Env;
  let installs: string[];
  const deps = () => ({
    gate: e.gate,
    store: e.store,
    snapshotsRoot: e.snapshots,
    invokerIsServerMachine: async () => true,
    install: async (dir: string) => {
      installs.push(dir);
      return { id: "demo", version: "1.0.0", status: "running", statusDetail: null };
    },
    changed: () => undefined,
  });

  beforeEach(async () => {
    e = new Env();
    installs = [];
    await e.register();
  });

  it("answers a closed window with the exact instruction and installs nothing", async () => {
    const dir = e.plugin("demo");
    const res = await propose(deps(), { path: dir, cwd: undefined, threadId: "T1" });
    expect(res.exitCode).toBe(3);
    expect(res.stdout).toContain("окно доверия для demo закрыто; попроси человека открыть его в secure-bb и повтори propose");
    expect(installs).toEqual([]);
    expect(e.store.listQueue()[0]).toMatchObject({ kind: "proposal", status: "held", pluginId: "demo", threadId: "T1" });
  });

  it("after a human opens the window, the same propose installs from the snapshot", async () => {
    const dir = e.plugin("demo");
    await propose(deps(), { path: dir, cwd: undefined, threadId: "T1" });
    e.gate.openWindow(e.store.listQueue()[0]!.id, e.code());
    const res = await propose(deps(), { path: dir, cwd: undefined, threadId: "T1" });
    expect(res.exitCode).toBe(0);
    expect(installs).toHaveLength(1);
    expect(installs[0]!.startsWith(join(e.snapshots, "demo"))).toBe(true);
    // the hook sees that snapshot and the window lets it through
    const decision = await e.gate.decide({
      pluginId: "demo", version: "1.0.0", source: `path:${installs[0]}`, sourceKind: "path", gitCommit: null, npmIntegrity: null,
      rootDir: installs[0]!, contentHash: "sha256:core", trigger: "install",
    });
    expect(decision).toEqual({ action: "proceed" });
  });

  it("a proposal in a closed window already carries its checks (keyed by the snapshot, before the core hashes it)", async () => {
    const dir = e.plugin("demo");
    const res = await propose(deps(), { path: dir, cwd: undefined, threadId: "T1" });
    expect(res.exitCode).toBe(3);
    const q = e.store.listQueue()[0]!;
    expect(q.contentHash).toBeNull();
    expect(e.gate.checkForQueue(q)).toEqual({ ...NETWORKED, v: CHECKS_VERSION });
    // and once the core hashes it, the same result is linked to the core's hash
    const p = e.store.getProposal(q.proposalId!)!;
    await e.gate.decide({ pluginId: "demo", version: "1.0.0", source: `path:${p.snapshotDir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: p.snapshotDir, contentHash: "sha256:core", trigger: "install" });
    expect(e.store.getCheck("sha256:core")!.result).toEqual({ ...NETWORKED, v: CHECKS_VERSION });
    expect(e.store.listLog().find((l) => l.kind === "check")!.detail).toMatchObject({ blocks: 0, reviews: 0, infos: 0 });
    expect(Object.keys(e.store.listLog().find((l) => l.kind === "check")!.detail as object)).not.toContain("review");
  });

  it("a clean safe-class plugin is installed outside a window (spec §5.3)", async () => {
    e.result = CLEAN;
    const res = await propose(deps(), { path: e.plugin("demo"), cwd: undefined, threadId: "T1" });
    expect(res.exitCode).toBe(0);
    expect(installs).toHaveLength(1);
  });

  it("a hard sign is not installed even inside an open window; the agent is told, the human sees the entry", async () => {
    const dir = e.plugin("demo");
    await propose(deps(), { path: dir, cwd: undefined, threadId: "T1" });
    e.gate.openWindow(e.store.listQueue()[0]!.id, e.code());
    installs.length = 0;
    e.result = withFindings([{ rule: "env-dump", severity: "block", file: "server.ts", line: 4, excerpt: "JSON.stringify(process.env)" }]);
    const res = await propose(deps(), { path: e.plugin("demo", { "extra.ts": "1" }), cwd: undefined, threadId: "T1" });
    expect(res.exitCode).toBe(3);
    expect(res.stdout).toContain("версия остановлена проверками (review #");
    expect(res.stdout).not.toMatch(/env-dump|server\.ts/);
    expect(installs).toEqual([]);
    expect(e.store.listQueue()[0]).toMatchObject({ status: "held", reason: expect.stringContaining("env-dump") });
    expect(e.gate.openWindows()).toHaveLength(1);
  });

  it("a thread outside the window is told the window is closed", async () => {
    const dir = e.plugin("demo");
    await propose(deps(), { path: dir, cwd: undefined, threadId: "T1" });
    e.gate.openWindow(e.store.listQueue()[0]!.id, e.code());
    const res = await propose(deps(), { path: dir, cwd: undefined, threadId: "STRANGER" });
    expect(res.exitCode).toBe(3);
    expect(installs).toEqual([]);
  });

  it("snapshots exclude .git and dist, and a changed plugin gets a new snapshot directory", async () => {
    const dir = e.plugin("demo", { ".git/config": "x", "dist/server.js": "built", "lib/a.ts": "1" });
    await propose(deps(), { path: dir, cwd: undefined, threadId: null });
    const first = e.store.listLog().find((l) => l.kind === "propose")!;
    const snap1 = join(e.snapshots, "demo", (first.detail as { snapshot: string }).snapshot);
    expect(existsSync(join(snap1, "lib/a.ts"))).toBe(true);
    expect(existsSync(join(snap1, ".git"))).toBe(false);
    expect(existsSync(join(snap1, "dist"))).toBe(false);
    expect(await hashTree(snap1)).toBe(await hashTree(dir));
    writeFileSync(join(dir, "lib/a.ts"), "2");
    await propose(deps(), { path: dir, cwd: undefined, threadId: null });
    const hashes = e.store.listLog().filter((l) => l.kind === "propose").map((l) => (l.detail as { snapshot: string }).snapshot);
    expect(new Set(hashes).size).toBe(2);
  });

  it("refuses a plugin with symlinks that leave its directory (absolute or ../ out)", async () => {
    const dir = e.plugin("demo");
    symlinkSync("/etc/passwd", join(dir, "abs-link"));
    const res = await propose(deps(), { path: dir, cwd: undefined, threadId: "T1" });
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toMatch(/symlinks that point outside/);
    expect(existsSync(join(e.snapshots, "demo"))).toBe(false);
    expect(installs).toEqual([]);
  });

  it("proposing the same snapshot again keeps its approval, and installs record what bb built", async () => {
    const dir = e.plugin("demo");
    const built: string[] = [];
    await propose({ ...deps(), afterInstall: async (d) => void built.push(d) }, { path: dir, cwd: undefined, threadId: "T1" });
    const q = e.store.listQueue()[0]!;
    const res = e.gate.approveQueue(q.id, e.code());
    expect(res.installDir).toBeTruthy();
    const again = await propose({ ...deps(), afterInstall: async (d) => void built.push(d) }, { path: dir, cwd: undefined, threadId: "T1" });
    expect(again.exitCode).toBe(0); // touch-approved: allowed without a window
    expect(built).toHaveLength(1);
    expect(e.store.listLog().filter((l) => l.kind === "propose")).toHaveLength(2);
  });

  it("refuses to propose secure-bb itself and directories that are not plugins", async () => {
    const own = e.plugin("secure-bb");
    expect((await propose(deps(), { path: own, cwd: undefined, threadId: null })).stderr).toMatch(/cannot be proposed/);
    expect((await propose(deps(), { path: join(e.root, "nope"), cwd: undefined, threadId: null })).exitCode).toBe(1);
  });

  it("refuses when the invoking thread runs on another machine", async () => {
    const res = await propose({ ...deps(), invokerIsServerMachine: async () => false }, { path: e.plugin("demo"), cwd: undefined, threadId: "T1" });
    expect(res.exitCode).toBe(1);
  });
});

describe("after the fact", () => {
  it("baselines pre-existing plugins, disables new or changed ones, and honours approval", async () => {
    const e = new Env();
    await e.register();
    const oldDir = e.plugin("old");
    const freshDir = e.plugin("fresh");
    let list: InstalledPluginLite[] = [lite("old", oldDir)];
    const disabled: string[] = [];
    const scanner = new AfterFactScanner({
      store: e.store,
      gate: e.gate,
      listPlugins: async () => list.filter((p) => p.enabled),
      disable: async (id) => {
        disabled.push(id);
        list = list.map((p) => (p.id === id ? { ...p, enabled: false } : p));
      },
      hashDir: hashTree,
      now: () => e.t,
      log: () => undefined,
    });

    expect(await scanner.scan()).toEqual([]); // first run = baseline
    list = [lite("old", oldDir), lite("fresh", freshDir)];
    e.t += 120_000; // past the hash cache
    expect(await scanner.scan()).toEqual(["fresh"]);
    const held = e.store.listQueue().find((q) => q.pluginId === "fresh")!;
    expect(held.kind).toBe("afterfact");

    // approve + re-enable: now it passes
    const res = e.gate.approveQueue(held.id, e.code());
    expect(res.enable).toBe(true);
    list = list.map((p) => (p.id === "fresh" ? { ...p, enabled: true } : p));
    e.t += 120_000;
    expect(await scanner.scan()).toEqual([]);

    // a baseline plugin that changes afterwards is caught
    writeFileSync(join(oldDir, "server.ts"), "export default () => { /* changed */ };\n");
    e.t += 120_000;
    expect(await scanner.scan()).toEqual(["old"]);
  });
});

function lite(id: string, rootDir: string): InstalledPluginLite {
  return { id, provenance: "direct", enabled: true, status: "running", version: "1.0.0", source: `path:${rootDir}`, rootDir };
}

describe("plugin id derivation", () => {
  it("follows bb's naming rule", () => {
    expect(pluginIdFromPackageName("bb-plugin-secure-bb")).toBe("secure-bb");
    expect(pluginIdFromPackageName("@acme/bb-plugin-Hello_World")).toBe("hello-world");
    expect(pluginIdFromPackageName("plain")).toBe("plain");
    expect(pluginIdFromPackageName("---")).toBeNull();
  });
});
