// Stage 2.3 wired into the §5.3 decision: dependency findings are `review`, so the table
// treats them like any other review finding. Real checks on real snapshot directories,
// a fake npm registry, no network.
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { beforeEach, describe, expect, it } from "vitest";
import { Gate, type HookCtx } from "../src/gate.js";
import type { FetchLike } from "../src/deps/registry.js";
import { verifyDependencies } from "../src/deps/verify.js";
import { runChecks, type CheckResult } from "../src/checks/index.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";
import { hashTree } from "../src/tree.js";

const DAY = 86_400_000;
const T0 = 1_800_000_000_000;
const iso = (t: number, agoMs: number): string => new Date(t - agoMs).toISOString();

class H {
  t = T0;
  store: Store;
  gate: Gate;
  root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-depgate-")));
  snaps = join(this.root, "snapshots");
  /** package name → publish times by version */
  registry = new Map<string, Record<string, string>>();
  online = true;
  requests = 0;
  code!: () => string;
  verifyThrows = false;
  fetch: FetchLike = async (url) => {
    this.requests++;
    if (!this.online) throw new TypeError("fetch failed");
    const name = decodeURIComponent(url.replace("https://registry.npmjs.org/", ""));
    const times = this.registry.get(name);
    if (!times) return new Response("{}", { status: 404 });
    return new Response(JSON.stringify({ "dist-tags": {}, time: times }), { status: 200 });
  };
  constructor() {
    mkdirSync(this.snaps);
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    this.store = new Store(db, () => this.t);
    this.store.setPolicy({ autoSafe: true }); // these tests are about the safe class; the default (off) is tested in threat-fixes.test.ts
    this.gate = new Gate({
      store: this.store,
      now: () => this.t,
      threads: { ancestors: async () => [], descendants: async () => [] },
      thirdPartyRunning: async () => [],
      externalTotpFile: null,
      snapshotsRoot: this.snaps, unsafeDirs: async () => [],
      runChecks,
      verifyDeps: async (r: CheckResult) => {
        if (this.verifyThrows) throw new Error("boom");
        return verifyDependencies(r, { cache: this.store, fetch: this.fetch, now: () => this.t, deadlineMs: 500, requestTimeoutMs: 300 });
      },
      checkWaitMs: 2000,
    });
  }
  /** Publishes `version` of `name` `agoMs` before the current time. */
  publish(name: string, version: string, agoMs: number): void {
    this.registry.set(name, { ...(this.registry.get(name) ?? {}), [version]: iso(this.t, agoMs) });
  }
  async register(): Promise<void> {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    this.code = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(this.code());
    this.t += 31_000;
  }
  tick(): void {
    this.t += 31_000;
  }
  async snapshot(n: number, deps: Record<string, string>, thread = "T1") {
    const dir = join(this.snaps, "demo", `h${n}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: `1.0.${n}`, dependencies: deps }));
    writeFileSync(join(dir, "server.ts"), `export default () => ${n};\n`);
    const w = await this.gate.windowCovering("demo", thread);
    const proposal = this.store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: thread, windowId: w?.id ?? null });
    return { dir, proposal, ctx: ctx(dir, `sha256:core${n}`, n) };
  }
}
const ctx = (rootDir: string, contentHash: string, n = 0): HookCtx => ({
  pluginId: "demo", version: `1.0.${n}`, source: `path:${rootDir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir, contentHash, trigger: "install",
});

describe("§5.3 outside a window, with dependencies", () => {
  let h: H;
  beforeEach(() => {
    h = new H();
    h.publish("zq-old", "1.0.0", 200 * DAY);
  });

  it("clean dependencies (old release, ordinary name) in the safe class → proceed, no touch", async () => {
    const s = await h.snapshot(1, { "zq-old": "1.0.0" });
    expect(await h.gate.decide(s.ctx)).toEqual({ action: "proceed" });
    expect(h.store.activeApproval("sha256:core1")).toMatchObject({ via: "auto" });
    const stored = h.store.getCheck("sha256:core1")!.result;
    expect(stored.dependencyStats).toMatchObject({ total: 1, verified: 1, unchecked: 0 });
  });

  it("a release younger than 3 days → held (review); a code approves exactly that version", async () => {
    await h.register();
    h.publish("zq-fresh", "2.0.0", 6 * 3_600_000);
    const s = await h.snapshot(1, { "zq-fresh": "2.0.0" });
    const d = await h.gate.decide(s.ctx);
    expect(d.action).toBe("wait");
    const q = h.store.listQueue()[0]!;
    expect(q.reason).toContain("dep-young-release");
    expect(h.gate.checkForQueue(q)!.findings.find((f) => f.rule === "dep-young-release")).toMatchObject({ severity: "review", file: "package.json" });
    h.tick();
    h.gate.approveQueue(q.id, h.code());
    expect((await h.gate.decide(s.ctx)).action).toBe("proceed");
  });

  it("the same dependency three days later is no longer young: the next version goes through by itself", async () => {
    h.publish("zq-fresh", "2.0.0", 6 * 3_600_000);
    expect((await h.gate.decide((await h.snapshot(1, { "zq-fresh": "2.0.0" })).ctx)).action).toBe("wait");
    h.t += 4 * DAY;
    expect((await h.gate.decide((await h.snapshot(2, { "zq-fresh": "2.0.0" })).ctx)).action).toBe("proceed");
  });

  it("a name that looks like a popular package → held", async () => {
    h.publish("lodahs", "1.0.0", 400 * DAY);
    const d = await h.gate.decide((await h.snapshot(1, { lodahs: "1.0.0" })).ctx);
    expect(d.action).toBe("wait");
    expect(h.store.listQueue()[0]!.reason).toContain("dep-lookalike");
  });

  it("a package that is not on the registry → held", async () => {
    expect((await h.gate.decide((await h.snapshot(1, { "zq-ghost": "1.0.0" })).ctx)).action).toBe("wait");
    expect(h.store.listQueue()[0]!.reason).toContain("dep-not-in-registry");
  });

  it("NO NETWORK: dependencies are 'not verified' and the version is held, never waved through", async () => {
    h.online = false;
    const s = await h.snapshot(1, { "zq-old": "1.0.0" });
    expect((await h.gate.decide(s.ctx)).action).toBe("wait");
    const q = h.store.listQueue()[0]!;
    expect(q.reason).toContain("dep-unchecked");
    expect(h.gate.checkForQueue(q)!.dependencyStats).toMatchObject({ unchecked: 1, verified: 0 });
  });

  it("a plugin without dependencies never touches the network", async () => {
    h.online = false;
    expect((await h.gate.decide((await h.snapshot(1, {})).ctx)).action).toBe("proceed");
    expect(h.requests).toBe(0);
  });

  it("unverified dependencies are verified again later, once the network is back (not before 10 minutes)", async () => {
    h.online = false;
    const s = await h.snapshot(1, { "zq-old": "1.0.0" });
    expect((await h.gate.decide(s.ctx)).action).toBe("wait");
    h.online = true;
    h.t += 5 * 60_000;
    const before = h.requests;
    expect((await h.gate.decide(s.ctx)).action).toBe("wait"); // the stored result is reused
    expect(h.requests).toBe(before);
    h.t += 6 * 60_000;
    expect((await h.gate.decide(s.ctx)).action).toBe("proceed"); // fresh result: clean
    expect(h.store.getCheck("sha256:core1")!.result.dependencyStats).toMatchObject({ verified: 1, unchecked: 0 });
  });

  it("the registry stage crashing holds the version (fail closed)", async () => {
    h.verifyThrows = true;
    const d = await h.gate.decide((await h.snapshot(1, { "zq-old": "1.0.0" })).ctx);
    expect(d.action).toBe("wait");
    expect(h.store.listLog(10).some((l) => l.kind === "check.error")).toBe(true);
  });

  it("a hard sign still rejects, whatever the dependencies say", async () => {
    const dir = join(h.snaps, "demo", "hb");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: "1.0.0", scripts: { postinstall: "node x.js" }, dependencies: { "zq-old": "1.0.0" } }));
    writeFileSync(join(dir, "server.ts"), "export default 1;\n");
    h.store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: "T1", windowId: null });
    expect((await h.gate.decide(ctx(dir, "sha256:coreb"))).action).toBe("reject");
  });
});

describe("§5.3 inside a window, with dependencies", () => {
  let h: H;
  const openWindow = async () => {
    h.store.putCheck("sha256:opening", "demo", { findings: [], capabilities: [], stats: { files: 1, parsed: 1, bytes: 1, ms: 0 } });
    const q = h.store.upsertQueue({ kind: "proposal", contentHash: "sha256:opening", pluginId: "demo", version: "1", source: "x", sourceKind: "path", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: "T1", proposalId: null, reason: null });
    h.tick();
    return h.gate.openWindow(q.id, h.code());
  };
  beforeEach(async () => {
    h = new H();
    await h.register();
    h.publish("zq-old", "1.0.0", 200 * DAY);
  });

  it("clean dependencies → proceed, window slides", async () => {
    const w = await openWindow();
    h.t += 60_000;
    expect((await h.gate.decide((await h.snapshot(1, { "zq-old": "1.0.0" })).ctx)).action).toBe("proceed");
    expect(h.store.activeApproval("sha256:core1")!.via).toBe("window");
    expect(h.store.getWindow(w.id)!.expiresAt).toBe(h.t + 30 * 60_000);
  });

  it("a fresh dependency inside the window → held for a code; the window stays open; the next clean version goes through", async () => {
    const w = await openWindow();
    h.publish("zq-fresh", "3.0.0", 3_600_000);
    const s1 = await h.snapshot(1, { "zq-fresh": "3.0.0" });
    expect((await h.gate.decide(s1.ctx)).action).toBe("wait");
    expect(h.store.listQueue()[0]!.reason).toContain("проверки требуют ревью: dep-young-release");
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull();
    expect(h.gate.openWindows()).toHaveLength(1);
    h.tick();
    h.gate.approveQueue(h.store.listQueue()[0]!.id, h.code());
    expect((await h.gate.decide(s1.ctx)).action).toBe("proceed");
    expect((await h.gate.decide((await h.snapshot(2, { "zq-old": "1.0.0" })).ctx)).action).toBe("proceed");
  });

  it("no network inside the window → held ('not verified'), window open", async () => {
    const w = await openWindow();
    h.online = false;
    expect((await h.gate.decide((await h.snapshot(1, { "zq-old": "1.0.0" })).ctx)).action).toBe("wait");
    expect(h.store.listQueue()[0]!.reason).toContain("dep-unchecked");
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull();
  });
});
