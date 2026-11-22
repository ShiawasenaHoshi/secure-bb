// One rule of what an open window lets in by rights (`windowAllows`, guard/src/trust.ts). The guard (`windowRefuses`) and the plugin's hook without a guard
// (`decideUnsafe`) both call it; this table feeds the SAME check result and the SAME baseline to both and wants the same decision.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import type { CheckResult } from "../../src/checks/index.js";
import { Gate, type HookCtx } from "../../src/gate.js";
import { MIGRATIONS, Store } from "../../src/store.js";
import { base32Decode, hotp, stepAt } from "../../guard/src/totp.ts";
import { hashTree } from "../../src/tree.js";
import { capabilityTokens, rightsOf, windowAllows } from "../../guard/src/trust.ts";
import { CLEAN, withFindings } from "../support/checks.js";
import { coreHash, startGuard, type TestGuard } from "./support.ts";

const cleanup: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});
const tmp = (p: string): string => {
  const d = realpathSync(mkdtempSync(join(tmpdir(), p)));
  cleanup.push(() => rmSync(d, { recursive: true, force: true }));
  return d;
};
const caps = (...c: Array<[CheckResult["capabilities"][number]["kind"], string[]]>): CheckResult => ({ ...CLEAN, capabilities: c.map(([kind, detail]) => ({ kind, detail, sites: [] })) });
const REVIEW = [{ rule: "dynamic-access", severity: "review" as const, file: "server.ts", line: 2, excerpt: "x[y]" }];
const withReview = (r: CheckResult): CheckResult => withFindings(REVIEW, r);

const NET_A = caps(["network", ["a.example"]]);
const CASES: Array<{ name: string; baseline: CheckResult; version: CheckResult; allowed: boolean }> = [
  { name: "the same rights", baseline: NET_A, version: NET_A, allowed: true },
  { name: "fewer rights", baseline: caps(["network", ["a.example"]], ["env", ["HOME"]]), version: NET_A, allowed: true },
  { name: "nothing at all, from nothing", baseline: CLEAN, version: CLEAN, allowed: true },
  { name: "a new host", baseline: NET_A, version: caps(["network", ["a.example", "b.example"]]), allowed: false },
  { name: "a new kind", baseline: NET_A, version: caps(["network", ["a.example"]], ["child_process", []]), allowed: false },
  { name: "rights from nothing", baseline: CLEAN, version: NET_A, allowed: false },
  // the hook held any review finding in a window, the guard only a new rule: the one rule is the stricter
  { name: "something for review, rights the same", baseline: NET_A, version: withReview(NET_A), allowed: false },
  { name: "the same review the baseline already had", baseline: withReview(NET_A), version: withReview(NET_A), allowed: false },
];

/** The guard: a real one, with the check result of each version supplied; an approved baseline; a window over everything. */
async function guardDecides(baseline: CheckResult, version: CheckResult): Promise<"proceed" | "wait"> {
  let current = baseline;
  const g: TestGuard = await startGuard({ trust: { checks: async () => current }, windowContentChecks: true });
  cleanup.push(() => g.close());
  const dir = tmp("sbb-wr-g-");
  const put = (n: number): string => {
    const d = join(dir, "p");
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "p", version: `1.0.${n}`, bb: { name: "p", server: "./server.ts" } }));
    writeFileSync(join(d, "server.ts"), `export default () => ${n};\n`);
    return d;
  };
  const req = (d: string, n: number) => ({ op: "decide", pluginId: "p", version: `1.0.${n}`, contentHash: coreHash(d), rootDir: d, source: `path:${d}`, sourceKind: "path", provenance: "direct", trigger: "update" });
  const d1 = put(1);
  const first = await g.send(req(d1, 1));
  // A baseline with a review finding is approved knowingly (the guard held it: it is not clean)
  await g.send({ op: "approve", requestId: first.requestId, acknowledgeBlock: false, code: g.nextCode() });
  g.guard.openWindow({ pluginId: "p", minutes: 30, code: g.nextCode() });
  current = version;
  const d2 = put(2);
  return (await g.send(req(d2, 2))).action;
}

/** The plugin's hook without a guard: a real gate, a window opened on the baseline, the same check result for the new version. */
async function hookDecides(baseline: CheckResult, version: CheckResult): Promise<"proceed" | "wait"> {
  const root = tmp("sbb-wr-h-");
  const snaps = join(root, "snapshots");
  mkdirSync(snaps);
  const db = new Database(":memory:");
  for (const s of MIGRATIONS) db.exec(s);
  let t = 1_800_000_000_000;
  const store = new Store(db, () => t);
  let next = baseline;
  const gate = new Gate({ store, now: () => t, threads: { ancestors: async () => [], descendants: async () => [] }, thirdPartyRunning: async () => [], externalTotpFile: null, snapshotsRoot: snaps, unsafeDirs: async () => [], runChecks: async () => next, checkWaitMs: 200 });
  const { secret } = await gate.beginRegistration({ attended: true, caller: "test" });
  const code = () => hotp(base32Decode(secret), stepAt(t));
  gate.confirmRegistration(code());
  t += 31_000;
  store.putCheck("sha256:opening", "p", baseline);
  const q = store.upsertQueue({ kind: "proposal", contentHash: "sha256:opening", pluginId: "demo", version: "1", source: "x", sourceKind: "path", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: "T1", proposalId: null, reason: null } as never);
  t += 31_000;
  await gate.openWindow(q.id, code());
  next = version;
  const dir = join(snaps, "demo", "h1");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: "1.0.1" }));
  writeFileSync(join(dir, "server.ts"), "export default () => 1;\n");
  const w = await gate.windowCovering("demo", "T1");
  store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: "T1", windowId: w?.id ?? null });
  const ctx: HookCtx = { pluginId: "demo", version: "1.0.1", source: `path:${dir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: dir, contentHash: "sha256:core1", trigger: "install" };
  return (await gate.decide(ctx)).action as "proceed" | "wait";
}

describe("one rule for the window: the guard and the hook decide alike", () => {
  for (const c of CASES) {
    it(`${c.name}: ${c.allowed ? "lets in" : "holds"} — in the function, at the guard and in the hook`, async () => {
      const expected = c.allowed ? "proceed" : "wait";
      expect(windowAllows(rightsOf(c.baseline), rightsOf(c.version)).allowed).toBe(c.allowed);
      expect(await guardDecides(c.baseline, c.version)).toBe(expected);
      expect(await hookDecides(c.baseline, c.version)).toBe(expected);
    });
  }

  it("the tokens of rights come from one function: the page's, the hook's and the guard's lists are the same", () => {
    expect(rightsOf(NET_A).tokens).toEqual(capabilityTokens(NET_A));
    expect(capabilityTokens(caps(["network", ["b", "a"]]))).toEqual(["network", "network:a", "network:b"]);
  });
});
