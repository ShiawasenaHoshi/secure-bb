// Spec §5.3: the decision table, branch by branch.
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { beforeEach, describe, expect, it } from "vitest";
import type { CheckResult } from "../src/checks/index.js";
import { Gate, GateError, type HookCtx } from "../src/gate.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";
import { hashTree } from "../src/tree.js";
import { CLEAN, NETWORKED, withCaps, withFindings } from "./support/checks.js";

const BLOCK = withFindings([{ rule: "decode-eval", severity: "block", file: "server.ts", line: 3, excerpt: "eval(atob(…))" }]);
const REVIEW = withFindings([{ rule: "dynamic-access", severity: "review", file: "server.ts", line: 2, excerpt: "x[y]" }]);

class H {
  t = 1_800_000_000_000;
  store: Store;
  gate: Gate;
  root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-dec-")));
  snaps = join(this.root, "snapshots");
  next: (dir: string) => Promise<CheckResult> = async () => CLEAN;
  runs = 0;
  wait = 8000;
  code!: () => string;
  constructor() {
    mkdirSync(this.snaps);
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    this.store = new Store(db, () => this.t);
    this.gate = new Gate({
      store: this.store,
      now: () => this.t,
      threads: { ancestors: async () => [], descendants: async () => [] },
      thirdPartyRunning: async () => [],
      externalTotpFile: null,
      snapshotsRoot: this.snaps, unsafeDirs: async () => [],
      runChecks: async (d) => (this.runs++, this.next(d)),
      checkWaitMs: 200,
    });
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
  /** A snapshot plus its proposal, as `propose` leaves them; `thread` is covered by an open window if there is one. */
  async snapshot(n: number, thread = "T1") {
    const dir = join(this.snaps, "demo", `h${n}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: `1.0.${n}` }));
    writeFileSync(join(dir, "server.ts"), `export default () => ${n};\n`);
    const w = await this.gate.windowCovering("demo", thread);
    const proposal = this.store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: thread, windowId: w?.id ?? null });
    return { dir, proposal, ctx: ctx(dir, `sha256:core${n}`, n) };
  }
}
const ctx = (rootDir: string, contentHash: string, n = 0): HookCtx => ({
  pluginId: "demo", version: `1.0.${n}`, source: `path:${rootDir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir, contentHash, trigger: "install",
});

describe("§5.3 outside a window", () => {
  let h: H;
  beforeEach(() => {
    h = new H();
  });

  it("block → reject with the reason; the entry is held for a knowing approval", async () => {
    h.next = async () => BLOCK;
    const s = await h.snapshot(1);
    const d = await h.gate.decide(s.ctx);
    // The agent learns only that it was stopped: no rule, no file (spec §11); the reasons are on the entry for the human.
    expect(d).toMatchObject({ action: "reject", message: "rejected by secure-bb: review #1" });
    expect((d as { message: string }).message).not.toMatch(/decode-eval|server\.ts/);
    const q = h.store.listQueue()[0]!;
    expect(q).toMatchObject({ status: "held", reason: expect.stringContaining("decode-eval server.ts:3") });
    expect(h.store.listLog().some((l) => l.kind === "reject")).toBe(true);
  });

  it("a block is lifted only with a code AND an explicit acknowledgement, then the snapshot loads", async () => {
    await h.register();
    h.next = async () => BLOCK;
    const s = await h.snapshot(1);
    await h.gate.decide(s.ctx);
    const q = h.store.listQueue()[0]!;
    expect(() => h.gate.approveQueue(q.id, h.code())).toThrow(GateError); // no acknowledgement
    h.tick();
    expect(() => h.gate.openWindow(q.id, h.code())).toThrow(/blocked/); // no window on a blocked version
    h.tick();
    const res = h.gate.approveQueue(q.id, h.code(), { acknowledgeBlock: true });
    expect(res.installDir).toBe(s.dir); // the server installs it again
    expect(h.store.listLog().some((l) => l.kind === "block.lifted")).toBe(true);
    expect((await h.gate.decide(s.ctx)).action).toBe("proceed");
  });

  it("safe class + clean + our snapshot → proceed without a touch", async () => {
    const s = await h.snapshot(1);
    expect(await h.gate.decide(s.ctx)).toEqual({ action: "proceed" });
    expect(h.store.activeApproval("sha256:core1")).toMatchObject({ via: "auto", localHash: s.proposal.localHash });
    expect(h.store.listLog().some((l) => l.kind === "approved.auto")).toBe(true);
  });

  it("a capability outside the safe class → held", async () => {
    h.next = async () => NETWORKED;
    const d = await h.gate.decide((await h.snapshot(1)).ctx);
    expect(d.action).toBe("wait");
    expect(h.store.listQueue()[0]!.reason).toContain("вне безопасного класса: network");
  });

  it("a review finding → held", async () => {
    h.next = async () => REVIEW;
    expect((await h.gate.decide((await h.snapshot(1)).ctx)).action).toBe("wait");
    expect(h.store.listQueue()[0]!.reason).toContain("dynamic-access");
  });

  it("not our snapshot (external / direct path) is never auto, even when clean", async () => {
    const dir = join(h.root, "elsewhere");
    mkdirSync(dir);
    expect((await h.gate.decide(ctx(dir, "sha256:ext"))).action).toBe("wait");
  });

  it("a snapshot checked at propose time is not checked again at load, and the result follows the core's hash", async () => {
    const s = await h.snapshot(1);
    await h.gate.checkSnapshot("demo", s.proposal.localHash, s.dir);
    expect(h.runs).toBe(1);
    await h.gate.decide(s.ctx);
    expect(h.runs).toBe(1);
    expect(h.store.getCheck("sha256:core1")).not.toBeNull();
  });
});

describe("§5.3 failures of the checks", () => {
  let h: H;
  beforeEach(() => {
    h = new H();
  });
  it("one failure is retried and the second run decides", async () => {
    let n = 0;
    h.next = async () => {
      if (n++ === 0) throw new Error("flaky");
      return CLEAN;
    };
    expect((await h.gate.decide((await h.snapshot(1)).ctx)).action).toBe("proceed");
    expect(h.runs).toBe(2);
  });
  it("two failures → held (fail closed)", async () => {
    h.next = async () => {
      throw new Error("down");
    };
    const d = await h.gate.decide((await h.snapshot(1)).ctx);
    expect(d.action).toBe("wait");
    expect(h.runs).toBe(2);
    expect(h.store.listQueue()[0]!.reason).toContain("проверки не завершились");
    expect(h.store.listLog().some((l) => l.kind === "check.error")).toBe(true);
  });
  it("checks slower than the hook may wait → held, and the late result is stored", async () => {
    h.next = () => new Promise((r) => setTimeout(() => r(CLEAN), 400));
    const s = await h.snapshot(1);
    expect((await h.gate.decide(s.ctx)).action).toBe("wait");
    await h.gate.checksIdle();
    expect(h.store.getCheck(`local:${s.proposal.localHash}`)).not.toBeNull();
    expect((await h.gate.decide(s.ctx)).action).toBe("proceed"); // the recheck after the late result
  });
});

describe("§5.3 inside a window", () => {
  let h: H;
  const open = async (opening: CheckResult) => {
    h.store.putCheck("sha256:opening", "demo", opening);
    const q = h.store.upsertQueue({ kind: "proposal", contentHash: "sha256:opening", pluginId: "demo", version: "1", source: "x", sourceKind: "path", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: "T1", proposalId: null, reason: null });
    h.tick();
    return h.gate.openWindow(q.id, h.code());
  };
  beforeEach(async () => {
    h = new H();
    await h.register();
  });

  it("clean and no new capability → proceed, window slides", async () => {
    const w = await open(NETWORKED);
    h.next = async () => NETWORKED;
    h.t += 60_000;
    expect((await h.gate.decide((await h.snapshot(1)).ctx)).action).toBe("proceed");
    expect(h.store.activeApproval("sha256:core1")!.via).toBe("window");
    expect(h.store.getWindow(w.id)!.expiresAt).toBe(h.t + 30 * 60_000);
  });

  it("a new capability → held until a code; the window stays open; after the code it is part of the window", async () => {
    const w = await open(NETWORKED);
    h.next = async () => withCaps("network", "child_process");
    const s1 = await h.snapshot(1);
    expect((await h.gate.decide(s1.ctx)).action).toBe("wait");
    const q = h.store.listQueue()[0]!;
    expect(q.reason).toContain("новая возможность в окне");
    expect(q.reason).toContain("child_process");
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull(); // never closes the window
    expect(h.gate.openWindows()).toHaveLength(1);

    h.tick();
    h.gate.approveQueue(q.id, h.code());
    expect(h.store.getWindow(w.id)!.caps).toContain("child_process");
    expect((await h.gate.decide(s1.ctx)).action).toBe("proceed"); // the approved version loads

    // the next version with the same capabilities goes straight through
    const s2 = await h.snapshot(2);
    expect((await h.gate.decide(s2.ctx)).action).toBe("proceed");
    expect(h.store.activeApproval("sha256:core2")!.via).toBe("window");
  });

  it("a new detail of a known kind (another host) also counts as new", async () => {
    await open({ ...NETWORKED, capabilities: [{ kind: "network", detail: ["host:a.example"], sites: [] }] });
    h.next = async () => ({ ...NETWORKED, capabilities: [{ kind: "network", detail: ["host:evil.example"], sites: [] }] });
    expect((await h.gate.decide((await h.snapshot(1)).ctx)).action).toBe("wait");
    expect(h.store.listQueue()[0]!.reason).toContain("network:host:evil.example");
  });

  it("a review finding in the window → held, window stays open", async () => {
    const w = await open(CLEAN);
    h.next = async () => REVIEW;
    expect((await h.gate.decide((await h.snapshot(1)).ctx)).action).toBe("wait");
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull();
  });

  it("a block in the window rejects only that version; the window stays open", async () => {
    const w = await open(CLEAN);
    h.next = async () => BLOCK;
    expect((await h.gate.decide((await h.snapshot(1)).ctx)).action).toBe("reject");
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull();
    h.next = async () => CLEAN;
    expect((await h.gate.decide((await h.snapshot(2)).ctx)).action).toBe("proceed");
  });

  it("if the opening version's checks are unknown, any capability is new (strict)", async () => {
    const q = h.store.upsertQueue({ kind: "proposal", contentHash: null, pluginId: "demo", version: "1", source: "x", sourceKind: "path", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: "T1", proposalId: null, reason: null });
    h.tick();
    h.gate.openWindow(q.id, h.code());
    h.next = async () => NETWORKED;
    expect((await h.gate.decide((await h.snapshot(1)).ctx)).action).toBe("wait");
  });

  it("an expired window gives no free pass: a capability is held like outside a window", async () => {
    await open(NETWORKED);
    h.next = async () => NETWORKED;
    const s = await h.snapshot(1);
    h.t += 31 * 60_000;
    expect((await h.gate.decide(s.ctx)).action).toBe("wait");
  });
});
