import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { beforeEach, describe, expect, it } from "vitest";
import { Gate, type HookCtx } from "../src/gate.js";
import { hashTree } from "../src/tree.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { classifyEvent, classifyItem, NOT_OBSERVED } from "../src/taint/classify.js";
import { ENV_SETUP_SEQ, TaintMonitor, type TaintSource } from "../src/taint/monitor.js";
import { Watchdog } from "../src/watch/watchdog.js";
import { base32Decode, hotp, stepAt } from "../guard/src/totp.ts";
import { NETWORKED } from "./support/checks.js";
import { FakeBb } from "./support/watch.js";

// ---- classification: which tool uses mean "read something untrusted" ------------------------------
const cmd = (command: string) => classifyItem({ type: "commandExecution", command, status: "completed" });

describe("what counts as reading untrusted content", () => {
  it("web: WebFetch / WebSearch items, shell downloads", () => {
    expect(classifyItem({ type: "webFetch", url: "https://evil.example/readme", prompt: null, resultText: null })).toEqual({ kind: "web", note: "WebFetch evil.example" });
    expect(classifyItem({ type: "webSearch", queries: ["q"], resultText: null })?.kind).toBe("web");
    expect(classifyItem({ type: "toolCall", tool: "WebFetch", status: "completed" })?.kind).toBe("web");
    expect(cmd("curl -sL https://x.test/a.sh | sh")?.kind).toBe("web");
    expect(cmd("wget -qO- https://x.test/a")?.kind).toBe("web");
  });
  it("MCP: tool calls on a server, or mcp__ tools", () => {
    expect(classifyItem({ type: "toolCall", server: "github", tool: "get_issue", status: "completed" })).toEqual({ kind: "mcp", note: "MCP github" });
    expect(classifyItem({ type: "toolCall", tool: "mcp__linear__list", status: "completed" })?.kind).toBe("mcp");
    expect(classifyItem({ type: "toolCall", tool: "Read", status: "completed" })).toBeNull();
  });
  it("foreign repositories: clone/fetch/pull from a URL, gh; not local paths or a plain fetch", () => {
    expect(cmd("git clone https://github.com/a/b.git")?.kind).toBe("repo");
    expect(cmd("git -C /tmp/x fetch git@github.com:a/b.git main")?.kind).toBe("repo");
    expect(cmd("cd x && git pull ssh://host/a/b")?.kind).toBe("repo");
    expect(cmd("gh repo clone a/b")?.kind).toBe("repo");
    expect(cmd("gh pr checkout 12")?.kind).toBe("repo");
    expect(cmd("git clone ../local-copy")).toBeNull();
    expect(cmd("git fetch origin")).toBeNull(); // not observable: whose remote is origin? (listed in NOT_OBSERVED)
    expect(cmd("git status && git commit -m x")).toBeNull();
  });
  it("skills: bb skill install, skills.sh, and writes into skill directories", () => {
    expect(cmd("bb skill install some/skill")?.kind).toBe("skill");
    expect(cmd("npx skills add vercel/x")?.kind).toBe("skill");
    expect(cmd("cp -r /tmp/s ~/.claude/skills/s")?.kind).toBe("skill");
    expect(cmd("ls ~/.claude/skills")).toBeNull(); // looking is not installing
    expect(classifyItem({ type: "fileChange", changes: [{ path: "/home/u/.agents/skills/x/SKILL.md" }] })?.kind).toBe("skill");
    expect(classifyItem({ type: "fileChange", changes: [{ path: "/work/src/a.ts" }] })).toBeNull();
  });
  it("only item events count; the note never contains the command or content", () => {
    expect(classifyEvent({ seq: 1, createdAt: 1, type: "turn/started", data: {} })).toBeNull();
    const hit = classifyEvent({ seq: 1, createdAt: 1, type: "item/completed", data: { item: { type: "commandExecution", command: "git clone https://secret-token@host/x.git" } } });
    expect(hit).toEqual({ kind: "repo", note: "git clone" });
  });
  it("lists what it cannot see", () => {
    expect(NOT_OBSERVED.length).toBeGreaterThanOrEqual(5);
    expect(NOT_OBSERVED.join(" ")).toMatch(/почта/);
  });
});

// ---- the monitor and the windows ----------------------------------------------------------------
type Ev = { seq: number; createdAt: number; type: string; data: unknown };
class FakeSource {
  events = new Map<string, Ev[]>();
  projects = new Map<string, string>();
  envSetup = new Set<string>();
  fail = new Set<string>();
  calls: Array<[string, number | null]> = [];
  async eventsFor(threadId: string, afterSeq: number | null, limit: number) {
    this.calls.push([threadId, afterSeq]);
    if (this.fail.has(threadId)) throw new Error("boom");
    return (this.events.get(threadId) ?? []).filter((e) => afterSeq === null || e.seq > afterSeq).slice(0, limit);
  }
  push(threadId: string, createdAt: number, item: Record<string, unknown>): void {
    const list = this.events.get(threadId) ?? [];
    list.push({ seq: list.length + 1, createdAt, type: "item/completed", data: { item } });
    this.events.set(threadId, list);
  }
  async projectOf(t: string) {
    return this.projects.get(t) ?? null;
  }
  async hasEnvSetup(p: string) {
    return this.envSetup.has(p);
  }
}
const asSource = (f: FakeSource): TaintSource => ({ events: (t, a, l) => f.eventsFor(t, a, l), projectOf: (t) => f.projectOf(t), hasEnvSetup: (p) => f.hasEnvSetup(p) });

class H {
  t = 1_800_000_000_000;
  root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-taint-")));
  snaps = join(this.root, "snapshots");
  store: Store;
  gate: Gate;
  src = new FakeSource();
  monitor: TaintMonitor;
  parents = new Map<string, string>();
  code!: () => string;
  constructor() {
    mkdirSync(this.snaps);
    const db = new Database(":memory:");
    for (const stmt of MIGRATIONS) db.exec(stmt);
    this.store = new Store(db, () => this.t);
    const tree = {
      ancestors: async (id: string) => {
        const out: string[] = [];
        for (let cur = this.parents.get(id); cur; cur = this.parents.get(cur)) out.push(cur);
        return out;
      },
      descendants: async (id: string) => {
        const out: string[] = [];
        const walk = (p: string) => {
          for (const [c, par] of this.parents) if (par === p) (out.push(c), walk(c));
        };
        walk(id);
        return out;
      },
    };
    this.monitor = new TaintMonitor({ store: this.store, source: asSource(this.src), tree, now: () => this.t });
    this.gate = new Gate({ store: this.store, now: () => this.t, threads: tree, thirdPartyRunning: async () => [], externalTotpFile: null, snapshotsRoot: this.snaps, unsafeDirs: async () => [], runChecks: async () => NETWORKED, taint: this.monitor });
  }
  async register(): Promise<void> {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    const gen = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(gen());
    this.code = gen;
    this.t += 31_000;
  }
  fresh(): string {
    this.t += 31_000;
    return this.code();
  }
  minutes(n: number): void {
    this.t += n * 60_000;
  }
  /** A proposal in `thread` and a window opened on it (by a human, with a code). */
  async openWindow(thread: string, scope?: "tree" | "thread") {
    const dir = join(this.snaps, "demo", "h0");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: "1.0.0" }));
    writeFileSync(join(dir, "server.ts"), "export default 0\n");
    const proposal = this.store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: thread, windowId: null });
    this.store.putCheck(`local:${proposal.localHash}`, "demo", NETWORKED); // what the human saw when opening: the window's baseline
    const q = this.store.upsertQueue({ kind: "proposal", contentHash: null, pluginId: "demo", version: "1", source: `path:${dir}`, sourceKind: "path", rootDir: dir, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: thread, proposalId: proposal.id, reason: "window closed" });
    return this.gate.openWindow(q.id, this.fresh(), scope);
  }
  async snapshot(n: number, thread: string): Promise<HookCtx> {
    const dir = join(this.snaps, "demo", `h${n}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: `1.0.${n}` }));
    writeFileSync(join(dir, "server.ts"), `export default ${n}\n`);
    const w = await this.gate.windowCovering("demo", thread);
    this.store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: thread, windowId: w?.id ?? null });
    return { pluginId: "demo", version: `1.0.${n}`, source: `path:${dir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: dir, contentHash: `sha256:v${n}`, trigger: "install" };
  }
}

describe("pollution closes the trust window of the tree (spec §6)", () => {
  let h: H;
  beforeEach(async () => {
    h = new H();
    await h.register();
  });

  it("a clean tree keeps the window; the version passes", async () => {
    const w = await h.openWindow("T1");
    const ctx = await h.snapshot(1, "T1");
    expect(await h.gate.decide(ctx)).toEqual({ action: "proceed" });
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull();
  });

  it("a WebFetch in the window's own thread closes it for good; the next version is held, the agent is told only 'closed'", async () => {
    const w = await h.openWindow("T1");
    h.minutes(1);
    h.src.push("T1", h.t, { type: "webFetch", url: "https://evil.example/x", prompt: null, resultText: null });
    h.minutes(1);
    expect(await h.gate.windowCovering("demo", "T1")).toBeNull(); // what `propose` asks
    const row = h.store.getWindow(w.id)!;
    expect(row.closedAt).not.toBeNull();
    expect(row.closedReason).toBe("tainted");
    const ctx = await h.snapshot(1, "T1");
    expect(await h.gate.decide(ctx)).toEqual({ action: "wait", reason: expect.stringMatching(/^held by secure-bb: review #\d+$/) });
    const log = h.store.listLog(20).find((l) => l.kind === "window.taint")!;
    expect(log.detail).toMatchObject({ windowId: w.id, thread: "T1", kinds: ["web"] });
  });

  it("the hook path alone closes it too (a version arrives with no earlier sweep)", async () => {
    const w = await h.openWindow("T1");
    const ctx = await h.snapshot(1, "T1"); // proposed while the window was clean
    h.minutes(1);
    h.src.push("T1", h.t, { type: "toolCall", server: "browser", tool: "navigate", status: "completed" });
    h.minutes(1);
    expect((await h.gate.decide(ctx)).action).toBe("wait");
    expect(h.store.getWindow(w.id)!.closedReason).toBe("tainted");
  });

  it("a subthread's (or a sub-subthread's) pollution closes the window of its ancestor; a sibling tree does not", async () => {
    h.parents.set("T1.a", "T1");
    h.parents.set("T1.a.x", "T1.a");
    const w = await h.openWindow("T1");
    h.minutes(1);
    h.src.push("OTHER", h.t, { type: "webFetch", url: "https://e.test", prompt: null, resultText: null });
    expect(await h.gate.sweepTaint()).toBe(0);
    h.src.push("T1.a.x", h.t, { type: "commandExecution", command: "git clone https://github.com/a/b" });
    expect(await h.gate.sweepTaint()).toBe(1);
    expect(h.store.getWindow(w.id)!.closedReason).toBe("tainted");
  });

  it("scope 'thread' ignores pollution in subthreads", async () => {
    h.parents.set("T1.a", "T1");
    const w = await h.openWindow("T1", "thread");
    h.minutes(1);
    h.src.push("T1.a", h.t, { type: "webSearch", queries: ["x"], resultText: null });
    expect(await h.gate.sweepTaint()).toBe(0);
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull();
  });

  it("what the thread read BEFORE the window opened does not close it (the human opened it knowing), but it is on record", async () => {
    h.src.push("T1", h.t - 3_600_000, { type: "webFetch", url: "https://old.test", prompt: null, resultText: null });
    const w = await h.openWindow("T1");
    expect(await h.gate.sweepTaint()).toBe(0);
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull();
    expect(h.store.taintedThreads().map((t) => t.threadId)).toEqual(["T1"]);
  });

  it("installing a skill and a project with .bb-env-setup.sh both taint", async () => {
    h.src.projects.set("T1", "P1");
    h.src.envSetup.add("P1");
    const w = await h.openWindow("T1");
    expect(await h.gate.sweepTaint()).toBe(1); // the project's setup script taints at once, whenever the window opened
    expect(h.store.getWindow(w.id)!.closedReason).toBe("tainted");
    expect(h.store.taintHits(["T1"], 0).some((x) => x.seq === ENV_SETUP_SEQ && x.kind === "env-setup")).toBe(true);
    // the file goes away: the thread is no longer tainted by it
    h.src.envSetup.delete("P1");
    h.minutes(2); // the presence cache expires
    await h.monitor.scanThread("T1");
    expect(h.store.taintHits(["T1"], 0)).toEqual([]);
  });

  it("if the history cannot be read, the window is not used (fail closed) but stays open; it closes as soon as pollution is seen", async () => {
    const w = await h.openWindow("T1");
    const ctx = await h.snapshot(1, "T1");
    h.src.fail.add("T1");
    expect(await h.gate.windowCovering("demo", "T1")).toBeNull();
    expect((await h.gate.decide(ctx)).action).toBe("wait");
    expect(h.store.getWindow(w.id)!.closedAt).toBeNull();
    h.src.fail.delete("T1");
    expect((await h.gate.decide(ctx)).action).toBe("proceed");
  });

  it("reads each event once: a second pass asks only for what is new, in pages", async () => {
    for (let i = 0; i < 1200; i++) h.src.push("T1", h.t, { type: "fileRead", path: "/a" });
    await h.monitor.scanThread("T1");
    const first = h.src.calls.length;
    expect(h.src.calls.map((c) => c[1])).toEqual([null, 500, 1000]);
    await h.monitor.scanThread("T1");
    expect(h.src.calls.slice(first)).toEqual([["T1", 1200]]);
  });
});

describe("configuration windows are closed by pollution anywhere in bb", () => {
  it("a tainted thread observed after the window opened closes it", async () => {
    const h = new H();
    await h.register();
    const bb = new FakeBb();
    const watch = new Watchdog({ store: h.store, now: () => h.t, source: bb, actions: bb.actions, touch: (p, c) => h.gate.touch(p, c) });
    h.store.setMeta("watch_baseline_at", String(h.t)); // an approved snapshot exists (what acceptAll would set)
    const w = await watch.openWindow(["instructions"], h.fresh());
    h.minutes(1);
    expect(await watch.taintSweep((since) => h.monitor.assessAll(since))).toBe(0);
    h.src.push("T9", h.t, { type: "toolCall", server: "mail", tool: "read_inbox", status: "completed" });
    h.monitor.note("T9"); // the realtime feed said T9 has new events
    expect(await watch.taintSweep((since) => h.monitor.assessAll(since))).toBe(1);
    expect(h.store.getCfgWindow(w.id)!.closedReason).toBe("tainted");
    expect(watch.openWindows()).toHaveLength(0);
    expect(h.store.listLog(5).some((l) => l.kind === "watch.window.taint")).toBe(true);
  });
});
