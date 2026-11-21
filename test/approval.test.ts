// Approval session and batch approval (docs: secure-bb-approval-ux.md §1–2) through the plugin's real surfaces
// (RPC, CLI, the plugin.activate hook) over the fake bb host, with a fake clock (Date only).
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import plugin from "../server.js";
import { RPC_AUTH, SESSION_CAP_MS, SESSION_IDLE_MS, SessionProof, authTableMarkdown, groupOf, hashToken, setHash, type RpcGroup } from "../src/approval.js";
import { rpcContract } from "../src/contract.js";
import { Gate } from "../src/gate.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";

const MIN = 60_000;

// ---------------------------------------------------------------------------------------------- the table
// The table of the document, written out a second time on purpose: the test fails if the code and the document differ.
// routine = a session covers it; dangerous = always a fresh code; free = no secret needed.
const EXPECTED: Record<string, RpcGroup> = {
  // routine (doc §1: одобрить удержанную версию, открыть/продлить окно, принять расхождение, одобрить скилл, принять эталон; + пакет)
  "queue.approve": "routine",
  "queue.dismiss": "free",
  "window.open": "routine",
  "window.close": "free", // tightening: no code (threat model F8)
  "approval.revoke": "free",
  "watch.accept": "routine",
  "watch.acceptAll": "routine",
  "watch.rollback": "routine",
  "watch.window.open": "routine",
  "watch.window.close": "free",
  "skills.approve": "routine",
  "batch.approve": "routine",
  // dangerous (doc §1: политика, снять блок, выключить защиту/откат, доверенные репозитории/источники, провайдер/адрес, регистрация)
  "session.open": "dangerous",
  "queue.approveTrust": "dangerous",
  "totp.confirm": "dangerous",
  "trusted.set": "dangerous",
  "skills.trusted": "dangerous",
  "policy.set": "dangerous",
  "watch.rollbackMode": "dangerous",
  "ai.settings": "dangerous",
  "publish.settings": "dangerous",
  "sentinel.settings": "dangerous",
  "setup-check": "dangerous",
  "approvals.export": "dangerous",
  "agents.accept": "dangerous", // a touch for exactly these differences, at the guard: a session does not do
  "trust.mode": "dangerous", // weakening the mode is a touch at the guard; strengthening needs none (the guard says which)
  "trust.add": "dangerous",
  "trust.migrate": "dangerous",
  // free
  overview: "free",
  "journal.verify": "free",
  "guard.verify": "free",
  "passkey.challenge": "free",
  "passkey.register": "free",
  "page.ping": "free",
  "totp.begin": "free",
  "session.close": "free",
  "batch.prepare": "free",
  "watch.scan": "free",
  "skills.scan": "free",
  "skills.remove": "free",
  "skills.removed": "free",
  "agents.scan": "free",
  "agents.reject": "free", // tightening: «Это не я — отклонить» marks a difference, takes nothing into the baseline
  "trust.remove": "free", // tightening
  "ai.scan": "free",
  "publish.run": "free",
};

describe("the table of RPC groups", () => {
  const contractNames = Object.keys(rpcContract).sort();

  it("lists every RPC of the contract exactly once, and nothing else", () => {
    expect(Object.keys(RPC_AUTH).sort()).toEqual(contractNames);
    expect(Object.keys(EXPECTED).sort()).toEqual(contractNames);
  });

  it.each(contractNames)("%s is in the right group", (name) => {
    expect(groupOf(name as keyof typeof rpcContract)).toBe(EXPECTED[name]);
  });

  // The group is not a label only: the input schema of a routine RPC takes a session token, and the schema of every other one refuses it.
  it.each(contractNames)("%s: the input schema takes a session token exactly when the RPC is routine", (name) => {
    const schema = (rpcContract as Record<string, { input: { "~standard": { validate: (v: unknown) => { issues?: Array<{ message: string; path?: ReadonlyArray<string | number> }> } } } }>)[name]!.input;
    const res = schema["~standard"].validate({ session: "token" });
    // Routine: the key is known (other fields may be missing). Any other RPC: the object is refused (unknown key, or no object at all).
    const refusesKey = (res.issues ?? []).some((i) => (i.message === "unknown key" && i.path?.[0] === "session") || i.message === "expected null");
    expect(refusesKey).toBe(EXPECTED[name] !== "routine");
  });

  it("the README prints the same table", () => {
    const readme = readFileSync(fileURLToPath(new URL("../README.md", import.meta.url)), "utf8");
    expect(readme).toContain(authTableMarkdown());
  });
});

describe("proofs cannot be forged", () => {
  it("a session proof is made by the gate only", () => {
    expect(() => new SessionProof("token", Symbol("mint"))).toThrow(/gate only/);
  });
  it("the set hash does not depend on order and changes with any item or fingerprint", () => {
    const a = { kind: "queue" as const, id: 1, fingerprint: "x" };
    const b = { kind: "skill" as const, id: 2, fingerprint: "y" };
    expect(setHash([a, b])).toBe(setHash([b, a]));
    expect(setHash([a, b])).not.toBe(setHash([a]));
    expect(setHash([a, b])).not.toBe(setHash([a, { ...b, fingerprint: "z" }]));
    expect(setHash([a, b])).not.toBe(setHash([a, { ...b, id: 3 }]));
  });
});

// ------------------------------------------------------------------------------------------- the server
interface Installed {
  id: string;
  provenance: string;
  enabled: boolean;
  status: string;
  version: string;
  source: string;
  rootDir: string;
}
async function boot() {
  let plugins: Installed[] = [];
  const dataDir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-appr-")));
  const { bb, harness } = createFakePluginHost({
    pluginId: "secure-bb",
    experimental_dataDir: dataDir,
    sdk: {
      plugins: { list: async () => ({ plugins }), enable: async () => ({}), disable: async () => ({}), install: async () => ({ id: "demo", version: "1.0.0", status: "disabled", statusDetail: null }) },
      system: { config: async () => ({ generalSettings: { telemetryEnabled: true }, primaryHostId: null }) },
      threads: {
        experimental_listAncestors: async () => ({ threads: [] }),
        experimental_listDescendants: async () => ({ threads: [] }),
        get: async () => ({ environmentId: null }),
      },
    } as never,
  } as never);
  await plugin(bb);
  const rpc = <T = unknown>(name: string, input: unknown = null) => harness.behavior.callRpc(name as never, input as never) as Promise<T>;
  const hook = harness.registrations.hooks["plugin.activate"]!;
  return { bb, harness, rpc, hook, setPlugins: (p: Installed[]) => (plugins = p) };
}
type Booted = Awaited<ReturnType<typeof boot>>;

const tick = (ms = 31_000) => vi.setSystemTime(Date.now() + ms);

/** Registers TOTP and returns `fresh()`: a code of a step that was not used yet (moves the clock by one step each call). */
async function register(h: Booted): Promise<() => string> {
  await h.rpc("page.ping");
  const begin = await h.rpc<{ secret: string }>("totp.begin");
  const gen = () => hotp(base32Decode(begin.secret), stepAt(Date.now()));
  await h.rpc("totp.confirm", { code: gen() });
  return () => (tick(), gen());
}

/** A plugin outside the safe class (it uses the network): the hook holds it, the queue gets an entry. */
function plugDir(name: string, body = "fetch('https://x.example');\n"): string {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-appr-p-")));
  chmodSync(dir, 0o755);
  const plug = join(dir, name);
  mkdirSync(plug, { mode: 0o755 });
  writeFileSync(join(plug, "package.json"), JSON.stringify({ name: `bb-plugin-${name}`, version: "1.0.0", bb: { server: "./server.ts" } }), { mode: 0o644 });
  writeFileSync(join(plug, "server.ts"), body, { mode: 0o644 });
  return plug;
}
const hookCtx = (name: string, dir: string) => ({ pluginId: name, version: "1.0.0", source: `path:${dir}`, sourceKind: "path" as const, provenance: "direct" as const, gitCommit: null, npmIntegrity: null, rootDir: dir, contentHash: `sha256:${name}`, trigger: "install" as const });

/** Holds a plugin through the hook; returns its queue id. */
async function hold(h: Booted, name: string, body?: string): Promise<{ id: number; ctx: ReturnType<typeof hookCtx> }> {
  const ctx = hookCtx(name, plugDir(name, body));
  const first = await h.hook(ctx);
  expect(first).toMatchObject({ action: expect.stringMatching(/wait|reject/) });
  const ov = await h.rpc<{ queue: Array<{ id: number; pluginId: string }> }>("overview");
  return { id: ov.queue.find((q) => q.pluginId === name)!.id, ctx };
}

const openSession = async (h: Booted, fresh: () => string) => (await h.rpc<{ token: string; idleMs: number; capMs: number }>("session.open", { code: fresh() })).token;
const failedAttempts = (h: Booted): number => (h.bb.storage.database().prepare(`SELECT COUNT(*) AS n FROM attempts WHERE ok = 0`).get() as { n: number }).n;

beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
afterEach(() => vi.useRealTimers());

describe("the approval session (§1)", () => {
  it("one code opens it; the server keeps only the hash; nothing the page can read shows the token", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const opened = await h.rpc<{ token: string; idleMs: number; capMs: number }>("session.open", { code: fresh() });
    expect(opened.idleMs).toBe(15 * MIN);
    expect(opened.capMs).toBe(60 * MIN);
    expect(opened.token.length).toBeGreaterThanOrEqual(43);
    const db = h.bb.storage.database();
    const rows = db.prepare(`SELECT * FROM approval_sessions`).all() as Array<{ token_hash: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.token_hash).toBe(hashToken(opened.token));
    // The token is in no table, no journal line, no overview.
    for (const { name } of db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as Array<{ name: string }>) {
      expect(JSON.stringify(db.prepare(`SELECT * FROM "${name}"`).all())).not.toContain(opened.token);
    }
    expect(JSON.stringify(await h.rpc("overview"))).not.toContain(opened.token);
  });

  it("covers routine approvals without a code; a session approval is a real approval", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const { id, ctx } = await hold(h, "demo");
    const token = await openSession(h, fresh);
    await h.rpc("queue.approve", { id, session: token });
    expect(await h.hook(ctx)).toEqual({ action: "proceed" });
  });

  it("slides 15 minutes from each action, up to the ceiling of one hour", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const held = [await hold(h, "a"), await hold(h, "b"), await hold(h, "c"), await hold(h, "d"), await hold(h, "e")];
    const token = await openSession(h, fresh);
    const use = (i: number) => h.rpc("queue.approve", { id: held[i]!.id, session: token });
    // Used at minute 14 and again at minute 28: it would be dead by then without sliding.
    tick(14 * MIN);
    await use(0);
    tick(14 * MIN);
    await use(1);
    tick(14 * MIN);
    await use(2); // minute 42
    tick(14 * MIN);
    await use(3); // minute 56: still within the ceiling
    // Never used for 14 minutes would be fine, but the ceiling is the ceiling: minute 70 is past one hour since opening.
    tick(14 * MIN);
    await expect(use(4)).rejects.toThrow(/invalid or expired session/);
  });

  it("goes quiet after 15 minutes without an action", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const { id } = await hold(h, "demo");
    const token = await openSession(h, fresh);
    tick(15 * MIN + 1000);
    await expect(h.rpc("queue.approve", { id, session: token })).rejects.toThrow(/invalid or expired session/);
  });

  it("a wrong, unknown or expired token is a wrong code: the same counter, five in an hour block every approval", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const { id } = await hold(h, "demo");
    const token = await openSession(h, fresh);
    const before = failedAttempts(h);
    // two wrong codes + three wrong tokens = five
    await expect(h.rpc("queue.approve", { id, code: "000000" })).rejects.toThrow();
    await expect(h.rpc("queue.approve", { id, code: "000001" })).rejects.toThrow();
    for (const bad of ["nope", token + "x", "A".repeat(43)]) await expect(h.rpc("queue.approve", { id, session: bad })).rejects.toThrow(/invalid or expired session/);
    expect(failedAttempts(h)).toBe(before + 5);
    // blocked: even the right token and the right code are refused now
    await expect(h.rpc("queue.approve", { id, session: token })).rejects.toThrow(/blocked|too many/);
    await expect(h.rpc("queue.approve", { id, code: fresh() })).rejects.toThrow(/blocked|too many/);
    tick(61 * MIN);
    const second = await openSession(h, fresh);
    expect(second).not.toBe(token);
  });

  it("cannot be opened while a third-party plugin runs; the page learns which; the code is not spent", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    h.setPlugins([{ id: "nosy", provenance: "direct", enabled: true, status: "running", version: "1.0.0", source: "path:/x", rootDir: "/x" }]);
    const code = fresh();
    await expect(h.rpc("session.open", { code })).rejects.toThrow(/nosy/);
    h.setPlugins([]);
    await h.rpc("session.open", { code }); // the same code still works: it was not consumed
  });

  it("\"Lock\" closes it for good; opening another one replaces the first; nobody needs a code to lock", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const { id } = await hold(h, "demo");
    const first = await openSession(h, fresh);
    const second = await openSession(h, fresh);
    await expect(h.rpc("queue.approve", { id, session: first })).rejects.toThrow(/invalid or expired session/);
    expect(await h.rpc("session.close")).toEqual({ ok: true });
    await expect(h.rpc("queue.approve", { id, session: second })).rejects.toThrow(/invalid or expired session/);
    expect(await h.rpc("session.close")).toEqual({ ok: true }); // the same answer with nothing open
  });

  it("the dangerous kind of a routine RPC still needs a fresh code, and a session there is a refusal, not a wrong code", { timeout: 30_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const blocked = await hold(h, "evil", "export const s = JSON.stringify(process.env);\nfetch('https://x.example');\n");
    const token = await openSession(h, fresh);
    const before = failedAttempts(h);
    // lifting a block of the checks
    await expect(h.rpc("queue.approve", { id: blocked.id, session: token, acknowledgeBlock: true })).rejects.toThrow(/fresh code/);
    // a window wider than the policy (policy: this thread only, so "tree" widens it)
    await h.rpc("policy.set", { scope: "thread", code: fresh() });
    await expect(h.rpc("window.open", { queueId: blocked.id, session: token, scope: "tree" })).rejects.toThrow(/fresh code/);
    expect(failedAttempts(h)).toBe(before);
    // with a fresh code the block is lifted
    await h.rpc("queue.approve", { id: blocked.id, code: fresh(), acknowledgeBlock: true });
  });

  it("every routine RPC asks the gate for a session-capable proof under its own name; no other RPC does", { timeout: 40_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const token = await openSession(h, fresh);
    // minimal arguments that pass the schema; the call itself may fail later (nothing to approve): only the proof matters here
    const args: Record<string, unknown> = {
      "queue.approve": { id: 999 },
      "queue.dismiss": { id: 999 },
      "window.open": { queueId: 999 },
      "window.close": { windowId: 999 },
      "approval.revoke": { approvalId: 999 },
      "watch.accept": { id: 999 },
      "watch.acceptAll": {},
      "watch.rollback": { id: 999 },
      "watch.window.open": { scopes: ["instructions"] },
      "watch.window.close": { windowId: 999 },
      "skills.approve": { id: 999 },
      "batch.approve": { batchId: "none", setHash: "0".repeat(64) },
    };
    const orig = Gate.prototype.proofFor;
    const seen: Array<{ rpc: string; proof: unknown }> = [];
    Gate.prototype.proofFor = function (this: Gate, rpc, cred, opts) {
      const proof = orig.call(this, rpc, cred, opts);
      seen.push({ rpc, proof });
      return proof;
    };
    try {
      for (const [name, group] of Object.entries(EXPECTED)) {
        if (group === "routine") {
          seen.length = 0;
          await h.rpc(name, { ...(args[name] as object), session: token }).catch(() => undefined);
          expect(seen.map((s) => s.rpc), name).toEqual([name]);
          expect(seen[0]!.proof, name).toBeInstanceOf(SessionProof);
        } else {
          // dangerous and free ones do not take a session: the schema refuses the key before any handler runs
          seen.length = 0;
          await expect(h.rpc(name, { session: token }), name).rejects.toThrow();
          expect(seen, name).toEqual([]);
        }
      }
    } finally {
      Gate.prototype.proofFor = orig;
    }
  });

  it("is invisible to agents: `status` and `log` say nothing of it, before, during and after", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const { id } = await hold(h, "demo");
    const before = [(await h.harness.behavior.runCli(["status"])).stdout, (await h.harness.behavior.runCli(["log"])).stdout];
    const token = await openSession(h, fresh);
    await h.rpc("queue.approve", { id, session: token });
    const during = [(await h.harness.behavior.runCli(["status"])).stdout, (await h.harness.behavior.runCli(["log"])).stdout];
    await h.rpc("session.close");
    const after = [(await h.harness.behavior.runCli(["status"])).stdout, (await h.harness.behavior.runCli(["log"])).stdout];
    for (const text of [...before, ...during, ...after]) expect(text).not.toMatch(/session|сесси/i);
    // `status` is the same line by line; only the journal's entry counter moves, as it does for any approval (it names no kind).
    const noJournal = (t: string) => t.split("\n").filter((l) => !l.startsWith("journal:")).join("\n");
    expect(noJournal(during[0]!)).toBe(noJournal(before[0]!));
    expect(noJournal(after[0]!)).toBe(noJournal(before[0]!));
    // the page's journal does have them
    const ov = await h.rpc<{ log: Array<{ kind: string }> }>("overview");
    expect(ov.log.map((l) => l.kind)).toEqual(expect.arrayContaining(["session.open", "session.use", "session.close"]));
  });
});

describe("batch approval (§2)", () => {
  it("one code approves the whole list, which was fixed before the code; the list is approved once", { timeout: 30_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const a = await hold(h, "alpha");
    const b = await hold(h, "beta");
    const blocked = await hold(h, "evil", "export const s = JSON.stringify(process.env);\nfetch('https://x.example');\n");
    const prepared = await h.rpc<{ batchId: string; setHash: string; items: Array<{ id: number; label: string }>; skipped: Array<{ id: number; reason: string }> }>("batch.prepare", {
      items: [{ kind: "queue", id: a.id }, { kind: "queue", id: b.id }, { kind: "queue", id: blocked.id }, { kind: "queue", id: a.id }],
    });
    expect(prepared.items.map((i) => i.label).sort()).toEqual(["alpha@1.0.0", "beta@1.0.0"]);
    expect(prepared.skipped).toEqual([{ kind: "queue", id: blocked.id, reason: expect.stringMatching(/заблокировано/) }]);
    expect(prepared.setHash).toMatch(/^[0-9a-f]{64}$/);

    // not a different list, not a different hash
    await expect(h.rpc("batch.approve", { batchId: prepared.batchId, setHash: "0".repeat(64), code: fresh() })).rejects.toThrow(/does not match/);
    // a wrong code does not burn the list
    await expect(h.rpc("batch.approve", { batchId: prepared.batchId, setHash: prepared.setHash, code: "000000" })).rejects.toThrow(/invalid or already used code/);
    const code = fresh();
    const done = await h.rpc<{ results: Array<{ ok: boolean; label: string }> }>("batch.approve", { batchId: prepared.batchId, setHash: prepared.setHash, code });
    expect(done.results.map((r) => [r.label, r.ok]).sort()).toEqual([["alpha@1.0.0", true], ["beta@1.0.0", true]]);
    expect(await h.hook(a.ctx)).toEqual({ action: "proceed" });
    expect(await h.hook(b.ctx)).toEqual({ action: "proceed" });
    expect(await h.hook(blocked.ctx)).toMatchObject({ action: "reject" }); // the blocked one was not approved
    // once: the same list again, even with a new code
    await expect(h.rpc("batch.approve", { batchId: prepared.batchId, setHash: prepared.setHash, code: fresh() })).rejects.toThrow(/already approved/);
  });

  it("takes only the id of the stored list: nothing can be added to it between showing and confirming", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const a = await hold(h, "alpha");
    const later = await hold(h, "later");
    const prepared = await h.rpc<{ batchId: string; setHash: string }>("batch.prepare", { items: [{ kind: "queue", id: a.id }] });
    // extra items in the approve call are refused outright (strict schema)
    await expect(h.rpc("batch.approve", { batchId: prepared.batchId, setHash: prepared.setHash, code: fresh(), items: [{ kind: "queue", id: later.id }] })).rejects.toThrow();
    // an unknown list id is refused
    await expect(h.rpc("batch.approve", { batchId: "f".repeat(24), setHash: prepared.setHash, code: fresh() })).rejects.toThrow(/no such list/);
    // a stored list edited in the database no longer adds up to its hash
    const db = h.bb.storage.database();
    db.prepare(`UPDATE approval_batches SET items = ? WHERE id = ?`).run(JSON.stringify([{ kind: "queue", id: later.id, fingerprint: "x", label: "later@1.0.0" }]), prepared.batchId);
    await expect(h.rpc("batch.approve", { batchId: prepared.batchId, setHash: prepared.setHash, code: fresh() })).rejects.toThrow(/does not match/);
    expect(await h.hook(later.ctx)).toMatchObject({ action: "wait" });
  });

  it("an item that changed after it was shown is not approved (the others are)", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const a = await hold(h, "alpha");
    const b = await hold(h, "beta");
    const prepared = await h.rpc<{ batchId: string; setHash: string }>("batch.prepare", { items: [{ kind: "queue", id: a.id }, { kind: "queue", id: b.id }] });
    h.bb.storage.database().prepare(`UPDATE queue SET version = '9.9.9' WHERE id = ?`).run(b.id); // another version took its place
    const done = await h.rpc<{ results: Array<{ ok: boolean; label: string; note: string }> }>("batch.approve", { batchId: prepared.batchId, setHash: prepared.setHash, code: fresh() });
    expect(done.results.map((r) => [r.label, r.ok]).sort()).toEqual([["alpha@1.0.0", true], ["beta@1.0.0", false]]);
    expect(done.results.find((r) => !r.ok)!.note).toMatch(/изменилось после показа/);
    expect(await h.hook(b.ctx)).toMatchObject({ action: "wait" });
  });

  it("an open session covers a batch; without a code or a session it is refused", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const a = await hold(h, "alpha");
    const prepared = await h.rpc<{ batchId: string; setHash: string }>("batch.prepare", { items: [{ kind: "queue", id: a.id }] });
    await expect(h.rpc("batch.approve", { batchId: prepared.batchId, setHash: prepared.setHash })).rejects.toThrow(/code, or an open session/);
    const token = await openSession(h, fresh);
    await h.rpc("batch.approve", { batchId: prepared.batchId, setHash: prepared.setHash, session: token });
    expect(await h.hook(a.ctx)).toEqual({ action: "proceed" });
  });

  it("an empty or all-skipped list is refused, and an item already decided is not in a list", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const a = await hold(h, "alpha");
    await h.rpc("queue.dismiss", { id: a.id });
    await expect(h.rpc("batch.prepare", { items: [{ kind: "queue", id: a.id }] })).rejects.toThrow(/nothing in the list/);
    await expect(h.rpc("batch.prepare", { items: [] })).rejects.toThrow(/nothing in the list/);
  });
});

describe("rejecting needs no code (it only tightens)", () => {
  it("queue.dismiss works without a code or session, and also while wrong codes block every approval", { timeout: 20_000 }, async () => {
    const h = await boot();
    const fresh = await register(h);
    const a = await hold(h, "alpha");
    const b = await hold(h, "beta");
    for (let i = 0; i < 5; i++) await expect(h.rpc("queue.approve", { id: a.id, code: "000000" })).rejects.toThrow();
    await expect(h.rpc("queue.approve", { id: a.id, code: fresh() })).rejects.toThrow(/blocked|too many/);
    const attempts = failedAttempts(h);
    await h.rpc("queue.dismiss", { id: a.id });
    expect(failedAttempts(h)).toBe(attempts); // not a code attempt
    const ov = await h.rpc<{ queue: Array<{ id: number; status: string }> }>("overview");
    expect(ov.queue.find((q) => q.id === a.id)!.status).toBe("dismissed");
    expect(ov.queue.find((q) => q.id === b.id)!.status).toBe("held");
    // the journal keeps the record; the version stays unapproved
    expect(h.bb.storage.database().prepare(`SELECT COUNT(*) AS n FROM log WHERE kind = 'dismissed'`).get()).toEqual({ n: 1 });
    expect(await h.hook(a.ctx)).toMatchObject({ action: expect.stringMatching(/wait|reject/) });
    // only a held entry: the second time it is refused
    await expect(h.rpc("queue.dismiss", { id: a.id })).rejects.toThrow(/already dismissed/);
  });

  it("a harmful plugin in the process may dismiss (tightening) but still cannot approve without a code", { timeout: 20_000 }, async () => {
    const h = await boot();
    await register(h);
    const a = await hold(h, "alpha");
    const b = await hold(h, "beta");
    // what any process with the API can do: no code, no session, an empty or a made-up one
    for (const proof of [{}, { code: "" }, { session: "A".repeat(43) }]) await expect(h.rpc("queue.approve", { id: a.id, ...proof })).rejects.toThrow();
    await expect(h.rpc("queue.approve", { id: a.id, acknowledgeBlock: true })).rejects.toThrow();
    expect(await h.hook(a.ctx)).toMatchObject({ action: expect.stringMatching(/wait|reject/) });
    await h.rpc("queue.dismiss", { id: b.id }); // allowed: the version simply stays out
    expect(await h.hook(b.ctx)).toMatchObject({ action: expect.stringMatching(/wait|reject/) });
    expect(h.bb.storage.database().prepare(`SELECT COUNT(*) AS n FROM approvals`).get()).toEqual({ n: 0 });
  });

  it("the table says so: dismiss is free, approve is not", () => {
    expect(groupOf("queue.dismiss")).toBe("free");
    expect(groupOf("queue.approve")).toBe("routine");
  });
});
