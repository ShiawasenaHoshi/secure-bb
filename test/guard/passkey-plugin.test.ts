// The plugin in guard mode with a passkey: RPC passkey.challenge and passkey.register, the `passkey` field in the existing RPCs, and the
// page's browser half (src/webauthn.ts) against the software authenticator. The guard is a real one on a temporary socket.
import { readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createCredential, fromB64u, getAssertion, originProblem, toB64u, type Credentials } from "../../src/webauthn.js";
import { SoftAuthenticator } from "./authenticator.ts";
import { bootPlugin, core, hookCtx, plugDir, startGuardOnDate, type Booted, type TestGuard } from "./support.ts";

let g: TestGuard | null = null;
beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
afterEach(async () => {
  vi.useRealTimers();
  await g?.close();
  g = null;
});
const tick = (ms = 31_000) => vi.setSystemTime(Date.now() + ms);
const ov = (h: Booted) => h.rpc<any>("overview");
const journal = async () => (await g!.send({ op: "state" })).journal.recent as Array<{ kind: string; detail: any }>;

const snapshotDir = (h: Booted, id: string): string => {
  const root = join(dirname(h.bb.storage.database().name), "snapshots", id);
  return readdirSync(root).map((d) => join(root, d)).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0]!;
};
async function proposed(h: Booted, name: string, body?: string, threadId = "T1") {
  const dir = plugDir(name, body);
  const res = await h.harness.behavior.runCli(["propose", dir], { threadId });
  const snap = snapshotDir(h, name);
  return { res, ctx: hookCtx(name, snap, `sha256:${name}:${snap.slice(-8)}`) };
}

/** Registers a key the way the page does (relayed by the plugin), with the console confirming. */
async function enrollThroughPlugin(h: Booted, auth: SoftAuthenticator) {
  const e = g!.guard.enrollStart("laptop");
  const first = await h.rpc<{ options: any }>("passkey.register", { token: e.token });
  const made = auth.create(first.options);
  const done = await h.rpc<any>("passkey.register", { token: e.token, ...made });
  g!.guard.confirmEnrollment(e.id);
  return { e, first, done };
}
/** What `navigator.credentials` is for the page in these tests: the software authenticator. */
const credsOf = (auth: SoftAuthenticator): Credentials => ({
  async create({ publicKey }) {
    const made = auth.create({ challenge: toB64u(publicKey.challenge as Uint8Array) });
    return { response: { clientDataJSON: fromB64u(made.clientDataJSON).buffer, attestationObject: fromB64u(made.attestationObject).buffer } };
  },
  async get({ publicKey }) {
    const a = auth.get(toB64u(publicKey.challenge as Uint8Array));
    return { rawId: fromB64u(a.credentialId).buffer, response: { clientDataJSON: fromB64u(a.clientDataJSON).buffer, authenticatorData: fromB64u(a.authenticatorData).buffer, signature: fromB64u(a.signature).buffer } };
  },
});

describe("registering a key through the page", () => {
  it("relays the token and the browser's answer; the key waits for the console, and the page says so", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    expect((await ov(h)).guard.passkey).toMatchObject({ rpId: "localhost", origin: "http://localhost:38886", keys: [], enrollmentOpen: false });
    // no window: refused, and the token the page asks about does not matter
    await expect(h.rpc("passkey.register", { token: "AAAA-BBBB-CCCC" })).rejects.toThrow(/passkey-enroll/);

    const e = g.guard.enrollStart("laptop");
    expect((await ov(h)).guard.passkey.enrollmentOpen).toBe(true);
    await expect(h.rpc("passkey.register", { token: "WRONG-TOKEN-XX" })).rejects.toThrow(/token/);
    const first = await h.rpc<{ options: any }>("passkey.register", { token: e.token });
    expect(first.options).toMatchObject({ rp: { id: "localhost" }, attestation: "none", pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { userVerification: "required" } });
    const done = await h.rpc<any>("passkey.register", { token: e.token, ...auth.create(first.options) });
    expect(done).toMatchObject({ ok: true, label: "laptop" });
    expect(done.note).toMatch(/console/);
    // not active yet: no key on the page, no challenge
    expect((await ov(h)).guard.passkey.keys).toEqual([]);
    await expect(h.rpc("passkey.challenge", { kind: "touch", purpose: "x" })).rejects.toThrow(/passkey-enroll|registered/);
    g.guard.confirmEnrollment(e.id);
    expect((await ov(h)).guard.passkey.keys).toMatchObject([{ label: "laptop" }]);
  });

  it("the page's browser half does the same with `navigator.credentials`", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    const e = g.guard.enrollStart("laptop");
    const { options } = await h.rpc<{ options: any }>("passkey.register", { token: e.token });
    const made = await createCredential(options, credsOf(auth), "http://localhost:38886", "http://localhost:38886");
    expect(await h.rpc("passkey.register", { token: e.token, ...made })).toMatchObject({ ok: true });
    g.guard.confirmEnrollment(e.id);
    const c = await h.rpc<any>("passkey.challenge", { kind: "touch", purpose: "approvals.export" });
    const passkey = await getAssertion(c, credsOf(auth), "http://localhost:38886");
    expect(await h.rpc("approvals.export", { passkey })).toMatchObject({ count: 0 });
  });

  it("not on localhost: a clear message instead of a failed touch", () => {
    expect(originProblem("http://localhost:38886", "http://localhost:38886")).toBeNull();
    const m = originProblem("http://127.0.0.1:38886", "http://localhost:38886")!;
    expect(m).toContain("откройте http://localhost:38886");
    expect(m).toContain("127.0.0.1");
    expect(originProblem("http://bb.lan:38886", "http://localhost:38886")).toContain("откройте http://localhost:38886");
    return expect(getAssertion({ challenge: "AAAA", allowCredentials: [], rpId: "localhost", origin: "http://localhost:38886" }, credsOf(new SoftAuthenticator()), "http://127.0.0.1:38886")).rejects.toThrow(/откройте http:\/\/localhost:38886/);
  });
});

describe("approving with a touch", () => {
  it("passkey.challenge describes the action in the guard's words; queue.approve with the signature approves at the guard", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    await enrollThroughPlugin(h, auth);
    const a = await proposed(h, "demo");
    expect(await core(g, h, a.ctx)).toBe("held");

    const c = await h.rpc<any>("passkey.challenge", { kind: "approve", queueId: 1 });
    expect(c).toMatchObject({ needed: true, rpId: "localhost", origin: "http://localhost:38886" });
    expect(c.description).toContain("«demo»");
    expect(c.allowCredentials).toHaveLength(1);
    const passkey = auth.get(c.challenge);
    expect(await h.rpc("queue.approve", { id: 1, passkey })).toMatchObject({ ok: true, note: "approved at the guard" });
    expect(await core(g, h, a.ctx)).toBe("load");
    expect((await journal()).find((j) => j.kind === "approved.touch")!.detail).toMatchObject({ via: "passkey", key: "laptop", action: { op: "approve", requestId: 1 } });
    // the same signature again: refused
    await expect(h.rpc("queue.approve", { id: 1, passkey })).rejects.toThrow();
  });

  it("a signature made for one entry cannot approve another through the plugin either", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    await enrollThroughPlugin(h, auth);
    const a = await proposed(h, "demo");
    const b = await proposed(h, "second", "fetch('https://y.example');\n");
    await core(g, h, a.ctx);
    await core(g, h, b.ctx);
    const c = await h.rpc<any>("passkey.challenge", { kind: "approve", queueId: 1 });
    await expect(h.rpc("queue.approve", { id: 2, passkey: auth.get(c.challenge) })).rejects.toThrow(/another action|forbidden|invalid/i);
    expect((await ov(h)).queue.filter((q: any) => q.status === "held")).toHaveLength(2);
  });

  it("a proposal the core has not asked about yet is installed first, and the touch is for the guard's entry", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const entryFor = new Map<string, number>();
    // the install of the snapshot is what makes the core ask the guard
    const h = await bootPlugin(g.paths.socket, {
      onInstall: async (source) => {
        const dir = source.replace(/^path:/, "");
        await g!.send({ op: "decide", pluginId: "demo", version: "1.0.0", contentHash: `sha256:demo:${dir.slice(-8)}`, rootDir: dir, source: `path:${dir}`, sourceKind: "path", trigger: "install" });
        entryFor.set(dir, 1);
      },
    });
    const auth = new SoftAuthenticator();
    await enrollThroughPlugin(h, auth);
    // a hard finding stops `propose` before the install: only a local proposal exists (negative id on the page)
    const dir = plugDir("demo", "eval(atob('YWxlcnQoMSk='));\n");
    expect((await h.harness.behavior.runCli(["propose", dir], { threadId: "T1" })).exitCode).toBe(3);
    const pending = (await ov(h)).queue.find((q: any) => q.id < 0);
    expect(pending).toBeDefined();
    // a block needs the owner's explicit acknowledgement, with a touch as with a code
    await expect(h.rpc("passkey.challenge", { kind: "approve", queueId: pending.id })).rejects.toThrow(/blocked|заблок/i);
    const c = await h.rpc<any>("passkey.challenge", { kind: "approve", queueId: pending.id, acknowledgeBlock: true });
    expect(c).toMatchObject({ needed: true });
    expect(h.installs).toHaveLength(1);
    expect(c.description).toContain("запись #1");
    expect(await h.rpc("queue.approve", { id: pending.id, passkey: auth.get(c.challenge), acknowledgeBlock: true })).toMatchObject({ ok: true });
  });

  it("opens a trust window with a touch; the thread scope is part of what was signed", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    await enrollThroughPlugin(h, auth);
    const a = await proposed(h, "demo");
    await core(g, h, a.ctx);
    const c = await h.rpc<any>("passkey.challenge", { kind: "window.open", queueId: 1, scope: "thread" });
    expect(c.description).toContain("только этот тред");
    // the signature is for "thread": asking for "tree" with it is another action
    await expect(h.rpc("window.open", { queueId: 1, scope: "tree", passkey: auth.get(c.challenge) })).rejects.toThrow();
    const c2 = await h.rpc<any>("passkey.challenge", { kind: "window.open", queueId: 1, scope: "thread" });
    expect(await h.rpc("window.open", { queueId: 1, scope: "thread", passkey: auth.get(c2.challenge) })).toMatchObject({ ok: true });
    expect((await g.send({ op: "state" })).windows).toMatchObject([{ pluginId: "demo" }]);
    expect((await ov(h)).windows).toMatchObject([{ pluginId: "demo", threadId: "T1", scope: "thread" }]);
    expect((await journal()).find((j) => j.kind === "window.open")!.detail).toMatchObject({ via: "passkey", key: "laptop", action: { op: "open-window", pluginId: "demo", scope: "thread" } });
  });
});

describe("policy and other RPCs with a touch", () => {
  const base = { autoSafe: false, scope: "tree" as const, cfgWindowMin: 10, cfgCapMin: 240, cfgMode: "sliding" as const };

  it("widening needs a touch; narrowing says it needs none", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    await enrollThroughPlugin(h, auth);
    const narrow = { windowMin: 20, capMin: 60, mode: "sliding" as const };
    expect(await h.rpc("passkey.challenge", { kind: "policy", ...narrow })).toEqual({ needed: false });
    await h.rpc("policy.set", { ...base, ...narrow });

    const wider = { windowMin: 20, capMin: 120, mode: "sliding" as const };
    const c = await h.rpc<any>("passkey.challenge", { kind: "policy", ...wider });
    expect(c).toMatchObject({ needed: true });
    expect(c.description).toContain("capMin: 60 → 120");
    await expect(h.rpc("policy.set", { ...base, ...wider })).rejects.toThrow();
    expect(await h.rpc("policy.set", { ...base, ...wider, passkey: auth.get(c.challenge) })).toMatchObject({ ok: true });
    expect((await g.send({ op: "policy" })).policy.capMin).toBe(120);
    // a signature for 120 does not give 240
    const c2 = await h.rpc<any>("passkey.challenge", { kind: "policy", ...wider, capMin: 180 });
    await expect(h.rpc("policy.set", { ...base, ...wider, capMin: 240, passkey: auth.get(c2.challenge) })).rejects.toThrow();
    expect((await g.send({ op: "policy" })).policy.capMin).toBe(120);
  });

  it("the plugin's own part of the policy (thread scope) is touched for as the plugin's purpose 'policy.set'", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    await enrollThroughPlugin(h, auth);
    await h.rpc("policy.set", { ...base, scope: "thread", windowMin: 30, capMin: 240, mode: "sliding" });
    const c = await h.rpc<any>("passkey.challenge", { kind: "policy", ...base, scope: "tree" });
    expect(c).toMatchObject({ needed: true });
    expect(c.description).toContain("policy.set");
    expect(await h.rpc("policy.set", { ...base, scope: "tree", passkey: auth.get(c.challenge) })).toMatchObject({ ok: true });
    expect((await ov(h)).policy.scope).toBe("tree");
  });

  it("a code that was not needed for the guard's narrowing does not vouch for the plugin's widening (it is checked, and a wrong one is refused)", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    await h.rpc("policy.set", { ...base, scope: "thread", windowMin: 30, capMin: 240, mode: "sliding" });
    // the guard's part only narrows (so the guard does not look at the code); the plugin's part widens the scope
    await expect(h.rpc("policy.set", { ...base, scope: "tree", windowMin: 20, capMin: 240, mode: "sliding", code: "000000" })).rejects.toThrow();
    expect((await ov(h)).policy.scope).toBe("thread");
    tick();
    expect(await h.rpc("policy.set", { ...base, scope: "tree", windowMin: 10, capMin: 240, mode: "sliding", code: g.code() })).toMatchObject({ ok: true });
    expect((await ov(h)).policy.scope).toBe("tree");
  });

  it("any other RPC takes the touch as 'touch <rpc name>' and nothing else", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    await enrollThroughPlugin(h, auth);
    const c = await h.rpc<any>("passkey.challenge", { kind: "touch", purpose: "trusted.set" });
    expect(await h.rpc("trusted.set", { add: "octo/repo", passkey: auth.get(c.challenge) })).toMatchObject({ ok: true, repos: ["octo/repo"] });
    const other = await h.rpc<any>("passkey.challenge", { kind: "touch", purpose: "approvals.export" });
    await expect(h.rpc("trusted.set", { add: "octo/evil", passkey: auth.get(other.challenge) })).rejects.toThrow();
    // neither a code nor a touch: refused without spending anything
    await expect(h.rpc("trusted.set", { add: "octo/evil" })).rejects.toThrow(/code|passkey/i);
    expect((await h.rpc<any>("overview")).trusted ?? null).not.toBeUndefined();
  });

  it("a wrong signature through the plugin is the guard's wrong code: the same counter", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    const h = await bootPlugin(g.paths.socket);
    const auth = new SoftAuthenticator();
    await enrollThroughPlugin(h, auth);
    for (let i = 0; i < 4; i++) {
      const c = await h.rpc<any>("passkey.challenge", { kind: "touch", purpose: "trusted.set" });
      await expect(h.rpc("trusted.set", { add: "octo/x", passkey: auth.get(c.challenge, { corrupt: true }) })).rejects.toThrow();
    }
    await expect(h.rpc("trusted.set", { add: "octo/x", code: "000000" })).rejects.toThrow();
    const c = await h.rpc<any>("passkey.challenge", { kind: "touch", purpose: "trusted.set" });
    await expect(h.rpc("trusted.set", { add: "octo/x", passkey: auth.get(c.challenge) })).rejects.toThrow(/blocked|too many/i);
    expect((await ov(h)).totp.blockedUntil).toBeGreaterThan(Date.now());
  });
});

describe("without a guard there are no passkeys", () => {
  it("the RPCs say so, and a passkey in any other RPC is refused instead of being taken for no code", async () => {
    const h = await bootPlugin(null);
    await expect(h.rpc("passkey.challenge", { kind: "touch", purpose: "x" })).rejects.toThrow(/guard/);
    await expect(h.rpc("passkey.register", { token: "AAAA-BBBB-CCCC" })).rejects.toThrow(/guard/);
    const passkey = new SoftAuthenticator().get("A".repeat(43));
    for (const [name, input] of [["queue.approve", { id: 1, passkey }], ["policy.set", { windowMin: 5, passkey }], ["trusted.set", { add: "a/b", passkey }], ["approvals.export", { passkey }]] as const)
      await expect(h.rpc(name, input as never), name).rejects.toThrow(/guard/);
    expect((await ov(h)).guard).toBeUndefined();
  });
});
