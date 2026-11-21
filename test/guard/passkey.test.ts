// Passkeys at the guard: registration only through the console, a touch bound to one action, and everything that must be refused.
// The authenticator is a program (test/guard/authenticator.ts): a P-256 key from node:crypto and the bytes a browser would return.
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { main, passkeyEnroll, passkeyList, passkeyRemove, totpDisable, type Io } from "../../guard/src/cli.ts";
import { resolvePaths, resolveRp } from "../../guard/src/config.ts";
import { cborDecode, coseToSpki, newToken, normalizeToken, PasskeyError, parseAttestationObject } from "../../guard/src/passkey.ts";
import { MAX_FAILURES, PASSKEY_FAIL_LOG_EVERY_MS } from "../../guard/src/guard.ts";
import { cbor, FLAGS, SoftAuthenticator } from "./authenticator.ts";
import { decideReq, enrollKey, startGuard, touchFor, type TestGuard } from "./support.ts";

let g: TestGuard;
afterEach(async () => {
  await g?.close();
});

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const approve = (requestId: number) => ({ op: "approve", requestId });
const journal = async () => (await g.send({ op: "state" })).journal.recent as Array<{ kind: string; detail: any }>;

/** A guard with two held versions (#1, #2) and one enrolled key. */
async function ready(opts: { signCount?: number } = {}) {
  g = await startGuard();
  const auth = new SoftAuthenticator(opts);
  await enrollKey(g, auth, { label: "laptop" });
  await g.send(decideReq({ contentHash: H1 }));
  await g.send(decideReq({ contentHash: H2, pluginId: "other" }));
  return auth;
}

// ------------------------------------------------------------------------------------------------ registration
describe("registration: only through the console, and only with its confirmation", () => {
  it("refuses everything while no window is open, and a wrong token; five wrong tokens close the window", async () => {
    g = await startGuard();
    expect(await g.send({ op: "passkey-register", token: "AAAA-BBBB-CCCC" })).toMatchObject({ ok: false, error: { code: "conflict" } });
    const e = g.guard.enrollStart("laptop");
    for (let i = 1; i < MAX_FAILURES; i++) expect(await g.send({ op: "passkey-register", token: `WRONG-TOKEN-${i}` })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    // the fifth wrong one closes it: even the right token is no good any more
    expect(await g.send({ op: "passkey-register", token: "WRONG-TOKEN-5" })).toMatchObject({ ok: false, error: { message: expect.stringContaining("closed") } });
    expect(await g.send({ op: "passkey-register", token: e.token })).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(g.guard.enrollmentStatus(e.id).state).toBe("closed");
    expect((await journal()).some((j) => j.kind === "passkey.token.fail")).toBe(true);
  });

  it("registers a key with the right token; it does NOT work until the console confirms, then it does", async () => {
    g = await startGuard();
    const auth = new SoftAuthenticator();
    const { enrollment, reg } = await enrollKey(g, auth, { confirm: false });
    expect(reg).toMatchObject({ ok: true, label: "laptop" });
    // waiting for the console: not a key that can touch
    expect(g.guard.enrollmentStatus(enrollment.id)).toMatchObject({ state: "registered", key: { label: "laptop", state: "pending" } });
    expect((await g.send({ op: "state" })).passkeys.keys).toEqual([]);
    expect(await g.send({ op: "challenge", action: approve(1) })).toMatchObject({ ok: false, error: { code: "not_registered" } });
    // the token is spent: a second use of it (another key, a plugin that saw it) is refused
    expect(await g.send({ op: "passkey-register", token: enrollment.token })).toMatchObject({ ok: false });
    // the console says yes
    const key = g.guard.confirmEnrollment(enrollment.id);
    expect(key).toMatchObject({ label: "laptop", state: "active" });
    expect((await g.send({ op: "state" })).passkeys.keys).toHaveLength(1);
    // The page shows where the key is stored: the state carries the key's AAGUID (the one the console prints), nothing secret.
    expect((await g.send({ op: "state" })).passkeys.keys[0]).toMatchObject({ label: "laptop", aaguid: auth.aaguid.toString("hex") });
    expect((await journal()).find((j) => j.kind === "passkey.enrolled")).toMatchObject({ detail: { key: "laptop", via: "console" } });
  });

  it("the window lasts five minutes", async () => {
    g = await startGuard();
    const e = g.guard.enrollStart("laptop");
    g.clock.advance(5 * 60_000 + 1);
    expect(await g.send({ op: "passkey-register", token: e.token })).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(g.guard.enrollmentStatus(e.id).state).toBe("expired");
  });

  it("a challenge of the registration expires, and is used once", async () => {
    g = await startGuard();
    const auth = new SoftAuthenticator();
    const e = g.guard.enrollStart("laptop");
    const options = (await g.send({ op: "passkey-register", token: e.token })).options;
    const made = auth.create(options);
    g.clock.advance(2 * 60_000 + 1);
    expect(await g.send({ op: "passkey-register", token: e.token, ...made })).toMatchObject({ ok: false, error: { code: "expired" } });
    // a fresh start in the same window: works once, and the same answer cannot be sent again
    const again = (await g.send({ op: "passkey-register", token: e.token })).options;
    const made2 = auth.create(again);
    expect((await g.send({ op: "passkey-register", token: e.token, ...made2 })).ok).toBe(true);
    expect((await g.send({ op: "passkey-register", token: e.token, ...made2 })).ok).toBe(false);
  });

  it.each([
    ["another origin", { origin: "https://evil.example" }, "opened at"],
    ["another RP ID", { rpId: "evil.example" }, "RP ID"],
    ["no user verification", { flags: FLAGS.UP }, "verification"],
    ["no user presence", { flags: FLAGS.UV }, "verification"],
    ["a touch type of client data", { type: "webauthn.get" }, "registration"],
    ["a cross-origin frame", { crossOrigin: true }, "opened at"],
  ] as const)("refuses a key made with %s", async (_name, create, hint) => {
    g = await startGuard();
    const { reg, enrollment } = await enrollKey(g, new SoftAuthenticator(), { create });
    expect(reg).toMatchObject({ ok: false, error: { code: "invalid_passkey", message: expect.stringContaining(hint) } });
    expect(g.guard.listPasskeys()).toEqual([]);
    expect(g.guard.enrollmentStatus(enrollment.id).key).toBeNull();
  });

  it("refuses an attestation other than none, and a second enrollment discards the unconfirmed key of the first", async () => {
    g = await startGuard();
    const e = g.guard.enrollStart("laptop");
    const options = (await g.send({ op: "passkey-register", token: e.token })).options;
    const auth = new SoftAuthenticator();
    const made = auth.create(options);
    const obj = cborDecode(Buffer.from(made.attestationObject, "base64url")) as Map<string, unknown>;
    const packed = cbor(new Map<any, any>([["fmt", "packed"], ["attStmt", new Map()], ["authData", obj.get("authData") as Buffer]])).toString("base64url");
    expect(await g.send({ op: "passkey-register", token: e.token, clientDataJSON: made.clientDataJSON, attestationObject: packed })).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });

    const first = await enrollKey(g, new SoftAuthenticator(), { label: "first", confirm: false });
    expect(first.reg.ok).toBe(true);
    const second = g.guard.enrollStart("second"); // the console starts over: the unconfirmed key is dropped
    expect(g.guard.listPasskeys().find((k) => k.label === "first")?.state).toBe("removed");
    expect(() => g.guard.confirmEnrollment(first.enrollment.id)).toThrow(/nothing registered/);
    expect(second.id).toBeGreaterThan(first.enrollment.id);
  });
});

describe("the console command passkey-enroll", () => {
  /** A console: prints into `lines`, answers the question with `answer`. */
  const consoleIo = (answer: string | null, lines: string[]): Io => ({ out: (t) => void lines.push(t), err: (t) => void lines.push(`ERR ${t}`), ask: async () => answer });
  const run = async (answer: string | null, act: (token: string) => Promise<void>) => {
    g = await startGuard({ serve: true });
    const lines: string[] = [];
    const io = consoleIo(answer, lines);
    const sleep = async () => {
      // while the console waits, the page does its part
      const token = lines.join("\n").match(/Token:\s+(\S+)/)?.[1];
      if (token && !done) {
        done = true;
        await act(token);
      }
      await new Promise((r) => setTimeout(r, 5));
    };
    let done = false;
    const code = await passkeyEnroll(g.paths, io, { label: "yubikey" }, g.clock.now, { sleep, pollMs: 1 });
    return { code, lines };
  };

  it("prints the token and the label, waits, shows what was registered, and `y` activates it", async () => {
    const auth = new SoftAuthenticator();
    const { code, lines } = await run("y", async (token) => {
      const options = (await g.send({ op: "passkey-register", token })).options;
      expect((await g.send({ op: "passkey-register", token, ...auth.create(options) })).ok).toBe(true);
    });
    const text = lines.join("\n");
    expect(code).toBe(0);
    expect(text).toMatch(/Token:\s+[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/);
    expect(text).toContain("Key label:  yubikey");
    expect(text).toContain(`AAGUID:       ${auth.aaguid.toString("hex")}`);
    expect(text).toContain("fingerprint:");
    expect(text).toContain("http://localhost:38886");
    expect(g.guard.listPasskeys()).toMatchObject([{ label: "yubikey", state: "active" }]);
  });

  it.each([["n"], [""], [null]])("an answer of %j discards the key and closes the window", async (answer) => {
    const { code, lines } = await run(answer, async (token) => {
      const options = (await g.send({ op: "passkey-register", token })).options;
      await g.send({ op: "passkey-register", token, ...new SoftAuthenticator().create(options) });
    });
    expect(code).toBe(1);
    expect(lines.join("\n")).toContain("not confirmed");
    expect(g.guard.listPasskeys().filter((k) => k.state === "active")).toEqual([]);
    expect((await g.send({ op: "state" })).passkeys.enrollmentOpen).toBe(false);
  });

  it("gives up when the window expires without a key", async () => {
    g = await startGuard();
    const lines: string[] = [];
    const code = await passkeyEnroll(g.paths, consoleIo("y", lines), {}, g.clock.now, { sleep: async () => g.clock.advance(60_000), pollMs: 1 });
    expect(code).toBe(1);
    expect(lines.join("\n")).toContain("expired");
  });

  it("is part of the CLI, with --rp-id and --origin, and has no flag that skips the question", async () => {
    g = await startGuard();
    const out: string[] = [];
    const io: Io = { out: (t) => void out.push(t), err: (t) => void out.push(t), ask: async () => null };
    // no key arrives and the clock is the real one: ask the usage instead, and check the flags are parsed
    expect(await main(["passkey-remove", "abc", "--data", g.paths.dataDir], io)).toBe(64);
    expect(await main(["passkey-list", "--data", g.paths.dataDir, "--rp-id", "127.0.0.1"], io)).toBe(64);
    expect(out.join("\n")).toMatch(/IP address cannot be a WebAuthn RP ID/);
    expect(await main(["help"], io)).toBe(0);
    for (const word of ["passkey-enroll", "passkey-list", "passkey-remove", "totp-disable", "--rp-id", "--origin"]) expect(out.join("\n")).toContain(word);
    expect(out.join("\n")).not.toMatch(/passkey-enroll[^\n]*--yes/);
  });
});

// ------------------------------------------------------------------------------------------------ the touch
describe("a touch with a passkey", () => {
  it("approves a held version, and the journal says via passkey, with the key's label and the action", async () => {
    const auth = await ready();
    const { passkey, challenge } = await touchFor(g, auth, approve(1));
    expect(challenge.description).toContain("«demo»");
    expect(challenge.description).toContain("запись #1");
    expect(challenge.allowCredentials).toHaveLength(1);
    expect(challenge).toMatchObject({ rpId: "localhost", origin: "http://localhost:38886" });
    expect(await g.send({ op: "approve", requestId: 1, passkey })).toMatchObject({ ok: true });
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "proceed", via: "approval" });
    const rec = (await journal()).find((j) => j.kind === "approved.touch")!;
    expect(rec.detail).toMatchObject({ via: "passkey", key: "laptop", action: { op: "approve", requestId: 1 }, review: 1 });
    // no code was needed and none was spent
    expect((await g.send({ op: "approve", requestId: 2, code: g.code() })).ok).toBe(true);
    expect((await journal()).find((j) => j.kind === "approved.touch" && j.detail.review === 2)!.detail).toMatchObject({ via: "totp" });
  });

  it("opens a window, widens the policy, and touches for a purpose", async () => {
    const auth = await ready();
    const win = { op: "open-window", pluginId: "demo", minutes: 20, scope: "thread" };
    const w = await touchFor(g, auth, win);
    expect(w.challenge.description).toContain("«demo»");
    expect(w.challenge.description).toContain("20 мин");
    expect(await g.send({ ...win, passkey: w.passkey })).toMatchObject({ ok: true, window: { sizeSec: 1200 } });
    expect((await journal()).find((j) => j.kind === "window.open")!.detail).toMatchObject({ via: "passkey", key: "laptop", action: win });

    const pol = { op: "policy", patch: { windowMin: 45, capMin: 300 } };
    const p = await touchFor(g, auth, pol);
    expect(p.challenge.description).toContain("windowMin: 30 → 45");
    expect(await g.send({ op: "policy", patch: pol.patch, passkey: p.passkey })).toMatchObject({ ok: true, policy: { windowMin: 45, capMin: 300 } });

    const t = await touchFor(g, auth, { op: "touch", purpose: "watch.accept" });
    expect(await g.send({ op: "touch", purpose: "watch.accept", passkey: t.passkey })).toMatchObject({ ok: true });
    expect((await journal()).find((j) => j.kind === "touch")!.detail).toMatchObject({ via: "passkey", key: "laptop", purpose: "watch.accept" });
  });

  it("a default window size is bound too: the action says the minutes", async () => {
    const auth = await ready();
    const w = await touchFor(g, auth, { op: "open-window", pluginId: "demo" });
    expect(w.challenge.description).toContain("30 мин");
    expect((await g.send({ op: "open-window", pluginId: "demo", minutes: 60, passkey: w.passkey })).ok).toBe(false); // not what was signed
    expect((await g.send({ op: "open-window", pluginId: "demo", passkey: w.passkey })).ok).toBe(true);
  });

  it("refuses a challenge for something that cannot be approved, and for nonsense", async () => {
    const auth = await ready();
    await g.send({ op: "approve", requestId: 1, passkey: (await touchFor(g, auth, approve(1))).passkey });
    expect(await g.send({ op: "challenge", action: approve(1) })).toMatchObject({ ok: false, error: { code: "conflict" } }); // already approved
    expect(await g.send({ op: "challenge", action: approve(99) })).toMatchObject({ ok: false, error: { code: "not_found" } });
    expect(await g.send({ op: "challenge", action: { op: "revoke", pluginId: "demo" } })).toMatchObject({ ok: false, error: { code: "invalid" } });
    expect(await g.send({ op: "challenge", action: { op: "open-window", pluginId: "demo", scope: "everything" } })).toMatchObject({ ok: false, error: { code: "invalid" } });
    expect(await g.send({ op: "challenge" })).toMatchObject({ ok: false });
  });

  it("never exposes a key, a credential or a token through the state", async () => {
    const auth = await ready();
    const text = JSON.stringify(await g.send({ op: "state" }));
    expect(text).not.toContain(auth.credentialId.toString("base64url"));
    expect(text).not.toContain("public");
    expect(text).not.toContain("token");
    expect((await g.send({ op: "state" })).passkeys).toMatchObject({ rpId: "localhost", origin: "http://localhost:38886", keys: [{ label: "laptop" }], enrollmentOpen: false });
  });
});

describe("what a touch must NOT do", () => {
  it("a signature made for one action cannot approve another one under the same challenge", async () => {
    const auth = await ready();
    const { passkey } = await touchFor(g, auth, approve(1));
    // the same challenge, the same genuine signature, another request
    expect(await g.send({ op: "approve", requestId: 2, passkey })).toMatchObject({ ok: false, error: { code: "invalid_passkey", message: expect.stringContaining("another action") } });
    expect(await g.send(decideReq({ contentHash: H2, pluginId: "other" }))).toMatchObject({ action: "wait" });
    // ...and not another kind of action either
    expect((await g.send({ op: "open-window", pluginId: "demo", minutes: 30, passkey })).ok).toBe(false);
    expect((await g.send({ op: "touch", purpose: "approve", passkey })).ok).toBe(false);
    // three refusals in one minute: one summary record now, the rest counted for the next one
    expect((await journal()).filter((j) => j.kind === "passkey.fail")).toHaveLength(1);
  });

  it("the same signature cannot be used twice", async () => {
    const auth = await ready();
    const { passkey } = await touchFor(g, auth, { op: "touch", purpose: "x" });
    expect((await g.send({ op: "touch", purpose: "x", passkey })).ok).toBe(true);
    expect(await g.send({ op: "touch", purpose: "x", passkey })).toMatchObject({ ok: false, error: { code: "invalid_passkey", message: expect.stringContaining("already used") } });
  });

  it("an expired challenge is refused (two minutes)", async () => {
    const auth = await ready();
    const { passkey } = await touchFor(g, auth, approve(1));
    g.clock.advance(2 * 60_000 + 1);
    expect(await g.send({ op: "approve", requestId: 1, passkey })).toMatchObject({ ok: false, error: { code: "expired" } });
    // not a wrong signature: it is not counted
    expect((await journal()).some((j) => j.kind === "passkey.fail")).toBe(false);
  });

  it("a challenge the guard never issued is refused", async () => {
    const auth = await ready();
    expect(await g.send({ op: "approve", requestId: 1, passkey: auth.get("A".repeat(43)) })).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });
  });

  it.each([
    ["another origin", { origin: "https://evil.example" }, "origin"],
    ["another RP ID", { rpId: "evil.example" }, "RP ID"],
    ["no user verification", { flags: FLAGS.UP }, "verification"],
    ["no user presence", { flags: FLAGS.UV }, "presence"],
    ["a registration's client data", { type: "webauthn.create" }, "not for a touch"],
    ["a cross-origin frame", { crossOrigin: true }, "origin"],
  ] as const)("refuses a touch made with %s", async (_n, o, hint) => {
    const auth = await ready();
    const { passkey } = await touchFor(g, auth, approve(1), o);
    expect(await g.send({ op: "approve", requestId: 1, passkey })).toMatchObject({ ok: false, error: { code: "invalid_passkey", message: expect.stringContaining(hint) } });
    expect((await g.send({ op: "state" })).approvals).toEqual([]);
  });

  it("refuses a counter that does not go up, and accepts counters that do (and a key that never counts)", async () => {
    const auth = await ready({ signCount: 10 }); // registered with 10: the next must be above it
    const action = { op: "touch", purpose: "x" };
    const stale = await touchFor(g, auth, action, { signCount: 10 });
    expect(await g.send({ op: "touch", purpose: "x", passkey: stale.passkey })).toMatchObject({ ok: false, error: { message: expect.stringContaining("counter") } });
    const back = await touchFor(g, auth, action, { signCount: 3 });
    expect((await g.send({ op: "touch", purpose: "x", passkey: back.passkey })).ok).toBe(false);
    const next = await touchFor(g, auth, action, { signCount: 11 });
    expect((await g.send({ op: "touch", purpose: "x", passkey: next.passkey })).ok).toBe(true);
    const again = await touchFor(g, auth, action, { signCount: 11 }); // a clone replays the counter
    expect((await g.send({ op: "touch", purpose: "x", passkey: again.passkey })).ok).toBe(false);

    // a synced passkey reports 0 every time: fine
    await g.close();
    const sync = await ready();
    for (let i = 0; i < 3; i++) {
      const t = await touchFor(g, sync, { op: "touch", purpose: "x" });
      expect((await g.send({ op: "touch", purpose: "x", passkey: t.passkey })).ok).toBe(true);
    }
  });

  it("a key that is not registered here, and a corrupted signature, are refused", async () => {
    const auth = await ready();
    const stranger = new SoftAuthenticator();
    const s = await touchFor(g, stranger, approve(1));
    expect(await g.send({ op: "approve", requestId: 1, passkey: s.passkey })).toMatchObject({ ok: false, error: { message: expect.stringContaining("not registered") } });
    // the stranger signs with its credential id replaced by the registered one: the signature does not verify
    const forged = await touchFor(g, stranger, approve(1));
    expect(await g.send({ op: "approve", requestId: 1, passkey: { ...forged.passkey, credentialId: auth.credentialId.toString("base64url") } })).toMatchObject({ ok: false, error: { message: expect.stringContaining("invalid signature") } });
    const bad = await touchFor(g, auth, approve(1), { corrupt: true });
    expect(await g.send({ op: "approve", requestId: 1, passkey: bad.passkey })).toMatchObject({ ok: false, error: { message: expect.stringContaining("invalid signature") } });
    // garbage in the fields is a malformed request, not a signature
    expect(await g.send({ op: "approve", requestId: 1, passkey: { credentialId: "!!", clientDataJSON: "x", authenticatorData: "y", signature: "z" } })).toMatchObject({ ok: false, error: { code: "invalid" } });
    expect(await g.send({ op: "approve", requestId: 1, passkey: "yes please" })).toMatchObject({ ok: false, error: { code: "invalid" } });
  });

  it("wrong codes block codes, wrong signatures pause signatures: two counters, neither takes the other's way", async () => {
    const auth = await ready();
    // three wrong signatures and two wrong codes: five failures in all, and nothing is blocked (they are not one counter any more)
    for (let i = 0; i < 3; i++) {
      const bad = await touchFor(g, auth, approve(1), { corrupt: true });
      expect((await g.send({ op: "approve", requestId: 1, passkey: bad.passkey })).ok).toBe(false);
    }
    for (let i = 0; i < 2; i++) expect(await g.send({ op: "approve", requestId: 1, code: "000000" })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    const still = await touchFor(g, auth, approve(1));
    expect((await g.send({ op: "approve", requestId: 1, passkey: still.passkey })).ok).toBe(true);
    // the fifth wrong CODE blocks codes for an hour…
    for (let i = 0; i < 3; i++) await g.send({ op: "approve", requestId: 2, code: "000000" });
    expect(await g.send({ op: "approve", requestId: 2, code: g.code() })).toMatchObject({ ok: false, error: { code: "blocked" } });
    expect((await journal()).some((j) => j.kind === "totp.blocked")).toBe(true);
    const st = await g.send({ op: "state" });
    expect(st.totp.blockedUntil).toBeGreaterThan(g.clock.t);
    // …and a passkey touch still works while they are blocked: the owner is not locked out by a process that spams wrong codes
    const good = await touchFor(g, auth, approve(2));
    expect((await g.send({ op: "approve", requestId: 2, passkey: good.passkey })).ok).toBe(true);
    g.clock.advance(3_600_001);
    expect((await g.send({ op: "state" })).totp.blockedUntil).toBe(0);
  });

  it("wrong signatures have no limit: 1000 in a row do not stop a genuine one, and the journal grows only by summaries", async () => {
    const auth = await ready();
    const c = await g.send({ op: "challenge", action: approve(1) });
    const before = (g.guard.state().journal as { head: { id: number } }).head.id;
    for (let i = 0; i < 1000; i++) {
      const bad = auth.get(c.challenge, { corrupt: true });
      expect(await g.send({ op: "approve", requestId: 1, passkey: bad })).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });
    }
    // nothing blocks anybody, and the guard's rows did not grow per attempt: one summary in this minute
    const st = await g.send({ op: "state" });
    expect(st.totp.blockedUntil).toBe(0);
    expect(st.passkeys.blockedUntil).toBeUndefined();
    const grown = (g.guard.state().journal as { head: { id: number } }).head.id - before;
    expect(grown).toBe(1);
    expect((g.guard as any).db.prepare("SELECT COUNT(*) AS n FROM attempts WHERE kind = 'passkey' AND ok = 0").get().n).toBe(0);
    // the genuine touch goes through, and so does a code
    expect((await g.send({ op: "approve", requestId: 1, passkey: auth.get(c.challenge) })).ok).toBe(true);
    expect((await g.send({ op: "touch", purpose: "t", code: g.code() })).ok).toBe(true);
    // a minute later the next refusal writes a summary with the number since the last one
    g.clock.advance(PASSKEY_FAIL_LOG_EVERY_MS + 1);
    const c2 = await g.send({ op: "challenge", action: approve(2) });
    for (let i = 0; i < 10; i++) await g.send({ op: "approve", requestId: 2, passkey: auth.get(c2.challenge, { corrupt: true }) });
    const sums = (await journal()).filter((j) => j.kind === "passkey.fail");
    expect(sums).toHaveLength(2);
    expect(sums.map((j) => j.detail.failures).sort((a, b) => a - b)).toEqual([1, 1000]); // the first at once, then the 999 held back plus the one that came a minute later
  });

  it("a harmful plugin in the process that captured the signature cannot approve something else with it", async () => {
    const auth = await ready();
    // the human touches for #1; the plugin sees the whole request on its way through bb
    const captured = (await touchFor(g, auth, approve(1))).passkey;
    // it tries everything it can think of with it
    const attempts: Array<Record<string, unknown>> = [
      { op: "approve", requestId: 2, passkey: captured },
      { op: "open-window", pluginId: "other", minutes: 240, passkey: captured },
      { op: "policy", patch: { windowMin: 1440, capMin: 1440 }, passkey: captured },
      { op: "touch", purpose: "approve", passkey: captured },
      { op: "touch", purpose: "anything", passkey: captured },
    ];
    for (const a of attempts.slice(0, 4)) expect(await g.send(a)).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });
    // five wrong signatures do not lock the owner out (they have their own, looser counter): the human's real touch for #2 still works
    expect(await g.send(attempts[4]!)).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });
    expect(await g.send({ op: "approve", requestId: 2, passkey: captured })).toMatchObject({ ok: false, error: { code: "invalid_passkey" } });
    expect((await g.send({ op: "state" })).approvals).toEqual([]);
    expect((await g.send({ op: "state" })).approvals).toEqual([]);
    expect((await g.send({ op: "state" })).windows).toEqual([]);
    expect((await g.send({ op: "state" })).policy).toMatchObject({ windowMin: 30, capMin: 240 });
    // the plugin asks for its own challenges and cannot sign them: a challenge alone approves nothing
    const own = await g.send({ op: "challenge", action: approve(2) });
    expect(own.ok).toBe(true);
    expect((await g.send({ op: "state" })).approvals).toEqual([]);
    // and it may fill the table of challenges, but only up to a cap, with the newest kept
    for (let i = 0; i < 300; i++) await g.send({ op: "challenge", action: { op: "touch", purpose: `flood-${i}` } });
    const last = await touchFor(g, auth, { op: "touch", purpose: "last" });
    expect((await g.send({ op: "touch", purpose: "last", passkey: last.passkey })).ok).toBe(true);
  });

  it("keys cannot be added, listed, removed, confirmed or codes switched off through the socket", async () => {
    const auth = await ready();
    for (const op of ["passkey-enroll", "passkey-list", "passkey-remove", "passkey-confirm", "passkey-add", "totp-disable", "totp-register", "enroll"]) {
      expect(await g.send({ op, id: 1, token: "X", label: "evil", requestId: 1 }), op).toMatchObject({ ok: false, error: { code: "unknown_op" } });
    }
    // registering without a window the console opened: refused, whatever the token. Opening one is the console's alone.
    await g.close();
    g = await startGuard();
    expect(await g.send({ op: "passkey-register", token: "ANYT-HING-HERE" })).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(await g.send({ op: "passkey-register", token: "" })).toMatchObject({ ok: false });
    expect(await g.send({ op: "passkey-register", clientDataJSON: "e30", attestationObject: "oA" })).toMatchObject({ ok: false });
    expect(g.guard.listPasskeys()).toEqual([]);
    void auth;
  });
});

// ------------------------------------------------------------------------------------------------ codes and keys
describe("TOTP stays, and can be switched off from the console", () => {
  it("codes keep working next to a key; totp-disable needs a key, then codes are refused with an honest message", async () => {
    g = await startGuard();
    const io: Io = { out: () => {}, err: () => {}, ask: async () => "y" };
    expect(await totpDisable(g.paths, io, {}, g.clock.now)).toBe(1); // no key yet: nobody could touch
    expect(g.guard.totpRegistered()).toBe(true);
    const auth = new SoftAuthenticator();
    await enrollKey(g, auth);
    await g.send(decideReq({ contentHash: H1 }));
    await g.send(decideReq({ contentHash: H2, pluginId: "other" }));
    expect((await g.send({ op: "approve", requestId: 1, code: g.code() })).ok).toBe(true); // both work

    expect(await totpDisable(g.paths, { ...io, ask: async () => "n" }, {}, g.clock.now)).toBe(1);
    expect(g.guard.totpRegistered()).toBe(true);
    expect(await totpDisable(g.paths, io, {}, g.clock.now)).toBe(0);
    expect(g.guard.totpRegistered()).toBe(false);
    expect(g.guard.totpDisabled()).toBe(true);
    expect(readFileOrNull(g.paths.secret)).toBeNull(); // the secret is gone, not hidden
    expect(await g.send({ op: "approve", requestId: 2, code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "not_registered", message: expect.stringContaining("switched off") } });
    const t = await touchFor(g, auth, approve(2));
    expect((await g.send({ op: "approve", requestId: 2, passkey: t.passkey })).ok).toBe(true);
    expect((await g.send({ op: "state" })).totp).toMatchObject({ registered: false, disabled: true });
    expect((await journal()).find((j) => j.kind === "totp.disabled")).toBeDefined();

    // totp-register brings codes back (a new secret; no old code is needed: there is none)
    const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    const { base32Decode, hotp, stepAt } = await import("../../guard/src/totp.ts");
    g.clock.advance(31_000);
    g.guard.registerSecret(secret, hotp(base32Decode(secret), stepAt(g.clock.t)));
    expect(g.guard.totpDisabled()).toBe(false);
    expect(g.guard.totpRegistered()).toBe(true);
  });

  it("the last way to touch cannot be removed; keys are listed and removed on the console only", async () => {
    g = await startGuard({ register: false });
    const lines: string[] = [];
    const io: Io = { out: (t) => void lines.push(t), err: (t) => void lines.push(t), ask: async () => "y" };
    const a = new SoftAuthenticator();
    const b = new SoftAuthenticator();
    await enrollKey(g, a, { label: "laptop" });
    await enrollKey(g, b, { label: "phone" });
    expect(passkeyList(g.paths, io, g.clock.now)).toBe(0);
    expect(lines.join("\n")).toMatch(/#1\s+laptop\s+active/);
    expect(lines.join("\n")).toMatch(/#2\s+phone\s+active/);
    expect(lines.join("\n")).toContain("codes (TOTP): not registered");

    expect(await passkeyRemove(g.paths, io, "2", {}, g.clock.now)).toBe(0);
    expect(await passkeyRemove(g.paths, io, "1", { yes: true }, g.clock.now)).toBe(1); // no TOTP, no other key: it would lock the owner out
    expect(lines.join("\n")).toContain("last way to touch");
    expect(await passkeyRemove(g.paths, io, "7", { yes: true }, g.clock.now)).toBe(1);
    expect(await passkeyRemove(g.paths, io, "one", {}, g.clock.now)).toBe(64);
    expect(await passkeyRemove(g.paths, { ...io, ask: async () => "n" }, "1", {}, g.clock.now)).toBe(1);

    // the removed key no longer touches; the remaining one still does
    await g.send(decideReq({ contentHash: H1 }));
    const removed = await touchFor(g, b, approve(1));
    expect(await g.send({ op: "approve", requestId: 1, passkey: removed.passkey })).toMatchObject({ ok: false, error: { message: expect.stringContaining("not registered") } });
    const kept = await touchFor(g, a, approve(1));
    expect((await g.send({ op: "approve", requestId: 1, passkey: kept.passkey })).ok).toBe(true);
    expect((await journal()).find((j) => j.kind === "passkey.removed")).toMatchObject({ detail: { key: "phone", via: "console" } });
  });
});

// ------------------------------------------------------------------------------------------------ the parts
describe("settings", () => {
  it("defaults to localhost and the bb port; refuses an IP address and a mismatching origin", () => {
    expect(resolveRp({}, {})).toEqual({ rpId: "localhost", origin: "http://localhost:38886" });
    expect(resolveRp({}, { SBB_GUARD_RP_ID: "guard.example.org", SBB_GUARD_ORIGIN: "https://guard.example.org" })).toEqual({ rpId: "guard.example.org", origin: "https://guard.example.org" });
    expect(resolveRp({ rpId: "example.org", origin: "https://bb.example.org" }, {})).toEqual({ rpId: "example.org", origin: "https://bb.example.org" });
    expect(() => resolveRp({ rpId: "127.0.0.1" }, {})).toThrow(/IP address/);
    expect(() => resolveRp({ origin: "http://127.0.0.1:38886" }, {})).toThrow(/localhost/);
    expect(() => resolveRp({ rpId: "example.org", origin: "https://other.test" }, {})).toThrow(/RP ID's domain/);
    expect(() => resolveRp({ origin: "http://localhost:38886/page" }, {})).toThrow(/bare origin/);
    expect(() => resolveRp({ origin: "not a url" }, {})).toThrow(/URL/);
    expect(resolvePaths({ data: "/x", rpId: "localhost", origin: "http://localhost:1234" }, {}).rp).toEqual({ rpId: "localhost", origin: "http://localhost:1234" });
  });

  it("a guard with another relying party signs and verifies for it, and refuses the default one", async () => {
    g = await startGuard({ rp: { rpId: "guard.example.org", origin: "https://guard.example.org" } });
    const auth = new SoftAuthenticator({ rpId: "guard.example.org", origin: "https://guard.example.org" });
    expect((await enrollKey(g, auth)).reg.ok).toBe(true);
    await g.send(decideReq({ contentHash: H1 }));
    const ok = await touchFor(g, auth, approve(1));
    expect(ok.challenge).toMatchObject({ rpId: "guard.example.org", origin: "https://guard.example.org" });
    expect((await g.send({ op: "approve", requestId: 1, passkey: ok.passkey })).ok).toBe(true);
    await g.send(decideReq({ contentHash: H2 }));
    const wrong = await touchFor(g, auth, approve(2), { origin: "http://localhost:38886", rpId: "localhost" });
    expect((await g.send({ op: "approve", requestId: 2, passkey: wrong.passkey })).ok).toBe(false);
  });
});

function readFileOrNull(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

describe("CBOR and keys: nothing but what the guard asked for", () => {
  it("decodes what an authenticator sends", () => {
    const v = cborDecode(cbor(new Map<any, any>([["fmt", "none"], [1, -7], [-3, Buffer.from([1, 2, 3])], ["big", 70000 > 65535 ? 65535 : 0], ["nested", new Map<any, any>([["a", 1]])]])));
    expect(v).toBeInstanceOf(Map);
    const m = v as Map<unknown, unknown>;
    expect(m.get("fmt")).toBe("none");
    expect(m.get(1)).toBe(-7);
    expect(m.get(-3)).toEqual(Buffer.from([1, 2, 3]));
    expect((m.get("nested") as Map<unknown, unknown>).get("a")).toBe(1);
    expect(cborDecode(Buffer.from([0x18, 0xff]))).toBe(255);
    expect(cborDecode(Buffer.from([0x39, 0x01, 0x00]))).toBe(-257);
    expect(cborDecode(Buffer.from([0xf5]))).toBe(true);
  });

  it.each([
    ["empty", []],
    ["truncated string", [0x63, 0x61]],
    ["truncated head", [0x19, 0x01]],
    ["trailing bytes", [0x01, 0x02]],
    ["indefinite length", [0x9f, 0x01, 0xff]],
    ["a tag", [0xc1, 0x01]],
    ["a float", [0xfb, 0, 0, 0, 0, 0, 0, 0, 0]],
    ["duplicate map keys", [0xa2, 0x01, 0x01, 0x01, 0x02]],
    ["a huge length", [0x5a, 0xff, 0xff, 0xff, 0xff]],
    ["nesting without end", Array(40).fill(0x81)],
  ])("refuses %s", (_name, bytes) => {
    expect(() => cborDecode(Buffer.from(bytes))).toThrow(PasskeyError);
  });

  it("accepts only ES256 keys on P-256 and a `none` attestation with an empty statement", () => {
    const x = Buffer.alloc(32, 1);
    const y = Buffer.alloc(32, 2);
    expect(() => coseToSpki(new Map<any, any>([[1, 3], [3, -257], [-1, x], [-2, x]]))).toThrow(/ES256/); // RSA
    expect(() => coseToSpki(new Map<any, any>([[1, 2], [3, -7], [-1, 2], [-2, x], [-3, y]]))).toThrow(/ES256/); // P-384
    expect(() => coseToSpki(new Map<any, any>([[1, 2], [3, -7], [-1, 1], [-2, x.subarray(1)], [-3, y]]))).toThrow(/coordinates/);
    expect(() => coseToSpki("nope" as never)).toThrow(/COSE/);
    const auth = new SoftAuthenticator();
    const att = auth.create({ challenge: "x" }).attestationObject;
    expect(parseAttestationObject(Buffer.from(att, "base64url")).attested?.credentialId).toEqual(auth.credentialId);
    expect(() => parseAttestationObject(cbor(new Map<any, any>([["fmt", "none"], ["attStmt", new Map<any, any>([["x", 1]])], ["authData", Buffer.alloc(37)]])))).toThrow(/empty statement/);
    expect(() => parseAttestationObject(cbor(new Map<any, any>([["fmt", "none"], ["attStmt", new Map()]])))).toThrow(/authenticator data/);
  });

  it("tokens are 12 readable characters, and compare without caring for dashes and case", () => {
    const t = newToken();
    expect(t).toMatch(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
    expect(normalizeToken(t.toLowerCase().replace(/-/g, " "))).toBe(t.replace(/-/g, ""));
    expect(new Set(Array.from({ length: 50 }, newToken)).size).toBe(50);
  });
});
