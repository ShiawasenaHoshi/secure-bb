import { readFileSync, statSync, writeFileSync, copyFileSync } from "node:fs";
import net from "node:net";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { journalVerify, main, parseExport, EXPORT_FORMAT, importCmd, status, totpRegister, serve, type Io } from "../../guard/src/cli.ts";
import { listen } from "../../guard/src/server.ts";
import { openDb } from "../../guard/src/db.ts";
import { Guard } from "../../guard/src/guard.ts";
import { encodeQr as pluginQr } from "../../src/qr.ts";
import { hotp as pluginHotp, base32Decode as pluginDecode, otpauthUri as pluginOtpauthUri } from "../../src/totp.ts";
import { encodeQr as guardQr } from "../../guard/src/qr.ts";
import { base32Decode, hotp, otpauthUri, stepAt } from "../../guard/src/totp.ts";
import { Clock, decideReq, startGuard, type TestGuard } from "./support.ts";

let g: TestGuard;
afterEach(async () => {
  await g?.close();
});

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);

describe("decide", () => {
  it("holds an unknown version and keeps one queue entry per version", async () => {
    g = await startGuard();
    const a = await g.send(decideReq({ contentHash: H1 }));
    expect(a).toMatchObject({ ok: true, action: "wait", requestId: 1 });
    expect(a.reason).toContain("review #1");
    const b = await g.send(decideReq({ contentHash: H1 }));
    expect(b.requestId).toBe(1);
    const c = await g.send(decideReq({ contentHash: H2 }));
    expect(c.requestId).toBe(2);
    const s = await g.send({ op: "state" });
    expect(s.queue.filter((q: any) => q.status === "held")).toHaveLength(2);
    expect(s.queue.find((q: any) => q.id === 1).seenCount).toBe(2);
  });

  it("a version the person rejected is rejected again without a new queue entry, journaled once an hour; «Вернуть» (a touch) undoes it", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    expect((await g.send({ op: "dismiss", requestId: 1 })).ok).toBe(true);
    // The core asks again at every start: five times, and still one entry and one journal line.
    for (let i = 0; i < 5; i++) {
      expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ ok: true, action: "reject" });
      expect(await g.send({ op: "hold", pluginId: "demo", version: "1.0.0", contentHash: H1, rootDir: "/tmp/demo", source: "path:/tmp/demo", sourceKind: "path", trigger: "install" })).toMatchObject({ ok: true, requestId: null });
    }
    const s = await g.send({ op: "state" });
    expect(s.queue).toHaveLength(1);
    expect(s.queue.filter((q: any) => q.status === "held")).toHaveLength(0);
    const countRepeats = async () => ((await g.send({ op: "state" })).journal.recent as any[]).filter((l: any) => l.kind === "reject.repeat").length;
    expect(await countRepeats()).toBe(1);
    expect((await g.send({ op: "lookup", pluginId: "demo", contentHash: H1 })).rejected).toBe(true);
    // An hour later: one more line, not one per ask.
    g.clock.advance(61 * 60_000);
    await g.send(decideReq({ contentHash: H1 }));
    await g.send(decideReq({ contentHash: H1 }));
    expect(await countRepeats()).toBe(2);
    // Another version of the plugin is a new question.
    expect(await g.send(decideReq({ contentHash: H2 }))).toMatchObject({ action: "wait" });
    // A wrong code does not bring it back; a right touch does, and the version then loads.
    expect((await g.send({ op: "approve", requestId: 1, code: "000000" })).ok).toBe(false);
    expect((await g.send({ op: "approve", requestId: 1, code: g.code() })).ok).toBe(true);
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "proceed", via: "approval" });
    expect((await g.send({ op: "lookup", pluginId: "demo", contentHash: H1 })).rejected).toBe(false);
  });

  it("an approval records why the version passed (the history shows it): by touch with the guard's note, by source with the guard's words", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    expect((await g.send({ op: "approve", requestId: 1, code: g.code() })).ok).toBe(true);
    const a = (await g.send({ op: "state" })).approvals[0];
    expect(a.via).toBe("touch");
    expect(a.why).toMatch(/^касанием: /);
  });

  it("proceeds on an approved hash, and only for that plugin id", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    expect((await g.send({ op: "approve", requestId: 1, code: g.code() })).ok).toBe(true);
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ ok: true, action: "proceed", via: "approval" });
    // The same bytes claimed by another plugin id are another question.
    expect(await g.send(decideReq({ contentHash: H1, pluginId: "other" }))).toMatchObject({ action: "wait" });
    expect(await g.send(decideReq({ contentHash: H2 }))).toMatchObject({ action: "wait" });
  });

  it("refuses malformed input without recording it", async () => {
    g = await startGuard();
    for (const bad of [{ pluginId: "../x" }, { pluginId: "" }, { contentHash: "x" }, { contentHash: "a b c d e f g h" }, { version: 5 }, { rootDir: "a\u0000b" }, { trigger: "x".repeat(100) }]) {
      const r = await g.send(decideReq(bad));
      expect(r).toMatchObject({ ok: false, error: { code: "invalid" } });
    }
    expect(((await g.send({ op: "state" })).queue as unknown[]).length).toBe(0);
  });

  it("does not let a flood of new holds fill the guard", async () => {
    g = await startGuard();
    for (let i = 0; i < 205; i++) g.guard.decide({ ...decideReq({ contentHash: `${String(i).padStart(8, "0")}${"f".repeat(32)}` }) });
    const s = (await g.send({ op: "state" })) as any;
    expect(s.queue.length).toBe(100); // the view is capped; the table holds 200
    const last = g.guard.decide(decideReq({ contentHash: "e".repeat(40) }) as never);
    expect(last).toMatchObject({ action: "wait", requestId: null });
    expect((s.journal.recent as any[]).some((j) => j.kind === "queue.flood")).toBe(true);
  });
});

describe("touches: codes", () => {
  it("refuses a missing, malformed, wrong and replayed code, and acts on none of them", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    for (const code of [undefined, "12345", 123456]) {
      expect(await g.send({ op: "approve", requestId: 1, code })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    }
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "wait" });
    const good = g.code();
    expect((await g.send({ op: "approve", requestId: 1, code: good })).ok).toBe(true);
    // The same code again, for something else: the step is spent.
    await g.send(decideReq({ contentHash: H2 }));
    expect(await g.send({ op: "approve", requestId: 2, code: good })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    // An older step than the last used one is refused too, though inside the ±1 window.
    g.clock.advance(30_000);
    const next = g.code();
    expect((await g.send({ op: "approve", requestId: 2, code: next })).ok).toBe(true);
    g.clock.advance(-30_000);
    await g.send(decideReq({ contentHash: "3".repeat(64) }));
    expect(await g.send({ op: "approve", requestId: 3, code: hotp(base32Decode(g.secret), stepAt(g.clock.t) - 1) })).toMatchObject({ ok: false });
  });

  it("blocks all touches for an hour after five wrong codes, even a right one; tightening still works", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    for (let i = 0; i < 4; i++) expect((await g.send({ op: "approve", requestId: 1, code: "000000" })).error.code).toBe("invalid_code");
    expect((await g.send({ op: "approve", requestId: 1, code: "000000" })).error.code).toBe("invalid_code"); // the fifth starts the block
    const blocked = await g.send({ op: "approve", requestId: 1, code: g.code() });
    expect(blocked).toMatchObject({ ok: false, error: { code: "blocked" } });
    expect((await g.send({ op: "state" })).totp.blockedUntil).toBeGreaterThan(g.clock.t);
    // Tightening is never blocked: whoever can call the guard must not keep the owner from closing things.
    expect((await g.send({ op: "revoke", pluginId: "demo" })).ok).toBe(false); // nothing to revoke, but it is answered, not blocked
    g.clock.advance(3_600_001);
    expect((await g.send({ op: "approve", requestId: 1, code: g.code() })).ok).toBe(true);
  });

  it("failures older than an hour do not add up", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    for (let i = 0; i < 4; i++) await g.send({ op: "approve", requestId: 1, code: "000000" });
    g.clock.advance(3_600_001);
    expect((await g.send({ op: "approve", requestId: 1, code: "000000" })).error.code).toBe("invalid_code");
    expect((await g.send({ op: "approve", requestId: 1, code: g.code() })).ok).toBe(true);
  });

  it("without a registered secret nothing can be approved", async () => {
    g = await startGuard({ register: false });
    await g.send(decideReq({ contentHash: H1 }));
    expect(await g.send({ op: "approve", requestId: 1, code: "123456" })).toMatchObject({ ok: false, error: { code: "not_registered" } });
    expect(await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 5, code: "123456" })).toMatchObject({ ok: false, error: { code: "not_registered" } });
  });

  it("does not spend a code on a request that cannot succeed", async () => {
    g = await startGuard();
    const code = g.code();
    expect(await g.send({ op: "approve", requestId: 99, code })).toMatchObject({ ok: false, error: { code: "not_found" } });
    await g.send(decideReq({ contentHash: H1 }));
    expect((await g.send({ op: "approve", requestId: 1, code })).ok).toBe(true);
    expect(await g.send({ op: "approve", requestId: 1, code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "conflict" } });
  });
});

describe("windows", () => {
  it("approves any version of the plugin inside, slides, and freezes at the end", async () => {
    g = await startGuard();
    const w = await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    expect(w.ok).toBe(true);
    g.clock.advance(5 * 60_000);
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "proceed", via: "window" });
    const open = (await g.send({ op: "state" })).windows[0];
    expect(open.expiresAt).toBe(g.clock.t + 10 * 60_000); // slid
    g.clock.advance(9 * 60_000);
    expect(await g.send(decideReq({ contentHash: H2 }))).toMatchObject({ action: "proceed", via: "window" });
    // another plugin is not covered
    expect(await g.send(decideReq({ contentHash: H2, pluginId: "other" }))).toMatchObject({ action: "wait" });
    g.clock.advance(11 * 60_000);
    const frozen = await g.send(decideReq({ contentHash: "9".repeat(64) }));
    expect(frozen).toMatchObject({ action: "wait" });
    const s = await g.send({ op: "state" });
    expect(s.windows).toHaveLength(0);
    expect((s.journal.recent as any[]).some((j) => j.kind === "window.freeze" && j.detail.pinnedVersion === "1.0.0")).toBe(true);
    // the versions approved in the window stay approved (pinned)
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "proceed", via: "approval" });
  });

  it("never outlives the ceiling", async () => {
    g = await startGuard();
    expect(await g.send({ op: "policy", patch: { capMin: 20, windowMin: 10 } })).toMatchObject({ ok: true }); // narrowing: no code
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    for (const minute of [8, 16]) {
      g.clock.advance(8 * 60_000);
      expect(await g.send(decideReq({ contentHash: `${minute}`.repeat(10) }))).toMatchObject({ action: "proceed", via: "window" });
    }
    // 16 min in: sliding wanted 26, the ceiling says 20
    expect((await g.send({ op: "state" })).windows[0].remainingSec).toBe(4 * 60);
    g.clock.advance(5 * 60_000);
    expect(await g.send(decideReq({ contentHash: "9".repeat(10) }))).toMatchObject({ action: "wait" });
    expect((await g.send({ op: "state" })).closedWindows[0].closedReason).toBe("ceiling");
  });

  it("window size is limited by the ceiling; policy widening needs a code, narrowing does not", async () => {
    g = await startGuard();
    expect(await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 241, code: g.code() })).toMatchObject({ ok: false, error: { code: "invalid" } });
    // narrowing without a code
    expect(await g.send({ op: "policy", patch: { capMin: 40, windowMin: 20, mode: "fixed" } })).toMatchObject({ ok: true, policy: { capMin: 40, windowMin: 20, mode: "fixed" } });
    // widening without / with a code
    expect(await g.send({ op: "policy", patch: { capMin: 60 } })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    expect(await g.send({ op: "policy", patch: { mode: "sliding" } })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
    expect(await g.send({ op: "policy", patch: { capMin: 60 }, code: g.code() })).toMatchObject({ ok: true, policy: { capMin: 60 } });
    expect(await g.send({ op: "policy", patch: { windowMin: 90 }, code: g.nextCode() })).toMatchObject({ ok: false, error: { code: "invalid" } });
    // fixed: does not slide
    await g.send({ op: "policy", patch: { mode: "fixed" } });
    const o = await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.nextCode() });
    const exp = o.window.expiresAt;
    g.clock.advance(5 * 60_000);
    await g.send(decideReq({ contentHash: H1 }));
    expect((await g.send({ op: "state" })).windows[0].expiresAt).toBe(exp);
  });

  it("is closed without a code, and a revoke closes it and the approvals of the plugin", async () => {
    g = await startGuard();
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    await g.send(decideReq({ contentHash: H1 }));
    expect((await g.send({ op: "close-window", pluginId: "demo" })).ok).toBe(true);
    expect(await g.send(decideReq({ contentHash: H2 }))).toMatchObject({ action: "wait" });
    expect(await g.send({ op: "close-window", pluginId: "demo" })).toMatchObject({ ok: false, error: { code: "not_found" } });
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.nextCode() });
    expect((await g.send({ op: "revoke", pluginId: "demo" })).revoked).toBe(1);
    const s = await g.send({ op: "state" });
    expect(s.windows).toHaveLength(0);
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "wait" });
  });

  it("reopening replaces the old window of the same plugin", async () => {
    g = await startGuard();
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 20, code: g.nextCode() });
    expect((await g.send({ op: "state" })).windows).toHaveLength(1);
  });
});

describe("dismiss: tightening, no code", () => {
  it("drops a held entry without a code, even while wrong codes block approvals; the journal gets a record; the version is not approved", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    await g.send(decideReq({ contentHash: H2 }));
    for (let i = 0; i < 5; i++) await g.send({ op: "approve", requestId: 1, code: "000000" });
    expect(await g.send({ op: "approve", requestId: 1, code: g.code() })).toMatchObject({ ok: false, error: { code: "blocked" } });
    expect((await g.send({ op: "dismiss", requestId: 1 })).ok).toBe(true); // no code, inside the block
    const s = await g.send({ op: "state" });
    expect(s.approvals).toHaveLength(0);
    expect((s.journal.recent as any[]).some((j) => j.kind === "dismissed" && j.contentHash === H1)).toBe(true);
    expect((await g.send({ op: "dismiss", requestId: 2, code: "123456" })).ok).toBe(true); // a code, if sent, is not needed and not checked
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "reject" }); // proposed again: rejected again, no new entry
  });

  it("only held entries: approved, dismissed or unknown entries are refused", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    await g.send(decideReq({ contentHash: H2 }));
    await g.send({ op: "approve", requestId: 1, code: g.code() });
    expect(await g.send({ op: "dismiss", requestId: 1 })).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect((await g.send({ op: "state" })).approvals).toHaveLength(1); // the approval is untouched
    expect((await g.send({ op: "dismiss", requestId: 2 })).ok).toBe(true);
    expect(await g.send({ op: "dismiss", requestId: 2 })).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(await g.send({ op: "dismiss", requestId: 99 })).toMatchObject({ ok: false, error: { code: "not_found" } });
  });
});

describe("revoke and annotate", () => {
  it("revoke by approval id withdraws the version, needs no code, and the version is held again", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    const a = await g.send({ op: "approve", requestId: 1, code: g.code() });
    expect((await g.send({ op: "revoke", approvalId: a.approval.id })).revoked).toBe(1);
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "wait" });
    expect(await g.send({ op: "revoke", approvalId: a.approval.id })).toMatchObject({ ok: false, error: { code: "not_found" } });
  });

  it("annotations are shown as unverified and change no decision", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    expect((await g.send({ op: "annotate", requestId: 1, findings: [{ rule: "net", severity: "review" }] })).ok).toBe(true);
    const q = (await g.send({ op: "state" })).queue[0];
    expect(q.annotation).toMatchObject({ verified: false, findings: [{ rule: "net" }] });
    // a plugin that says "all clean" does not make anything proceed
    await g.send({ op: "annotate", contentHash: H1, findings: [] });
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "wait" });
    expect(await g.send({ op: "annotate", requestId: 1, findings: "x".repeat(70_000) })).toMatchObject({ ok: false, error: { code: "invalid" } });
    expect(await g.send({ op: "annotate", requestId: 77, findings: [] })).toMatchObject({ ok: false, error: { code: "not_found" } });
  });

  it("lookup tells the plugin's hook what the guard knows, read-only", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    expect(await g.send({ op: "lookup", pluginId: "demo", contentHash: H1 })).toMatchObject({ ok: true, approved: false, window: null, requestId: 1 });
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    const l = await g.send({ op: "lookup", pluginId: "demo", contentHash: H2 });
    expect(l.window).toMatchObject({ sizeSec: 600 });
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0); // looking approved nothing
  });
});

describe("hold (a request of the plugin's hook: tightening only)", () => {
  const holdReq = (over: Record<string, unknown> = {}) => ({ ...decideReq(over), op: "hold" });

  it("keeps a version for a human without a code, and approves nothing", async () => {
    g = await startGuard();
    expect(await g.send(holdReq({ contentHash: H1 }))).toMatchObject({ ok: true, requestId: 1 });
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "wait", requestId: 1 }); // the same entry
    expect((await g.send({ op: "state" })).approvals).toHaveLength(0);
  });

  it("a hold with `stop` is not lifted by a window: only a human's approval lifts it", async () => {
    g = await startGuard();
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    await g.send(holdReq({ contentHash: H1, stop: true }));
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "wait" });
    // other versions of the plugin still pass by the window
    expect(await g.send(decideReq({ contentHash: H2 }))).toMatchObject({ action: "proceed", via: "window" });
    expect((await g.send({ op: "approve", requestId: 1, code: g.nextCode() })).ok).toBe(true);
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "proceed", via: "approval" });
  });

  it("dismissing a stopped entry (no code) neither lifts the stop nor leaves the window open: decide stays `wait`, the window is closed, the journal says so", async () => {
    g = await startGuard();
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    await g.send(holdReq({ contentHash: H1, stop: true }));
    expect((await g.send({ op: "dismiss", requestId: 1 })).ok).toBe(true); // no code
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "reject" });
    const s = await g.send({ op: "state" });
    expect(s.windows).toHaveLength(0);
    expect(s.closedWindows[0]).toMatchObject({ pluginId: "demo", closedReason: "dismissed-stop" });
    expect((s.journal.recent as any[]).some((j) => j.kind === "dismissed" && j.detail.stop === true)).toBe(true);
    expect((s.journal.recent as any[]).some((j) => j.kind === "window.close" && j.detail.reason === "dismissed-stop")).toBe(true);
    // a window opened again (with a code) still does not wave this version in; the entry decide makes keeps the stop
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.nextCode() });
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "reject" });
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "reject" });
    expect(await g.send(decideReq({ contentHash: H2 }))).toMatchObject({ action: "proceed", via: "window" }); // other versions: the window works
    // and the way out is a code («Вернуть» on the rejected entry)
    expect((await g.send({ op: "approve", requestId: 1, code: g.nextCode() })).ok).toBe(true);
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "proceed", via: "approval" });
  });

  it("the stop of a dismissed entry is not pruned by a flood of other entries; dismissing a plain entry leaves the window alone", async () => {
    g = await startGuard();
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    await g.send(holdReq({ contentHash: H1, stop: true }));
    await g.send({ op: "dismiss", requestId: 1 });
    for (let i = 0; i < 150; i++) g.guard.hold({ ...holdReq({ pluginId: "other", contentHash: `${String(i).padStart(8, "0")}${"e".repeat(32)}` }) });
    for (const r of (await g.send({ op: "state" })).queue.filter((q: any) => q.status === "held")) await g.send({ op: "dismiss", requestId: r.id });
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.nextCode() });
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "reject" });
    // plain (stop=0) entry: dismissing it does not close the window
    await g.send(holdReq({ contentHash: H2 }));
    const h2 = (await g.send({ op: "state" })).queue.find((q: any) => q.status === "held" && q.contentHash === H2);
    await g.send({ op: "dismiss", requestId: h2.id });
    expect((await g.send({ op: "state" })).windows).toHaveLength(1);
  });

  it("a plain hold is lifted by a window opened later, as a hold of decide is", async () => {
    g = await startGuard();
    await g.send(holdReq({ contentHash: H1 }));
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.code() });
    expect(await g.send(decideReq({ contentHash: H1 }))).toMatchObject({ action: "proceed", via: "window" });
    expect((await g.send({ op: "state" })).queue[0].status).toBe("approved");
  });

  it("does nothing for a version that is already approved, and counts against the flood limit like decide", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    await g.send({ op: "approve", requestId: 1, code: g.code() });
    expect(await g.send(holdReq({ contentHash: H1, stop: true }))).toMatchObject({ ok: true, requestId: null });
    for (let i = 0; i < 205; i++) g.guard.hold({ ...holdReq({ contentHash: `${String(i).padStart(8, "0")}${"d".repeat(32)}` }) });
    expect(g.guard.hold(holdReq({ contentHash: "c".repeat(40) }))).toEqual({ requestId: null });
  });
});

describe("protocol", () => {
  it("answers one JSON line per request, echoes id, and rejects what it cannot read", async () => {
    g = await startGuard();
    expect(await g.send({ op: "ping", id: "abc" })).toMatchObject({ ok: true, id: "abc", protocol: 1 });
    const raw = (line: string): Promise<any> =>
      new Promise((resolve) => {
        const c = net.connect(g.paths.socket, () => c.write(line));
        c.setEncoding("utf8");
        c.once("data", (d: string) => (c.destroy(), resolve(JSON.parse(d))));
      });
    expect(await raw("not json\n")).toMatchObject({ ok: false, error: { code: "invalid" } });
    expect(await raw("[1,2]\n")).toMatchObject({ ok: false, error: { code: "invalid" } });
    expect(await raw('{"op":"rm -rf"}\n')).toMatchObject({ ok: false, error: { code: "unknown_op" } });
    expect(await raw('{"op":"totp-secret"}\n')).toMatchObject({ ok: false, error: { code: "unknown_op" } });
  });

  it("answers several requests on one connection, in order", async () => {
    g = await startGuard();
    const got = await new Promise<string[]>((resolve) => {
      const c = net.connect(g.paths.socket, () => c.write('{"op":"ping","id":1}\n{"op":"ping","id":2}\n{"op":"ping","id":3}\n'));
      let buf = "";
      c.setEncoding("utf8");
      c.on("data", (d: string) => {
        buf += d;
        if (buf.split("\n").filter(Boolean).length === 3) (c.destroy(), resolve(buf.split("\n").filter(Boolean)));
      });
    });
    expect(got.map((l) => JSON.parse(l).id)).toEqual([1, 2, 3]);
  });

  it("drops a connection that sends an endless line, and one that stays silent", async () => {
    g = await startGuard({ serve: false });
    g.server = await listen({ guard: g.guard, socket: g.paths.socket, socketGid: null, version: "t", timeoutMs: 150 });
    const closed = (write?: string): Promise<void> =>
      new Promise((resolve) => {
        const c = net.connect(g.paths.socket, () => write && c.write(write));
        c.on("close", () => resolve());
        c.on("error", () => resolve());
      });
    await closed(); // silent: timeout closes it
    await closed("x".repeat(600 * 1024)); // no newline, too long
    expect((await g.send({ op: "ping" })).ok).toBe(true); // the guard is still fine
  });

  it("the socket is 0660", async () => {
    g = await startGuard();
    expect(statSync(g.paths.socket).mode & 0o777).toBe(0o660);
  });

  it("refuses to start a second guard on a live socket, and replaces a stale one", async () => {
    g = await startGuard();
    await expect(listen({ guard: g.guard, socket: g.paths.socket, socketGid: null, version: "t" })).rejects.toThrow(/already listening/);
    await new Promise<void>((r) => g.server!.close(() => r()));
    writeFileSync(g.paths.socket, ""); // a stale file where a socket was
    g.server = await listen({ guard: g.guard, socket: g.paths.socket, socketGid: null, version: "t" });
    expect((await g.send({ op: "ping" })).ok).toBe(true);
  });
});

describe("the secret", () => {
  it("is in no answer of any op, in no journal record, and the files are private", async () => {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    await g.send({ op: "approve", requestId: 1, code: g.code() });
    await g.send({ op: "approve", requestId: 1, code: "000000" });
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 5, code: g.nextCode() });
    await g.send({ op: "touch", purpose: "x", code: g.nextCode() });
    const answers: string[] = [];
    for (const req of [{ op: "state" }, { op: "ping" }, { op: "policy" }, { op: "journal-verify" }, { op: "lookup", pluginId: "demo", contentHash: H1 }, { op: "secret" }, { op: "totp" }, { op: "state", include: "secret" }, { op: "export" }]) {
      answers.push(JSON.stringify(await g.send(req)));
    }
    for (const a of answers) {
      expect(a).not.toContain(g.secret);
      expect(a).not.toContain(Buffer.from(g.secret).toString("hex"));
    }
    const dump = readFileSync(g.paths.db).toString("latin1") + readFileSync(`${g.paths.db}-wal`, { flag: "r" }).toString("latin1");
    expect(dump).not.toContain(g.secret);
    expect(statSync(g.paths.secret).mode & 0o777).toBe(0o600);
    expect(statSync(g.paths.stateDir).mode & 0o777).toBe(0o700);
    expect(statSync(g.paths.db).mode & 0o777).toBe(0o600);
    expect(statSync(g.paths.head).mode & 0o777).toBe(0o600);
  });
});

describe("journal", () => {
  async function busy(): Promise<void> {
    g = await startGuard();
    await g.send(decideReq({ contentHash: H1 }));
    await g.send({ op: "approve", requestId: 1, code: g.code() });
    await g.send({ op: "open-window", scope: "tree", pluginId: "demo", minutes: 10, code: g.nextCode() });
    await g.send(decideReq({ contentHash: H2 }));
    await g.send({ op: "close-window", pluginId: "demo" });
  }
  const raw = (): DatabaseSync => new DatabaseSync(g.paths.db);

  it("is an unbroken chain, with its head in a separate file", async () => {
    await busy();
    const r = g.guard.verifyJournal();
    expect(r).toMatchObject({ ok: true, problems: [] });
    expect(r.entries).toBeGreaterThan(5);
    expect(readFileSync(g.paths.head, "utf8")).toBe(`${r.head!.id} ${r.head!.hash}\n`);
  });

  it("notices an edited record", async () => {
    await busy();
    const db = raw();
    db.prepare(`UPDATE journal SET detail = ? WHERE kind = 'approved.touch'`).run('{"version":"6.6.6"}');
    db.close();
    expect(g.guard.verifyJournal().problems.map((p) => p.kind)).toContain("hash-mismatch");
  });

  it("notices a removed record in the middle", async () => {
    await busy();
    const db = raw();
    db.prepare(`DELETE FROM journal WHERE kind = 'hold'`).run();
    db.close();
    expect(g.guard.verifyJournal().problems.map((p) => p.kind)).toContain("prev-mismatch");
  });

  it("notices a cut tail, even if the chain is consistent up to the cut", async () => {
    await busy();
    const db = raw();
    db.prepare(`DELETE FROM journal WHERE id > (SELECT MAX(id) - 2 FROM journal)`).run();
    db.close();
    const kinds = g.guard.verifyJournal().problems.map((p) => p.kind);
    expect(kinds).toContain("anchor-ahead");
    expect(kinds).toContain("tail-removed");
  });

  it("notices a rolled-back copy of the database, and a head file that is gone", async () => {
    await busy();
    const copy = `${g.paths.db}.old`;
    const db = raw();
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    db.close();
    copyFileSync(g.paths.db, copy);
    await g.send(decideReq({ contentHash: "7".repeat(64) })); // a record newer than the copy
    const live = raw();
    live.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    live.close();
    copyFileSync(copy, g.paths.db);
    expect(g.guard.verifyJournal().problems.map((p) => p.kind)).toContain("anchor-ahead");
    writeFileSync(g.paths.head, "garbage");
    expect(g.guard.verifyJournal().problems.map((p) => p.kind)).toContain("anchor-missing");
  });

  it("notices an approval written straight into the database", async () => {
    await busy();
    const db = raw();
    db.prepare(`INSERT INTO approvals (content_hash, plugin_id, version, source, source_kind, via, approved_at) VALUES (?, 'evil', '1', 's', 'path', 'touch', 1)`).run("e".repeat(64));
    db.close();
    expect(g.guard.verifyJournal().problems.map((p) => p.kind)).toContain("orphan-approval");
  });

  it("journal-verify exits 0 on a sound journal and 2 on a broken one", async () => {
    await busy();
    const out: string[] = [];
    const io: Io = { out: (t) => out.push(t), err: (t) => out.push(t), ask: async () => null };
    expect(journalVerify(g.paths, io)).toBe(0);
    const db = raw();
    db.prepare(`UPDATE journal SET kind = 'nothing' WHERE id = 2`).run();
    db.close();
    expect(journalVerify(g.paths, io)).toBe(2);
    expect(out.join("\n")).toContain("hash-mismatch");
    expect(await main(["journal-verify", "--data", g.paths.dataDir], io)).toBe(2);
  });

  it("records what exactly was approved", async () => {
    await busy();
    const rec = (await g.send({ op: "state" })).journal.recent.find((j: any) => j.kind === "approved.touch");
    expect(rec).toMatchObject({ pluginId: "demo", contentHash: H1, detail: { version: "1.0.0", source: "path:/tmp/demo", sourceKind: "path", rootDir: "/tmp/demo" } });
  });
});

describe("console: totp-register", () => {
  const lines: string[] = [];
  const io = (answers: string[] = []): Io => ({ out: (t) => lines.push(t), err: (t) => lines.push(`ERR ${t}`), ask: async () => answers.shift() ?? null });
  const secretFrom = (): string => /by hand: ([A-Z2-7]+)/.exec(lines.join("\n"))![1]!;

  it("shows a QR and the key once, registers on the first valid code, and then refuses to show anything", async () => {
    lines.length = 0;
    g = await startGuard({ register: false, serve: false });
    const clock = g.clock;
    // a person reads the key from the screen and types the current code
    const ask = async (): Promise<string> => hotp(base32Decode(secretFrom()), stepAt(clock.t));
    expect(await totpRegister(g.paths, { out: (t) => lines.push(t), err: (t) => lines.push(`ERR ${t}`), ask }, {}, clock.now)).toBe(0);
    expect(lines.join("\n")).toMatch(/[█▀▄]/); // the QR
    expect(readFileSync(g.paths.secret, "utf8").trim()).toBe(secretFrom());
    expect(statSync(g.paths.secret).mode & 0o777).toBe(0o600);
    // second time: needs a code of the current one, and the old key is not shown again
    lines.length = 0;
    clock.advance(31_000);
    expect(await totpRegister(g.paths, io(), {}, clock.now)).toBe(1);
    expect(lines.join("\n")).toContain("already registered");
    expect(lines.join("\n")).not.toContain(g.secret);
  });

  it("rejects a wrong first code and saves nothing", async () => {
    lines.length = 0;
    g = await startGuard({ register: false, serve: false });
    expect(await totpRegister(g.paths, io(), { code: "000000" }, g.clock.now)).toBe(1);
    expect(() => statSync(g.paths.secret)).toThrow();
  });

  it("replacing works with a code of the old secret, and the new one takes over", async () => {
    lines.length = 0;
    g = await startGuard({ serve: false });
    const oldCode = g.code();
    const clock = g.clock;
    let first = true;
    const ask = async (): Promise<string> => {
      if (first) {
        first = false;
        return oldCode;
      }
      clock.advance(31_000); // the new secret's code must be a later step than the one just spent
      return hotp(base32Decode(secretFrom()), stepAt(clock.t));
    };
    const rc = await totpRegister(g.paths, { out: (t) => lines.push(t), err: (t) => lines.push(`ERR ${t}`), ask }, {}, clock.now);
    expect(rc).toBe(0);
    expect(readFileSync(g.paths.secret, "utf8").trim()).toBe(secretFrom());
    expect(readFileSync(g.paths.secret, "utf8").trim()).not.toBe(g.secret);
  });
});

describe("import", () => {
  const exportFile = (items: unknown[]): string => JSON.stringify({ format: EXPORT_FORMAT, approvals: items });
  const item = (hash: string, over: Record<string, unknown> = {}) => ({ contentHash: hash, pluginId: "demo", version: "1.0.0", source: "path:/x", sourceKind: "path", gitCommit: null, npmIntegrity: null, approvedAt: 1, ...over });
  const quiet = (answers: string[] = []): Io => ({ out: () => {}, err: () => {}, ask: async () => answers.shift() ?? null });

  it("adds approvals (journaled, so the chain stays sound), skips existing ones, and they proceed", async () => {
    g = await startGuard({ serve: false });
    const file = join(g.paths.dataDir, "export.json");
    writeFileSync(file, exportFile([item(H1), item(H2, { pluginId: "other" })]));
    expect(await importCmd(g.paths, quiet(), file, { yes: true }, g.clock.now)).toBe(0);
    expect(await importCmd(g.paths, quiet(), file, { yes: true }, g.clock.now)).toBe(0); // again: all skipped
    expect(g.guard.decide(decideReq({ contentHash: H1 }) as never)).toMatchObject({ action: "proceed" });
    expect(g.guard.decide(decideReq({ contentHash: H2, pluginId: "other" }) as never)).toMatchObject({ action: "proceed" });
    expect(g.guard.verifyJournal().ok).toBe(true);
    expect(g.guard.state().journal).toMatchObject({ recent: expect.arrayContaining([expect.objectContaining({ kind: "approved.import" })]) });
  });

  it("asks first, and does nothing without a yes", async () => {
    g = await startGuard({ serve: false });
    const file = join(g.paths.dataDir, "export.json");
    writeFileSync(file, exportFile([item(H1)]));
    expect(await importCmd(g.paths, quiet(), file, {}, g.clock.now)).toBe(1); // no terminal
    expect(await importCmd(g.paths, quiet(["n"]), file, {}, g.clock.now)).toBe(1);
    expect(g.guard.decide(decideReq({ contentHash: H1 }) as never)).toMatchObject({ action: "wait" });
    expect(await importCmd(g.paths, quiet(["y"]), file, {}, g.clock.now)).toBe(0);
  });

  it("refuses a file that is not what was exported (digest), or malformed", async () => {
    g = await startGuard({ serve: false });
    const file = join(g.paths.dataDir, "export.json");
    writeFileSync(file, exportFile([item(H1)]));
    expect(await importCmd(g.paths, quiet(), file, { yes: true, digest: "0".repeat(64) }, g.clock.now)).toBe(1);
    expect(() => parseExport("{}")).toThrow();
    expect(() => parseExport(exportFile([{ contentHash: "x" }]))).toThrow(/malformed/);
    expect(() => parseExport(JSON.stringify({ format: EXPORT_FORMAT, approvals: new Array(6000).fill(item(H1)) }))).toThrow(/too many/);
    expect(g.guard.decide(decideReq({ contentHash: H1 }) as never)).toMatchObject({ action: "wait" });
  });
});

describe("serve / status", () => {
  it("starts, answers, is seen by `status`, journals start and stop, and stops on abort", async () => {
    g = await startGuard({ serve: false });
    const out: string[] = [];
    const io: Io = { out: (t) => out.push(t), err: (t) => out.push(t), ask: async () => null };
    await g.close();
    const ac = new AbortController();
    const done = serve(g.paths, io, ac.signal);
    for (let i = 0; i < 50; i++) {
      try {
        if ((await g.send({ op: "ping" })).ok) break;
      } catch {
        await new Promise((r) => setTimeout(r, 40));
      }
    }
    out.length = 0;
    expect(await status(g.paths, io)).toBe(0);
    expect(out.join("\n")).toContain("daemon:  running");
    expect(out.join("\n")).toContain("journal: ok");
    ac.abort();
    expect(await done).toBe(0);
    const db = openDb(g.paths.db);
    const kinds = (db.prepare(`SELECT kind FROM journal ORDER BY id`).all() as Array<{ kind: string }>).map((r) => r.kind);
    db.close();
    expect(kinds).toContain("start");
    expect(kinds).toContain("stop");
    expect(await status(g.paths, io)).toBe(1); // stopped: not answering
  });
});

describe("agrees with the plugin's own primitives", () => {
  it("the plugin's totp.ts and qr.ts are the guard's own functions (no copy that could drift); only the issuer of the plugin's own code differs", () => {
    expect(pluginHotp).toBe(hotp);
    expect(pluginDecode).toBe(base32Decode);
    expect(pluginQr).toBe(guardQr);
    const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    expect(pluginOtpauthUri(secret)).toContain("issuer=secure-bb");
    expect(pluginOtpauthUri(secret)).not.toContain("secure-bb-guard");
    expect(otpauthUri(secret)).toContain("issuer=secure-bb-guard");
    expect(pluginOtpauthUri(secret, "x")).toBe(otpauthUri(secret, "x"));
  });

  it("has no dependencies and imports only node:* and its own files", () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, "../../guard/package.json"), "utf8"));
    expect(pkg.dependencies ?? {}).toEqual({});
    expect(pkg.devDependencies ?? {}).toEqual({});
    for (const f of ["cli", "config", "db", "guard", "journal", "qr", "server", "totp"]) {
      const src = readFileSync(join(__dirname, `../../guard/src/${f}.ts`), "utf8");
      for (const m of src.matchAll(/(?:from|import)\s+"([^"]+)"/g)) expect(m[1]!.startsWith("node:") || m[1]!.startsWith("./"), `${f}: ${m[1]}`).toBe(true);
    }
  });
});

void Clock;
void Guard;
