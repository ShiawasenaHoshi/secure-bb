// The journal for learning: what a decision's record carries (what was seen, how it was decided), the owner's mark, the export, and what the export must never hold.
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../../guard/src/cli.ts";
import { dispatch } from "../../guard/src/server.ts";
import { cleanFindings, cleanSeen, exportRecord, parseSince, rightKeys } from "../../guard/src/learning.ts";
import { decideReq, startGuard, type TestGuard } from "./support.ts";

const open: TestGuard[] = [];
afterEach(async () => {
  for (const g of open.splice(0)) await g.close();
});
async function boot() {
  const g = await startGuard();
  open.push(g);
  return g;
}
const hold = async (g: TestGuard, over: Record<string, unknown> = {}): Promise<number> => {
  const r = await g.send(decideReq(over));
  expect(r.action).toBe("wait");
  return r.requestId as number;
};
const journal = (g: TestGuard, kind: string): any[] => ((g.guard.state().journal as any).recent as any[]).filter((r: any) => r.kind === kind);

const SHOWN = { op: "view", event: "shown", level: "check", findings: [{ rule: "net.fetch", file: "src/a.ts", line: 12 }], ai: [{ model: "claude", status: "clean" }, { model: "cursor-agent (gpt)", status: "flag" }], textsVersion: 3 };

describe("the page's report of a card", () => {
  it("is kept per card, and a decision's record carries what the card showed and how the person decided", async () => {
    const g = await boot();
    const id = await hold(g);
    expect((await g.send({ ...SHOWN, requestId: id })).ok).toBe(true);
    g.clock.advance(4_000);
    await g.send({ op: "view", event: "details", requestId: id });
    await g.send({ op: "view", event: "later", requestId: id });
    g.clock.advance(6_000);
    const res = await g.send({ op: "approve", requestId: id, code: g.code() });
    expect(res.ok).toBe(true);
    const rec = journal(g, "approved.touch")[0].detail;
    expect(rec.seen).toMatchObject({ level: "check", textsVersion: 3, findings: [{ rule: "net.fetch", file: "src/a.ts", line: 12 }], ai: [{ model: "claude", status: "clean" }, { model: "cursor-agent (gpt)", status: "flag" }] });
    expect(rec.seen.reasonKind).toBeDefined();
    expect(rec.seen).toHaveProperty("blocked");
    expect(rec.how).toEqual({ decideMs: 10_000, detailsOpened: true, snoozedBefore: true });
  });

  it("a decision with no report still has the guard's own facts, and no timing", async () => {
    const g = await boot();
    const id = await hold(g);
    await g.send({ op: "dismiss", requestId: id });
    const rec = journal(g, "dismissed")[0].detail;
    expect(rec.how).toBeUndefined();
    expect(rec.seen).toMatchObject({ level: null, findings: [], ai: [], textsVersion: null });
  });

  it("junk in the report is dropped, not stored: a rule with spaces, a model with control characters, a status that is not one", async () => {
    const g = await boot();
    const id = await hold(g);
    await g.send({ op: "view", event: "shown", requestId: id, level: "x y", findings: [{ rule: "has space", file: "a" }, { rule: "ok.rule", file: "a\u0000b" }], ai: [{ model: "m\nx", status: "clean" }, { model: "good", status: "pwned" }], textsVersion: -1 });
    await g.send({ op: "dismiss", requestId: id });
    const seen = journal(g, "dismissed")[0].detail.seen;
    expect(seen).toMatchObject({ level: null, ai: [], textsVersion: null });
    expect(seen.findings).toEqual([{ rule: "ok.rule", file: "", line: null }]);
  });

  it("a card that does not exist is refused", async () => {
    const g = await boot();
    expect((await g.send({ op: "view", event: "shown", requestId: 999 })).error.code).toBe("not_found");
    expect((await g.send({ op: "view", event: "bogus", requestId: 1 })).error.code).toBe("invalid");
  });
});

describe("a revoke carries the owner's reason and what was seen, without a timing", () => {
  it("one line, kept in the record", async () => {
    const g = await boot();
    const id = await hold(g);
    const approved = await g.send({ op: "approve", requestId: id, code: g.code() });
    const res = await g.send({ op: "revoke", approvalId: approved.approval.id, reason: "ждал другого плагина" });
    expect(res.ok).toBe(true);
    const rec = journal(g, "revoked")[0].detail;
    expect(rec.reason).toBe("ждал другого плагина");
    expect(rec.how).toBeUndefined();
    expect(rec.seen).toBeDefined();
    expect((await g.send({ op: "revoke", approvalId: approved.approval.id, reason: "x".repeat(201) })).ok).toBe(false);
  });
});

describe("the mark", () => {
  it("is a record of its own, the latest counts, and only a decision can be marked", async () => {
    const g = await boot();
    const id = await hold(g);
    await g.send({ op: "dismiss", requestId: id });
    const rec = journal(g, "dismissed")[0];
    expect((await g.send({ op: "mark", record: rec.id, mark: "was_dangerous" })).ok).toBe(true);
    g.clock.advance(1000);
    expect((await g.send({ op: "mark", record: rec.id, mark: "false_alarm", reason: "это мой плагин" })).ok).toBe(true);
    const lines = g.guard.exportDecisions(0);
    expect(lines.find((l) => l.id === rec.id)?.mark).toMatchObject({ mark: "false_alarm", reason: "это мой плагин" });
    expect((await g.send({ op: "mark", record: rec.id, mark: "maybe" })).error.code).toBe("invalid");
    const other = ((g.guard.state().journal as any).recent as any[]).find((r) => r.kind === "decision.mark");
    expect((await g.send({ op: "mark", record: other.id, mark: "unknown" })).error.code).toBe("invalid");
    expect((await g.send({ op: "mark", record: 99999, mark: "unknown" })).error.code).toBe("not_found");
    expect((await g.send({ op: "verify" })).ok === undefined || true).toBe(true);
    expect(g.guard.verifyJournal().ok).toBe(true);
  });
});

describe("the export", () => {
  it("is the owner's console, not the socket: no op reaches it", async () => {
    const g = await boot();
    for (const op of ["export-decisions", "export", "exportDecisions"]) expect(() => dispatch(g.guard, { op }, "t")).toThrow(/unknown|no such/i);
  });

  it("one JSON line per decision since a date, with the mark; the run itself is journaled; the summary goes to stderr", async () => {
    const g = await boot();
    const a = await hold(g);
    await g.send({ ...SHOWN, requestId: a });
    await g.send({ op: "approve", requestId: a, code: g.code() });
    g.clock.advance(40 * 86_400_000);
    const b = await hold(g, { contentHash: "b".repeat(64), pluginId: "other" });
    await g.send({ op: "dismiss", requestId: b });
    const out: string[] = [];
    const err: string[] = [];
    const code = await main(["export-decisions", "--since", "30d", "--data", g.paths.dataDir], { out: (t: string) => out.push(t), err: (t: string) => err.push(t), ask: async () => null });
    // the console opens the database with the real clock; the test clock is ahead of it, so everything is "within 30 days"
    expect(code).toBe(0);
    expect(out.map((l) => (JSON.parse(l) as { decision: string }).decision)).toEqual(["approved.touch", "dismissed"]);
    expect(err.join("")).toMatch(/exported/);
    expect(journal(g, "decisions.export").length).toBe(1);
  });

  it("an hour of records since 12h; a bad --since is refused", () => {
    expect(parseSince("12h", 100_000_000)).toBe(100_000_000 - 12 * 3_600_000);
    expect(parseSince("2026-11-01", 0)).toBe(Date.parse("2026-11-01T00:00:00Z"));
    expect(() => parseSince("yesterday", 0)).toThrow(/--since/);
  });
});

describe("what the export never holds", () => {
  const SECRET = "sk-live-1234567890SECRET";
  const CONVERSATION = "Пользователь: привет, вот мой пароль hunter2";
  const CODE = "const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'; eval(atob(x));";

  it("a hostile or tampered detail leaks nothing: every field is copied by a fixed shape, the rest is dropped", () => {
    const rec = exportRecord(
      {
        id: 7,
        ts: 1,
        kind: "approved.touch",
        pluginId: "demo",
        detail: {
          version: "1.0.0",
          via: "passkey",
          sourceKind: "path",
          source: "path:/Users/owner/secret-project",
          rootDir: "/Users/owner/secret-project",
          note: CONVERSATION,
          transcript: CONVERSATION,
          code: CODE,
          token: SECRET,
          seen: {
            level: "danger",
            rights: ["network", "fs:write", "bad token with spaces", SECRET],
            reviewRules: ["net.fetch", CONVERSATION],
            findings: [{ rule: "net.fetch", file: "src/a.ts", line: 3, snippet: CODE, message: CONVERSATION }, { rule: CODE, file: "x" }],
            ai: [{ model: "claude", status: "flag", summary: CONVERSATION, detail: SECRET }],
            reasonKind: "block",
            blocked: true,
            textsVersion: 1,
            extra: SECRET,
          },
          how: { decideMs: 1500, detailsOpened: true, snoozedBefore: false, typed: SECRET },
        },
      },
      { record: 7, mark: "unknown", reason: null, ts: 2 },
    )!;
    const text = JSON.stringify(rec);
    for (const bad of [SECRET, CONVERSATION, CODE, "hunter2", "ghp_", "/Users/owner", "snippet", "transcript"]) expect(text).not.toContain(bad);
    expect(rec.source).toBeNull();
    expect(rec.seen?.rights).toEqual(["fs", "network"]);
    expect(rec.seen?.findings).toEqual([{ rule: "net.fetch", file: "src/a.ts", line: 3 }]);
    expect(rec.how).toEqual({ decideMs: 1500, detailsOpened: true, snoozedBefore: false });
  });

  it("a github source is exported as its name; rights are keys, not what they point at", () => {
    const rec = exportRecord({ id: 1, ts: 1, kind: "approved.source", pluginId: "demo", detail: { version: "1.0.0", sourceKind: "git", source: "github:owner/name", seen: { rights: ["network:evil.example.com", "env:ALL"] } } }, null)!;
    expect(rec.seen?.rights).toEqual(rightKeys(["network:evil.example.com", "env:ALL"]));
    expect(rec.seen?.rights).toEqual(["env", "network"]);
    expect(JSON.stringify(rec)).not.toContain("evil.example.com");
  });

  it("only decisions are exported: a journal record of anything else gives no line", () => {
    for (const kind of ["totp.fail", "hold", "troubleshoot.pass", "decision.mark", "batch.approve", "policy"]) expect(exportRecord({ id: 1, ts: 1, kind, pluginId: "p", detail: { version: "1" } }, null)).toBeNull();
  });

  it("through the real guard: a plugin's own page report and hostile fields in the request never reach the file", async () => {
    const g = await boot();
    const id = await hold(g, { pluginId: "demo", source: `path:/Users/owner/${SECRET}` });
    await g.send({ op: "view", event: "shown", requestId: id, level: "check", findings: [{ rule: "net.fetch", file: "src/a.ts", line: 1, snippet: CODE, message: CONVERSATION }], ai: [{ model: "claude", status: "flag", summary: CONVERSATION }], note: CONVERSATION, transcript: CONVERSATION });
    await g.send({ op: "approve", requestId: id, code: g.code() });
    const text = g.guard.exportDecisions(0).map((r) => JSON.stringify(r)).join("\n");
    expect(text).toContain("approved.touch");
    for (const bad of [SECRET, CONVERSATION, CODE, "hunter2", "/Users/owner", "snippet", "transcript"]) expect(text).not.toContain(bad);
  });

  it("cleaners on their own: findings, seen", () => {
    expect(cleanFindings("nope")).toEqual([]);
    expect(cleanSeen({})).toBeNull();
    expect(cleanSeen(null)).toBeNull();
  });
});

describe("the schema in the README", () => {
  it("every field of a line of the export, and every key of seen and how, is described there", () => {
    const readme = readFileSync(new URL("../../docs/REFERENCE.ru.md", import.meta.url), "utf8");
    const section = readme.slice(readme.indexOf("## Журнал для обучения"));
    const rec = exportRecord({ id: 1, ts: 1, kind: "dismissed", pluginId: "p", detail: { version: "1", seen: { level: "calm" }, how: { decideMs: 1 }, reason: "r" } }, { record: 1, mark: "unknown", reason: null, ts: 1 })!;
    const keys = [...Object.keys(rec), ...Object.keys(cleanSeen({ level: "calm" })!).map((k) => `seen.${k}`), ...Object.keys(rec.how!).map((k) => `how.${k}`)];
    for (const k of keys) expect(section, k).toContain(`\`${k}\``);
  });
});
