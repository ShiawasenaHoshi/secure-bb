// The journal for learning through the plugin in guard mode: the page's report goes to the guard, the approval's record carries it, a mark and a revoke reason come back.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { bootPlugin, core, hookCtx, plugDir, startGuardOnDate, type Booted, type TestGuard } from "./support.ts";

let g: TestGuard;
let h: Booted;
beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
afterEach(async () => {
  vi.useRealTimers();
  await g?.close();
});
const fresh = (): string => (vi.setSystemTime(Date.now() + 31_000), g.code());
const kinds = async (kind: string) => ((await g.send({ op: "state" })).journal.recent as Array<{ id: number; kind: string; detail: any }>).filter((r) => r.kind === kind);

describe("the journal for learning, through the plugin", () => {
  it("card.view reaches the guard; the approval carries what was shown; a mark and a revoke reason are recorded", { timeout: 30_000 }, async () => {
    g = await startGuardOnDate();
    h = await bootPlugin(g.paths.socket);
    expect(await core(g, h, hookCtx("p1", plugDir("p1"), "sha256:p1"))).toBe("held");
    await h.rpc("card.view", { id: 1, event: "shown", level: "check", findings: [{ rule: "net.fetch", file: "src/a.ts", line: 2 }], ai: [{ model: "claude", status: "clean" }], textsVersion: 1, detailsOpen: false });
    await h.rpc("card.view", { id: 1, event: "details" });
    await h.rpc("queue.approve", { id: 1, code: fresh() });
    const approved = (await kinds("approved.touch"))[0]!;
    expect(approved.detail.seen).toMatchObject({ level: "check", textsVersion: 1, findings: [{ rule: "net.fetch", file: "src/a.ts", line: 2 }], ai: [{ model: "claude", status: "clean" }] });
    expect(approved.detail.how).toMatchObject({ detailsOpened: true, snoozedBefore: false });
    await h.rpc("decision.mark", { record: approved.id, mark: "false_alarm", reason: "мой плагин" });
    expect((await kinds("decision.mark"))[0]!.detail).toEqual({ record: approved.id, mark: "false_alarm", reason: "мой плагин" });
    const approvalId = ((await g.send({ op: "state" })).approvals as Array<{ id: number }>)[0]!.id;
    await h.rpc("approval.revoke", { approvalId, reason: "не тот плагин" });
    expect((await kinds("revoked"))[0]!.detail).toMatchObject({ reason: "не тот плагин" });
    // the card's report for a local proposal (negative id) is not sent anywhere and does not fail
    await expect(h.rpc("card.view", { id: -5, event: "shown" })).resolves.toEqual({ ok: true });
  });
});
