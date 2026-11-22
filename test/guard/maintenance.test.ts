// A planned maintenance window (an update the owner runs) is declared ONLY at the guard's console: there is no op for it on the socket, so neither the server of bb, nor an agent,
// nor a plugin can declare one. It is limited in time, ends by itself, and every declaration and end is in the journal («с консоли», when, why).
import { afterEach, describe, expect, it } from "vitest";
import { maintenance, type Io } from "../../guard/src/cli.ts";
import { MAINTENANCE_DEFAULT_MIN, MAINTENANCE_MAX_MIN } from "../../guard/src/guard-types.ts";
import { startGuard, type TestGuard } from "./support.ts";

let g: TestGuard | null = null;
afterEach(async () => {
  await g?.close();
  g = null;
});
const journal = (guard: TestGuard, kind: string) => (guard.guard.state().journal as { recent: Array<{ kind: string; detail: Record<string, any> | null; ts: number }> }).recent.filter((r) => r.kind === kind);
const state = async (guard: TestGuard): Promise<any> => guard.send({ op: "state" });

describe("nobody but the console can declare a window", () => {
  it("over the socket every way to ask for one is refused as an unknown op, and the state stays empty", async () => {
    g = await startGuard({});
    for (const op of ["maintenance", "maintenance-begin", "maintenance.begin", "begin-maintenance", "maintenance-end", "maintenance_begin", "update"]) {
      const r = await g.send({ op, reason: "update", minutes: 20, code: g.nextCode() });
      expect(r, op).toMatchObject({ ok: false, error: { code: "unknown_op" } });
    }
    expect((await state(g)).maintenance).toEqual([]);
    expect(journal(g, "maintenance.begin")).toEqual([]);
  });
  it("what a peer of the socket can do is only to read: `state` lists the windows", async () => {
    g = await startGuard({});
    g.guard.maintenanceBegin("update");
    const s = await state(g);
    expect(s.maintenance).toHaveLength(1);
    expect(s.maintenance[0]).toMatchObject({ reason: "update", endedAt: null });
  });
  it("the console command works on the data directory (as `totp-register` does) and says what it did", async () => {
    g = await startGuard({});
    const lines: string[] = [];
    const io: Io = { out: (t) => void lines.push(t), err: (t) => void lines.push(`ERR ${t}`), ask: async () => null };
    expect(await maintenance(g.paths, io, "begin", { reason: "update", minutes: "20" }, g.clock.now)).toBe(0);
    expect(lines.join("\n")).toMatch(/Maintenance window until .* \(20 min, reason: update\)/);
    expect((await state(g)).maintenance).toHaveLength(1);
    expect(await maintenance(g.paths, io, "status", {}, g.clock.now)).toBe(0);
    expect(lines.join("\n")).toMatch(/Maintenance window open until/);
    expect(await maintenance(g.paths, io, "end", {}, g.clock.now)).toBe(0);
    expect((await state(g)).maintenance[0].endedAt).toBe(g.clock.t);
    expect(await maintenance(g.paths, io, "nonsense", {}, g.clock.now)).toBe(64);
  });
});

describe("a window is limited and ends by itself", () => {
  it("20 minutes by default, 60 at most; nothing longer, nothing shorter than a minute", async () => {
    g = await startGuard({});
    expect(MAINTENANCE_DEFAULT_MIN).toBe(20);
    const w = g.guard.maintenanceBegin("update");
    expect(w.until - w.beganAt).toBe(20 * 60_000);
    expect(() => g!.guard.maintenanceBegin("update", MAINTENANCE_MAX_MIN + 1)).toThrow();
    expect(() => g!.guard.maintenanceBegin("update", 0)).toThrow();
    expect(g.guard.maintenanceBegin("update", MAINTENANCE_MAX_MIN).until - g.clock.t).toBe(60 * 60_000);
  });
  it("it ends at its time without anybody, and the end is in the journal", async () => {
    g = await startGuard({});
    const w = g.guard.maintenanceBegin("update");
    g.clock.advance(19 * 60_000);
    g.guard.sweep();
    expect(journal(g, "maintenance.end")).toEqual([]);
    g.clock.advance(2 * 60_000);
    g.guard.sweep();
    const end = journal(g, "maintenance.end");
    expect(end).toHaveLength(1);
    expect(end[0]!.detail).toMatchObject({ id: w.id, how: "expired" });
    expect((await state(g)).maintenance[0]).toMatchObject({ id: w.id, endedAt: w.until });
  });
  it("a new window ends the open one; the console's end closes it earlier", async () => {
    g = await startGuard({});
    const a = g.guard.maintenanceBegin("update");
    g.clock.advance(60_000);
    const b = g.guard.maintenanceBegin("update again");
    const list = g.guard.maintenanceWindows();
    expect(list.find((w) => w.id === a.id)!.endedAt).toBe(g.clock.t);
    expect(list.find((w) => w.id === b.id)!.endedAt).toBeNull();
    expect(g.guard.maintenanceEnd()).toBe(true);
    expect(g.guard.maintenanceEnd()).toBe(false);
  });
});

describe("the journal says who, when, why", () => {
  it("the declaration and the end are records «via: console» with the reason, the minutes and the time", async () => {
    g = await startGuard({});
    const w = g.guard.maintenanceBegin("update of secure-bb", 30);
    g.clock.advance(5 * 60_000);
    g.guard.maintenanceEnd();
    const begin = journal(g, "maintenance.begin");
    expect(begin).toHaveLength(1);
    expect(begin[0]!.detail).toMatchObject({ id: w.id, reason: "update of secure-bb", minutes: 30, until: w.until, via: "console" });
    const end = journal(g, "maintenance.end");
    expect(end[0]!.detail).toMatchObject({ id: w.id, how: "console", via: "console" });
    expect(begin[0]!.ts).toBe(w.beganAt);
    expect((g.guard.verifyJournal() as unknown as { ok: boolean }).ok).toBe(true);
  });
});
