// A pause of the plugin during an update the owner declared is a calm line; every other pause stays an alarm. Pure functions (the pause and the windows are all they read),
// the page's sorting of the pauses, and «Я проверил»: confirms exactly the pauses named, and a later pause is red again.
import { describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { Alive, GAP_THRESHOLD_MS } from "../src/alive.js";
import { GateError } from "../src/errors.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { GAP_START_SLACK_MS, gapPlan, gapView, groupGaps, type GapContext, type GapLike, type MaintenanceWindow } from "../src/ux.js";
import { gapsBySeverity, overlayView } from "../src/pageview.js";
import type { Overview } from "../src/overview.js";
import { pageRpc } from "../src/rpc/page.js";

const MIN = 60_000;
const T0 = 1_800_000_000_000;
const win = (fromMin: number, toMin: number, over: Partial<MaintenanceWindow> = {}): MaintenanceWindow => ({ beganAt: T0 + fromMin * MIN, until: T0 + toMin * MIN, endedAt: null, reason: "update", ...over });
const gap = (fromMin: number, toMin: number): GapLike & { at: number } => ({ from: T0 + fromMin * MIN, to: T0 + toMin * MIN, ms: (toMin - fromMin) * MIN, at: T0 + toMin * MIN, mode: "guard", cause: "unknown" });
const fmt = (t: number): string => `t${Math.round((t - T0) / MIN)}`;
const ctx: GapContext = { guardModeNow: true, coreHoldsNow: false, configWatch: true };

describe("was the pause the owner's planned update?", () => {
  it("no window at all: outside (an alarm, as before)", () => {
    expect(gapPlan(gap(1, 4), [])).toBe("outside");
  });
  it("it began and ended inside a window: planned", () => {
    expect(gapPlan(gap(1, 4), [win(0, 20)])).toBe("planned");
    expect(gapPlan(gap(0, 20), [win(0, 20)])).toBe("planned");
  });
  it("it began inside and ended after the window: overrun (an alarm, with a note)", () => {
    expect(gapPlan(gap(15, 25), [win(0, 20)])).toBe("overrun");
  });
  it("it began before the window (and ended inside it, or after it): outside, a plain alarm", () => {
    expect(gapPlan(gap(-10, 5), [win(0, 20)])).toBe("outside");
    expect(gapPlan(gap(-10, 30), [win(0, 20)])).toBe("outside");
  });
  it("it is all outside the window, before or after it: outside", () => {
    expect(gapPlan(gap(-30, -20), [win(0, 20)])).toBe("outside");
    expect(gapPlan(gap(30, 33), [win(0, 20)])).toBe("outside");
  });
  it("the last mark of a pause comes up to one beat before the declaration: that much is allowed, more is not", () => {
    const w = win(0, 20);
    expect(gapPlan({ from: w.beganAt - GAP_START_SLACK_MS, to: w.beganAt + 3 * MIN }, [w])).toBe("planned");
    expect(gapPlan({ from: w.beganAt - GAP_START_SLACK_MS - 1000, to: w.beganAt + 3 * MIN }, [w])).toBe("outside");
  });
  it("a window that ran out (until passed, nobody closed it) is over at `until`; a window the owner closed early is over then", () => {
    expect(gapPlan(gap(1, 25), [win(0, 20)])).toBe("overrun");
    expect(gapPlan(gap(1, 12), [win(0, 20, { endedAt: T0 + 10 * MIN })])).toBe("overrun");
    expect(gapPlan(gap(1, 9), [win(0, 20, { endedAt: T0 + 10 * MIN })])).toBe("planned");
    // `endedAt` after `until` cannot lengthen it
    expect(gapPlan(gap(1, 25), [win(0, 20, { endedAt: T0 + 30 * MIN })])).toBe("overrun");
  });
  it("of several windows the one that covers the pause counts; planned beats overrun", () => {
    expect(gapPlan(gap(50, 53), [win(0, 20), win(45, 65)])).toBe("planned");
    expect(gapPlan(gap(15, 25), [win(0, 20), win(14, 30)])).toBe("planned");
  });
});

describe("the words", () => {
  it("a planned pause: «Обновление secure-bb: страница не работала 3 мин (с … по …), сторож работал», calm, and what did not work is kept for «Подробнее»", () => {
    const v = gapView(gap(1, 4), ctx, [win(0, 20)], fmt);
    expect(v.plan).toBe("planned");
    expect(v.severity).toBe("calm");
    expect(v.headline).toBe("Обновление secure-bb: страница не работала 3 мин (с t1 по t4), сторож работал");
    expect(v.headline).not.toMatch(/Не работало/);
    expect(v.notWorking).toMatch(/^Не работало: страница, коды и касания/);
    expect(v.works).toMatch(/^Сторож в это время работал/);
  });
  it("one that ran past the window is still red, and says so", () => {
    const v = gapView(gap(15, 25), ctx, [win(0, 20)], fmt);
    expect(v.plan).toBe("overrun");
    expect(v.severity).toBe("critical");
    expect(v.headline).toBe("Страница защиты не работала 10 мин — во время обновления, но дольше окна");
  });
  it("without a window, or before it, it is the alarm it always was, word for word", () => {
    const plain = gapView(gap(1, 4), ctx, [], fmt);
    expect(plain.severity).toBe("critical");
    expect(plain.headline).toBe("Страница защиты не работала 3 мин");
    expect(gapView(gap(-10, 5), ctx, [win(0, 20)], fmt).headline).toBe("Страница защиты не работала 15 мин");
  });
  it("without a guard there are no windows to trust: the alarm stays whatever the windows say", () => {
    const v = gapView({ ...gap(1, 4), mode: "hook" }, { ...ctx, guardModeNow: false }, [win(0, 20)], fmt);
    expect(v.severity).toBe("critical");
    expect(v.plan).toBe("outside");
  });
  it("pauses of one kind are told together: one line, a list under «Подробнее», and what worked and what did not once", () => {
    const lines = [gap(1, 4), gap(30, 43)].map((g) => ({ gap: g, text: gapView(g, ctx, [], fmt) }));
    const [group] = groupGaps(lines, fmt);
    expect(group!.summary).toBe("Страница защиты не работала 2 раза: 3 мин и 13 мин");
    expect(group!.items).toEqual(["t1 — t4: 3 мин", "t30 — t43: 13 мин"]);
    expect(group!.works).toMatch(/^Сторож в это время работал/);
    expect(group!.notWorking).toMatch(/^Не работало/);
    expect(group!.count).toBe(2);
    const one = groupGaps([lines[0]!], fmt)[0]!;
    expect(one.summary).toBe("Страница защиты не работала 3 мин (с t1 по t4)");
    const five = groupGaps([1, 2, 3, 4, 5].map((n) => ({ gap: gap(n * 10, n * 10 + n), text: gapView(gap(n * 10, n * 10 + n), ctx, [], fmt) })), fmt)[0]!;
    expect(five.summary).toBe("Страница защиты не работала 5 раз: 1 мин, 2 мин, 3 мин, 4 мин и 5 мин");
  });
  it("an overrun among the pauses is named in the line", () => {
    const lines = [gap(1, 4), gap(15, 25)].map((g) => ({ gap: g, text: gapView(g, ctx, [win(10, 20)], fmt) }));
    expect(groupGaps(lines, fmt)[0]!.summary).toContain("в том числе во время обновления, но дольше окна");
  });
});

const ovOf = (gaps: Array<GapLike & { at: number }>, maintenance: MaintenanceWindow[], over: { reviewedAts?: number[]; ackedAt?: number | null } = {}): Overview =>
  ({ now: T0 + 100 * MIN, journal: { ok: true }, windows: [], watch: { drifts: [], baselineAt: 1, windows: [] }, guard: { connected: true, maintenance }, alive: { gaps, safeMode: false, safeModeSeen: false, gapsAckedAt: over.ackedAt ?? null, reviewedAts: over.reviewedAts ?? [], coreHolds: false } }) as unknown as Overview;

describe("the page sorts the pauses", () => {
  it("the owner's two updates (3 and 13 min) inside declared windows are calm lines, not an alarm; the strip over bb is silent", () => {
    const ov = ovOf([gap(30, 43), gap(1, 4)], [win(0, 20), win(29, 49)]);
    const s = gapsBySeverity(ov, fmt);
    expect(s.critical).toEqual([]);
    expect(s.calm).toHaveLength(2);
    expect(overlayView(ov, null).alarmLine).toBeNull();
  });
  it("a pause outside every window stays a red alarm next to the calm ones", () => {
    const ov = ovOf([gap(1, 4), gap(60, 62)], [win(0, 20)]);
    const s = gapsBySeverity(ov, fmt);
    expect(s.calm.map((l) => l.gap.at)).toEqual([T0 + 4 * MIN]);
    expect(s.critical.map((l) => l.gap.at)).toEqual([T0 + 62 * MIN]);
  });
  it("a guard that does not answer (no windows known) leaves every pause red", () => {
    const ov = { ...ovOf([gap(1, 4)], []), guard: { connected: false, maintenance: [] } } as unknown as Overview;
    expect(gapsBySeverity(ov, fmt).critical).toHaveLength(1);
  });
});

describe("«Я проверил»", () => {
  const setup = () => {
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    const clock = { t: T0 };
    const store = new Store(db, () => clock.t);
    const alive = new Alive({ store, now: () => clock.t, safeMode: async () => false, guardMode: true });
    return { store, clock, alive };
  };
  /** Two pauses, found at two starts. */
  async function twoGaps(h: ReturnType<typeof setup>): Promise<number[]> {
    const ats: number[] = [];
    await h.alive.start();
    for (const minutes of [3, 13]) {
      h.clock.t += GAP_THRESHOLD_MS + minutes * MIN;
      ats.push((await h.alive.start())!.at);
      h.clock.t += 1000;
    }
    return ats;
  }
  const handlers = (h: ReturnType<typeof setup>, factor: { ok: (code: string) => boolean }) =>
    pageRpc({
      alive: h.alive,
      guardLink: null,
      changed: () => undefined,
      gate: {
        touch: (_purpose: string, code: string) => {
          if (!factor.ok(code)) throw new GateError("invalid_code", "wrong code");
        },
      },
      needCode: (code: string | undefined) => {
        if (code === undefined) throw new GateError("invalid_code", "a code is needed");
        return code;
      },
      proofOf: (code: string | undefined, passkey: unknown) => (passkey !== undefined ? { passkey } : code),
      wrap: <A, R>(fn: (i: A) => R) => fn,
    } as never) as unknown as { "alive.review": (i: { ats: number[]; code?: string }) => Promise<{ ok: true; reviewed: number }> };

  it("without a code nothing is hidden, with a wrong one nothing is hidden", async () => {
    const h = setup();
    const ats = await twoGaps(h);
    const rpc = handlers(h, { ok: (c) => c === "123456" });
    await expect(rpc["alive.review"]({ ats })).rejects.toThrow(/code/);
    await expect(rpc["alive.review"]({ ats, code: "000000" })).rejects.toThrow(/wrong code/);
    expect(h.alive.view().reviewedAts).toEqual([]);
  });
  it("with the code exactly the named pauses are confirmed; the journal says when and with what; the pauses stay in the journal", async () => {
    const h = setup();
    const [first, second] = await twoGaps(h);
    const rpc = handlers(h, { ok: (c) => c === "123456" });
    expect(await rpc["alive.review"]({ ats: [first!], code: "123456" })).toEqual({ ok: true, reviewed: 1 });
    expect(h.alive.view().reviewedAts).toEqual([first]);
    const rec = h.store.listLog(50).filter((l) => l.kind === "gate.gap.review");
    expect(rec).toHaveLength(1);
    expect(rec[0]!.detail).toMatchObject({ ats: [first], via: "code" });
    expect(h.store.listLog(50).filter((l) => l.kind === "gate.gap")).toHaveLength(2);
    expect(h.alive.view().gaps.map((g) => g.at).sort()).toEqual([first, second].sort());
    // a number nobody has (not a pause of this journal) confirms nothing
    expect(await rpc["alive.review"]({ ats: [12345], code: "123456" })).toEqual({ ok: true, reviewed: 0 });
    expect(h.alive.view().reviewedAts).toEqual([first]);
  });
  it("what is confirmed is not red any more, the other pause still is, and a NEW pause is red again", async () => {
    const h = setup();
    const [first, second] = await twoGaps(h);
    const rpc = handlers(h, { ok: () => true });
    await rpc["alive.review"]({ ats: [first!], code: "1" });
    const ovNow = () => ({ ...ovOf(h.alive.view().gaps as never, [], { reviewedAts: h.alive.view().reviewedAts }), now: h.clock.t }) as Overview;
    expect(gapsBySeverity(ovNow(), fmt).critical.map((l) => l.gap.at)).toEqual([second]);
    await rpc["alive.review"]({ ats: [second!], code: "1" });
    expect(gapsBySeverity(ovNow(), fmt).critical).toEqual([]);
    expect(overlayView(ovNow(), null).alarmLine).toBeNull();
    h.clock.t += GAP_THRESHOLD_MS + 5 * MIN;
    const third = (await h.alive.start())!.at;
    expect(gapsBySeverity(ovNow(), fmt).critical.map((l) => l.gap.at)).toEqual([third]);
    expect(overlayView(ovNow(), null).alarmLine).toBe("Тревога: защита не работала 6 мин");
  });
});
