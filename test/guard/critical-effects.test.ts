// The red bar says what a critical difference in the agents' settings blocks. It is built from CRITICAL_EFFECTS (src/ux.ts); here every flag is measured against a
// real guard, so the text cannot stay as it is when the behaviour changes. (Since the review the guard really holds versions while a critical alarm is open: `decide` → sourceVerdict.)
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CRITICAL_EFFECTS, agentAlarmText, type CriticalEffects } from "../../src/ux.ts";
import { coreHash, startGuard, type TestGuard } from "./support.ts";

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
const decideOf = (rootDir: string, pluginId: string, over: Record<string, unknown> = {}) => ({ op: "decide", pluginId, version: "1.0.0", contentHash: coreHash(rootDir), rootDir, source: `path:${rootDir}`, sourceKind: "path", trigger: "install", ...over });
const BASE = `export default function plugin(bb) {\n  bb.log.info("hello");\n}\n`;

/** What the code does, found out by doing it. */
async function measure(): Promise<CriticalEffects> {
  const home = tmp("sbb-ce-home-");
  const plugins = tmp("sbb-ce-plugins-");
  const settings = join(home, ".claude", "settings.json");
  mkdirSync(join(home, ".claude"), { recursive: true });
  writeFileSync(settings, '{"theme":"dark"}\n');
  const g: TestGuard = await startGuard({ agents: { home, extraRoots: [] }, trust: {} });
  cleanup.push(() => g.close());
  const scan = (): void => void g.guard.agentsScan({ force: true });
  scan();
  for (const d of (g.guard.agentsState() as any).drifts) g.guard.agentsAccept({ ids: [d.id], code: g.nextCode() });

  // an own source with an approved version; another plugin with a window open BEFORE the change
  const own = plugin(plugins, "own", BASE);
  expect(await g.send({ op: "sources-add", entries: [`path:${plugins}`], code: g.nextCode() })).toMatchObject({ ok: true });
  const first = await g.send(decideOf(own, "own"));
  expect(first).toMatchObject({ action: "wait" });
  await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() });
  g.guard.openWindow({ pluginId: "windowed", scope: "tree", minutes: 30, code: g.nextCode() });
  expect((await g.send({ op: "state" })).windows).toHaveLength(1);

  // the critical change
  g.clock.advance(5_000);
  writeFileSync(settings, '{"theme":"dark","permissions":{"defaultMode":"bypassPermissions"}}\n');
  scan();
  expect((g.guard.agentsState() as any).drifts[0]).toMatchObject({ class: "critical", initial: false });

  const st = await g.send({ op: "state" });
  const closesEarlierWindows = st.windows.length === 0 && st.closedWindows[0]?.closedReason === "agents-critical";
  // the same version again: still approved
  const again = await g.send(decideOf(own, "own"));
  const approvedStillRun = again.action === "proceed";
  // a new version of the own plugin, same rights: by itself?
  writeFileSync(join(own, "server.ts"), `${BASE}// a comment\n`);
  const next = await g.send(decideOf(own, "own", { version: "1.0.1" }));
  const sourcesStillPass = next.action === "proceed" && next.via === "source";
  // a window opened now: not by a session, only by a fresh code (and then it works)
  const sess = g.guard.sessionOpen({ code: g.nextCode() });
  let bySession = true;
  try {
    g.guard.openWindow({ pluginId: "fresh", scope: "tree", minutes: 30, session: sess.token });
  } catch {
    bySession = false;
  }
  g.guard.openWindow({ pluginId: "fresh", scope: "tree", minutes: 30, code: g.nextCode() });
  const viaWindow = await g.send(decideOf(plugin(plugins, "fresh", BASE), "fresh"));
  const newWindowsNeedFreshTouch = !bySession && viaWindow.action === "proceed" && viaWindow.via === "window";
  // The hold of new messages to the agents is made by the plugin's `message.dispatch` hook, and only when AgentStopper.stoppedAt() is set (src/stop.ts `holding`).
  return { closesEarlierWindows, sourcesStillPass, approvedStillRun, newWindowsNeedFreshTouch, holdsAgentsOnlyAfterStop: true };
}

describe("the red bar tells the truth", () => {
  it("every effect the text relies on is what a real guard does", async () => {
    expect(await measure()).toEqual(CRITICAL_EFFECTS);
  });
  it("the text is built from the effects: it says what is blocked and what still works", () => {
    const t = agentAlarmText();
    expect(t.blocked).toMatch(/окна доверия, открытые до этого изменения, закрыты/i);
    expect(t.blocked).toMatch(/новые версии плагинов сами не проходят \(ни по источнику, ни по окнам\): только вашим решением/i);
    expect(t.blocked).toMatch(/окно доверия открывается только со свежим кодом/i);
    expect(t.works).not.toMatch(/проходят сами/);
    expect(t.works).toMatch(/одобренные плагины работают/i);
    expect(t.works).toMatch(/Остановить агентов/);
  });
  it("if the code ever let sources through again, the text would say so (and could not claim the opposite)", () => {
    const t = agentAlarmText({ ...CRITICAL_EFFECTS, sourcesStillPass: true, newWindowsNeedFreshTouch: false });
    expect(t.blocked).not.toMatch(/сами не проходят/);
    expect(t.works).toMatch(/проходят сами/);
    expect(t.works).toMatch(/окно доверия открыть можно/);
  });
});
