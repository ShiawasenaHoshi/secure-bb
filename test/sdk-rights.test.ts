// Round 5, item 1: the rights a plugin gets from bb's own API and from pressing bb's buttons are counted (by the checks, so by the guard too),
// and «безопасно: только оформление» is said only of a plugin that has none of them.
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runChecks as guardRunChecks } from "../guard/src/checks/index.ts";
import { grown, rightsOf } from "../guard/src/trust.ts";
import { runChecks, type CheckResult } from "../src/checks/index.js";
import { capabilityTokens, newTokens } from "../src/decision.js";
import { classifySdkChain } from "../src/checks/sdk-rights.js";
import { capabilityPhrase, capsWithPaths, riskHeadline } from "../src/ux.js";

const FIXTURES = new URL("./fixtures/", import.meta.url).pathname;
const scratch = realpathSync(mkdtempSync(join(tmpdir(), "sbb-sdk-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
function normalise(dir: string): void {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      chmodSync(p, 0o755);
      normalise(p);
    } else if (e.isFile()) chmodSync(p, 0o644);
  }
}
let n = 0;
async function fixture(name: string): Promise<CheckResult> {
  const dir = join(scratch, `f${n++}-${name}`);
  cpSync(join(FIXTURES, name), dir, { recursive: true });
  chmodSync(dir, 0o755);
  normalise(dir);
  return runChecks(dir);
}
/** A plugin with one app file. */
async function app(code: string, server?: string): Promise<CheckResult> {
  const dir = join(scratch, `t${n++}`);
  mkdirSync(dir, { mode: 0o755 });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t", bb: { app: "./app.tsx", ...(server ? { server: "./server.ts" } : {}) } }), { mode: 0o644 });
  writeFileSync(join(dir, "app.tsx"), code, { mode: 0o644 });
  if (server) writeFileSync(join(dir, "server.ts"), server, { mode: 0o644 });
  return runChecks(dir);
}
const kinds = (r: CheckResult): string[] => r.capabilities.map((c) => c.kind);
const detail = (r: CheckResult, kind: string): string[] => r.capabilities.find((c) => c.kind === kind)?.detail ?? [];
const headline = (r: CheckResult) => riskHeadline(capsWithPaths(r), r.findings.filter((f) => f.severity === "review").map((f) => f.rule));

describe("a plugin that reads threads and starts agents (bb-recap)", () => {
  it("is not the safe class: reads conversations, starts, stops and archives agents", async () => {
    const r = await fixture("sdk-threads-read-spawn");
    expect(kinds(r)).toEqual(expect.arrayContaining(["ui", "sdk_read", "sdk_agents"]));
    expect(detail(r, "sdk_read")).toEqual(expect.arrayContaining(["events.on", "threads.get", "threads.output", "threads.timeline"]));
    expect(detail(r, "sdk_agents")).toEqual(["threads.archive", "threads.spawn", "threads.stop"]);
    expect(r.capabilities.length).toBeGreaterThan(1); // the gate's safe class is «no capabilities at all»
  });
  it("is never called safe, and says what it does in words", async () => {
    const r = await fixture("sdk-threads-read-spawn");
    const h = headline(r);
    expect(h.level).toBe("danger");
    expect(h.text).toBe("Может запускать и останавливать агентов; читает ваши переписки в bb");
    expect(h.text).not.toMatch(/Безопасно|только оформление|ничего не читает/);
  });
});

describe("a plugin that finds a button in the page and clicks it (auto-answer)", () => {
  it("has the right to press bb's buttons, and to answer the agent's questions", async () => {
    const r = await fixture("dom-click-answer");
    expect(kinds(r)).toContain("ui_click");
    expect(detail(r, "ui_click")).toEqual(expect.arrayContaining(["agent-prompts", "click()", "requestSubmit()"]));
    const h = headline(r);
    expect(h.level).toBe("danger");
    expect(h.text).toBe("Нажимает кнопки в интерфейсе bb и отвечает на вопросы агентов за вас");
  });
  it("a click on an element found by selector (no question words) is yellow, in plain words", async () => {
    const r = await app('export default function A() { document.getElementById("go")?.click(); return null; }');
    expect(detail(r, "ui_click")).toEqual(["click()"]);
    expect(headline(r)).toEqual({ level: "caution", text: "Нажимает кнопки в интерфейсе bb за вас" });
    expect(capabilityPhrase({ kind: "ui_click", detail: ["click()"] })).toContain("нажимать кнопки в интерфейсе bb за вас");
  });
  it("dispatchEvent with a hand-made event counts as a press", async () => {
    const r = await app('export default function A() { const b = document.querySelector(".x"); b?.dispatchEvent(new MouseEvent("click", { bubbles: true })); return null; }');
    expect(detail(r, "ui_click")).toEqual(expect.arrayContaining(["dispatchEvent()", "new MouseEvent()"]));
  });
  it("a press without any lookup of the page's elements is not the right (the plugin's own ref)", async () => {
    const r = await app("import { useRef } from 'react'; export default function A() { const r = useRef<HTMLInputElement>(null); return <button onClick={() => r.current?.click()} />; }");
    expect(kinds(r)).not.toContain("ui_click");
  });
});

describe("a theme with none of that stays green", () => {
  it("own markup, own ref, no sdk, no lookups: only «ui»", async () => {
    const r = await fixture("theme-only");
    expect(kinds(r)).toEqual(["ui"]);
    expect(r.findings.filter((f) => f.severity !== "info")).toEqual([]);
    expect(headline(r)).toEqual({ level: "safe", text: "Безопасно: только оформление — ничего не читает" });
  });
});

describe("what else of bb's API counts", () => {
  it("send / message / queuedMessages.create write as the person", async () => {
    const r = await app("import { useSdk } from '@get-bb/plugin-sdk/app'; export default function A() { const s = useSdk(); s.threads.send({}); s.threads.queuedMessages.create({}); return null; }");
    expect(detail(r, "sdk_send")).toEqual(["threads.queuedMessages.create", "threads.send"]);
    expect(headline(r)).toEqual({ level: "danger", text: "Отправляет сообщения от вашего имени" });
  });
  it("interactions.respond answers the agent's questions", async () => {
    const r = await app("export default function A({ sdk }: any) { sdk.threads.interactions.respond({}); return null; }");
    expect(detail(r, "sdk_answer")).toEqual(["threads.interactions.respond"]);
    expect(headline(r).text).toBe("Отвечает на вопросы агентов за вас");
  });
  it("setting bb up: machine variables, installing and enabling plugins", async () => {
    const r = await app("export default function A({ sdk }: any) { sdk.system.setMachineEnvironmentVariable({}); sdk.plugins.enable({}); sdk.plugins.list(); return null; }");
    expect(detail(r, "sdk_settings")).toEqual(["plugins.enable", "system.setMachineEnvironmentVariable"]);
    expect(headline(r)).toEqual({ level: "danger", text: "Меняет настройки bb" });
  });
  it("sdk files and terminals are files and programs", async () => {
    const r = await app("export default function A({ sdk }: any) { sdk.files.write({}); sdk.terminals.input({}); return null; }");
    expect(kinds(r)).toEqual(expect.arrayContaining(["fs", "child_process"]));
  });
  it("aliases are followed: const { threads } = sdk; const { spawn } = sdk.threads; const t = bb.sdk.threads", async () => {
    const a = await app("export default function A({ sdk }: any) { const { threads } = sdk; threads.spawn({}); return null; }");
    expect(detail(a, "sdk_agents")).toEqual(["threads.spawn"]);
    const b = await app("export default function A({ sdk }: any) { const { stop } = sdk.threads; stop({}); return null; }");
    expect(detail(b, "sdk_agents")).toEqual(["threads.stop"]);
    const c = await app("export default function A(bb: any) { const t = bb.sdk.threads; t.get({}); t.get.call(t, {}); return null; }");
    expect(detail(c, "sdk_read")).toEqual(["threads.get"]);
  });
  it("a computed method on the threads API is a review finding and the widest right", async () => {
    const r = await app("export default function A({ sdk }: any) { const m = (window as any).m; sdk.threads[m]({}); return null; }");
    expect(detail(r, "sdk_agents")).toEqual(["threads[?]"]);
    expect(r.findings.some((f) => f.rule === "dynamic-access" && f.severity === "review")).toBe(true);
  });
  it("a Map or an array named «threads» is not the SDK", async () => {
    const r = await app("export default function A() { const threads = new Map<string, number>(); threads.get('a'); threads.delete('a'); const state = { threads: [] as number[] }; state.threads.list; return null; }");
    expect(kinds(r)).toEqual(["ui"]);
  });
  it("a lifecycle event that is not about conversations is not a read", async () => {
    const r = await app("export default function A() { return null; }", "export default function (bb: any) { bb.events.on('plugins-changed', () => {}); }");
    expect(kinds(r)).not.toContain("sdk_read");
  });
  it("an unknown call into the threads API is a review finding, not silence", async () => {
    const r = await app("export default function A({ sdk }: any) { sdk.threads.teleport({}); return null; }");
    expect(r.findings.some((f) => f.rule === "sdk-unclassified" && f.severity === "review")).toBe(true);
  });
  it("harmless sidebar calls give no right", () => {
    for (const c of ["sdk.threads.markRead", "sdk.threads.pin", "sdk.threads.open", "sdk.theme.set"]) expect(classifySdkChain(c, true)).toBeNull();
  });
});

describe("the guard counts the same rights (one checks module)", () => {
  it("the plugin and the guard run the very same function", () => {
    expect(guardRunChecks).toBe(runChecks);
  });
  it("a new right in a new version is a new capability: a window holds it", async () => {
    const old = await fixture("theme-only");
    const now = await fixture("sdk-threads-read-spawn");
    expect(newTokens(now, capabilityTokens(old))).toEqual(expect.arrayContaining(["sdk_agents", "sdk_agents:threads.spawn", "sdk_read"]));
    expect(newTokens(old, capabilityTokens(now))).toEqual([]);
  });
  it("the guard's own comparison with the approved ancestor (a trusted source passes only with the same rights) sees them as new", async () => {
    const old = await fixture("theme-only");
    const now = await fixture("sdk-threads-read-spawn");
    const g = grown(rightsOf(old), rightsOf(now));
    expect(g.tokens).toEqual(expect.arrayContaining(["sdk_read", "sdk_agents", "sdk_agents:threads.spawn"]));
    expect(grown(rightsOf(now), rightsOf(old)).tokens).toEqual([]);
  });
});
