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
    expect(kinds(r)).toEqual(expect.arrayContaining(["ui", "sdk_read", "sdk_meta", "sdk_agents"]));
    // `lastAssistantText` of a thread.idle handler is what the agent said: it is a read of the conversation, too
    expect(detail(r, "sdk_read")).toEqual(["event.lastAssistantText", "threads.output", "threads.timeline"]);
    expect(detail(r, "sdk_meta")).toEqual(expect.arrayContaining(["events.on:thread.idle", "threads.get"]));
    expect(detail(r, "sdk_agents")).toEqual(["threads.archive", "threads.spawn", "threads.stop"]);
    expect(r.capabilities.length).toBeGreaterThan(1); // the gate's safe class is «no capabilities at all»
  });
  it("is never called safe, and says what it does in words", async () => {
    const r = await fixture("sdk-threads-read-spawn");
    const h = headline(r);
    expect(h.level).toBe("danger");
    // the checks follow the text to the agent it starts (`threads.spawn`): that is the first, red line
    expect(h.text).toBe("Читает ваши переписки в bb и передаёт запускаемому агенту; может запускать и останавливать агентов; знает названия и состояние ваших тредов (когда агенты начинают и заканчивают)");
    expect(h.text).not.toMatch(/Безопасно|только оформление|ничего не читает/);
  });
});

describe("a plugin that finds a button in the page and clicks it (auto-answer)", () => {
  it("has the right to press bb's buttons, and to answer the agent's questions", async () => {
    const r = await fixture("dom-click-answer");
    expect(kinds(r)).toContain("ui_click");
    expect(detail(r, "ui_click")).toEqual(expect.arrayContaining(["target:answers", "click()", "requestSubmit()"]));
    const h = headline(r);
    expect(h.level).toBe("danger");
    expect(h.text).toBe("Отвечает на вопросы агентов за вас (нажимает кнопки их виджета)");
  });
  it("a click on an element found by selector (no question words) is yellow, in plain words", async () => {
    const r = await app('export default function A() { document.getElementById("go")?.click(); return null; }');
    expect(detail(r, "ui_click")).toEqual(["click()", "target:other"]);
    expect(headline(r)).toEqual({ level: "caution", text: "Может нажимать элементы интерфейса bb" });
    expect(capabilityPhrase({ kind: "ui_click", detail: ["click()"] })).toContain("нажимать элементы интерфейса bb");
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
    expect(detail(c, "sdk_meta")).toEqual(["threads.get"]);
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
    expect(kinds(r)).not.toContain("sdk_meta");
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

describe("names and states of threads are not the conversations", () => {
  it("chime: get, interactions.list and thread.active/idle/failed → yellow, not «читает переписки»", async () => {
    const r = await fixture("chime-sdk");
    expect(kinds(r)).toEqual(expect.arrayContaining(["sdk_meta", "sdk_questions"]));
    expect(kinds(r)).not.toContain("sdk_read");
    expect(detail(r, "sdk_meta")).toEqual(["events.on:thread.active", "events.on:thread.failed", "events.on:thread.idle", "threads.get"]);
    expect(headline(r)).toEqual({ level: "caution", text: "Видит вопросы ваших агентов и никуда не отправляет; знает названия и состояние ваших тредов (когда агенты начинают и заканчивают)" });
    expect(headline(r).text).not.toMatch(/переписк/);
  });
  it("what carries text is a read: timeline, output, message.* and turn.* events, a computed event name is only noted", async () => {
    for (const code of [
      "sdk.threads.timeline({})",
      "sdk.threads.output({})",
      "sdk.threads.search({})",
    ]) expect(kinds(await app(`export default function A({ sdk }: any) { ${code}; return null; }`))).toContain("sdk_read");
    for (const ev of ["message.dispatch", "turn.submit"]) {
      const r = await app("export default function A() { return null; }", `export default function (bb: any) { bb.events.on(${JSON.stringify(ev)}, () => {}); }`);
      expect(kinds(r)).toContain("sdk_read");
    }
    const dyn = await app("export default function A() { return null; }", "export default function (bb: any) { bb.events.on((globalThis as any).name, () => {}); }");
    // a name the code does not give is not a proof of reading text: the lesser right, and a review finding that says the name is computed
    expect(kinds(dyn)).toContain("sdk_meta");
    expect(kinds(dyn)).not.toContain("sdk_read");
    expect(dyn.findings.some((f) => f.rule === "dynamic-access" && f.severity === "review")).toBe(true);
  });
  it("interactions.respond is still answering for the person; list only looks", async () => {
    expect(classifySdkChain("sdk.threads.interactions.list", true)).toEqual({ kind: "sdk_questions", detail: "threads.interactions.list" });
    expect(classifySdkChain("sdk.threads.interactions.respond", true)).toEqual({ kind: "sdk_answer", detail: "threads.interactions.respond" });
  });
});

describe("a repository of several plugins: only the plugin's own code counts", () => {
  const monoDir = (): string => {
    const dir = join(scratch, `mono${n++}`);
    cpSync(join(FIXTURES, "monorepo"), dir, { recursive: true });
    chmodSync(dir, 0o755);
    normalise(dir);
    return dir;
  };
  it("the theme next to a plugin with threads.send is green", async () => {
    const r = await runChecks(monoDir(), { pluginId: "beautiful-theme" });
    expect(kinds(r)).toEqual(["ui"]);
    expect(headline(r)).toEqual({ level: "safe", text: "Безопасно: только оформление — ничего не читает" });
  });
  it("each plugin gets its own rights, not the neighbours'", async () => {
    const dir = monoDir();
    const a = await runChecks(dir, { pluginId: "agentation" });
    expect(kinds(a)).toContain("sdk_send");
    expect(kinds(a)).not.toContain("sdk_read");
    const g = await runChecks(dir, { pluginId: "gh-stack" });
    expect(kinds(g)).toContain("sdk_read");
    expect(kinds(g)).not.toContain("sdk_send");
  });
  it("without an id and with several plugins nothing is cut out (the whole tree counts: the safe side)", async () => {
    expect(kinds(await runChecks(monoDir()))).toEqual(expect.arrayContaining(["sdk_send", "sdk_read"]));
  });
  it("the guard asks with the id too: its run function takes it", async () => {
    const r = await runChecks(monoDir(), { pluginId: "beautiful-theme" });
    expect(r.findings.filter((f) => f.severity !== "info")).toEqual([]);
  });
});

describe("what a press goes for decides what the card says", () => {
  it("a click on a thread's row in the sidebar (notify): opens threads, soft yellow", async () => {
    const r = await fixture("dom-click-nav");
    expect(detail(r, "ui_click")).toEqual(["click()", "target:nav"]);
    expect(headline(r)).toEqual({ level: "caution", text: "Открывает треды и разделы bb за вас" });
    expect(headline(r).text).not.toMatch(/отвечает|вопрос/i);
  });
  it("a click on the Submit button of a question widget: answers for the person", async () => {
    const r = await app('export default function A() { const b = document.querySelector("form button"); if (b?.textContent === "Submit") (b as HTMLElement).click(); return null; }');
    expect(detail(r, "ui_click")).toContain("target:answers");
    expect(headline(r)).toEqual({ level: "danger", text: "Отвечает на вопросы агентов за вас (нажимает кнопки их виджета)" });
  });
  it("a click on an arbitrary selector: may press elements of bb", async () => {
    const r = await fixture("dom-click-other");
    expect(detail(r, "ui_click")).toEqual(["dispatchEvent()", "new MouseEvent()", "target:other"]);
    expect(headline(r)).toEqual({ level: "caution", text: "Может нажимать элементы интерфейса bb" });
  });
  it("the protection's own buttons: red", async () => {
    const r = await app('export default function A() { (document.querySelector("[data-secure-bb-card] button") as HTMLElement).click(); return null; }');
    expect(detail(r, "ui_click")).toContain("target:gate");
    expect(headline(r)).toEqual({ level: "danger", text: "Может нажимать кнопки защиты secure-bb и «Разрешить» за вас" });
  });
  it("a target the code does not show, next to words of approval: red; without them: yellow", async () => {
    const hidden = (extra: string) => `export default function A(p: { sel: string }) { ${extra} (document.querySelector(p.sel) as HTMLElement).click(); return null; }`;
    expect(headline(await app(hidden('const w = "Allow";')))).toMatchObject({ level: "danger" });
    expect(headline(await app(hidden('const w = "Разрешить";')))).toMatchObject({ level: "danger" });
    expect(headline(await app(hidden("")))).toEqual({ level: "caution", text: "Может нажимать элементы интерфейса bb" });
  });
  it("words of approval next to a known harmless target do not make it red", async () => {
    const r = await app('export default function A() { const label = "Allow notifications"; (document.querySelector("[data-sidebar-thread-id]") as HTMLElement).click(); return label; }');
    expect(headline(r)).toEqual({ level: "caution", text: "Открывает треды и разделы bb за вас" });
  });
  it("interactions.respond is still answering", async () => {
    const r = await app("export default function A({ sdk }: any) { sdk.threads.interactions.respond({}); return null; }");
    expect(headline(r).text).toBe("Отвечает на вопросы агентов за вас");
  });
});
