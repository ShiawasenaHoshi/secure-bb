// @vitest-environment jsdom
// The whole page drawn from a real overview of the plugin (over the fake host), with three versions waiting: the header says one thing, the three cards
// carry a level badge and their rights as rows, no card has a code field, the summary does not repeat what waits, and the tabs have their new names.
import { act } from "react";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { loadPluginApp, renderSlot } from "@get-bb/plugin-sdk/testing/app";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import plugin from "../server.js";
import type { Overview } from "../src/overview";
import { CLEAN } from "./support/checks";

vi.setConfig({ testTimeout: 20_000 }); // the first draw of the page compiles a lot of modules

// jsdom has none of these; the host's overlays ask for them.
beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  window.matchMedia ??= ((query: string) => ({ matches: false, media: query, onchange: null, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false })) as never;
  (globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} };
  Element.prototype.scrollIntoView ??= () => undefined;
});

// A page of the plugin is its own React world; the scroll lock of the radix dialog uses a second copy of React, so it is a pass-through here.
vi.mock("react-remove-scroll", () => ({ RemoveScroll: ({ children }: { children: unknown }) => children }));

const mounted: Array<{ lifecycle: { unmount(): void } }> = [];
afterEach(() => {
  for (const m of mounted.splice(0)) m.lifecycle.unmount();
  document.body.innerHTML = "";
});

async function overviewWithThreeWaiting(): Promise<Overview> {
  const dataDir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-page-")));
  const { bb, harness } = createFakePluginHost({ pluginId: "secure-bb", experimental_dataDir: dataDir } as never);
  await plugin(bb);
  const base = (await harness.behavior.callRpc("overview", null)) as Overview;
  const names = ["auto-answer", "chime", "notify"];
  const queue = names.map((pluginId, i) => ({ id: i + 1, kind: "hook" as const, contentHash: `h${i}`, pluginId, version: "0.1.0", source: `github.com/someone/bb-plugin-${pluginId}`, sourceKind: "git", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: null, threadId: null, proposalId: null, status: "held" as const, reason: "plugin from an unknown source", firstSeen: base.now - 60_000, lastSeen: base.now - 60_000 }));
  const caps = (kind: string): never => ({ ...CLEAN, capabilities: [{ kind, detail: [], sites: [{ file: "app.tsx", line: 1 }] }] }) as never;
  return {
    ...base,
    queue,
    // what the journal says happened: the three holds (these wait: the cards are the place for them), and one version that passed by itself
    log: [
      ...names.map((pluginId, i) => ({ id: 10 + i, ts: base.now - 50_000, kind: "hold", pluginId, contentHash: `h${i}`, detail: { reason: "plugin from an unknown source" } })),
      { id: 20, ts: base.now - 40_000, kind: "approved.source", pluginId: "figma-sync", contentHash: "f1", detail: { why: "прошла сама: свой источник" } },
    ],
    queueChecks: { 1: caps("sdk_answer"), 2: caps("child_process"), 3: caps("sdk_read") },
    ux: Object.fromEntries(queue.map((q) => [q.id, { why: null, chain: [], level: "unknown", entry: null, sourceLabel: q.source }])),
    // a registered second factor: the page offers the decisions
    totp: { ...base.totp, state: "locked" },
  } as Overview;
}

async function drawPage(ov: Overview | (() => Overview), waitFor = "Ждут вашего решения: 3", rpc: Record<string, (i: unknown) => unknown> = {}) {
  const app = await loadPluginApp(() => import("../app"));
  const slot = renderSlot(app.navPanels[0]!, { subPath: "" }, { rpc: { overview: () => (typeof ov === "function" ? ov() : ov), "page.ping": () => null, ...rpc } as never });
  mounted.push(slot);
  // the overview arrives after the first draw
  await act(async () => void (await new Promise((r) => setTimeout(r, 300))));
  await act(async () => void (await slot.findByText(waitFor, {}, { timeout: 2500 })));
  return slot;
}

const typeCode = async (code: string) => {
  const input = document.body.querySelector('input[autocomplete="one-time-code"]') as HTMLInputElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, code);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => void (await new Promise((r) => setTimeout(r, 50))));
};
const flush = async (ms = 100) => act(async () => void (await new Promise((r) => setTimeout(r, ms))));

describe("the page, drawn", () => {
  it("one state in the header, three cards with a level and rights as rows, no code field on a card, tabs with the new names", async () => {
    const ov = await overviewWithThreeWaiting();
    await drawPage(ov);
    const text = document.body.textContent ?? "";
    // 1. one line of state; the old three-fold repetition is gone
    expect(text).not.toContain("Требует внимания (3)");
    expect(text.match(/ждут? вашего решения/gi)).toHaveLength(1); // the header's line; not the summary, not the cards
    const away = document.body.querySelector("[data-secure-bb-away]");
    expect(away).not.toBeNull(); // there is something quiet to tell: a version of figma-sync passed by itself
    expect(away?.textContent).toMatch(/figma-sync/);
    await act(async () => (away!.querySelector("button[aria-expanded]") as HTMLButtonElement).click()); // opened: the whole list
    expect(document.body.querySelector("[data-secure-bb-away]")?.querySelectorAll("li").length).toBeGreaterThan(0);
    expect(document.body.querySelector("[data-secure-bb-away]")?.textContent ?? "").not.toMatch(/auto-answer|chime|notify|ждёт|ждут/);
    // 2. three cards: level badge, rights rows, no code field
    const cards = Array.from(document.body.querySelectorAll("[data-secure-bb-card]"));
    expect(cards).toHaveLength(3);
    for (const c of cards) {
      expect(c.querySelector("[data-secure-bb-level]")).not.toBeNull();
      expect(c.querySelector("[data-secure-bb-rights] li")).not.toBeNull();
      expect(c.querySelector("input")).toBeNull();
    }
    // 4. tabs
    const tabs = Array.from(document.body.querySelectorAll('[role="tab"]')).map((t) => t.textContent);
    expect(tabs.map((t) => t?.replace(/\d+$/, ""))).toEqual(["Обзор", "Карантин", "Доверие и исключения", "Журнал"]);
  });

  it("«Разрешить» opens the confirmation dialog for that version instead of asking for a code on the card", async () => {
    const ov = await overviewWithThreeWaiting();
    await drawPage(ov);
    const approve = Array.from(document.body.querySelectorAll("button")).find((b) => /^(Разрешить|Включить) chime 0\.1\.0$/.test(b.textContent ?? ""));
    expect(approve).toBeDefined();
    await act(async () => approve!.click());
    const what = document.body.querySelector("[data-secure-bb-confirm-what]");
    expect(what?.textContent).toMatch(/chime 0\.1\.0/);
    expect(document.body.querySelector('input[autocomplete="one-time-code"]')).not.toBeNull();
  });

  it("after «Разрешить»: ONE short line in the card's place, no empty frame, no second plate, the focus on the line", async () => {
    let ov = await overviewWithThreeWaiting();
    const approved: unknown[] = [];
    await drawPage(() => ov, "Ждут вашего решения: 3", {
      "queue.approve": (i) => {
        approved.push(i);
        ov = { ...ov, queue: ov.queue.filter((q) => q.id !== (i as { id: number }).id) };
        return { ok: true };
      },
    });
    const approve = Array.from(document.body.querySelectorAll("button")).find((b) => /^(Разрешить|Включить) chime 0\.1\.0$/.test(b.textContent ?? ""))!;
    await act(async () => approve.click());
    await typeCode("123456");
    await flush(300);
    expect(approved).toHaveLength(1);
    const rows = Array.from(document.body.querySelectorAll("[data-secure-bb-stub]"));
    expect(rows).toHaveLength(1);
    const row = rows[0] as HTMLElement;
    expect(row.textContent).toContain("Готово: chime 0.1.0 разрешён и включён");
    expect(Array.from(row.querySelectorAll("button")).map((b) => b.textContent)).toContain("Скрыть");
    // the row is a short line: no frame as tall as the card
    expect(row.style.minHeight).toBe("");
    // one message, not three: no toasts, no «Разрешено: плагин …» plate
    expect(document.body.querySelector("[data-secure-bb-toast]")).toBeNull();
    expect(document.body.textContent).not.toContain("Разрешено: плагин");
    expect((document.body.textContent ?? "").split("разрешён и включён")).toHaveLength(2);
    // the keyboard stays where the person was: on the line
    expect(document.activeElement).toBe(row);
    // «Скрыть» takes the line away
    await act(async () => (Array.from(row.querySelectorAll("button")).find((b) => b.textContent === "Скрыть") as HTMLButtonElement).click());
    expect(document.body.querySelector("[data-secure-bb-stub]")).toBeNull();
  });

  it("no second factor: the header asks for it (an alarm, not a calm line), with a button; the summary does not carry it", async () => {
    const ov = await overviewWithThreeWaiting();
    const slot = await drawPage({ ...ov, totp: { ...ov.totp, state: "none" } } as Overview, "Настройте второй фактор: без него ничего нельзя подтвердить");
    const status = document.body.querySelector("[data-secure-bb-status]") as HTMLElement;
    expect(status.getAttribute("data-secure-bb-alarm-alert")).not.toBeNull();
    expect(Array.from(status.querySelectorAll("button")).map((b) => b.textContent)).toContain("Настроить");
    expect(document.body.querySelector("[data-secure-bb-away]")?.textContent ?? "").not.toContain("Второй фактор");
    void slot;
  });

  it("the session that cannot be opened is one short state in the header; the reason is behind «почему?»", async () => {
    const ov = await overviewWithThreeWaiting();
    const reason = "Сессия недоступна, пока работает плагин chime не из ваших источников: его код мог бы её перехватить.";
    await drawPage({ ...ov, sessionBlockers: [{ id: "chime", foreign: true, ui: true }] } as Overview);
    const header = document.body.querySelector("[data-secure-bb-status]") as HTMLElement;
    expect(header.textContent).toContain("Сессия: недоступна");
    expect(header.textContent).not.toContain("его код мог бы");
    const why = Array.from(header.querySelectorAll("button")).find((b) => b.textContent === "почему?")!;
    await act(async () => why.click());
    expect(document.body.textContent).toContain("chime");
    expect(document.body.textContent).toMatch(/Сессия подтверждения/);
    void reason;
  });

  it("the shield is in the line of the sentence; the source chip is cut with an ellipsis; a version that waits is one line in «Под защитой»", async () => {
    const ov = await overviewWithThreeWaiting();
    await drawPage({ ...ov, plugins: ov.queue.map((q) => ({ id: q.pluginId, version: q.version, status: "disabled", statusDetail: null, enabled: false, source: q.source, pin: null, history: [], window: null, frozenPin: false, unreviewedBaseline: false, threadId: null })) } as unknown as Overview);
    const text = document.body.querySelector("[data-secure-bb-status-text]") as HTMLElement;
    expect(text.previousElementSibling?.getAttribute("data-secure-bb-shield")).not.toBeNull(); // the icon and the sentence are in one row
    for (const chip of Array.from(document.body.querySelectorAll("[data-secure-bb-source]"))) expect(chip.className).toMatch(/\btruncate\b/);
    const rows = Array.from(document.body.querySelectorAll("[data-protected-plugin]"));
    expect(rows.length).toBe(3);
    for (const r of rows) {
      expect(r.textContent).toContain("ждёт решения · к карточке");
      expect(r.textContent).not.toMatch(/Откуда|версия не одобрена/);
    }
  });

  it("«Под защитой»: the status of a plugin is the one of ITS id in the newest data, whatever order the rows come in between two draws", async () => {
    const ov = await overviewWithThreeWaiting();
    const plugin = (id: string, status: string, statusDetail: string | null, pinned: boolean) => ({ id, version: "0.1.0", status, statusDetail, enabled: status === "running", source: `github.com/someone/bb-plugin-${id}`, pin: pinned ? { id: 1, via: "touch", version: "0.1.0", approvedAt: ov.now, why: null } : null, history: [], window: null, frozenPin: false, unreviewedBaseline: false, threadId: null });
    const held = "held by activation guard";
    // before: both wait. after the decision on chime: chime runs, auto-answer is held; the plugins come back in the OTHER order
    const before = { ...ov, queue: ov.queue.filter((q) => q.pluginId !== "notify"), plugins: [plugin("auto-answer", "disabled", held, false), plugin("chime", "disabled", held, false)] };
    const after = { ...ov, queue: ov.queue.filter((q) => q.pluginId === "auto-answer"), plugins: [plugin("chime", "running", null, true), plugin("auto-answer", "disabled", held, false)] };
    let current: Overview = before as unknown as Overview;
    const slot = await drawPage(() => current, "Ждут вашего решения: 2");
    const pairs = () => Object.fromEntries(Array.from(document.body.querySelectorAll("[data-protected-plugin]")).map((r) => [r.getAttribute("data-protected-plugin"), r.querySelector("[data-secure-bb-standing]")?.textContent]));
    expect(pairs()).toEqual({ "auto-answer": "ждёт вашего решения", chime: "ждёт вашего решения" });
    current = after as unknown as Overview;
    await act(async () => void (await slot.behavior.emitRealtime("changed", null)));
    await flush(300);
    expect(pairs()).toEqual({ chime: "работает", "auto-answer": "ждёт вашего решения" });
    // and back to the first order, a third draw: the pair name → status follows the data, not the place
    current = { ...after, plugins: [...(after.plugins as unknown[]).reverse()] } as unknown as Overview;
    await act(async () => void (await slot.behavior.emitRealtime("changed", null)));
    await flush(300);
    expect(pairs()).toEqual({ chime: "работает", "auto-answer": "ждёт вашего решения" });
  });

  it("an older overview that arrives late never replaces a newer one", async () => {
    const ov = await overviewWithThreeWaiting();
    const newer = { ...ov, queue: ov.queue.slice(0, 2), ux: ov.ux } as Overview;
    let calls = 0;
    const app = await loadPluginApp(() => import("../app"));
    const slot = renderSlot(app.navPanels[0]!, { subPath: "" }, {
      rpc: {
        // the first answer (3 waiting) is slow; the second one (2 waiting) is quick
        overview: async () => (++calls === 1 ? (await new Promise((r) => setTimeout(r, 600)), ov) : newer),
        "page.ping": () => null,
      } as never,
    });
    mounted.push(slot);
    await act(async () => void (await slot.behavior.emitRealtime("changed", null)));
    await flush(1000);
    expect(document.body.textContent).toContain("Ждут вашего решения: 2");
    expect(document.body.textContent).not.toContain("Ждут вашего решения: 3");
  });
});
