// @vitest-environment jsdom
// SecureBB: the shield in bb's chrome says what the header of the page says (one rule, one place), the footer's registration and the entry's badge,
// the page's tabs in their order (Обзор, Карантин, Доверие и исключения, Журнал, Настройки), the saved tab and a saved tab that is no longer a tab,
// and «Журнал» holding events only: every control that changes behaviour is on «Настройки».
import { act } from "react";
import { createRoot } from "react-dom/client";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { loadPluginApp, renderSlot } from "@get-bb/plugin-sdk/testing/app";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import plugin from "../server.js";
import type { Overview } from "../src/overview";
import { headerLine, iconView, registeredOf, summarize, summaryOf, type PageSummary } from "../src/pageview";
import { TAB_KEY, TAB_LABEL, TAB_ORDER, parseTab, planCards } from "../src/ux";
import { heldOf } from "../src/pageview";
import { ShieldStatusIcon } from "../app/status-icon";
import { protectionView, publishStatus } from "../app/status-store";

vi.setConfig({ testTimeout: 20_000 });

// jsdom under this Node has no localStorage (the page's conveniences live there): a plain in-memory one.
const memory = new Map<string, string>();
const storage = { getItem: (k: string) => memory.get(k) ?? null, setItem: (k: string, v: string) => void memory.set(k, String(v)), removeItem: (k: string) => void memory.delete(k), clear: () => memory.clear() };

beforeAll(() => {
  Object.defineProperty(window, "localStorage", { value: storage, configurable: true });
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  window.matchMedia ??= ((query: string) => ({ matches: false, media: query, onchange: null, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false })) as never;
  (globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} };
  Element.prototype.scrollIntoView ??= () => undefined;
});
vi.mock("react-remove-scroll", () => ({ RemoveScroll: ({ children }: { children: unknown }) => children }));

const mounted: Array<{ lifecycle: { unmount(): void } }> = [];
beforeEach(() => window.localStorage.clear());
afterEach(() => {
  for (const m of mounted.splice(0)) m.lifecycle.unmount();
  document.body.innerHTML = "";
  publishStatus(null);
});

async function baseOverview(): Promise<Overview> {
  const dataDir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-sidebar-")));
  const { bb, harness } = createFakePluginHost({ pluginId: "secure-bb", experimental_dataDir: dataDir } as never);
  await plugin(bb);
  const base = (await harness.behavior.callRpc("overview", null)) as Overview;
  return { ...base, totp: { ...base.totp, state: "locked" } } as Overview;
}

/** Two versions that wait, as the page-render test builds them. */
async function waitingOverview(): Promise<Overview> {
  const base = await baseOverview();
  const queue = ["chime", "notify"].map((pluginId, i) => ({ id: i + 1, kind: "hook" as const, contentHash: `h${i}`, pluginId, version: "0.1.0", source: `github.com/someone/bb-plugin-${pluginId}`, sourceKind: "git", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: null, threadId: null, proposalId: null, status: "held" as const, reason: "plugin from an unknown source", firstSeen: base.now - 60_000, lastSeen: base.now - 60_000 }));
  return { ...base, queue, ux: Object.fromEntries(queue.map((q) => [q.id, { why: null, chain: [], level: "unknown", entry: null, sourceLabel: q.source }])) } as Overview;
}

const alarmOverview = async (): Promise<Overview> => {
  const base = await baseOverview();
  return { ...base, totp: { ...base.totp, state: "none" } };
};

describe("the shield's status is the header's: one rule", () => {
  it("all is well: calm, no badge; the sentence is the header's", async () => {
    const ov = await baseOverview();
    const v = protectionView(ov);
    expect(v.tone).toBe("ok");
    expect(v.badge).toBeNull();
    expect(v.text).toBe(summaryOf(ov, { deferred: [], kept: [] }).header.text);
    expect(v.text).toBe("Всё под защитой");
  });

  it("something waits: a warning badge with the number of cards, the tooltip says the header's sentence", async () => {
    const ov = await waitingOverview();
    const v = protectionView(ov);
    expect(v.tone).toBe("waiting");
    expect(v.badge).toEqual({ tone: "warning", count: 2, label: "Ждут вашего решения: 2" });
    expect(v.text).toBe("Ждут вашего решения: 2");
  });

  it("an alarm: destructive, a dot (no number), the sentence is the header's alarm line", async () => {
    const ov = await alarmOverview();
    const v = protectionView(ov);
    expect(v.tone).toBe("alarm");
    expect(v.badge).toEqual({ tone: "critical", label: v.text });
    expect(v.text).toBe("Настройте второй фактор: без него ничего нельзя подтвердить");
  });

  it("the icon is made from the very summary the page draws: for every state the text is summarize(...).header.text", async () => {
    for (const ov of [await baseOverview(), await waitingOverview(), await alarmOverview()]) {
      const decisions = { deferred: [], kept: [] };
      const pageSummary: PageSummary = summarize(ov, planCards(heldOf(ov), decisions), registeredOf(ov));
      expect(iconView(pageSummary).text).toBe(pageSummary.header.text);
      expect(protectionView(ov).text).toBe(pageSummary.header.text);
      expect(headerLine).toBeTypeOf("function");
    }
  });

  it("what the person put aside on this page counts as the header counts it", async () => {
    const ov = await waitingOverview();
    const h = heldOf(ov)[0]!;
    window.localStorage.setItem("secure-bb.deferred", JSON.stringify([`${h.pluginId}|${h.contentHash}|${h.id}@${Date.now()}`]));
    const fromMarks = protectionView(ov).text;
    expect(fromMarks).toMatch(/^(Ждут вашего решения: \d|Отложено вами: \d)/);
  });
});

describe("the registrations: the footer of the sidebar, the glyph, the badge of the entry", () => {
  it("the footer holds one item, named SecureBB, with the registered glyph; the entry is called SecureBB with a live badge", async () => {
    const app = await loadPluginApp(() => import("../app"));
    expect(app.experimentalSidebarFooterItems.map((i) => ({ id: i.id, label: i.label, icon: i.icon, kind: i.kind }))).toEqual([{ id: "status", label: "SecureBB", icon: "secure-bb-shield", kind: "disclosure" }]);
    expect(app.icons.map((i) => i.name)).toEqual(["secure-bb-shield"]);
    const panel = app.navPanels[0]!;
    expect(panel).toMatchObject({ id: "gate", title: "SecureBB", icon: "secure-bb-shield", path: "gate" });
    expect(typeof panel.experimental_useBadge).toBe("function");
  });

  it("the glyph draws the state: check when calm, the number waiting, an alert when it is an alarm", async () => {
    const draw = async () => {
      const host = document.createElement("div");
      document.body.append(host);
      const root = createRoot(host);
      await act(async () => root.render(<ShieldStatusIcon className="size-4" />));
      return { host, root };
    };
    const { host, root } = await draw();
    expect(host.querySelector("[data-secure-bb-sidebar-icon]")?.getAttribute("data-secure-bb-sidebar-icon")).toBe("unknown");
    await act(async () => publishStatus(protectionView(await baseOverview())));
    expect(host.querySelector('[data-secure-bb-shield="check"]')).not.toBeNull();
    expect(host.querySelector("[data-secure-bb-sidebar-badge]")).toBeNull();
    await act(async () => publishStatus(protectionView(await waitingOverview())));
    expect(host.querySelector("[data-secure-bb-sidebar-badge='warning']")?.textContent).toBe("2");
    await act(async () => publishStatus(protectionView(await alarmOverview())));
    expect(host.querySelector('[data-secure-bb-shield="alert"]')).not.toBeNull();
    expect(host.querySelector("[data-secure-bb-sidebar-badge='critical']")).not.toBeNull();
    await act(async () => root.unmount());
  });
});

async function drawPage(ov: Overview, waitFor: string) {
  const app = await loadPluginApp(() => import("../app"));
  const slot = renderSlot(app.navPanels[0]!, { subPath: "" }, { rpc: { overview: () => ov, "page.ping": () => null } as never });
  mounted.push(slot);
  await act(async () => void (await new Promise((r) => setTimeout(r, 300))));
  await act(async () => void (await slot.findByText(waitFor, {}, { timeout: 2500 })));
  return slot;
}

const tabButtons = (): HTMLElement[] => Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]'));
const tabNamed = (name: string): HTMLElement => tabButtons().find((t) => (t.textContent ?? "").replace(/\d+$/, "") === name)!;
const openTab = async (name: string) => {
  await act(async () => tabNamed(name).click());
  await act(async () => void (await new Promise((r) => setTimeout(r, 50))));
};
const selectedTab = (): string => (tabButtons().find((t) => t.getAttribute("aria-selected") === "true")?.textContent ?? "").replace(/\d+$/, "");

describe("the tabs", () => {
  it("their order and words; the title of the page is SecureBB", async () => {
    expect(TAB_ORDER.map((t) => TAB_LABEL[t])).toEqual(["Обзор", "Карантин", "Доверие и исключения", "Журнал", "Настройки"]);
    await drawPage(await baseOverview(), "Всё под защитой");
    expect(document.body.querySelector("h1")?.textContent).toBe("SecureBB");
    expect(document.body.textContent).not.toMatch(/Статус защиты secure-bb/);
  });

  it("a saved tab that is no longer a tab (an older page's «more», anything else) opens «Обзор»; a saved tab that exists is opened", () => {
    expect(parseTab(null)).toBe("status");
    expect(parseTab("more")).toBe("status");
    expect(parseTab("")).toBe("status");
    expect(parseTab("<script>")).toBe("status");
    for (const t of TAB_ORDER) expect(parseTab(t)).toBe(t);
  });

  it("the page opens on the saved tab, and remembers the one it was left on", async () => {
    window.localStorage.setItem(TAB_KEY, "more");
    await drawPage(await baseOverview(), "Всё под защитой");
    expect(selectedTab()).toBe("Обзор");
    await openTab("Настройки");
    expect(window.localStorage.getItem(TAB_KEY)).toBe("settings");
    mounted.pop()!.lifecycle.unmount();
    document.body.innerHTML = "";
    await drawPage(await baseOverview(), "Защита и второй фактор");
    expect(selectedTab()).toBe("Настройки");
  });
});

describe("«Журнал» holds events only; behaviour is changed on «Настройки»", () => {
  const headings = (root: Element, sel: string) => Array.from(root.querySelectorAll(sel)).map((h) => h.textContent ?? "");

  it("«Журнал»: no switches, fields, selects or codes; its sections are the journals and the feeds; the only buttons are checks of a chain", async () => {
    await drawPage(await baseOverview(), "Всё под защитой");
    await openTab("Журнал");
    const j = document.body.querySelector('[data-secure-bb-tabpanel="journal"]')!;
    expect(j).not.toBeNull();
    expect(j.querySelectorAll('input, select, textarea, [role="switch"], [role="checkbox"], [role="combobox"]')).toHaveLength(0);
    expect(headings(j, "h2")).toEqual(["Журнал решений", "Лента дозора (0)", "Загрязнение тредов"]);
    const buttons = Array.from(j.querySelectorAll("button")).map((b) => b.textContent);
    for (const b of buttons) expect(b).toMatch(/^Проверить (целостность|журнал сторожа)$/);
  });

  it("«Настройки»: the groups in order, each with its sections; the controls are here", async () => {
    await drawPage(await baseOverview(), "Всё под защитой");
    await openTab("Настройки");
    const s = document.body.querySelector('[data-secure-bb-tabpanel="settings"]')!;
    expect(s).not.toBeNull();
    expect(Array.from(s.querySelectorAll("[data-secure-bb-group]")).map((g) => g.getAttribute("data-secure-bb-group"))).toEqual(["Защита и второй фактор", "Гейт плагинов", "ИИ-модели и публикация", "Наблюдение за конфигурацией и агентами", "Скиллы"]);
    const subs = headings(s, "h3").join("|");
    for (const title of ["Второй фактор", "Окна доверия", "ИИ-скан плагинов", "Публикация замороженных версий", "Сторож конфигурации", "Дозор", "Скиллы"]) expect(subs).toContain(title);
    expect(s.querySelectorAll('input[type="checkbox"]').length).toBeGreaterThan(0);
  });

  it("no section is on both tabs: what is a setting is not in the journal, and the events are not in the settings", async () => {
    await drawPage(await baseOverview(), "Всё под защитой");
    await openTab("Журнал");
    const journal = headings(document.body.querySelector('[data-secure-bb-tabpanel="journal"]')!, "h2");
    await openTab("Настройки");
    const settings = [...headings(document.body.querySelector('[data-secure-bb-tabpanel="settings"]')!, "h2"), ...headings(document.body.querySelector('[data-secure-bb-tabpanel="settings"]')!, "h3")];
    for (const t of journal) expect(settings).not.toContain(t);
  });

  it("with a guard: its journal and the check of it are on «Журнал»; its card on «Настройки» has no journal and no check", async () => {
    const base = await baseOverview();
    const guard = { connected: true, journal: { valid: true, entries: 3, head: "abc123", problems: [] }, recent: [{ id: 3, ts: base.now - 1000, kind: "approve", pluginId: "chime", detail: null }], passkey: { keys: [], totpOff: false, origin: window.location.origin, enrollmentOpen: false }, troubleshootUntil: 0 };
    await drawPage({ ...base, guard } as unknown as Overview, "Всё под защитой");
    await openTab("Журнал");
    const j = document.body.querySelector('[data-secure-bb-tabpanel="journal"]')!;
    expect(headings(j, "h2")).toContain("Журнал сторожа");
    expect(Array.from(j.querySelectorAll("button")).map((b) => b.textContent)).toContain("Проверить журнал сторожа");
    await openTab("Настройки");
    const s = document.body.querySelector('[data-secure-bb-tabpanel="settings"]')!;
    expect(headings(s, "h3")).toContain("Сторож решений");
    expect(Array.from(s.querySelectorAll("button")).map((b) => b.textContent)).not.toContain("Проверить журнал сторожа");
    expect(s.textContent).not.toContain("Последние записи журнала сторожа");
  });

  it("an alarm about the second factor leads to «Настройки», where the factor is", async () => {
    await drawPage(await alarmOverview(), "Настройте второй фактор: без него ничего нельзя подтвердить");
    const show = Array.from(document.body.querySelectorAll("button")).find((b) => b.textContent === "Настроить")!;
    await act(async () => show.click());
    expect(selectedTab()).toBe("Настройки");
    expect(document.body.querySelector("#sbb-registration")).not.toBeNull();
  });
});
