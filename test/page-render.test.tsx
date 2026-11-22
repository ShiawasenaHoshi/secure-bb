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

async function drawPage(ov: Overview) {
  const app = await loadPluginApp(() => import("../app"));
  const slot = renderSlot(app.navPanels[0]!, { subPath: "" }, { rpc: { overview: () => ov, "page.ping": () => null } as never });
  mounted.push(slot);
  // the overview arrives after the first draw
  await act(async () => void (await new Promise((r) => setTimeout(r, 300))));
  await act(async () => void (await slot.findByText("Ждут вашего решения: 3", {}, { timeout: 2500 })));
  return slot;
}

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
});
