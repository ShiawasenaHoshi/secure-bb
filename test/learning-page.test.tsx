// @vitest-environment jsdom
// The page side of the journal for learning: what a card reports it showed, and the one-click mark on a decision.
import { act, createElement } from "react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { renderSlot } from "@get-bb/plugin-sdk/testing/app";
import { DecisionMark, markOf } from "../app/decision-mark";
import { shownReport } from "../app/card-log";
import { CARD_TEXTS_VERSION, MARK_LABEL, MARKABLE_KINDS } from "../src/ux";
import { DECISION_KINDS, MARKS } from "../guard/src/learning";

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});
const mounted: Array<{ lifecycle: { unmount(): void } }> = [];
afterEach(() => {
  for (const m of mounted.splice(0)) m.lifecycle.unmount();
  document.body.innerHTML = "";
});

describe("what a card reports", () => {
  it("level, findings by rule/file/line, the verdict per model and the version of the texts: no code, no messages", () => {
    const found = { findings: [{ rule: "net.fetch", severity: "review", file: "src/a.ts", line: 4, message: "fetch(secret)", snippet: "const t = 'sk-1'" }] };
    const scan = { models: [{ model: "claude", label: "claude", status: "flag", detail: "про переписки", report: null, ms: 1 }] };
    const r = shownReport("danger", found as never, scan as never, true);
    expect(r).toEqual({ level: "danger", findings: [{ rule: "net.fetch", file: "src/a.ts", line: 4 }], ai: [{ model: "claude", status: "flag" }], textsVersion: CARD_TEXTS_VERSION, detailsOpen: true });
    expect(JSON.stringify(r)).not.toMatch(/fetch\(secret\)|sk-1|переписки/);
  });

  it("the page's list of markable kinds is the guard's list, and its marks are the guard's marks", () => {
    expect([...MARKABLE_KINDS].sort()).toEqual([...DECISION_KINDS].sort());
    expect(Object.keys(MARK_LABEL).sort()).toEqual([...MARKS].sort());
  });
});

type Rec = Parameters<typeof markOf>[0][number];
const rec = (id: number, kind: string, detail: unknown = null): Rec => ({ id, ts: 1, kind, pluginId: "demo", contentHash: null, detail });

function mount(r: Rec, recent: Rec[], call: (m: string, i: unknown) => unknown) {
  const rpc = { call: (m: string, i?: unknown) => Promise.resolve(call(m, i)) };
  const slot = renderSlot({ component: () => createElement(DecisionMark, { r, recent, rpc: rpc as never, refetch: () => undefined }) }, {});
  mounted.push(slot);
  return slot;
}
const buttons = (): string[] => Array.from(document.body.querySelectorAll("button")).map((b) => b.textContent ?? "");

describe("the mark on a decision", () => {
  it("one click sends the record and the mark", async () => {
    const call = vi.fn(() => ({ ok: true }));
    mount(rec(5, "approved.touch"), [], call);
    expect(buttons()).toEqual(["ложная тревога", "правда было опасно", "не знаю"]);
    await act(async () => void (document.body.querySelector('[data-secure-bb-mark-button="false_alarm"]') as HTMLButtonElement).click());
    await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
    expect(call).toHaveBeenCalledWith("decision.mark", { record: 5, mark: "false_alarm" });
  });

  it("a revoke has a field for the reason, sent with the mark", async () => {
    const call = vi.fn(() => ({ ok: true }));
    mount(rec(6, "revoked"), [], call);
    const field = document.body.querySelector("input") as HTMLInputElement;
    expect(field).not.toBeNull();
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(field, "не тот плагин");
      field.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => void (document.body.querySelector('[data-secure-bb-mark-button="unknown"]') as HTMLButtonElement).click());
    await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
    expect(call).toHaveBeenCalledWith("decision.mark", { record: 6, mark: "unknown", reason: "не тот плагин" });
  });

  it("the latest mark is shown; a record that is not a decision has no buttons", () => {
    const recent = [rec(9, "decision.mark", { record: 5, mark: "was_dangerous" }), rec(8, "decision.mark", { record: 5, mark: "false_alarm" })];
    expect(markOf(recent, 5)).toEqual({ mark: "was_dangerous", reason: null });
    mount(rec(5, "approved.touch"), recent, () => ({ ok: true }));
    expect(document.body.textContent).toContain("отметка: правда было опасно");
    document.body.innerHTML = "";
    mount(rec(1, "totp.fail"), [], () => ({ ok: true }));
    expect(buttons()).toEqual([]);
  });
});
