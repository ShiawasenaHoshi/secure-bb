// @vitest-environment jsdom
// The one confirmation dialog: which action it shows, what it sends, that the sixth digit sends the code by itself, and that an error stays in it.
import { act, createElement } from "react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { renderSlot } from "@get-bb/plugin-sdk/testing/app";
import { ConfirmHost, ConfirmPanel, useAskConfirm, type ConfirmProof, type ConfirmRequest, type PanelParts, type PanelProps } from "../app/confirm-dialog";
import { ConfirmCancelled } from "../app/confirm-error";
import type { Overview } from "../src/overview";

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  // The dialog asks for the viewport kind; jsdom has no matchMedia.
  window.matchMedia ??= ((query: string) => ({ matches: false, media: query, onchange: null, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false })) as never;
  // jsdom has no WebAuthn: the dialog offers the key only where it can work.
  Object.defineProperty(navigator, "credentials", { value: { get: () => Promise.resolve(null) }, configurable: true });
  (globalThis as { ResizeObserver?: unknown }).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} };
});

const ovOf = (guard?: unknown): Overview => ({ guard, totp: { state: "locked", blockedUntil: 0 } }) as unknown as Overview;

// The dialog around the panel (radix) is the host's; the panel is what is tested, drawn in a plain box.
const PLAIN: PanelParts = { Title: ({ className, children }) => createElement("h2", { className }, children), Description: ({ children }) => createElement("p", null, children) };
const Bare = (props: PanelProps) => createElement("div", { "data-secure-bb-confirm": "" }, createElement(ConfirmPanel, { ...props, parts: PLAIN }));

/** A page of one button that asks the dialog and records how it ended. */
function Asker({ req, onEnd }: { req: ConfirmRequest; onEnd: (r: { ok: unknown } | { err: unknown }) => void }) {
  const ask = useAskConfirm();
  return createElement("button", { onClick: () => void ask(req).then((ok) => onEnd({ ok }), (err) => onEnd({ err })) }, "go");
}

const mounted: Array<{ lifecycle: { unmount(): void } }> = [];
afterEach(() => {
  for (const m of mounted.splice(0)) m.lifecycle.unmount();
  document.body.innerHTML = "";
});

function mount(req: ConfirmRequest, opts: { guard?: unknown; rpc?: Record<string, (i: unknown) => unknown> } = {}) {
  const ends: Array<{ ok: unknown } | { err: unknown }> = [];
  const rpcFake = { call: (m: string, i?: unknown) => Promise.resolve((opts.rpc?.[m] ?? (() => undefined))(i)) };
  const slot = renderSlot(
    { component: () => createElement(ConfirmHost, { ov: ovOf(opts.guard), rpc: rpcFake as never, Shell: Bare, children: createElement(Asker, { req, onEnd: (r) => ends.push(r) }) }) },
    {},
  );
  mounted.push(slot);
  return { slot, ends };
}

const typeInto = async (input: HTMLInputElement, value: string) => {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
};

const codeField = (): HTMLInputElement => document.body.querySelector('input[autocomplete="one-time-code"]') as HTMLInputElement;
const flush = async () => act(async () => void (await new Promise((r) => setTimeout(r, 0))));

describe("the confirmation dialog", () => {
  it("says what exactly is approved, and nothing is sent before the code is complete", async () => {
    const call = vi.fn(async (_p: ConfirmProof) => "done");
    const { slot } = mount({ what: "Разрешить chime 0.1.0", detail: "Плагин читает переписки.", query: { kind: "approve", queueId: 1 }, draftKey: "t1", call });
    await act(async () => void (await slot.findByText("go")).click());
    expect(document.body.querySelector("[data-secure-bb-confirm-what]")?.textContent).toBe("Разрешить chime 0.1.0");
    expect(document.body.textContent).toContain("Плагин читает переписки.");
    await typeInto(codeField(), "12345");
    await flush();
    expect(call).not.toHaveBeenCalled();
  });

  it("the sixth digit sends the code by itself, once, as {code}", async () => {
    const call = vi.fn(async (_p: ConfirmProof) => "done");
    const { slot, ends } = mount({ what: "Разрешить chime 0.1.0", query: { kind: "approve", queueId: 1 }, draftKey: "t2", call });
    await act(async () => void (await slot.findByText("go")).click());
    await typeInto(codeField(), "12345");
    await typeInto(codeField(), "123456");
    await flush();
    expect(call).toHaveBeenCalledTimes(1);
    expect(call).toHaveBeenCalledWith({ code: "123456" });
    expect(ends).toEqual([{ ok: "done" }]);
    // the dialog closed with the answer
    expect(document.body.querySelector("[data-secure-bb-confirm]")).toBeNull();
  });

  it("an error stays under the field: the dialog is not closed, the code is cleared, nothing is resolved", async () => {
    const call = vi.fn(async (_p: ConfirmProof) => {
      throw new Error("invalid_code");
    });
    const { slot, ends } = mount({ what: "Разрешить chime 0.1.0", query: { kind: "approve", queueId: 1 }, draftKey: "t3", call });
    await act(async () => void (await slot.findByText("go")).click());
    await typeInto(codeField(), "654321");
    await flush();
    expect(call).toHaveBeenCalledTimes(1);
    expect(document.body.querySelector("[data-secure-bb-confirm]")).not.toBeNull();
    expect(document.body.querySelector("[data-secure-bb-confirm-error]")?.textContent).toMatch(/Код не подошёл/);
    expect(codeField().value).toBe("");
    expect(ends).toEqual([]);
  });

  it("closing it is a cancel: the action is not run and the asker gets ConfirmCancelled", async () => {
    const call = vi.fn(async (_p: ConfirmProof) => "done");
    const { slot, ends } = mount({ what: "Удалить chime 0.1.0", query: { kind: "approve", queueId: 1 }, draftKey: "t4", call });
    await act(async () => void (await slot.findByText("go")).click());
    const cancel = Array.from(document.body.querySelectorAll("button")).find((b) => b.textContent === "Отмена")!;
    await act(async () => cancel.click());
    await flush();
    expect(call).not.toHaveBeenCalled();
    expect(ends).toHaveLength(1);
    expect((ends[0] as { err: unknown }).err).toBeInstanceOf(ConfirmCancelled);
  });

  it("with a key the main button is the touch, and the code is under «или код из приложения»", async () => {
    const guard = { connected: true, passkey: { keys: [{ id: "k", label: "Mac", aaguid: "", lastUsedAt: null }], totpOff: false, origin: window.location.origin, enrollmentOpen: false } };
    const call = vi.fn(async (_p: ConfirmProof) => "done");
    // The guard says this action needs no touch: the dialog's touch button sends {} (nothing to sign) and the query it asked about is the action's.
    const challenges: unknown[] = [];
    const { slot } = mount({ what: "Открыть сессию подтверждения на 15 минут", query: { kind: "session.open" }, draftKey: "t5", call }, { guard, rpc: { "passkey.challenge": (i) => (challenges.push(i), { needed: false }) } });
    await act(async () => void (await slot.findByText("go")).click());
    const touch = Array.from(document.body.querySelectorAll("button")).find((b) => b.textContent === "Приложить палец / ключ");
    expect(touch).toBeDefined();
    expect(document.body.textContent).toContain("или код из приложения");
    await act(async () => touch!.click());
    await flush();
    expect(challenges).toEqual([{ kind: "session.open" }]);
    expect(call).toHaveBeenCalledWith({});
  });

  it("when only keys work (codes switched off) there is no code field", async () => {
    const guard = { connected: true, passkey: { keys: [{ id: "k", label: "Mac", aaguid: "", lastUsedAt: null }], totpOff: true, origin: window.location.origin, enrollmentOpen: false } };
    const { slot } = mount({ what: "Разрешить chime 0.1.0", query: { kind: "approve", queueId: 1 }, draftKey: "t6", call: async () => "done" }, { guard });
    await act(async () => void (await slot.findByText("go")).click());
    expect(codeField()).toBeNull();
    expect(document.body.textContent).toContain("Приложить палец / ключ");
  });

  const keyGuard = (origin: string, totpOff = false) => ({ connected: true, passkey: { keys: [{ id: "k", label: "Mac", aaguid: "", lastUsedAt: null }], totpOff, origin, enrollmentOpen: false } });
  const buttonTexts = () => Array.from(document.body.querySelectorAll("button")).map((b) => b.textContent);
  const open = async (guard: unknown) => {
    const { slot } = mount({ what: "Разрешить chime 0.1.0", query: { kind: "approve", queueId: 1 }, draftKey: `o${Math.random()}`, call: async () => "done" }, { guard });
    await act(async () => void (await slot.findByText("go")).click());
  };

  it("on another origin the code is offered at once, the key is not, and the link leads to the guard's address", async () => {
    await open(keyGuard("http://localhost:38886"));
    expect(codeField()).not.toBeNull();
    expect(buttonTexts()).not.toContain("Приложить палец / ключ");
    expect(document.body.querySelector("[data-secure-bb-key-note]")?.textContent).toContain("Ключ работает в браузере на http://localhost:38886; здесь — код из приложения.");
    const link = document.body.querySelector("[data-secure-bb-key-note] a") as HTMLAnchorElement;
    expect(link.textContent).toBe("Открыть в браузере");
    expect(link.href).toBe(`http://localhost:38886${window.location.pathname}`);
    expect(link.rel).toContain("noopener");
  });

  it("in the bb app the code comes first and the key is secondary, even at the right origin", async () => {
    const ua = vi.spyOn(navigator, "userAgent", "get").mockReturnValue("Mozilla/5.0 Chrome/140 Electron/44.1 Safari/537");
    try {
      await open(keyGuard(window.location.origin));
      const html = document.body.innerHTML;
      expect(html.indexOf('autocomplete="one-time-code"')).toBeLessThan(html.indexOf("Приложить палец / ключ"));
      expect(document.body.querySelector("[data-secure-bb-key-note] a")).not.toBeNull();
    } finally {
      ua.mockRestore();
    }
  });

  it("with codes off and a foreign origin there is no code and no key: the words and the link only", async () => {
    await open(keyGuard("http://localhost:38886", true));
    expect(codeField()).toBeNull();
    expect(buttonTexts()).not.toContain("Приложить палец / ключ");
    expect(document.body.textContent).toContain("Коды отключены");
    expect(document.body.querySelector("[data-secure-bb-key-note] a")).not.toBeNull();
  });
});
