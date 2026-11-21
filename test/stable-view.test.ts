// A page that does not jump: scroll and focus survive a redraw; the toast stands by the button. DOM logic over jsdom (no layout there: scrollTop is a plain number).
// @vitest-environment node
import { describe, expect, it } from "vitest";
// @ts-expect-error jsdom ships no types in this tree
import { JSDOM } from "jsdom";
import { anchorOf, emptySnapshot, findFocus, focusIdOf, pressTracker, restoreView, snapshotView, toastPosition } from "../src/stable-view.ts";

function page(html: string) {
  const dom = new JSDOM(`<!doctype html><body><div id="root">${html}</div></body>`, { pretendToBeVisual: true });
  const g = globalThis as Record<string, unknown>;
  // the module tests `instanceof HTMLInputElement` etc.: the jsdom window's classes
  for (const k of ["HTMLInputElement", "HTMLTextAreaElement", "Element"]) g[k] = dom.window[k];
  const doc = dom.window.document as Document;
  const root = doc.getElementById("root") as HTMLElement;
  return { dom, doc, root };
}
const CARDS = `
  <div id="sbb-card-1"><input id="x1" placeholder="код"><button>Разрешить</button></div>
  <div id="sbb-card-2"><input placeholder="код"><button>Разрешить</button></div>`;

describe("scroll and focus after a redraw", () => {
  it("a field is named by its card and its place in it, and found again after the card is drawn anew", () => {
    const { doc, root } = page(CARDS);
    const second = root.querySelectorAll("#sbb-card-2 input")[0]!;
    const id = focusIdOf(second, root);
    expect(id).toEqual({ scopeId: "sbb-card-2", tag: "input", index: 0 });
    // the card is drawn again: a new element in the same place
    root.innerHTML = CARDS;
    expect(findFocus(root, id!)).toBe(root.querySelector("#sbb-card-2 input"));
    expect(doc.activeElement).toBe(doc.body);
  });

  it("the focused field that was drawn anew gets the focus back, with the caret and what was typed in it kept by the page's own draft", () => {
    const { doc, root } = page(CARDS);
    const input = root.querySelector("#sbb-card-2 input") as HTMLInputElement;
    input.focus();
    input.value = "123";
    input.setSelectionRange(2, 2);
    const snap = snapshotView(root, doc);
    expect(snap.focus).toEqual({ scopeId: "sbb-card-2", tag: "input", index: 0 });
    expect(snap.selection).toEqual([2, 2]);
    root.innerHTML = CARDS;
    (root.querySelector("#sbb-card-2 input") as HTMLInputElement).value = "123";
    const out = restoreView(root, doc, snap);
    expect(out.focused).toBe(true);
    expect(doc.activeElement).toBe(root.querySelector("#sbb-card-2 input"));
    expect((doc.activeElement as HTMLInputElement).selectionStart).toBe(2);
  });

  it("a person who moved on is not pulled back: focus on another field, or clicked away to the page, stays", () => {
    const { doc, root } = page(CARDS);
    (root.querySelector("#sbb-card-1 input") as HTMLInputElement).focus();
    const snap = snapshotView(root, doc);
    const other = root.querySelector("#sbb-card-2 input") as HTMLInputElement;
    other.focus();
    expect(restoreView(root, doc, snap).focused).toBe(false);
    expect(doc.activeElement).toBe(other);
    // nothing was focused when the snapshot was taken: nothing is focused after
    (doc.activeElement as HTMLElement).blur();
    expect(restoreView(root, doc, emptySnapshot()).focused).toBe(false);
    expect(doc.activeElement).toBe(doc.body);
  });

  it("the scroll that the draw moved goes back; the scroll of the person (already remembered) is not undone", () => {
    const { doc, root } = page(CARDS);
    root.scrollTop = 480;
    const snap = snapshotView(root, doc);
    expect(snap.scrollTop).toBe(480);
    // the draw threw the page to the top
    root.scrollTop = 0;
    expect(restoreView(root, doc, snap)).toMatchObject({ scrolled: true });
    expect(root.scrollTop).toBe(480);
    // the person scrolls: the page remembers it (the page's scroll listener takes a new snapshot), so the next draw leaves it alone
    root.scrollTop = 900;
    const mine = snapshotView(root, doc);
    expect(restoreView(root, doc, mine).scrolled).toBe(false);
    expect(root.scrollTop).toBe(900);
    // a page that was at the top stays there (nothing to restore)
    root.scrollTop = 0;
    expect(restoreView(root, doc, snapshotView(root, doc)).scrolled).toBe(false);
  });

  it("a field outside any card has no name, so nothing is restored for it (never a wrong field)", () => {
    const { doc, root } = page(`<input id="loose">`);
    const input = root.querySelector("input") as HTMLInputElement;
    input.focus();
    expect(snapshotView(root, doc).focus).toBeNull();
  });
});

describe("the toast by the button", () => {
  const vp = { width: 1000, height: 700 };
  const toast = { width: 300, height: 40 };
  it("under the button, left edges together", () => {
    expect(toastPosition({ left: 100, top: 200, right: 180, bottom: 230 }, vp, toast)).toEqual({ left: 100, top: 236 });
  });
  it("above the button when there is no room below; inside the window at the right edge", () => {
    expect(toastPosition({ left: 900, top: 660, right: 980, bottom: 690 }, vp, toast)).toEqual({ left: 692, top: 614 });
    expect(toastPosition({ left: -20, top: 10, right: 40, bottom: 30 }, vp, toast).left).toBe(8);
  });
  it("the place of the last press: a button, with its box; an old press is not the place of a late answer", () => {
    const { dom, doc } = page(`<button id="b">Разрешить</button>`);
    let t = 1000;
    const tracker = pressTracker(doc, () => t);
    expect(tracker.last(5000)).toBeNull();
    const b = doc.getElementById("b")!;
    b.dispatchEvent(new dom.window.Event("pointerdown", { bubbles: true }));
    expect(tracker.last(5000)).toMatchObject({ left: 0, top: 0 });
    t += 6000;
    expect(tracker.last(5000)).toBeNull();
    expect(anchorOf(doc.body)).toBeNull();
    tracker.stop();
  });
});
