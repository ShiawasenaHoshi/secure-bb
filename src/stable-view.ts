// A page that does not jump: after a redraw the scroll position and the focused field are where the person left them, and the result of an action appears
// at the place of the action (a toast next to the button that was pressed). The decisions are plain functions over the DOM, tested with jsdom; the page only calls them.

export interface FocusId {
  /** The id of the nearest ancestor that has one (a card, a section): the field is looked for inside it. */
  scopeId: string;
  tag: string;
  /** Its number among the fields of that tag inside the scope. */
  index: number;
}
export interface ViewSnapshot {
  scrollTop: number;
  focus: FocusId | null;
  selection: [number, number] | null;
}
export const emptySnapshot = (): ViewSnapshot => ({ scrollTop: 0, focus: null, selection: null });

// Fields that take typing. A button is not remembered: a card that is gone would hand its place to the next card's button, which a press must never land on.
const FIELD = "input, textarea, select";
const isField = (el: Element | null): el is HTMLElement => el !== null && el.matches?.(FIELD) === true;

/** What names a field after the page is drawn again: its card (or section) and its place in it. Null: there is nothing to name it by. */
export function focusIdOf(el: Element, root: Element): FocusId | null {
  if (!isField(el)) return null;
  let scope: Element | null = el.parentElement;
  while (scope && scope !== root && !scope.id) scope = scope.parentElement;
  if (!scope || scope === root || !scope.id) return null;
  const same = Array.from(scope.querySelectorAll(el.tagName.toLowerCase()));
  const index = same.indexOf(el);
  return index < 0 ? null : { scopeId: scope.id, tag: el.tagName.toLowerCase(), index };
}
export function findFocus(root: Element, id: FocusId): HTMLElement | null {
  const scope = Array.from(root.querySelectorAll("[id]")).find((e) => e.id === id.scopeId);
  const el = scope ? (Array.from(scope.querySelectorAll(id.tag))[id.index] ?? null) : null;
  return isField(el) ? el : null;
}

/** Takes the view as it is: where the page is scrolled, which field has the focus (and the caret in it). */
export function snapshotView(root: HTMLElement, doc: Document): ViewSnapshot {
  const a = doc.activeElement;
  const focus = a && root.contains(a) ? focusIdOf(a, root) : null;
  const sel = focus && (a instanceof HTMLInputElement || a instanceof HTMLTextAreaElement) && a.selectionStart !== null && a.selectionEnd !== null ? ([a.selectionStart, a.selectionEnd] as [number, number]) : null;
  return { scrollTop: root.scrollTop, focus, selection: sel };
}

export interface RestoreOutcome {
  scrolled: boolean;
  focused: boolean;
}
/**
 * Called after every draw. The scroll goes back when the draw moved it and the person did not (a scroll of the person is remembered at once, so it is never
 * undone). The focus goes back only when it was LOST (the field was drawn anew): a person who moved to another field, or clicked away, keeps what they did.
 */
export function restoreView(root: HTMLElement, doc: Document, snap: ViewSnapshot): RestoreOutcome {
  let scrolled = false;
  if (snap.scrollTop > 0 && root.scrollTop !== snap.scrollTop) {
    root.scrollTop = snap.scrollTop;
    scrolled = true;
  }
  let focused = false;
  const a = doc.activeElement;
  const lost = a === null || a === doc.body || a === doc.documentElement;
  if (lost && snap.focus) {
    const el = findFocus(root, snap.focus);
    if (el) {
      el.focus({ preventScroll: true });
      if (snap.selection && (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) {
        try {
          el.setSelectionRange(snap.selection[0], snap.selection[1]);
        } catch {
          /* a field type without a caret */
        }
      }
      focused = doc.activeElement === el;
    }
  }
  return { scrolled, focused };
}

// ---- the toast at the place of the action ----------------------------------------------------------------------------------
export interface Box {
  left: number;
  top: number;
  right: number;
  bottom: number;
}
export interface Size {
  width: number;
  height: number;
}
const GAP = 6;
const EDGE = 8;
/** Where a toast goes: under the button that was pressed, left edges together; above it when there is no room below; never out of the window. */
export function toastPosition(anchor: Box, viewport: Size, toast: Size): { left: number; top: number } {
  const below = anchor.bottom + GAP;
  const top = below + toast.height + EDGE <= viewport.height ? below : Math.max(EDGE, anchor.top - GAP - toast.height);
  const left = Math.min(Math.max(EDGE, anchor.left), Math.max(EDGE, viewport.width - toast.width - EDGE));
  return { left, top };
}
/** The button a pointer came down on, as a box, for a toast to stand by (the focus is no help: Safari does not focus a button that is pressed). */
export function anchorOf(target: EventTarget | null): Box | null {
  const el = target instanceof Element ? target.closest("button, a, input, [role=button]") : null;
  if (!el) return null;
  const r = el.getBoundingClientRect();
  return { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
}
/** The last place the person pressed, and when; an action that took longer than `maxAgeMs` is not tied to it. */
export function pressTracker(doc: Document, now: () => number = Date.now): { last: (maxAgeMs: number) => Box | null; stop: () => void } {
  let at = 0;
  let box: Box | null = null;
  const on = (e: Event): void => {
    const b = anchorOf(e.target);
    if (b) {
      box = b;
      at = now();
    }
  };
  doc.addEventListener("pointerdown", on, true);
  doc.addEventListener("keydown", (e) => (e as KeyboardEvent).key === "Enter" && on(e), true);
  return { last: (maxAgeMs) => (box !== null && now() - at <= maxAgeMs ? box : null), stop: () => doc.removeEventListener("pointerdown", on, true) };
}

// ---- notes: where each one is shown ---------------------------------------------------------------------------------------------
export interface NoteLike {
  id: number;
  text: string;
  kind: "done" | "info" | "error";
  /** Where the button that was pressed stood; null: the note has no place and goes to the strip at the top. */
  anchor: Box | null;
}
/** A note as it is kept. The anchor MUST be kept with it (it is what takes the note from the top strip to the button). */
export function makeNote(id: number, text: string, opts: { kind?: NoteLike["kind"]; anchor?: Box | null } = {}): NoteLike {
  return { id, text, kind: opts.kind ?? "done", anchor: opts.anchor ?? null };
}
/** The notes that stand by a button, and the notes of the top strip. */
export function splitNotes<T extends { anchor?: Box | null }>(notes: T[]): { placed: T[]; pinned: T[] } {
  return { placed: notes.filter((n) => n.anchor), pinned: notes.filter((n) => !n.anchor) };
}
