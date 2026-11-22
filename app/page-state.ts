// What the page remembers about itself while it is open, as hooks: the view (scroll and focus), the notes and the lines that stand where a card was, the marks the
// person made (put aside, kept, seen, switched off), and the jump of «Показать». The page draws; these keep the state. Conveniences of the page, not security facts.
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { QueueRow } from "../src/store";
import { AWAY_KEY, DEFERRED_KEY, FREQ_KEY, FREQ_OFF_KEY, KEPT_KEY, WIZARD_KEY, deferKey, dropUnstamped, makeDeferStub, makeStub, parseDeferred, parseFreqAt, stampMark, withoutMark, type Stub } from "../src/ux";
import { emptySnapshot, makeNote, restoreView, snapshotView, type ViewSnapshot } from "../src/stable-view";
import { lsGet, lsSet } from "./confirm";
import { DONE_MS, type AnnounceOpts, type Note } from "./ui";

/** What a place gets for a moment when «Показать» takes the person to it: the theme's ring. */
const FLASH = ["ring-2", "ring-ring", "ring-offset-2", "ring-offset-background", "rounded-lg"];

/** Scroll and focus survive a redraw: what the person did is remembered as it happens, and put back when a draw moved or dropped it. */
export function useStableView() {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<ViewSnapshot>(emptySnapshot());
  const rememberView = useCallback(() => {
    if (scrollRef.current) viewRef.current = snapshotView(scrollRef.current, document);
  }, []);
  useLayoutEffect(() => {
    if (scrollRef.current) restoreView(scrollRef.current, document, viewRef.current);
  });
  return { scrollRef, rememberView };
}

/**
 * «Показать» and the banners: scroll to the element, flash it, so that a press is always seen to do something (also when the element is already on the screen).
 * The element is looked for after every draw until it is there (the tab it stands on may not be drawn yet).
 */
export function useFocusJump(focus: string | null, setFocus: (id: string | null) => void, rememberView: () => void, redrawKey: unknown[]) {
  useEffect(() => {
    if (!focus) return;
    const el = document.getElementById(focus);
    if (!el) return;
    el.scrollIntoView({ block: "start" });
    // The jump is the person's own («Показать»): remembered at once, so that it is not taken for a draw's.
    rememberView();
    el.classList.add(...FLASH);
    window.setTimeout(() => el.classList.remove(...FLASH), 1800);
    setFocus(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the draws that may bring the element are the ones listed
  }, [focus, ...redrawKey]);
}

/**
 * The notes of results and the lines that stand where a card was. A resolved card leaves ONE short line where it stood (the result, no toast beside it); the list
 * keeps its order while the page is open. The list is shorter when a card turns into a line and the next card comes up under the pointer: for a moment it takes no presses.
 */
export function useNotes() {
  const [doneNotes, setDoneNotes] = useState<Note[]>([]);
  const [stubs, setStubs] = useState<Stub[]>([]);
  const [settling, setSettling] = useState(false);
  const doneSeq = useRef(0);
  const settle = useCallback(() => {
    setSettling(true);
    window.setTimeout(() => setSettling(false), 700);
  }, []);
  const dismiss = useCallback((id: number) => setDoneNotes((l) => l.filter((n) => n.id !== id)), []);
  const announce = useCallback(
    (text: string, opts: AnnounceOpts = {}) => {
      const id = ++doneSeq.current;
      const kind = opts.kind ?? "done";
      if (opts.slot && kind === "done") {
        const { key, height } = opts.slot;
        setStubs((l) => [...l.filter((x) => x.key !== key), makeStub(key, text, height)]);
        settle();
        return;
      }
      setDoneNotes((l) => [...l, makeNote(id, text, { kind, anchor: opts.anchor })].slice(-4));
      if (kind !== "error") window.setTimeout(() => setDoneNotes((l) => l.filter((n) => n.id !== id)), DONE_MS);
    },
    [settle],
  );
  const ctx = useMemo(() => ({ notes: doneNotes, announce, dismiss }), [doneNotes, announce, dismiss]);
  return { ctx, announce, stubs, setStubs, settling, settle };
}

const store = (key: string, list: string[]) => lsSet(key, JSON.stringify(list.slice(-500)));
const newestFirstMark = (list: string[], k: string): string[] => [...withoutMark(list, k), stampMark(k, Date.now())];

/** The marks the person made, kept in this browser. A mark carries the time it was made: one older than the entry belongs to an earlier data set and does not count. */
export function useMarks(notes: Pick<ReturnType<typeof useNotes>, "setStubs" | "settle">) {
  // Marks of an older page, with no time on them, cannot be told from such ones: they are dropped once.
  const [deferredKeys, setDeferredKeys] = useState<string[]>(() => dropUnstamped(parseDeferred(lsGet(DEFERRED_KEY))));
  const [keptKeys, setKeptKeys] = useState<string[]>(() => dropUnstamped(parseDeferred(lsGet(KEPT_KEY))));
  const [seenAt, setSeenAt] = useState<string | null>(() => lsGet(AWAY_KEY));
  // «Вы часто одобряете…»: when the hint was last used or put away, and whether the person switched it off.
  const [freqAt, setFreqAt] = useState<number | null>(() => parseFreqAt(lsGet(FREQ_KEY)));
  const [freqOff, setFreqOff] = useState<boolean>(() => lsGet(FREQ_OFF_KEY) === "1");
  const [wizardDone, setWizardDone] = useState<boolean>(() => lsGet(WIZARD_KEY) !== null);
  const { setStubs, settle } = notes;

  const onDefer = (q: QueueRow, on: boolean) => {
    const k = deferKey(q.pluginId, q.contentHash, q.id);
    const next = on ? newestFirstMark(deferredKeys, k) : withoutMark(deferredKeys, k);
    // «Решить позже»: the card becomes a short line («Отложено: X · Вернуть»).
    if (on) {
      const height = document.getElementById(`sbb-card-${q.id}`)?.offsetHeight ?? 0;
      setStubs((l) => [...l.filter((x) => x.key !== q.pluginId), makeDeferStub(q, height)]);
      settle();
    } else setStubs((l) => l.filter((x) => !(x.restore && x.key === q.pluginId)));
    setDeferredKeys(next);
    store(DEFERRED_KEY, next);
  };
  // «Оставить в карантине» is an answer: the entry is held at the guard as before, but it leaves «Ждут решения» and the status.
  const onKeep = (q: QueueRow) => {
    const next = newestFirstMark(keptKeys, deferKey(q.pluginId, q.contentHash, q.id));
    setKeptKeys(next);
    store(KEPT_KEY, next);
    onDefer(q, false);
  };
  const onUnkeep = (q: QueueRow) => {
    const next = withoutMark(keptKeys, deferKey(q.pluginId, q.contentHash, q.id));
    setKeptKeys(next);
    store(KEPT_KEY, next);
  };
  const seen = (mark: number) => {
    lsSet(AWAY_KEY, String(mark));
    setSeenAt(String(mark));
  };
  const closeWizard = (now: number) => {
    lsSet(WIZARD_KEY, String(now));
    setWizardDone(true);
  };
  const onFreqDone = () => {
    lsSet(FREQ_KEY, String(Date.now()));
    setFreqAt(Date.now());
  };
  const setFreqSwitch = (off: boolean) => {
    lsSet(FREQ_OFF_KEY, off ? "1" : "0");
    setFreqOff(off);
  };
  return { decisions: { deferred: deferredKeys, kept: keptKeys }, seenAt, freqAt, freqOff, wizardDone, onDefer, onKeep, onUnkeep, seen, closeWizard, onFreqDone, setFreqSwitch };
}
