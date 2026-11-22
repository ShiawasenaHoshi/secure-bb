// What the sidebar says about the protection, as a small store outside React: the registered icon is drawn by bb's own chrome (the sidebar footer), not inside the page,
// so it cannot ask the server itself. The overlay (always mounted, it already polls the overview) publishes the view here; the icon, the badge and the footer's
// status read it. The view is made by `iconView(summaryOf(...))` of src/pageview.ts: the same sentence and the same tone as the header of the page, never a second rule.
import { useEffect, useSyncExternalStore } from "react";
import type { Overview } from "../src/overview";
import { iconView, summaryOf, type IconView } from "../src/pageview";
import { readDecisions } from "./page-state";

let current: IconView | null = null;
const listeners = new Set<() => void>();

/** Sets the view; a view equal to the one held changes nothing and wakes nobody. */
export function publishStatus(next: IconView | null): void {
  if (JSON.stringify(next) === JSON.stringify(current)) return;
  current = next;
  for (const l of [...listeners]) l();
}

const subscribe = (l: () => void): (() => void) => {
  listeners.add(l);
  return () => listeners.delete(l);
};

export const protectionView = (ov: Overview): IconView => iconView(summaryOf(ov, readDecisions()));

/** The latest view, or null until the first overview came. */
export const useProtectionView = (): IconView | null => useSyncExternalStore(subscribe, () => current, () => current);

/** Called by the always-mounted overlay with every new overview: publishes what the icon shows. */
export function usePublishStatus(ov: Overview | null): void {
  useEffect(() => publishStatus(ov ? protectionView(ov) : null), [ov]);
}
