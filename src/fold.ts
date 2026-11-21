import { setFold } from "./ux.js";

/**
 * Open or closed folds live OUTSIDE the components, keyed by the id of the element they belong to (a plugin version's hash, a change's number,
 * a fixed name): a refresh, a list that is built again, even a component that is mounted anew find them as the person left them.
 */
export const foldState: { open: Record<string, boolean> } = { open: {} };

/** Is the fold open now? `defaultOpen` counts only until the person has touched it. */
export const isFoldOpen = (id: string, defaultOpen = false): boolean => foldState.open[id] ?? defaultOpen;

/** A click: flips the fold, returns the new state. */
export function toggleFold(id: string, defaultOpen = false): boolean {
  const next = !isFoldOpen(id, defaultOpen);
  foldState.open = setFold(foldState.open, id, next);
  return next;
}

/** Opens or closes a fold from outside (a «Показать» that leads into a folded list). */
export function openFold(id: string, open: boolean): void {
  foldState.open = setFold(foldState.open, id, open);
}
