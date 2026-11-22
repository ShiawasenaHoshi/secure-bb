import { pressTracker } from "../src/stable-view";

// Where the person pressed last: the result of the action is shown there.
export const press = typeof document !== "undefined" ? pressTracker(document) : null;

export const PRESS_MAX_AGE_MS = 120_000;
