// The page's decisions and words as pure functions (no React, no I/O, no clock), split by the part of the subject they belong to: see src/ux/*.ts.
// Nothing here decides anything about plugins: approving and holding stay with the guard; these modules choose what to SHOW.
// This file only gathers them under the old name, so that the page and the tests import from one place.
export * from "./ux/agents-copy.js";
export * from "./ux/away.js";
export * from "./ux/card-actions.js";
export * from "./ux/cards.js";
export * from "./ux/decisions.js";
export * from "./ux/entry-facts.js";
export * from "./ux/errors.js";
export * from "./ux/findings.js";
export * from "./ux/frequent.js";
export * from "./ux/modes.js";
export * from "./ux/phrases.js";
export * from "./ux/protected.js";
export * from "./ux/status.js";
export * from "./ux/touch.js";
export * from "./ux/view-state.js";
export * from "./ux/words.js";
