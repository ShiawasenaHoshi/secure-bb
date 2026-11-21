// What a call into bb's own API (`sdk.threads.spawn(…)`, `bb.sdk.system.setMachineEnvironmentVariable(…)`) and a press on a button of bb's page
// (`document.querySelector(…).click()`) let a plugin do. These do not look like network, files or processes, but run with the signed-in user's own
// authority: "there is no narrower plugin scope" (plugin SDK, `PluginBrowserBbSdk`). Pure tables, no I/O: the plugin's checks and the guard's are
// the same module, so both count the same rights.
import type { CapabilityKind } from "./types.ts";

export type SdkRightKind = Extract<CapabilityKind, "sdk_read" | "sdk_agents" | "sdk_send" | "sdk_answer" | "sdk_settings" | "fs" | "child_process">;
export interface SdkRight {
  kind: SdkRightKind;
  /** Stable token `area.method` (`threads.spawn`): it is what the window compares, so it names the call, not its arguments. */
  detail: string;
}
/** A call into an SDK area that is not in the tables: it may do anything, so a person looks at it. */
export interface SdkUnclassified {
  unclassified: true;
  detail: string;
}

// ---- threads ---------------------------------------------------------------------------------------------------------------
/** Read what is said in the conversations (and who is running what). */
const THREADS_READ = new Set([
  "get", "list", "listRunning", "count", "search", "timeline", "timelineTurnSummaryDetails", "output", "conversationOutline", "childSummary", "context",
  "promptHistory", "storageFiles", "storageLocation", "storagePaths", "resolveMentions", "wait", "defaultExecutionOptions",
  "experimental_listPluginMetadata", "experimental_listAncestors", "experimental_listDescendants", "experimental_listCascade",
  "events.list", "events.wait", "queue.list", "queuedMessages.list", "interactions.get", "interactions.list",
]);
/** Start, stop, archive, delete agents' threads. */
const THREADS_AGENTS = new Set(["spawn", "stop", "archive", "archiveAll", "unarchive", "fork", "delete", "retry", "compact", "clearContext", "clearGoal", "cancelPlan", "restoreEnvironment"]);
/** Put a message into a conversation: it goes out as the person's own. */
const THREADS_SEND = new Set(["send", "message", "editMessage", "queuedMessages.create", "queuedMessages.update", "queuedMessages.delete"]);
/** Answer an agent's question or permission request. */
const THREADS_ANSWER = new Set(["interactions.respond", "interactions.resolve", "interactions.cancel"]);
/** Only the look of the sidebar or the plugin's own notes: no right of its own. */
const THREADS_HARMLESS = new Set(["markRead", "markUnread", "pin", "unpin", "reorderPinned", "open", "paneAction", "update", "getPluginMetadata", "updatePluginMetadata", "experimental_regenerateTitle", "tabs"]);
/**
 * Method names that a plain `Map`/array called `threads` also has. `x.threads.get(id)` is the SDK only when `x` is the SDK (`sdk`, `bb.sdk`, `useSdk()`);
 * the unique names (`spawn`, `timeline`, `interactions.respond`…) are the SDK wherever they are seen.
 */
const THREADS_AMBIGUOUS = new Set(["get", "list", "count", "search", "send", "stop", "message", "open", "update", "delete", "fork", "retry", "wait", "pin", "unpin", "archive", "unarchive", "context", "output", "compact", "events", "queue"]);

// ---- settings --------------------------------------------------------------------------------------------------------------
/** Areas whose mutating (and secret-reading) methods change how bb is set up. */
const SETTINGS_AREAS = new Set(["system", "providers", "plugins", "skills", "projects", "environments", "hosts"]);
const MUTATING = /^(experimental_)?(set|delete|replace|update|install|startInstall|startUpdate|enable|disable|remove|apply|reload|token|create|commit|cleanup|reorder|reconnect|suspend|resume|reconcile|retry|installProvider|startProvider|acknowledge|schedule|cancel|record)/;
/** Reads that hand out secrets or other plugins' settings. */
const SETTINGS_SECRET_READS = new Set(["machineEnvironment", "getSettings", "getSource", "token"]);
const SETTINGS_BENIGN = new Set(["list", "get", "models", "catalog", "version", "status", "search", "detail", "entries", "branches", "files", "paths", "fileContent", "commands", "attention", "config", "usageLimits", "providerStates", "executionOptions"]);

/** Dotted chain → the area it reaches (`sdk.threads.spawn` → ["threads", "spawn"]); null if the chain does not go through an SDK area. */
function areaOf(parts: string[], areas: ReadonlySet<string>): { area: string; rest: string[]; rooted: boolean } | null {
  for (let i = 1; i < parts.length; i++) {
    if (areas.has(parts[i]!) && parts.length > i + 1) return { area: parts[i]!, rest: parts.slice(i + 1), rooted: parts[i - 1] === "sdk" };
  }
  return null;
}
const THREADS = new Set(["threads"]);
const OTHER_AREAS = new Set([...SETTINGS_AREAS, "files", "terminals"]);

/**
 * What the dotted callee/reference `chain` means. `rooted`: the chain is known to start at the SDK (an alias of `sdk`, `bb.sdk`, `useSdk()`).
 * Returns null for anything that is not an SDK right (a different object that happens to have a `threads` property).
 */
export function classifySdkChain(chain: string, rooted = false): SdkRight | SdkUnclassified | null {
  const parts = chain.split(".");
  const t = areaOf(parts, THREADS);
  if (t) {
    const method = t.rest.join(".");
    const first = t.rest[0]!;
    const isSdk = t.rooted || rooted || !THREADS_AMBIGUOUS.has(first);
    if (!isSdk) return null;
    // `queuedMessages.list` is a read, the other queuedMessages calls are not; a bare `interactions` / `queuedMessages` is the area itself.
    if (THREADS_ANSWER.has(method)) return { kind: "sdk_answer", detail: `threads.${method}` };
    if (THREADS_SEND.has(method)) return { kind: "sdk_send", detail: `threads.${method}` };
    if (THREADS_AGENTS.has(method)) return { kind: "sdk_agents", detail: `threads.${method}` };
    if (THREADS_READ.has(method)) return { kind: "sdk_read", detail: `threads.${method}` };
    if (THREADS_HARMLESS.has(method) || THREADS_HARMLESS.has(first)) return null;
    if (["events", "queue", "interactions", "queuedMessages"].includes(first) && t.rest.length === 1) return null; // the area itself, not a call
    return t.rooted || rooted ? { unclassified: true, detail: `threads.${method}` } : null;
  }
  const o = areaOf(parts, OTHER_AREAS);
  if (o && (o.rooted || rooted)) {
    const method = o.rest.join(".");
    const last = o.rest[o.rest.length - 1]!;
    if (o.area === "files") return { kind: "fs", detail: `sdk.files.${method}` };
    if (o.area === "terminals") return /^(create|input|restart)$/.test(last) ? { kind: "child_process", detail: `sdk.terminals.${method}` } : null;
    if (SETTINGS_SECRET_READS.has(last) || (MUTATING.test(last) && !SETTINGS_BENIGN.has(last))) return { kind: "sdk_settings", detail: `${o.area}.${method}` };
    return null;
  }
  return null;
}

/** An SDK area reached through a computed key (`sdk.threads[name](…)`): which call it is, is not known. */
export const isThreadsArea = (chain: string): boolean => /(^|\.)threads$/.test(chain);

// ---- the page --------------------------------------------------------------------------------------------------------------
/** Finding an element of the page that the plugin did not draw itself. */
export const DOM_LOOKUPS = new Set(["querySelector", "querySelectorAll", "getElementById", "getElementsByClassName", "getElementsByTagName", "getElementsByName", "closest", "elementFromPoint", "elementsFromPoint", "getElementsByTagNameNS"]);
/** Pressing it: a call on the element, or an event sent to it. */
export const DOM_PRESSES: Record<string, { minArgs: number; maxArgs: number; detail: string }> = {
  click: { minArgs: 0, maxArgs: 0, detail: "click()" },
  requestSubmit: { minArgs: 0, maxArgs: 1, detail: "requestSubmit()" },
  submit: { minArgs: 0, maxArgs: 0, detail: "submit()" },
  dispatchEvent: { minArgs: 1, maxArgs: 1, detail: "dispatchEvent()" },
};
/** Events built by hand to be sent to an element. */
export const SYNTHETIC_EVENTS = new Set(["MouseEvent", "PointerEvent", "KeyboardEvent", "InputEvent", "TouchEvent", "FocusEvent", "SubmitEvent"]);
/**
 * A string that says which button the plugin goes for. The buttons of an agent's question or permission request («Next», «Submit», «Allow»)
 * are the ones a plugin presses to answer for the person.
 */
const ANSWER_WORDS = /\b(question|answer|permission|approv\w*|interaction|ask-?user|elicitation)\b/i;
const ANSWER_BUTTONS = /^(next|submit|allow|approve|accept|confirm|continue|yes|ok|send|deny|reject|allow once|allow always)$/i;
export const looksLikeAnswerButton = (s: string): boolean => {
  const t = s.trim();
  return t.length > 0 && t.length <= 80 && (ANSWER_BUTTONS.test(t) || ANSWER_WORDS.test(t));
};
/** The detail of the `ui_click` right when the plugin goes for an agent's question widget. */
export const UI_CLICK_ANSWERS = "agent-prompts";

/** The detail of an `fs` right when the code reaches the person's own folders (home directory, Documents…). */
export const FS_HOME = "home";
