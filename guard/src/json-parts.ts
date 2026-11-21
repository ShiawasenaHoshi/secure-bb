// A change of a Claude Code settings file, split into parts by the path inside the JSON (design: «принять своё, откатить чужое»).
//
// A part is one key (a scalar, or a list taken as a whole when its type changed) or one ELEMENT of a list (`permissions.allow`, `hooks.PreToolUse`…).
// Pure functions, no I/O: the guard works the parts out from its own baseline and the file it read, never from what a page sends; the page only names
// a part by its id (a hash of what the part is), so a part that is not in the current difference is simply not found.
import { createHash } from "node:crypto";
import { analyze, isTightening, maskSecrets } from "./agents-rules.ts";
import { applyPathChange, settingsPathAllowed, type PathAction } from "./restore.ts";

export type PartKind = "key-added" | "key-changed" | "key-removed" | "elem-added" | "elem-removed";
export interface JsonPart {
  /** 16 hex digits: what the part is (path, kind and values), so the same change has the same id on every look. */
  id: string;
  path: string[];
  kind: PartKind;
  before?: unknown;
  after?: unknown;
  elem?: unknown;
}
export const MAX_PARTS = 100;
const MAX_DEPTH = 8;

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const has = (o: Record<string, unknown>, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
export function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (isPlain(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
}
const partId = (p: Omit<JsonPart, "id">): string => createHash("sha256").update(stable([p.path, p.kind, p.before ?? null, p.after ?? null, p.elem ?? null])).digest("hex").slice(0, 16);

const parse = (t: string): Record<string, unknown> | null => {
  try {
    const v = JSON.parse(t) as unknown;
    return isPlain(v) ? v : null;
  } catch {
    return null;
  }
};

/**
 * The parts of the difference between the approved text (`base`, null: there was none) and the file as it is now. Null: it cannot be split (not JSON, too deep,
 * more than MAX_PARTS parts): then only «Вернуть всё» / «Принять» work on the whole file.
 */
export function splitSettings(base: string | null, now: string): JsonPart[] | null {
  const b = base === null ? {} : parse(base);
  const n = parse(now);
  if (b === null || n === null) return null;
  const out: JsonPart[] = [];
  let ok = true;
  const push = (p: Omit<JsonPart, "id">): void => {
    if (out.length >= MAX_PARTS) return void (ok = false);
    out.push({ ...p, id: partId(p) });
  };
  const walk = (was: unknown, is: unknown, path: string[]): void => {
    if (!ok) return;
    if (path.length > MAX_DEPTH) return void (ok = false);
    if (stable(was) === stable(is)) return;
    if ((was === undefined || isPlain(was)) && (is === undefined || isPlain(is)) && (isPlain(was) || isPlain(is))) {
      const w = (was ?? {}) as Record<string, unknown>;
      const i = (is ?? {}) as Record<string, unknown>;
      for (const k of [...new Set([...Object.keys(w), ...Object.keys(i)])].sort()) walk(has(w, k) ? w[k] : undefined, has(i, k) ? i[k] : undefined, [...path, k]);
      return;
    }
    if ((was === undefined || Array.isArray(was)) && (is === undefined || Array.isArray(is)) && path.length > 0) {
      const w = (was ?? []) as unknown[];
      const i = (is ?? []) as unknown[];
      const wk = new Set(w.map(stable));
      const ik = new Set(i.map(stable));
      for (const e of w) if (!ik.has(stable(e))) push({ path, kind: "elem-removed", elem: e });
      for (const e of i) if (!wk.has(stable(e))) push({ path, kind: "elem-added", elem: e });
      return;
    }
    if (path.length === 0) return void (ok = false);
    if (was === undefined) push({ path, kind: "key-added", after: is });
    else if (is === undefined) push({ path, kind: "key-removed", before: was });
    else push({ path, kind: "key-changed", before: was, after: is });
  };
  walk(b, n, []);
  return ok ? out : null;
}

/** What the part does when it is put back (`rollback`) or taken into the approved text (`forward`). */
export function partAction(p: JsonPart, direction: "forward" | "rollback"): { action: PathAction; value?: unknown } {
  const add = direction === "forward";
  switch (p.kind) {
    case "key-added":
      return add ? { action: "set", value: p.after } : { action: "delete" };
    case "key-changed":
      return { action: "set", value: add ? p.after : p.before };
    case "key-removed":
      return add ? { action: "delete" } : { action: "set", value: p.before };
    case "elem-added":
      return { action: add ? "array-add" : "array-remove", value: p.elem };
    case "elem-removed":
      return { action: add ? "array-remove" : "array-add", value: p.elem };
  }
}

/** The approved text with this part taken in: the new approved text. Null: it cannot be done. */
export function applyForward(base: string | null, p: JsonPart): string | null {
  const doc = base === null ? {} : parse(base);
  if (doc === null) return null;
  const a = partAction(p, "forward");
  try {
    applyPathChange(doc, p.path, a.action, a.value);
  } catch {
    return null;
  }
  return `${JSON.stringify(doc, null, 2)}\n`;
}

/** Can the helper put this part back? */
export const partRestorable = (p: JsonPart): boolean => settingsPathAllowed(p.path);

// ---- what makes the agent more dangerous ------------------------------------------------------------------------------------
const FILE = "x/.claude/settings.json";
/** The same rules as for the whole file, applied to this part alone: a reason in Russian, or null. */
export function partDanger(p: JsonPart): string | null {
  if (p.kind === "key-removed" || p.kind === "elem-removed") {
    const key = p.path.join(".");
    if (/^permissions\.(?:deny|ask)$/.test(key) || key === "permissions.disableBypassPermissionsMode" || key === "sandbox" || key.startsWith("sandbox.")) return `убирает ограничение (${key})`;
    return null;
  }
  const value = p.kind === "elem-added" ? [p.elem] : p.after;
  const doc: Record<string, unknown> = {};
  let cur = doc;
  p.path.forEach((k, i) => {
    if (i === p.path.length - 1) cur[k] = value;
    else cur = (cur[k] = {}) as Record<string, unknown>;
  });
  const a = analyze({ rel: FILE, kind: "claude-settings", change: "changed", prev: "{}", next: JSON.stringify(doc) });
  const bad = a.reasons.filter((r) => !isTightening(r));
  return a.cls === "critical" && bad.length > 0 ? bad[0]! : null;
}

// ---- what the page shows ---------------------------------------------------------------------------------------------------
const SECRET_NAME = /token|secret|password|passwd|api[_-]?key|apikey|authorization|credential|private[_-]?key/i;
const clip = (t: string, n = 160): string => (t.length > n ? `${t.slice(0, n)}…` : t);
/** A value for the screen: a secret is hidden (by the name of the key, and by what the value looks like), the rest is cut short. */
export function shownValue(path: readonly string[], v: unknown): string {
  if (v === undefined) return "";
  if (path.some((k) => SECRET_NAME.test(k))) return "«скрыто»";
  const t = typeof v === "string" ? v : JSON.stringify(v);
  return clip(maskSecrets(t ?? ""));
}

export interface PartView {
  id: string;
  path: string[];
  kind: PartKind;
  /** Before / after / the element, as text for the screen (secrets hidden). */
  before: string | null;
  after: string | null;
  elem: string | null;
  /** Why this makes the agent more dangerous, or null. */
  danger: string | null;
  /** The helper can put it back (the path is on its list). */
  restorable: boolean;
}
export function viewPart(p: JsonPart): PartView {
  const shown = (v: unknown): string | null => (v === undefined ? null : shownValue(p.path, v));
  const danger = partDanger(p);
  return { id: p.id, path: p.path, kind: p.kind, before: shown(p.before), after: shown(p.after), elem: shown(p.elem), danger: danger === null ? null : maskSecrets(danger), restorable: partRestorable(p) };
}
