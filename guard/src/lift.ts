// What may lift a held version: ONE rule, read from the guard's own facts and never from a note's words. A LEAF: it imports nothing, not even `node:*`, because the
// page (which is built for the browser) calls it too; `trust.ts` re-exports it for the guard. Do not add an import here that reaches the analyser or Node.
export type TrustMode = "simple" | "detailed" | "strict";

/** Why a version is held (the guard's own reading). `mismatch`: the directory's hash is not the request's; `block`: a hard flag; `growth`: a new right. */
export const REASON_KINDS = ["mismatch", "block", "growth", "unknown-source", "strict", "first", "other"] as const;
export type ReasonKind = (typeof REASON_KINDS)[number];
export const isReasonKind = (x: unknown): x is ReasonKind => typeof x === "string" && (REASON_KINDS as readonly string[]).includes(x);

export interface LiftInput {
  /** Absent (an entry older than the column, or from a guard that predates it): unknown. */
  reasonKind?: string | null;
  /** The hard flags the guard's own `evaluate` found. `null` or absent: the guard did not read the version, so a block may be there. */
  blocks?: string[] | null;
}
export interface Lift {
  /** Never: the directory is not what the request says (reinstall). */
  never: boolean;
  /** A hard flag is there, or may be (not read): approving takes `acknowledgeBlock` AND a fresh touch; a session never covers it. */
  needsAck: boolean;
  /** Why `needsAck`: `block` (flags found) or `unread` (nothing was read). */
  why: "mismatch" | "block" | "unread" | null;
  /** Strict mode lets no block be lifted. */
  refusedByMode: boolean;
}
/**
 * The ONE rule of lifting a stop, used by the guard (`approve`, batch, «Вернуть», «доверять источнику») and by the page (the buttons it shows).
 * It reads facts: `reasonKind === "mismatch"`, a non-empty `blocks`, or `blocks` not read at all. A note's text is never looked at.
 */
export function liftBlock(e: LiftInput, mode: TrustMode | null): Lift {
  const kind = e.reasonKind ?? null;
  if (kind === "mismatch") return { never: true, needsAck: true, why: "mismatch", refusedByMode: false };
  const unread = e.blocks === null || e.blocks === undefined;
  const found = !unread && (e.blocks as string[]).length > 0;
  const needsAck = unread || found || kind === "block";
  return { never: false, needsAck, why: !needsAck ? null : found || kind === "block" ? "block" : "unread", refusedByMode: needsAck && mode === "strict" };
}

// ---- the same rule for an entry that has only words -----------------------------------------------------------------------------
// An entry the PLUGIN keeps itself (no guard) has no facts the guard read, only the words its gate wrote in `reason`. Those words are turned into facts HERE, and
// then the one rule above decides: the page does not decide anything about a block by itself.
export interface EntryLiftInput extends LiftInput {
  reason: string | null;
}
/** «the directory's files did not match the hash of the request»: the words of the gate's own reason for a mismatch. */
export const isMismatchWords = (reason: string | null): boolean => /не совпал с хешем/.test(reason ?? "");
const BLOCKED_WORDS = /заблокирован(о)? проверками|жёсткий флаг/;
/** The facts an entry kept by the plugin states in words. A block in the words is a flag found; no such words means nothing was found (the plugin's own gate has read it). */
export function factsOfReasonWords(reason: string | null): { reasonKind: string | null; blocks: string[] } {
  return { reasonKind: isMismatchWords(reason) ? "mismatch" : null, blocks: BLOCKED_WORDS.test(reason ?? "") ? ["words"] : [] };
}
/** The entry comes from the guard and carries its facts: then no word of `reason` decides anything. */
const carriesFacts = (e: LiftInput): boolean => e.reasonKind !== undefined || e.blocks !== undefined;
/** `liftBlock` for an entry as the page holds it: by the guard's facts when it has them, else by the facts read from the gate's words. */
export function liftOfEntry(e: EntryLiftInput, mode: TrustMode | null): Lift {
  return liftBlock(carriesFacts(e) ? { reasonKind: e.reasonKind ?? null, blocks: e.blocks ?? null } : factsOfReasonWords(e.reason), mode);
}
/** «Всё равно разрешить…» exists on a red card only if the mode allows it (Strict does not) AND the stop is not a mismatch (an approval would be written for the hash of a suspect request). */
export function bypassOffered(e: EntryLiftInput, mode: TrustMode | null): boolean {
  return mode !== "strict" && !liftOfEntry(e, mode).never;
}
