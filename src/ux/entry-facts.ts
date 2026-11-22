// The facts a card is built on, as predicates: is it blocked, is it a mismatch, can it be put back, is there a record at the guard. Every decision about a block is the guard's `liftBlock` (guard/src/trust.ts), reached through `liftOfEntry`; nothing here decides by itself.
import type { TrustMode } from "../guardlink.js";
import { isReasonKind, type ReasonKind as GuardReasonKind } from "../../guard/src/lift.ts";
import { bypassOffered, isMismatchWords, liftOfEntry } from "../../guard/src/lift.ts";

export type CardColor = "red" | "yellow";

export interface ReviewEntry {
  id: number;
  status: string;
  reason: string | null;
  /** The guard's facts about the entry (guard mode); when `reasonKind` is present the words of `reason` are not looked at. */
  reasonKind?: string | null;
  blocks?: string[] | null;
  /** Checks of this version: severities of the findings. */
  findings: Array<{ rule: string; severity: string }>;
}

/** The gate's own words for a mismatch (the guard's fact is `reasonKind: "mismatch"`; the words are read in guard/src/trust.ts). */
export const isMismatch = (reason: string | null): boolean => isMismatchWords(reason);

/** An entry as the page holds it: the words of the reason, and (from the guard) the facts it read itself. */
export interface EntryFacts {
  reason: string | null;
  reasonKind?: string | null;
  blocks?: string[] | null;
}

/** The entry comes from the guard and carries its facts: then no word of `reason` decides anything. */
const hasFacts = (e: EntryFacts): boolean => e.reasonKind !== undefined || e.blocks !== undefined;

/** The one rule of lifting a stop (`liftBlock`, guard/src/trust.ts) on an entry as the page holds it: the guard's facts, or the facts read from the gate's words. */
export const liftOf = (e: EntryFacts, mode: TrustMode | null = null) => liftOfEntry(e, mode);

export const isMismatchEntry = (e: EntryFacts): boolean => liftOf(e).never;

export const isBlockedEntry = (e: Pick<ReviewEntry, "reason" | "findings" | "reasonKind" | "blocks">): boolean => {
  const lift = liftOf(e);
  return lift.never || lift.needsAck || e.findings.some((f) => f.severity === "block");
};

/** Why the guard held a version (the card's words follow this, not a default): its fact when it has one, else the words of an entry the plugin keeps itself. */
export type ReasonKind = GuardReasonKind;

export function reasonKind(reason: string | null): ReasonKind {
  const r = reason ?? "";
  if (isMismatch(r)) return "mismatch";
  if (/новое право|новое замечание/.test(r)) return "growth";
  if (/неизвестный источник|нельзя назвать своим/.test(r)) return "unknown-source";
  if (/Строгий/.test(r)) return "strict";
  if (/нет одобренной версии/.test(r)) return "first";
  return "other";
}

export const entryReasonKind = (e: EntryFacts): ReasonKind => (hasFacts(e) ? (isReasonKind(e.reasonKind) ? e.reasonKind : "other") : reasonKind(e.reason));

/** «Всё равно разрешить…» on a red card: decided by `bypassOffered` (guard/src/trust.ts), not here. */
export const bypassAllowed = (mode: TrustMode | null, e: EntryFacts): boolean => bypassOffered(e, mode);

/** A rejected version (a card the person dismissed): the version's own version can be put back only if its files are what was checked. */
export const canRestore = (q: EntryFacts & { contentHash: string | null }): boolean => !isMismatchEntry(q) && q.contentHash !== null;

/** The page's own record of a version that loaded without the guard's check: it has no core hash, so it cannot be approved by hash. */
export const hasNoGuardRecord = (q: { kind: string; contentHash: string | null }): boolean => q.kind === "afterfact" && q.contentHash === null;

/**
 * In guard mode the card of a version comes from the guard's own record. A page-side record of the same version (it has no core hash) is dropped when
 * the guard has one; otherwise two cards would stand for one version, and the one without the hash would say «Включить» where nothing can be enabled.
 */
export function dropShadowedLocal<T extends { pluginId: string; version: string }>(guardEntries: Array<{ pluginId: string; version: string }>, local: T[]): T[] {
  const have = new Set(guardEntries.map((g) => `${g.pluginId}\0${g.version}`));
  return local.filter((l) => !have.has(`${l.pluginId}\0${l.version}`));
}
