// The plan of the cards of the first screen, as a hook: ONE card per plugin (its latest version, the other versions that wait are folded under it), in an order that
// holds while the page is open (what was there keeps its place, what is new goes to the end and is marked «новое»), and the one «you often approve this» hint.
import { useRef } from "react";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";
import { approvalEventsOf, decisionOf, layoutItems, pickFrequent, planCards, stableOrder, trustButton, windowAvailability, type CardPlan, type Decisions, type FreqCard, type PluginCard, type Stub } from "../src/ux";
import { heldOf } from "../src/pageview";

/** The card of a plugin as the hint reads it: can its source be trusted by one touch, can a window be opened. */
function freqCards(ov: Overview, active: Array<PluginCard<QueueRow>>): FreqCard[] {
  return active.map((c) => {
    const u = ov.ux[c.shown.id];
    const level = u?.level ?? "unknown";
    return { pluginId: c.pluginId, source: c.shown.source, canTrust: trustButton({ entry: u?.entry ?? null, level, queueId: c.shown.id }).enabled, canWindow: windowAvailability({ threadId: c.shown.threadId, queueId: c.shown.id, sourceKind: c.shown.sourceKind, level }).available };
  });
}

export interface CardPlanView {
  held: QueueRow[];
  plan: CardPlan<QueueRow>;
  activeItems: ReturnType<typeof layoutItems>;
  /** The order of the put-aside cards. */
  laterOrder: string[];
  /** The plugins whose cards came after the page was opened. */
  fresh: ReadonlySet<string>;
  freqPick: ReturnType<typeof pickFrequent>;
  isDeferred: (q: QueueRow) => boolean;
  isKept: (q: QueueRow) => boolean;
}

export function useCardPlan(ov: Overview, decisions: Decisions, freq: { off: boolean; lastAt: number | null }, stubs: Stub[]): CardPlanView {
  const orderRef = useRef<string[] | null>(null);
  const laterOrderRef = useRef<string[] | null>(null);
  const freshRef = useRef<Set<string>>(new Set());
  const held = heldOf(ov);
  const plan = planCards(held, decisions);
  const active = stableOrder(orderRef.current, plan.active.map((c) => c.pluginId), stubs.map((x) => x.key));
  orderRef.current = active.order;
  const later = stableOrder(laterOrderRef.current, plan.later.map((c) => c.pluginId));
  laterOrderRef.current = later.order;
  for (const k of [...active.fresh, ...later.fresh]) freshRef.current.add(k);
  // The count is by the journal: the guard's in guard mode, the plugin's own otherwise (the guard's record would count the same approval twice).
  const events = approvalEventsOf(ov.guard?.connected ? (ov.guard.recent ?? []) : ov.log);
  return {
    held,
    plan,
    activeItems: layoutItems(active.order, new Set(plan.active.map((c) => c.pluginId)), stubs),
    laterOrder: later.order,
    fresh: freshRef.current,
    freqPick: pickFrequent(freqCards(ov, plan.active), events, ov.now, freq, ov.policy.windowMin),
    isDeferred: (q) => decisionOf(q, decisions) === "deferred",
    isKept: (q) => decisionOf(q, decisions) === "kept",
  };
}
