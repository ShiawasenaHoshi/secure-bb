// The policy of trust windows, and the ONE place that says which change of it WIDENS (and so needs a fresh factor: a code or a touch).
// The guard keeps the part that is its own (`GuardPolicy`: window size, ceiling, mode); the plugin keeps the rest (`LocalPolicy`: thread scope, the
// configuration windows, the safe-class pass, `flow.downgrade`). A change is checked by three callers — the guard (`setPolicy`), the plugin without a guard
// (`Gate.setPolicy`) and the plugin over a guard (`policyPlan`) — and all of them ask the functions below; none keeps a comparison of its own.
// A new field of the policy cannot be added without a row in `POLICY_FIELDS` (the type demands it), and test/policy-widens.test.ts walks the table.

export interface GuardPolicy {
  /** Default size of a window, minutes. */
  windowMin: number;
  /** Hard ceiling of a window from its opening, minutes. */
  capMin: number;
  mode: "sliding" | "fixed";
}
export interface LocalPolicy {
  /** Which threads a window covers: the thread it was opened from, or its whole tree. */
  scope: "tree" | "thread";
  /** Configuration trust window (spec §6): size in minutes, default 10. */
  cfgWindowMin: number;
  /** Hard ceiling of one configuration window, minutes. */
  cfgCapMin: number;
  cfgMode: "sliding" | "fixed";
  /**
   * Threat model F7: any server code of a plugin runs in the gate's process and uid and can rewrite its state, so
   * "clean checks, no capabilities" is not a reason to skip the touch. Off by default; turned on only with a code. Does not exist in guard mode.
   */
  autoSafe: boolean;
  /**
   * `flow.downgrade`: a card may be less red because the checks followed what a plugin reads and found no way out. Off by default: the analysis is not yet
   * proven complete, so «никуда не отправляет» is told but does not lower the level. Turning it on loosens the protection: only with a code or a touch.
   */
  flowDowngrade: boolean;
}
export type FullPolicy = GuardPolicy & LocalPolicy;

export interface PolicyField<V> {
  /** Whose field it is: the guard's own, or the plugin's. */
  owner: "guard" | "local";
  /** `next` is wider than `cur`: a longer window, a higher ceiling, sliding instead of fixed, the whole tree instead of the thread, a switch turned on. */
  widens: (cur: V, next: V) => boolean;
  /** For the test: a change that widens, and one that does not (a different value of the same field). */
  wide: { cur: V; next: V };
  narrow: { cur: V; next: V };
}
const more = (cur: number, next: number): boolean => next > cur;
const slidingOverFixed = (cur: "sliding" | "fixed", next: "sliding" | "fixed"): boolean => next === "sliding" && cur === "fixed";
const turnedOn = (cur: boolean, next: boolean): boolean => next && !cur;

export const POLICY_FIELDS: { [K in keyof FullPolicy]: PolicyField<FullPolicy[K]> } = {
  windowMin: { owner: "guard", widens: more, wide: { cur: 30, next: 60 }, narrow: { cur: 60, next: 30 } },
  capMin: { owner: "guard", widens: more, wide: { cur: 240, next: 480 }, narrow: { cur: 480, next: 240 } },
  mode: { owner: "guard", widens: slidingOverFixed, wide: { cur: "fixed", next: "sliding" }, narrow: { cur: "sliding", next: "fixed" } },
  scope: { owner: "local", widens: (cur, next) => next === "tree" && cur === "thread", wide: { cur: "thread", next: "tree" }, narrow: { cur: "tree", next: "thread" } },
  cfgWindowMin: { owner: "local", widens: more, wide: { cur: 10, next: 20 }, narrow: { cur: 20, next: 10 } },
  cfgCapMin: { owner: "local", widens: more, wide: { cur: 240, next: 480 }, narrow: { cur: 480, next: 240 } },
  cfgMode: { owner: "local", widens: slidingOverFixed, wide: { cur: "fixed", next: "sliding" }, narrow: { cur: "sliding", next: "fixed" } },
  autoSafe: { owner: "local", widens: turnedOn, wide: { cur: false, next: true }, narrow: { cur: true, next: false } },
  flowDowngrade: { owner: "local", widens: turnedOn, wide: { cur: false, next: true }, narrow: { cur: true, next: false } },
};

const widensAmong = (owner: "guard" | "local", cur: Partial<FullPolicy>, next: Partial<FullPolicy>): boolean =>
  (Object.keys(POLICY_FIELDS) as Array<keyof FullPolicy>).some((k) => {
    const f = POLICY_FIELDS[k] as PolicyField<unknown>;
    return f.owner === owner && cur[k] !== undefined && next[k] !== undefined && f.widens(cur[k], next[k]);
  });
/** The guard's own fields (window size, ceiling, mode): does `next` widen `cur`? */
export const guardPolicyWidens = (cur: GuardPolicy, next: GuardPolicy): boolean => widensAmong("guard", cur, next);
/** The plugin's fields (thread scope, configuration windows, safe-class pass, `flow.downgrade`). */
export const localPolicyWidens = (cur: LocalPolicy, next: LocalPolicy): boolean => widensAmong("local", cur, next);
/** A window of this scope, opened under a policy of that scope, is wider than the policy: the same rule as for the policy's own `scope`. */
export const windowScopeWidens = (policyScope: LocalPolicy["scope"], windowScope: LocalPolicy["scope"] | undefined): boolean =>
  windowScope !== undefined && POLICY_FIELDS.scope.widens(policyScope, windowScope);
