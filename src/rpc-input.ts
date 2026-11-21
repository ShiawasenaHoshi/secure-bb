// Helpers for building RPC inputs. bb rejects a field whose value is `undefined` ("is not a JSON value"),
// so inputs assembled from state that may be undefined must pass through `defined`.

/** A copy of `obj` without the keys whose value is `undefined` (other falsy values stay). */
export function defined<T extends Record<string, unknown>>(obj: T): { [K in keyof T]: Exclude<T[K], undefined> } {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) if (v !== undefined) out[k] = v;
  return out as { [K in keyof T]: Exclude<T[K], undefined> };
}

export interface PolicyForm {
  /** Absent in guard mode: "safe class passes" does not exist there. */
  autoSafe: boolean | undefined;
  windowMin: string;
  capMin: string;
  mode: "sliding" | "fixed";
  scope: "tree" | "thread";
  cfgWindowMin: string;
  cfgCapMin: string;
  cfgMode: "sliding" | "fixed";
}

/** The policy change from the form: no `autoSafe` key when it is undefined (guard mode). */
export function buildPolicyChange(f: PolicyForm) {
  return defined({
    autoSafe: f.autoSafe,
    windowMin: Number(f.windowMin),
    capMin: Number(f.capMin),
    mode: f.mode,
    scope: f.scope,
    cfgWindowMin: Number(f.cfgWindowMin),
    cfgCapMin: Number(f.cfgCapMin),
    cfgMode: f.cfgMode,
  });
}

/** The `passkey.challenge` query for a policy change: the same change without `autoSafe` (it never widens by itself there). */
export function buildPolicyTouchQuery(change: ReturnType<typeof buildPolicyChange>) {
  const { autoSafe: _omit, ...rest } = change;
  return { kind: "policy" as const, ...rest };
}

/** The full `policy.set` input: the change plus the proof (touch, else 6-digit code). */
export function buildPolicySetInput(change: ReturnType<typeof buildPolicyChange>, proof: { passkey?: unknown; code?: string }) {
  return defined({ ...change, ...proof });
}
