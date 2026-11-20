// Minimal Standard Schema v1 validators. secure-bb is the root of trust and
// has zero runtime dependencies, so it cannot ship zod; the SDK only needs
// objects that implement the Standard Schema interface.

export interface Issue {
  message: string;
  path?: ReadonlyArray<string | number>;
}
type Result<T> = { value: T } | { issues: Issue[] };

export interface Schema<T> {
  readonly "~standard": {
    readonly version: 1;
    readonly vendor: "secure-bb";
    readonly validate: (value: unknown) => Result<T>;
    readonly types?: { readonly input: T; readonly output: T };
  };
}

function make<T>(check: (value: unknown) => Result<T>): Schema<T> {
  return { "~standard": { version: 1, vendor: "secure-bb", validate: check } };
}

const fail = (message: string, path: Array<string | number> = []): { issues: Issue[] } => ({
  issues: [{ message, path }],
});

export const string = (opts: { max?: number; min?: number } = {}): Schema<string> =>
  make((v) => {
    if (typeof v !== "string") return fail("expected a string");
    if (opts.min !== undefined && v.length < opts.min) return fail(`at least ${opts.min} characters`);
    if (v.length > (opts.max ?? 4096)) return fail("string too long");
    return { value: v };
  });

export const integer = (opts: { min?: number; max?: number } = {}): Schema<number> =>
  make((v) => {
    if (typeof v !== "number" || !Number.isInteger(v)) return fail("expected an integer");
    if (opts.min !== undefined && v < opts.min) return fail(`must be >= ${opts.min}`);
    if (opts.max !== undefined && v > opts.max) return fail(`must be <= ${opts.max}`);
    return { value: v };
  });

export const boolean = (): Schema<boolean> =>
  make((v) => (typeof v === "boolean" ? { value: v } : fail("expected a boolean")));

export const nullValue = (): Schema<null> =>
  make((v) => (v === null || v === undefined ? { value: null } : fail("expected null")));

export const oneOf = <const T extends string>(values: readonly T[]): Schema<T> =>
  make((v) =>
    typeof v === "string" && (values as readonly string[]).includes(v)
      ? { value: v as T }
      : fail(`expected one of ${values.join(", ")}`),
  );

export const array = <T>(item: Schema<T>, opts: { max?: number } = {}): Schema<T[]> =>
  make((v) => {
    if (!Array.isArray(v)) return fail("expected an array");
    if (v.length > (opts.max ?? 64)) return fail("array too long");
    const out: T[] = [];
    for (let i = 0; i < v.length; i++) {
      const res = item["~standard"].validate(v[i]);
      if ("issues" in res) return { issues: res.issues.map((x) => ({ message: x.message, path: [i, ...(x.path ?? [])] })) };
      out.push(res.value);
    }
    return { value: out };
  });

/** Marks an object field optional. */
export const optional = <T>(schema: Schema<T>): Schema<T | undefined> =>
  make((v) => (v === undefined ? { value: undefined } : schema["~standard"].validate(v) as Result<T | undefined>));

/** Strict object: unknown keys are rejected. */
type Val<X> = X extends Schema<infer T> ? T : never;
type Obj<S> = { [K in keyof S as undefined extends Val<S[K]> ? never : K]: Val<S[K]> } & {
  [K in keyof S as undefined extends Val<S[K]> ? K : never]?: Val<S[K]>;
};
export function object<S extends Record<string, Schema<any>>>(shape: S): Schema<Obj<S>> {
  return make((v) => {
    if (typeof v !== "object" || v === null || Array.isArray(v)) return fail("expected an object");
    const input = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const issues: Issue[] = [];
    for (const key of Object.keys(input)) {
      if (!(key in shape)) issues.push({ message: "unknown key", path: [key] });
    }
    for (const [key, schema] of Object.entries(shape)) {
      const res = schema["~standard"].validate(input[key]);
      if ("issues" in res) {
        for (const issue of res.issues) issues.push({ message: issue.message, path: [key, ...(issue.path ?? [])] });
      } else if (res.value !== undefined) out[key] = res.value;
    }
    return issues.length > 0 ? { issues } : { value: out as never };
  });
}

/**
 * Output schema: results are produced by our own code, so only JSON-ness is
 * enforced by the host. This keeps the contract typed without duplicating
 * every response shape as a validator.
 */
export const json = <T>(): Schema<T> => make((v) => ({ value: v as T }));

