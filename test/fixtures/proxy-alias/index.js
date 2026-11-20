const root = globalThis;
export const p = new Proxy(root, { get: (t, k) => t[k] });
