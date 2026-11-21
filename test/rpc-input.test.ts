import { describe, expect, it } from "vitest";
import { buildPolicyChange, buildPolicySetInput, buildPolicyTouchQuery, defined } from "../src/rpc-input";

const form = { windowMin: "30", capMin: "240", mode: "sliding", scope: "tree", cfgWindowMin: "10", cfgCapMin: "240", cfgMode: "sliding" } as const;
const noUndefined = (o: object) => expect(Object.values(o).some((v) => v === undefined)).toBe(false);

describe("defined", () => {
  it("drops undefined keys, keeps other falsy values", () => {
    expect(defined({ a: undefined, b: false, c: 0, d: "", e: null })).toEqual({ b: false, c: 0, d: "", e: null });
    expect("a" in defined({ a: undefined })).toBe(false);
  });
});

describe("policy.set input", () => {
  it("guard mode (autoSafe undefined): no autoSafe key, no undefined anywhere", () => {
    const change = buildPolicyChange({ ...form, autoSafe: undefined });
    expect("autoSafe" in change).toBe(false);
    for (const input of [buildPolicySetInput(change, { code: "123456" }), buildPolicySetInput(change, {}), buildPolicyTouchQuery(change)]) {
      noUndefined(input);
      expect("autoSafe" in input).toBe(false);
    }
    // survives the JSON round trip unchanged
    const input = buildPolicySetInput(change, { code: "123456" });
    expect(JSON.parse(JSON.stringify(input))).toEqual(input);
  });

  it("normal mode: autoSafe is sent (false too); the touch query never carries it", () => {
    for (const autoSafe of [true, false]) {
      const change = buildPolicyChange({ ...form, autoSafe });
      const input = buildPolicySetInput(change, { code: "123456" });
      noUndefined(input);
      expect(input.autoSafe).toBe(autoSafe);
      expect(input.windowMin).toBe(30);
      expect(input.code).toBe("123456");
      const q = buildPolicyTouchQuery(change);
      noUndefined(q);
      expect("autoSafe" in q).toBe(false);
      expect(q.kind).toBe("policy");
    }
  });

  it("an undefined proof field is dropped", () => {
    noUndefined(buildPolicySetInput(buildPolicyChange({ ...form, autoSafe: true }), { passkey: undefined, code: undefined }));
  });
});
