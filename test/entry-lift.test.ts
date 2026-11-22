// A stop is lifted by ONE rule (`liftBlock`, guard/src/trust.ts). An entry that has only words gets its facts read from the words in trust.ts, and the page's predicates
// call it: none of them decides by itself.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bypassOffered, factsOfReasonWords, isMismatchWords, liftBlock, liftOfEntry } from "../guard/src/trust.ts";
import { bypassAllowed, isBlockedEntry, isMismatchEntry } from "../src/ux.ts";

const MIS = "каталог плагина не совпал с хешем запроса";
const BLOCK = "заблокировано проверками: decode-eval";

describe("the facts of an entry that has only words are read in trust.ts", () => {
  it("words → facts", () => {
    expect(isMismatchWords(MIS)).toBe(true);
    expect(isMismatchWords("новое право")).toBe(false);
    expect(factsOfReasonWords(MIS)).toEqual({ reasonKind: "mismatch", blocks: [] });
    expect(factsOfReasonWords(BLOCK)).toEqual({ reasonKind: null, blocks: ["words"] });
    expect(factsOfReasonWords("жёсткий флаг: x").blocks).toEqual(["words"]);
    expect(factsOfReasonWords("неизвестный источник")).toEqual({ reasonKind: null, blocks: [] });
  });
  it("liftOfEntry: the guard's facts win over the words; without facts the words are read", () => {
    expect(liftOfEntry({ reason: MIS }, null).never).toBe(true);
    expect(liftOfEntry({ reason: MIS, reasonKind: "other", blocks: [] }, null)).toEqual(liftBlock({ reasonKind: "other", blocks: [] }, null));
    expect(liftOfEntry({ reason: BLOCK }, "strict")).toEqual({ never: false, needsAck: true, why: "block", refusedByMode: true });
    expect(liftOfEntry({ reason: "новое право" }, null).needsAck).toBe(false);
  });
  it("bypass: not in Strict, never for a mismatch", () => {
    expect(bypassOffered({ reason: BLOCK }, "simple")).toBe(true);
    expect(bypassOffered({ reason: BLOCK }, "strict")).toBe(false);
    expect(bypassOffered({ reason: MIS }, "detailed")).toBe(false);
    expect(bypassOffered({ reason: "x", reasonKind: "mismatch", blocks: null }, "simple")).toBe(false);
  });
});

describe("the page's predicates agree with it", () => {
  it("same answers from ux and from trust", () => {
    for (const e of [{ reason: MIS }, { reason: BLOCK }, { reason: null }, { reason: "x", reasonKind: "other", blocks: [] as string[] }, { reason: "x", reasonKind: "mismatch", blocks: null }, { reason: "x", reasonKind: "other", blocks: ["decode-eval"] }]) {
      expect(isMismatchEntry(e)).toBe(liftOfEntry(e, null).never);
      expect(isBlockedEntry({ ...e, findings: [] })).toBe(liftOfEntry(e, null).never || liftOfEntry(e, null).needsAck);
      for (const m of ["simple", "detailed", "strict", null] as const) expect(bypassAllowed(m, e)).toBe(bypassOffered(e, m));
    }
    expect(isBlockedEntry({ reason: null, findings: [{ rule: "r", severity: "block" }] })).toBe(true);
  });
  it("the predicates do not read the words themselves", () => {
    const src = readFileSync(new URL("../src/ux/entry-facts.ts", import.meta.url), "utf8");
    expect(src).not.toMatch(/заблокирован|жёсткий флаг|не совпал с хешем/);
  });
});
