// The card of a version the guard did not read says so, and does not call the plugin harmful. «Ведёт себя как вредоносный» is for real hard flags only.
// The decision (`liftBlock`) is the same for both: a fresh touch and the acknowledgement; only the words differ.
import { describe, expect, it } from "vitest";
import { isBlockedEntry, isUnreadOnly, liftOf, redText, unreadText } from "../src/ux.js";

const none: Array<{ rule: string; severity: string }> = [];
const unread = { reason: "источник не назван (не github и не каталог на диске)", reasonKind: "other", blocks: null, findings: none };

describe("a version the guard could not read", () => {
  it("is red (it needs the acknowledgement and a fresh touch) but is told as «not read», with the guard's reason", () => {
    expect(isBlockedEntry(unread)).toBe(true);
    expect(liftOf(unread)).toMatchObject({ needsAck: true, why: "unread", never: false });
    expect(isUnreadOnly(unread)).toBe(true);
    const t = unreadText("chime", "1.0.0", unread.reason);
    expect(t.title).toBe("Сторож не смог сам прочитать эту версию");
    expect(t.line).toContain("Причина: источник не назван (не github и не каталог на диске).");
    expect(t.line).toContain("Разрешить можно только с подтверждением риска и свежим касанием");
    expect(`${t.title} ${t.line}`).not.toMatch(/вредонос/);
  });
  it("without a note it says the reason is not recorded, still not «harmful»", () => {
    const t = unreadText("chime", "1.0.0", null);
    expect(t.line).toContain("Причина в записи сторожа не указана.");
    expect(`${t.title} ${t.line}`).not.toMatch(/вредонос/);
  });
});

describe("«ведёт себя как вредоносный» stays for what was really found", () => {
  it("real hard flags found by the guard: red, not «unread», and the old words", () => {
    const found = { reason: "жёсткий флаг: decode-eval a.js:1", reasonKind: "block", blocks: ["decode-eval a.js:1"], findings: none };
    expect(isBlockedEntry(found)).toBe(true);
    expect(isUnreadOnly(found)).toBe(false);
    expect(redText([]).title).toBe("плагин ведёт себя как вредоносный");
  });
  it("a version the guard read and found clean is not red and not «unread»", () => {
    const clean = { reason: "неизвестный источник", reasonKind: "unknown-source", blocks: [], findings: none };
    expect(isBlockedEntry(clean)).toBe(false);
    expect(isUnreadOnly(clean)).toBe(false);
  });
  it("unread by the guard but with a block found by the plugin's own checks: the red words, with the real rule", () => {
    const both = { ...unread, findings: [{ rule: "decode-eval", severity: "block" }] };
    expect(isBlockedEntry(both)).toBe(true);
    expect(isUnreadOnly(both)).toBe(false);
  });
  it("an entry without the guard's facts (the plugin's own, no guard) is never «unread»: its words decide as before", () => {
    expect(isUnreadOnly({ reason: "заблокировано проверками: decode-eval", findings: none })).toBe(false);
  });
  it("a hash mismatch is its own thing, not «unread»", () => {
    const mis = { reason: "хеш не совпал", reasonKind: "mismatch", blocks: null, findings: none };
    expect(isUnreadOnly(mis)).toBe(false);
    expect(liftOf(mis).never).toBe(true);
  });
});
