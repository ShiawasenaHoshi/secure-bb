// Which way of proving a change this page offers, by where the page is open: the key where it can work, the code everywhere, a link to the right address.
import { describe, expect, it } from "vitest";
import { isDesktopApp, proofPlan, type ProofPlanInput } from "../src/proofplan";

const GUARD = "http://localhost:38886";
const base: ProofPlanInput = { currentOrigin: GUARD, currentPath: "/plugins/secure-bb/gate", guardOrigin: GUARD, hasKey: true, keyOnly: false, webauthn: true, desktopApp: false };

describe("proofPlan", () => {
  it("at the guard's own address in a browser: the key first, the code after, nothing to explain", () => {
    expect(proofPlan(base)).toEqual({ key: "first", code: true, note: null, openUrl: null });
  });

  it("on another origin (tailnet :8443): no key, the code, the words and a link to the right address", () => {
    const p = proofPlan({ ...base, currentOrigin: "https://mac.tail1234.ts.net:8443" });
    expect(p.key).toBe("none");
    expect(p.code).toBe(true);
    expect(p.note).toBe(`Ключ работает в браузере на ${GUARD}; здесь — код из приложения.`);
    expect(p.openUrl).toBe(`${GUARD}/plugins/secure-bb/gate`);
  });

  it("in the bb app: the code first, the key only after it and only where the origin is right; a link either way", () => {
    expect(isDesktopApp("Mozilla/5.0 (Macintosh) Chrome/140 Electron/44.1 Safari/537")).toBe(true);
    expect(isDesktopApp("Mozilla/5.0 (Macintosh) Chrome/140 Safari/537")).toBe(false);
    const wrong = proofPlan({ ...base, currentOrigin: "https://mac.tail1234.ts.net:8443", desktopApp: true });
    expect(wrong).toMatchObject({ key: "none", code: true, openUrl: `${GUARD}/plugins/secure-bb/gate` });
    expect(wrong.note).toContain("приложении bb");
    expect(proofPlan({ ...base, desktopApp: true })).toMatchObject({ key: "second", code: true, openUrl: `${GUARD}/plugins/secure-bb/gate` });
  });

  it("codes switched off and no way to touch here: it says so and gives the link, and offers no code", () => {
    const p = proofPlan({ ...base, currentOrigin: "https://x.ts.net:8443", keyOnly: true, desktopApp: true });
    expect(p).toMatchObject({ key: "none", code: false });
    expect(p.note).toContain("Коды отключены");
    expect(p.openUrl).not.toBeNull();
  });

  it("a browser without WebAuthn at the right address: the code, and no link to the same place", () => {
    const p = proofPlan({ ...base, webauthn: false });
    expect(p).toMatchObject({ key: "none", code: true, openUrl: null });
    expect(p.note).toContain("нет WebAuthn");
  });

  it("no key registered: the code alone, nothing said", () => {
    expect(proofPlan({ ...base, hasKey: false, currentOrigin: "https://x.ts.net:8443" })).toEqual({ key: "none", code: true, note: null, openUrl: null });
  });

  it("the link takes the guard's origin and this page's path only: never the query or the fragment of this page", () => {
    const p = proofPlan({ ...base, currentOrigin: "https://x.ts.net:8443", currentPath: "/plugins/secure-bb/gate" });
    expect(new URL(p.openUrl!).origin).toBe(GUARD);
    expect(p.openUrl).not.toMatch(/[?#]/);
  });
});
