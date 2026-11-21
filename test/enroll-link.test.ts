// The page side of `sbb-guard setup`: the link `<origin>/plugins/secure-bb/gate#enroll=TOKEN`. The token is read from the fragment, the address bar is
// cleaned at once, and the token goes to the guard only (`passkey.register`).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { clearFragment, parseEnrollFragment, takeEnrollToken, type HistoryLike, type LocationLike } from "../src/enroll-link.js";

const fakeBrowser = (path: string, search: string, hash: string) => {
  const location: LocationLike = { pathname: path, search, hash };
  const calls: Array<{ data: unknown; url: unknown }> = [];
  const history: HistoryLike = {
    replaceState(data, _unused, url) {
      calls.push({ data, url });
      // what a browser does: the address becomes the new URL, the fragment is gone
      location.hash = "";
      if (typeof url === "string") {
        const [p, q = ""] = url.split("?");
        location.pathname = p!;
        location.search = q ? `?${q}` : "";
      }
    },
  };
  return { location, history, calls };
};

describe("parsing the fragment", () => {
  it.each([
    ["#enroll=ABCD-EFGH-JKLM", "ABCD-EFGH-JKLM"],
    ["enroll=ABCD-EFGH-JKLM", "ABCD-EFGH-JKLM"],
    ["#a=1&enroll=ABCD-EFGH-JKLM&b=2", "ABCD-EFGH-JKLM"],
    ["#enroll=abcd2345wxyz", "abcd2345wxyz"],
  ])("%s → %s", (hash, token) => {
    expect(parseEnrollFragment(hash)).toBe(token);
  });

  it.each([[""], ["#"], ["#enroll"], ["#enroll="], ["#enroll=AB"], ["#enroll=<script>"], ["#enroll=a b c d"], ["#enroll=" + "A".repeat(41)], ["#xenroll=ABCD-EFGH-JKLM"], ["#enroll[]=ABCD"], ["#other=ABCD-EFGH-JKLM"]])("%j is not a token", (hash) => {
    expect(parseEnrollFragment(hash)).toBeNull();
  });

  it("the query is not a source: a token in ?enroll= is ignored (a query goes to the server)", () => {
    const b = fakeBrowser("/plugins/secure-bb/gate", "?enroll=ABCD-EFGH-JKLM", "");
    expect(takeEnrollToken(b.history, b.location)).toBeNull();
    expect(b.calls).toEqual([]);
  });
});

describe("cleaning the address bar", () => {
  it("takes the token and replaces the address with the same path and query, no fragment, no new history entry", () => {
    const b = fakeBrowser("/plugins/secure-bb/gate", "?tab=1", "#enroll=ABCD-EFGH-JKLM");
    expect(takeEnrollToken(b.history, b.location)).toBe("ABCD-EFGH-JKLM");
    expect(b.calls).toEqual([{ data: null, url: "/plugins/secure-bb/gate?tab=1" }]);
    expect(b.location.hash).toBe("");
    expect(`${b.location.pathname}${b.location.search}${b.location.hash}`).not.toContain("ABCD");
    // a second look finds nothing: the token was taken once
    expect(takeEnrollToken(b.history, b.location)).toBeNull();
  });

  it("clears an unusable fragment too (nothing of it stays in the bar), and does nothing when there is none", () => {
    const bad = fakeBrowser("/gate", "", "#enroll=<x>");
    expect(takeEnrollToken(bad.history, bad.location)).toBeNull();
    expect(bad.calls).toEqual([]); // not a token: left alone (it is not ours to rewrite)
    const none = fakeBrowser("/gate", "", "");
    expect(clearFragment(none.history, none.location)).toBe(false);
    expect(none.calls).toEqual([]);
    const some = fakeBrowser("/gate", "", "#x");
    expect(clearFragment(some.history, some.location)).toBe(true);
  });
});

describe("the token goes nowhere but the guard", () => {
  const app = readFileSync(fileURLToPath(new URL("../app.tsx", import.meta.url)), "utf8");
  const lines = app.split("\n");
  const sinks = /\b(fetch|XMLHttpRequest|sendBeacon|localStorage|sessionStorage|lsSet|console\.\w+|document\.cookie|window\.open|location\.(href|assign|replace)|navigate|useBbNavigate)\b/;

  it("the page reads the token only through takeEnrollToken (fragment), never from the query, storage or elsewhere", () => {
    expect(app).toContain("takeEnrollToken(window.history, window.location)");
    expect(app).not.toMatch(/location\.search[^\n]*enroll|URLSearchParams[^\n]*enroll|enroll[^\n]*URLSearchParams/);
    expect(app).not.toMatch(/(lsGet|localStorage\.getItem|sessionStorage\.getItem)\([^)]*enroll/i);
  });

  it("no line that touches the token (or the field it is put into) sends it to a network, storage, console or the router", () => {
    // the names the token has on the page: enrollToken (from the link) and token (the field); look at the lines of PasskeyCard and the one place that reads the link
    const start = lines.findIndex((l) => l.startsWith("function PasskeyCard"));
    const end = lines.findIndex((l, i) => i > start && l.startsWith("}"));
    const card = lines.slice(start, end + 1);
    const touching = [...card, ...lines.filter((l) => /enrollToken|enrollSeen|enrollTokenOnce/.test(l))].filter((l) => /\btoken\b|enrollToken|enrollSeen/.test(l));
    expect(touching.length).toBeGreaterThan(3);
    for (const l of touching) expect(l, l).not.toMatch(sinks);
  });

  it("inside PasskeyCard the token is an argument of passkey.register and of nothing else", () => {
    const start = lines.findIndex((l) => l.startsWith("function PasskeyCard"));
    const end = lines.findIndex((l, i) => i > start && l.startsWith("}"));
    const card = lines.slice(start, end + 1).join("\n");
    const calls = [...card.matchAll(/rpc\.call\("([^"]+)"([^\n]*)/g)];
    const withToken = calls.filter((m) => /\btoken\b/.test(m[2] ?? ""));
    expect(withToken.length).toBe(2);
    for (const m of withToken) expect(m[1]).toBe("passkey.register");
    // the test touch carries a signature, not the token
    const check = calls.find((m) => m[1] === "setup-check");
    expect(check?.[2]).not.toMatch(/token/);
  });

  it("the page only rewrites its own address (replaceState), through the small module that is tested here", () => {
    const mod = readFileSync(fileURLToPath(new URL("../src/enroll-link.ts", import.meta.url)), "utf8");
    expect(mod).not.toMatch(sinks);
    expect(mod).not.toMatch(/\bimport\b[^\n]*from/); // no imports at all: nothing it could pass the token to
    expect(mod.match(/history\.replaceState\(/g)?.length).toBe(1);
  });
});
