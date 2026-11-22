// What an approval session covers is ONE table (guard/src/session-rules.ts). The guard decides with it (`isRoutineAction`), its description of «Открыть сессию»
// and the page's paragraph are built from it, and the plugin's RPC table (RPC_AUTH) must agree with it. This test fails when they drift apart, as the one for RPC_AUTH does.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { RPC_AUTH } from "../src/approval.js";
import { sessionText, SESSION_LINE } from "../src/ux.js";
import { SESSION_CAP_MS, SESSION_IDLE_MS, SESSION_RULES, ROUTINE_TOUCH_PURPOSES, isRoutineAction, sessionCoverage } from "../guard/src/session-rules.ts";
import { Guard } from "../guard/src/guard.ts";

describe("the table of what a session covers", () => {
  it("every rule's example is decided by that rule, and `isRoutineAction` says what the rule says", () => {
    for (const r of SESSION_RULES) {
      expect(SESSION_RULES.find((x) => x.match(r.example))?.id, r.id).toBe(r.id);
      expect(isRoutineAction(r.example), r.id).toBe(r.routine);
    }
  });
  it("the routine RPCs of the plugin's table are exactly the routine rows (and each routine row's purposes are the touch purposes)", () => {
    const fromTable = SESSION_RULES.filter((r) => r.routine).flatMap((r) => r.rpcs).sort();
    const fromRpc = Object.entries(RPC_AUTH).filter(([, a]) => a.group === "routine").map(([n]) => n).sort();
    expect(fromTable).toEqual(fromRpc);
    const purposes = SESSION_RULES.find((r) => r.id === "routine-touch")!.rpcs;
    expect([...ROUTINE_TOUCH_PURPOSES].sort()).toEqual([...purposes].sort());
    // no rule outside the table's routine rows names an RPC
    for (const r of SESSION_RULES.filter((x) => !x.routine)) expect(r.rpcs, r.id).toEqual([]);
  });
  it("an action nobody listed is never routine", () => {
    for (const a of [{ op: "nothing" }, { op: "touch", purpose: "policy.set" }, { op: "touch" }, { op: "agents-accept" }, {}]) expect(isRoutineAction(a as Record<string, unknown>), JSON.stringify(a)).toBe(false);
  });
});

describe("the words come from the table", () => {
  const cov = sessionCoverage();
  it("the page's paragraph names every routine and every fresh-factor row, and the numbers of the guard", () => {
    for (const guard of [true, false]) {
      const t = sessionText("detailed", guard);
      for (const w of [...cov.routine, ...cov.fresh]) expect(t.details, w).toContain(w);
      expect(t.details).toContain(`${SESSION_IDLE_MS / 60_000} минут`);
    }
    expect(SESSION_LINE).toContain(`${SESSION_IDLE_MS / 60_000} минут`);
    expect(SESSION_CAP_MS).toBe(60 * 60_000);
  });
  it("the guard's own description of «Открыть сессию» names the same rows", () => {
    const text = (Guard.prototype as unknown as { describe: (a: Record<string, unknown>) => string }).describe.call({ db: null }, { op: "session-open" });
    for (const w of [...cov.routine, ...cov.fresh]) expect(text, w).toContain(w);
    const hour = (Guard.prototype as unknown as { describe: (a: Record<string, unknown>) => string }).describe.call({ db: null }, { op: "session-open", hour: true });
    for (const w of [...cov.routine, ...cov.fresh]) expect(hour, w).toContain(w);
  });
});

describe("the numbers live once", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const sources = (dir: string): string[] =>
    readdirSync(dir).flatMap((n) => {
      const p = join(dir, n);
      if (n === "node_modules" || n === "test" || n === ".git") return [];
      return statSync(p).isDirectory() ? sources(p) : /\.(ts|tsx)$/.test(n) ? [p] : [];
    });
  it("SESSION_IDLE_MS and SESSION_CAP_MS are defined in guard/src/session-rules.ts and nowhere else", () => {
    const defs = sources(root).filter((p) => /export const SESSION_(IDLE|CAP)_MS\s*=/.test(readFileSync(p, "utf8")));
    expect(defs.map((p) => p.slice(root.length + 1))).toEqual(["guard/src/session-rules.ts"]);
  });
});
