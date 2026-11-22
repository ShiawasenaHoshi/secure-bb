// Every field of the policy that WIDENS needs a fresh factor on all three paths: at the guard (`setPolicy`), in the plugin without a guard (`Gate.setPolicy`)
// and in the plugin over a guard (`policy.set`). One table (POLICY_FIELDS, guard/src/policy.ts); this test walks it, so a field added to the policy
// without a row there fails the build, and a path that keeps a list of its own fails here.
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Gate } from "../../src/gate.js";
import { DEFAULT_POLICY, MIGRATIONS, Store } from "../../src/store.js";
import { base32Decode, hotp, stepAt } from "../../src/totp.js";
import { DEFAULT_POLICY as GUARD_DEFAULT } from "../../guard/src/guard.ts";
import { POLICY_FIELDS, guardPolicyWidens, localPolicyWidens, windowScopeWidens, type FullPolicy } from "../../guard/src/policy.ts";
import { bootPlugin, startGuard, startGuardOnDate, type TestGuard } from "./support.ts";

const FIELDS = Object.keys(POLICY_FIELDS) as Array<keyof FullPolicy>;
const GUARD_FIELDS = FIELDS.filter((k) => POLICY_FIELDS[k].owner === "guard");

const cleanup: Array<() => void | Promise<void>> = [];
let g: TestGuard | null = null;
beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
afterEach(async () => {
  vi.useRealTimers();
  await g?.close();
  g = null;
  for (const f of cleanup.splice(0).reverse()) await f();
});
const tick = (ms = 31_000) => vi.setSystemTime(Date.now() + ms);
const fresh = (gd: TestGuard): string => (tick(), gd.code());

describe("the table covers the whole policy", () => {
  it("has a row for each field of the plugin's policy and of the guard's, and the owner is right", () => {
    expect(FIELDS.sort()).toEqual(Object.keys(DEFAULT_POLICY).sort());
    for (const k of Object.keys(GUARD_DEFAULT)) expect(POLICY_FIELDS[k as keyof FullPolicy].owner, k).toBe("guard");
    expect(GUARD_FIELDS.sort()).toEqual(Object.keys(GUARD_DEFAULT).sort());
  });
  it("each row says that its wide change widens and its narrow one does not (the function and the table agree)", () => {
    for (const k of FIELDS) {
      const f = POLICY_FIELDS[k] as { owner: string; widens: (a: unknown, b: unknown) => boolean; wide: { cur: unknown; next: unknown }; narrow: { cur: unknown; next: unknown } };
      expect(f.widens(f.wide.cur, f.wide.next), `${k} wide`).toBe(true);
      expect(f.widens(f.narrow.cur, f.narrow.next), `${k} narrow`).toBe(false);
      expect(f.widens(f.wide.cur, f.wide.cur), `${k} same`).toBe(false);
      const cur = { ...DEFAULT_POLICY, [k]: f.wide.cur } as FullPolicy;
      const next = { ...cur, [k]: f.wide.next } as FullPolicy;
      expect(f.owner === "guard" ? guardPolicyWidens(cur, next) : localPolicyWidens(cur, next), k).toBe(true);
      expect(f.owner === "guard" ? localPolicyWidens(cur, next) : guardPolicyWidens(cur, next), `${k} not the other owner's`).toBe(false);
    }
  });
  it("a window wider than the policy's scope is the same rule", () => {
    expect(windowScopeWidens("thread", "tree")).toBe(true);
    expect(windowScopeWidens("thread", "thread")).toBe(false);
    expect(windowScopeWidens("tree", "tree")).toBe(false);
    expect(windowScopeWidens("thread", undefined)).toBe(false);
  });
});

describe("path 1: the guard's own fields (guard.setPolicy)", () => {
  for (const k of GUARD_FIELDS) {
    it(`${k}: widening needs a code, narrowing does not`, async () => {
      const f = POLICY_FIELDS[k] as { wide: { cur: unknown; next: unknown }; narrow: { cur: unknown; next: unknown } };
      g = await startGuard({ trust: {} });
      const set = (patch: Record<string, unknown>, code?: string) => g!.send({ op: "policy", patch, ...(code ? { code } : {}) });
      // to the starting point: by a code (it may be a widening), then the test
      expect((await set({ [k]: f.wide.cur }, g.nextCode())).ok).toBe(true);
      expect(await set({ [k]: f.wide.next })).toMatchObject({ ok: false, error: { code: "invalid_code" } });
      expect(((await g.send({ op: "policy" })).policy as Record<string, unknown>)[k]).toBe(f.wide.cur);
      expect((await set({ [k]: f.wide.next }, g.nextCode())).ok).toBe(true);
      expect((await set({ [k]: f.narrow.next })).ok).toBe(true);
    });
  }
});

describe("path 2: the plugin without a guard (Gate.setPolicy)", () => {
  async function gate() {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-pw-")));
    cleanup.push(() => rmSync(root, { recursive: true, force: true }));
    mkdirSync(join(root, "snapshots"));
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    const store = new Store(db, () => Date.now());
    const gt = new Gate({ store, now: () => Date.now(), threads: { ancestors: async () => [], descendants: async () => [] }, thirdPartyRunning: async () => [], externalTotpFile: null, snapshotsRoot: join(root, "snapshots"), unsafeDirs: async () => [] });
    const { secret } = await gt.beginRegistration({ attended: true, caller: "test" });
    const code = () => hotp(base32Decode(secret), stepAt(Date.now()));
    gt.confirmRegistration(code());
    tick();
    return { gt, store, code };
  }
  for (const k of FIELDS) {
    it(`${k}: widening needs a code, narrowing does not`, async () => {
      const f = POLICY_FIELDS[k] as { wide: { cur: unknown; next: unknown }; narrow: { cur: unknown; next: unknown } };
      const { gt, store, code } = await gate();
      store.setPolicy({ [k]: f.wide.cur } as Partial<FullPolicy>);
      expect(() => gt.setPolicy({ [k]: f.wide.next } as Partial<FullPolicy>, undefined), k).toThrow(/needs a code/);
      expect((store.policy() as unknown as Record<string, unknown>)[k]).toBe(f.wide.cur);
      tick();
      gt.setPolicy({ [k]: f.wide.next } as Partial<FullPolicy>, code());
      expect((store.policy() as unknown as Record<string, unknown>)[k]).toBe(f.wide.next);
      gt.setPolicy({ [k]: f.narrow.next } as Partial<FullPolicy>, undefined);
      expect((store.policy() as unknown as Record<string, unknown>)[k]).toBe(f.narrow.next);
    });
  }
});

describe("path 3: the plugin over a guard (policy.set)", () => {
  for (const k of FIELDS) {
    it(`${k}: widening is refused without a factor (and passes with a code, except the safe-class pass, which does not exist there); narrowing needs none`, async () => {
      const f = POLICY_FIELDS[k] as { wide: { cur: unknown; next: unknown }; narrow: { cur: unknown; next: unknown } };
      g = await startGuardOnDate({ trust: {} });
      const h = await bootPlugin(g.paths.socket);
      const policy = async () => ((await h.rpc<any>("overview")).policy as Record<string, unknown>)[k];
      // the starting point is always reached by narrowing (or is the default)
      if (policy && (await policy()) !== f.wide.cur) await h.rpc("policy.set", { [k]: f.wide.cur });
      expect(await policy(), `${k} start`).toBe(f.wide.cur);
      await expect(h.rpc("policy.set", { [k]: f.wide.next })).rejects.toThrow();
      expect(await policy()).toBe(f.wide.cur);
      if (k === "autoSafe") await expect(h.rpc("policy.set", { [k]: f.wide.next, code: fresh(g) })).rejects.toThrow();
      else {
        await h.rpc("policy.set", { [k]: f.wide.next, code: fresh(g) });
        expect(await policy()).toBe(f.wide.next);
      }
      await h.rpc("policy.set", { [k]: f.narrow.next });
      expect(await policy()).toBe(f.narrow.next);
    });
  }
});
