// «After the fact» next to a guard: the guard's approvals are keyed by the CORE's hash; our local hash never becomes a version's hash there.
import { describe, expect, it } from "vitest";
import { AfterFactScanner, NO_CORE_HASH_REASON } from "../src/afterfact.ts";
import { cardColor, isMismatch, reasonKind } from "../src/ux.ts";
import type { InstalledPluginLite } from "../src/probe.ts";

const plugin = (o: Partial<InstalledPluginLite> = {}): InstalledPluginLite => ({ id: "hello", provenance: "direct", enabled: true, status: "running", statusDetail: null, version: "0.0.4", source: "path:/x/hello", rootDir: "/x/hello", ...o });

function setup(o: { plugins: InstalledPluginLite[]; coreHash?: string | null; approved?: boolean; baseline?: string }) {
  const meta = new Map<string, string>([["afterfact_baseline", "1"]]);
  const baseline = new Map<string, string>(o.baseline ? [["hello", o.baseline]] : []);
  const decided: unknown[] = [];
  const disabled: string[] = [];
  const noHash: string[] = [];
  const asked: Array<[string, string]> = [];
  const store = {
    getMeta: (k: string) => meta.get(k) ?? null,
    setMeta: (k: string, v: string) => void meta.set(k, v),
    hasBaselineRow: (id: string) => baseline.has(id),
    baselineHash: (id: string) => baseline.get(id) ?? null,
    markBaseline: (id: string, h: string) => void baseline.set(id, h),
    log: () => undefined,
  };
  const scanner = new AfterFactScanner({
    store: store as never,
    gate: { decide: async (ctx: unknown) => (decided.push(ctx), { action: "wait" }) } as never,
    listPlugins: async () => o.plugins,
    disable: async (id) => void disabled.push(id),
    hashDir: async () => "abc123",
    now: () => 1_000,
    log: () => undefined,
    guard: {
      coreHash: () => (o.coreHash === undefined ? "sha256:" + "3d".repeat(32) : o.coreHash),
      guardApproved: async (id, h) => (asked.push([id, h]), o.approved === true),
      noCoreHash: (p) => void noHash.push(p.id),
    },
  });
  return { scanner, decided, disabled, noHash, asked };
}

describe("after the fact, guard mode", () => {
  it("1. a version the guard approved by the core's hash is not «after the fact»: nothing is held, disabled or decided", async () => {
    const t = setup({ plugins: [plugin()], approved: true, baseline: "local:old" });
    expect(await t.scanner.scan()).toEqual([]);
    expect(t.asked).toEqual([["hello", "sha256:" + "3d".repeat(32)]]); // the guard was asked by the core's hash
    expect(t.decided).toEqual([]);
    expect(t.disabled).toEqual([]);
    expect(t.noHash).toEqual([]);
  });
  it("2. our local hash is never sent to the guard as a version's hash (the gate is not asked at all)", async () => {
    const t = setup({ plugins: [plugin()], approved: false, baseline: "local:old" });
    expect(await t.scanner.scan()).toEqual(["hello"]);
    expect(t.decided).toEqual([]);
    expect(t.disabled).toEqual(["hello"]);
  });
  it("2. no core hash: a plain entry for a person (not «не совпал», not red), and the plugin is stopped; the guard is not asked", async () => {
    const t = setup({ plugins: [plugin()], coreHash: null, baseline: "local:old" });
    await t.scanner.scan();
    expect(t.noHash).toEqual(["hello"]);
    expect(t.decided).toEqual([]);
    expect(t.asked).toEqual([]);
    expect(NO_CORE_HASH_REASON).toContain("не удалось получить хеш ядра");
    expect(isMismatch(NO_CORE_HASH_REASON)).toBe(false);
    expect(cardColor({ reason: NO_CORE_HASH_REASON, findings: [] })).toBe("yellow");
    expect(reasonKind(NO_CORE_HASH_REASON)).not.toBe("mismatch");
  });
  it("3. allowed but failed to start (core status `error`): not «after the fact»", async () => {
    const t = setup({ plugins: [plugin({ status: "error", statusDetail: "fetch failed" })], approved: false, baseline: "local:old" });
    expect(await t.scanner.scan()).toEqual([]);
    expect(t.disabled).toEqual([]);
    expect(t.decided).toEqual([]);
    expect(t.noHash).toEqual([]);
    expect(t.asked).toEqual([]);
  });
});

