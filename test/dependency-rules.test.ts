// Import cycles and the borders of trust, checked by dependency-cruiser from the same config the `lint:deps` script uses (.dependency-cruiser.cjs).
// No cycles (a module that is imported by what it imports is a module nobody can read first), the guard imports nothing of the plugin, and the page
// imports no server module. A violation is named with its path in the failure message. Runs in the network-less test script: the tool is in devDependencies.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("dependency rules (.dependency-cruiser.cjs)", () => {
  it("0 violations: no import cycle, guard/ imports no plugin code, app/ imports no server module", { timeout: 120_000 }, async () => {
    const { cruise } = await import("dependency-cruiser");
    const extract = (await import("dependency-cruiser/config-utl/extract-depcruise-config")).default;
    const ruleSet = await extract(join(root, ".dependency-cruiser.cjs"));
    const prev = process.cwd();
    process.chdir(root);
    try {
      const { output } = await cruise(["."], { ...ruleSet.options, validate: true, ruleSet }, {}, { tsConfig: { fileName: "tsconfig.json" } } as never);
      const o = output as { summary: { violations: Array<{ rule: { name: string }; from: string; to: string; cycle?: Array<{ name: string }> }>; error: number } };
      const lines = o.summary.violations.map((v) => `${v.rule.name}: ${v.from} → ${v.to}${v.cycle ? ` (${[v.from, ...v.cycle.map((c) => c.name)].join(" → ")})` : ""}`);
      expect(lines).toEqual([]);
      expect(o.summary.error).toBe(0);
    } finally {
      process.chdir(prev);
    }
  });
});
