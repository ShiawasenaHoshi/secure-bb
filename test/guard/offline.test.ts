import { describe, expect, it } from "vitest";
import { parseArgs } from "../../guard/src/cli.ts";
import { resolvePaths } from "../../guard/src/config.ts";

describe("--offline", () => {
  it("is a flag without a value, or SBB_GUARD_OFFLINE", () => {
    expect(parseArgs(["serve", "--offline", "--data", "/d"]).opts).toMatchObject({ offline: true, data: "/d" });
    expect(resolvePaths({ offline: true }, {}).offline).toBe(true);
    expect(resolvePaths({}, { SBB_GUARD_OFFLINE: "1" }).offline).toBe(true);
    expect(resolvePaths({}, {}).offline).toBe(false);
  });
});
