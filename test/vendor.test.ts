import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const HASHES: Record<string, string> = {
  "acorn.mjs": "76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b",
  "walk.mjs": "24bc7ea73dcc319360090f4849746b7493bf234f951ea99ae0b89105981b1b42",
  "acorn-jsx.mjs": "699f555f7886852da766df6ffe0d8e7787211f1e72acda7a20e76c981dad2e67",
};

describe("vendored parser", () => {
  for (const [file, hash] of Object.entries(HASHES)) {
    it(`${file} matches vendor/README.md`, () => {
      const bytes = readFileSync(new URL(`../vendor/${file}`, import.meta.url));
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(hash);
      expect(readFileSync(new URL("../vendor/README.md", import.meta.url), "utf8")).toContain(hash);
    });
  }
  it("acorn-jsx embeds the original files between markers", () => {
    const text = readFileSync(new URL("../vendor/acorn-jsx.mjs", import.meta.url), "utf8");
    expect(text).toContain("// ---- BEGIN index.js ----");
    expect(text).toContain("// ---- END xhtml.js ----");
  });
});
