import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const HASHES: Record<string, string> = {
  "acorn.mjs": "76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b",
  "acorn-jsx.mjs": "699f555f7886852da766df6ffe0d8e7787211f1e72acda7a20e76c981dad2e67",
  "acorn-typescript.mjs": "e8e9281a975668bddb679c6cdc266e699cc69ddfeada1e4b3e4dc6def9bbe0e7",
};

describe("vendored parser", () => {
  for (const [file, hash] of Object.entries(HASHES)) {
    it(`${file} matches vendor/README.md`, () => {
      const bytes = readFileSync(new URL(`../vendor/${file}`, import.meta.url));
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(hash);
      expect(readFileSync(new URL("../vendor/README.md", import.meta.url), "utf8")).toContain(hash);
    });
  }
  it("acorn-typescript differs from the npm original in exactly one line (the import of acorn)", () => {
    const text = readFileSync(new URL("../vendor/acorn-typescript.mjs", import.meta.url), "utf8");
    expect(text).toContain('import * as acornNamespace from "./acorn.mjs";');
    expect(text).not.toContain('from "acorn"');
  });
  it("acorn-jsx embeds the original files between markers", () => {
    const text = readFileSync(new URL("../vendor/acorn-jsx.mjs", import.meta.url), "utf8");
    expect(text).toContain("// ---- BEGIN index.js ----");
    expect(text).toContain("// ---- END xhtml.js ----");
  });
});
