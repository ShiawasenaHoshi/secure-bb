// The page is built by bb as a BROWSER bundle (`bb plugin build`: entry `app.tsx`, the host's modules left out). Vitest runs in Node, where `node:fs` resolves, so a
// page that reaches Node code through some chain of imports passes every other test and then fails to install («Could not resolve "node:crypto"»). This test
// builds the page the way bb does, and fails on anything that cannot be resolved for the browser.
// The bundler is rolldown (what vite brings; no network is needed). The externals are what the host provides at run time.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** What the host swaps for its own copy (frontend-hooks-and-ui: react, the portaling radix families, sonner, vaul, clsx, tailwind-merge, cva, the SDK, the diff viewer). */
const HOST_PROVIDED = [/^react($|\/)/, /^react-dom($|\/)/, /^@get-bb\/plugin-sdk($|\/)/, /^@radix-ui\//, /^@pierre\/diffs($|\/)/, "sonner", "vaul", "clsx", "tailwind-merge", "class-variance-authority", "zod"];

async function buildPage(entry: string): Promise<{ problems: string[]; files: number }> {
  const { rolldown } = await import("rolldown");
  const problems: string[] = [];
  const bundle = await rolldown({
    cwd: root,
    input: entry,
    platform: "browser",
    external: HOST_PROVIDED,
    // what cannot be resolved is not silently left as an import: it is a problem (rolldown only warns, and treats it as external)
    onLog: (level, log) => {
      if (log.code === "UNRESOLVED_IMPORT") problems.push(`${log.code}: ${log.message.split("\n")[0]}`);
    },
  });
  const out = await bundle.generate({ format: "esm" });
  await bundle.close();
  return { problems, files: out.output.length };
}

describe("the page builds as a browser bundle, the way bb builds it", () => {
  it("app.tsx: nothing it reaches needs Node or fails to resolve", { timeout: 120_000 }, async () => {
    const r = await buildPage("app.tsx");
    expect(r.problems).toEqual([]);
    expect(r.files).toBeGreaterThan(0);
  });

  it("the check sees a break: an entry that imports a Node module does not pass", { timeout: 120_000 }, async () => {
    // test/support/node-import.ts imports `node:crypto`; the same build, with the same externals, must report it
    const r = await buildPage("test/support/node-import.ts");
    expect(r.problems.join("\n")).toMatch(/node:crypto/);
  });

  it("the leaves the page shares with the guard import nothing (no node:*, no analyser)", () => {
    for (const f of ["guard/src/lift.ts", "guard/src/github-address.ts"]) {
      const code = readFileSync(join(root, f), "utf8").split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join("\n");
      expect(code, f).not.toMatch(/(^|\n)\s*(import|export)\b[^\n]*\bfrom\s+["']/);
      expect(code, f).not.toMatch(/\brequire\(|\bimport\(/);
    }
  });
});
