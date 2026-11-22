// The page is scanned by the gate like any plugin's: the redesign (vendored components, a dialog, tabs) must not make secure-bb show a right it did not show.
import { cpSync, existsSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runChecks } from "../src/checks/index.js";

const root = fileURLToPath(new URL("..", import.meta.url));

/** The page alone: its entry, its sections and the vendored components, as a plugin that has only an app part. */
async function scanPage() {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-selfscan-")));
  for (const p of ["app.tsx", "app", "components", "lib", "hooks", "src", "guard/src/checks"]) if (existsSync(join(root, p))) cpSync(join(root, p), join(dir, p), { recursive: true });
  mkdirSync(join(dir, "guard"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "page-only", version: "1.0.0", bb: { name: "x", app: "./app.tsx" } }));
  return runChecks(dir);
}

describe("the page's own scan", () => {
  it("shows the rights the page had before the redesign and no new one (no press on bb's navigation, no network, no files)", async () => {
    const r = await scanPage();
    const caps = r.capabilities.filter((c) => c.sites.some((s) => /^(app\.tsx|app\/|components\/|lib\/|hooks\/)/.test(s.file)));
    const shown = caps.map((c) => `${c.kind}:${[...c.detail].sort().join(",")}`).sort();
    for (const s of shown) expect(s, s).toMatch(/^(ui|ui_click|database):/);
    // a press on elements of the page is the one that was there (the Enter in a code field presses the button next to it); not a press on bb's navigation
    for (const s of shown.filter((x) => x.startsWith("ui_click"))) expect(s).not.toContain("target:nav");
    expect(r.findings.filter((f) => f.severity === "block" && caps.some((c) => c.sites.some((st) => st.file === f.file)))).toEqual([]);
  });
});
