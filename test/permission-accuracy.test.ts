import { chmodSync, cpSync, mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runChecks, type CheckResult } from "../src/checks/index.js";
import { capabilityPhrase, capsWithPaths, riskHeadline } from "../src/ux.js";

const FIXTURES = new URL("./fixtures/", import.meta.url).pathname;
const scratch = realpathSync(mkdtempSync(join(tmpdir(), "sbb-perm-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
function normalise(dir: string): void {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      chmodSync(p, 0o755);
      normalise(p);
    } else if (e.isFile()) chmodSync(p, 0o644);
  }
}
let n = 0;
async function fixture(name: string): Promise<CheckResult> {
  const dir = join(scratch, `f${n++}-${name}`);
  cpSync(join(FIXTURES, name), dir, { recursive: true });
  chmodSync(dir, 0o755);
  normalise(dir);
  return runChecks(dir);
}
const headline = (r: CheckResult) => riskHeadline(capsWithPaths(r), r.findings.filter((f) => f.severity === "review").map((f) => f.rule));
const hosts = (r: CheckResult) => (r.capabilities.find((c) => c.kind === "network")?.detail ?? []).filter((d) => d.startsWith("host:"));

describe("network: only real calls name a host", () => {
  it("a $schema / react.dev / github.com string of a library is not the network", async () => {
    const r = await fixture("zod-schema-string");
    expect(hosts(r)).toEqual([]);
    expect(JSON.stringify(r.capabilities)).not.toMatch(/json-schema|react\.dev|github\.com/);
    expect(headline(r).text).toBe("Может обращаться по сети к адресам, которые не видны в коде");
  });
  it("fetch with a literal / computable address names its host; a string that is not a call does not", async () => {
    const r = await fixture("fetch-literal");
    expect(hosts(r)).toEqual(["host:api.example.com", "host:live.example.com"]);
    expect(headline(r).text).toBe("Может обращаться по сети к api.example.com, live.example.com");
  });
  it("a call whose address is not computable says so", async () => {
    const r = await fixture("fetch-computed");
    expect(hosts(r)).toEqual([]);
    expect(r.capabilities.find((c) => c.kind === "network")!.detail).toContain("unresolved-host");
    expect(headline(r).text).toBe("Может обращаться по сети к адресам, которые не видны в коде");
  });
});

describe("started programs are not files", () => {
  it("spawn('/usr/bin/afplay') starts a program, reads and writes no files", async () => {
    const r = await fixture("spawn-afplay");
    expect(r.programs).toEqual(["afplay"]);
    expect(r.fsPaths).toBeUndefined();
    expect(r.capabilities.map((c) => c.kind)).not.toContain("fs");
    const h = headline(r);
    expect(h).toEqual({ level: "caution", text: "Запускает программу: проигрыватель звука macOS" });
    expect(h.text).not.toMatch(/файл/);
  });
  it("osascript is named, and is a risk", async () => {
    const r = await fixture("osascript");
    expect(r.programs).toEqual(["osascript"]);
    expect(headline(r)).toEqual({ level: "danger", text: "Запускает программу: скрипты macOS (может управлять другими программами)" });
    expect(capabilityPhrase({ kind: "child_process", detail: [], programs: ["notify-send", "git"] })).toBe("запускает программы: уведомления Linux, git (работа с кодом)");
  });
  it("an unnamed program stays honest", () => {
    expect(capabilityPhrase({ kind: "child_process", detail: [], programs: [] })).toContain("из кода не видно");
    expect(capabilityPhrase({ kind: "child_process", detail: [], programs: ["afplay"], programsUnknown: true })).toContain("не видны в коде");
  });
});

describe("other programs' credentials come first", () => {
  it("readFileSync(os.homedir() + '/.gemini/google_accounts.json')", async () => {
    const r = await fixture("gemini-credentials");
    expect(r.credentials).toEqual(["Google (Gemini)"]);
    expect(headline(r)).toEqual({ level: "caution", text: "Читает ваши учётные данные других программ: Google (Gemini)" });
  });
  it("is red when the plugin can also reach the network, and beats «переменные окружения»", () => {
    const caps = capsWithPaths({ capabilities: [{ kind: "env", detail: ["*"] }, { kind: "network", detail: ["fetch"] }], credentials: ["Google (Gemini)", "Amazon AWS"] });
    expect(riskHeadline(caps)).toEqual({ level: "danger", text: "Читает ваши учётные данные других программ: Google (Gemini), Amazon AWS" });
  });
});
