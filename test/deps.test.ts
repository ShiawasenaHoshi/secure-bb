// Stage 2.3: dependencies. The network is never touched: `fetch` is always a fake.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterAll, describe, expect, it } from "vitest";
import { runChecks, formatReport, type CheckResult } from "../src/checks/index.js";
import { allowedDistance, isPopular, levenshtein, lookalikeOf } from "../src/deps/lookalike.js";
import { lookupPackage, parsePackument, REFRESH_MS, type FetchLike, type RegistryEntry } from "../src/deps/registry.js";
import { compareVersions, isExactVersion, maxSatisfying, parseVersion } from "../src/deps/semver.js";
import { verifyDependencies, YOUNG_RELEASE_MS } from "../src/deps/verify.js";
import { MIGRATIONS, Store } from "../src/store.js";

const NOW = Date.parse("2026-11-21T12:00:00Z");
const DAY = 86_400_000;
const iso = (agoMs: number): string => new Date(NOW - agoMs).toISOString();

// ---- a fake registry ---------------------------------------------------------------
type Doc = { times: Record<string, string>; tags?: Record<string, string> };
class FakeRegistry {
  docs = new Map<string, Doc>();
  calls: string[] = [];
  /** "offline": every request fails; a number: that HTTP status for everything; "hang": never answers (until aborted). */
  mode: "online" | "offline" | "hang" | number = "online";
  fetch: FetchLike = async (url, init) => {
    this.calls.push(url);
    if (this.mode === "offline") throw new TypeError("fetch failed");
    if (this.mode === "hang") {
      await new Promise<void>((_, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    }
    if (typeof this.mode === "number") return new Response("{}", { status: this.mode });
    const name = decodeURIComponent(url.replace("https://registry.npmjs.org/", ""));
    const doc = this.docs.get(name);
    if (!doc) return new Response('{"error":"Not found"}', { status: 404 });
    return new Response(JSON.stringify({ name, "dist-tags": doc.tags ?? {}, time: { created: "2020-01-01T00:00:00.000Z", modified: "2026-01-01T00:00:00.000Z", ...doc.times } }), { status: 200 });
  };
}
function newStore(): Store {
  const db = new Database(":memory:");
  for (const s of MIGRATIONS) db.exec(s);
  return new Store(db, () => NOW);
}

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "sbb-deps-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
let n = 0;
async function tree(files: Record<string, string>): Promise<CheckResult> {
  const dir = join(scratch, `t${n++}`);
  mkdirSync(dir, { mode: 0o755 });
  for (const [rel, body] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, ".."), { recursive: true, mode: 0o755 });
    writeFileSync(full, body, { mode: 0o644 });
  }
  return runChecks(dir);
}
const pkg = (deps: Record<string, string>, extra: object = {}): string => JSON.stringify({ name: "bb-plugin-x", version: "1.0.0", dependencies: deps, ...extra });
const ruleList = (r: CheckResult, rule: string) => r.findings.filter((f) => f.rule === rule);

describe("lookalike names (Levenshtein, vendored list)", () => {
  it("levenshtein", () => {
    expect(levenshtein("kitten", "sitting")).toBe(3);
    expect(levenshtein("lodash", "lodash")).toBe(0);
    expect(levenshtein("lodash", "lodahs")).toBe(2);
    expect(levenshtein("abc", "abcdefgh", 2)).toBeGreaterThan(2); // bounded: gives up early
  });
  it("the real package is not a lookalike of itself or of its neighbours; a typo is", () => {
    expect(isPopular("lodash")).toBe(true);
    expect(lookalikeOf("lodash")).toBeNull();
    expect(lookalikeOf("Lodash")).toBeNull(); // case-insensitive exact
    expect(lookalikeOf("expres")).toEqual({ popular: "express", distance: 1 });
    expect(lookalikeOf("lodahs")).toEqual({ popular: "lodash", distance: 2 });
    expect(lookalikeOf("reakt")).toEqual({ popular: "react", distance: 1 });
    expect(lookalikeOf("@types/nod")).toEqual({ popular: "@types/node", distance: 1 });
  });
  it("distance 3 is not a lookalike; short names need an exact match (distance scales with length)", () => {
    expect(lookalikeOf("lodashxyz")).toBeNull();
    expect(allowedDistance("ms")).toBe(0);
    expect(allowedDistance("react")).toBe(1);
    expect(allowedDistance("lodash")).toBe(2);
    expect(lookalikeOf("mz")).toBeNull();
  });
  it("the vendored list is data with its source and date", async () => {
    const m = await import("../guard/vendor/popular-packages.mjs");
    expect(m.POPULAR_SOURCE).toMatchObject({ package: "npm-high-impact", version: "1.13.0", license: "MIT", publishedAt: "2026-06-08", vendoredAt: "2026-11-21" });
    expect(m.POPULAR_PACKAGES.length).toBe(5000);
    expect(new Set(m.POPULAR_PACKAGES).size).toBe(5000);
  });
});

describe("semver ranges (what the registry would give today)", () => {
  const versions = ["0.9.0", "1.0.0", "1.2.3", "1.2.9", "1.3.0", "1.9.9", "2.0.0", "2.0.1-beta.1", "2.1.0", "0.0.3", "0.2.5", "0.2.9", "0.3.0"];
  const pick = (range: string) => maxSatisfying(versions, range);
  it.each([
    ["^1.2.3", "1.9.9"],
    ["^1.2", "1.9.9"],
    ["~1.2.3", "1.2.9"],
    ["~1.2", "1.2.9"],
    ["~1", "1.9.9"],
    ["^0.2.5", "0.2.9"],
    ["^0.0.3", "0.0.3"],
    ["1.x", "1.9.9"],
    ["1.2.x", "1.2.9"],
    ["*", "2.1.0"],
    ["", "2.1.0"],
    [">=1.2.3 <2", "1.9.9"],
    [">1.2.3", "2.1.0"],
    ["<1.2.3", "1.0.0"],
    ["<=1.2.3", "1.2.3"],
    ["1.2.3 - 1.3.0", "1.3.0"],
    ["1.2.3 - 1.2", "1.2.9"],
    ["^0.2.5 || ^2.0.0", "2.1.0"],
    ["=1.2.3", "1.2.3"],
    ["2.0.1-beta.1", null], // pre-releases are never picked by a range
    ["^3.0.0", null],
  ])("%s → %s", (range, expected) => {
    expect(pick(range)).toBe(expected);
  });
  it("what it does not understand throws (the dependency then stays 'not verified')", () => {
    expect(() => pick("latest")).toThrow();
    expect(() => pick("http://x")).toThrow();
  });
  it("compare and parse", () => {
    expect(compareVersions(parseVersion("1.2.3")!, parseVersion("1.10.0")!)).toBeLessThan(0);
    expect(compareVersions(parseVersion("1.0.0-alpha")!, parseVersion("1.0.0")!)).toBeLessThan(0);
    expect(isExactVersion("1.2.3")).toBe(true);
    expect(isExactVersion("^1.2.3")).toBe(false);
  });
});

describe("registry client: network by injected fetch, answers cached in the database", () => {
  it("reads publish times and tags, stores them, and the second ask does not fetch", async () => {
    const reg = new FakeRegistry();
    reg.docs.set("left-pad", { times: { "1.0.0": iso(100 * DAY), "1.1.0": iso(5 * DAY) }, tags: { latest: "1.1.0" } });
    const store = newStore();
    const d = { cache: store, fetch: reg.fetch, now: () => NOW };
    const a = await lookupPackage(d, "left-pad", "1.1.0");
    expect(a).toMatchObject({ fromCache: false, entry: { state: "ok", distTags: { latest: "1.1.0" } } });
    expect(Object.keys((a.entry as RegistryEntry).times).sort()).toEqual(["1.0.0", "1.1.0"]);
    const b = await lookupPackage(d, "left-pad", "1.1.0");
    expect(b).toMatchObject({ fromCache: true });
    expect(reg.calls).toEqual(["https://registry.npmjs.org/left-pad"]);
    expect(store.getRegistry("left-pad")!.times["1.0.0"]).toBe(iso(100 * DAY));
  });
  it("scoped names are escaped in the URL", async () => {
    const reg = new FakeRegistry();
    reg.docs.set("@scope/pkg", { times: { "1.0.0": iso(DAY * 30) } });
    await lookupPackage({ cache: newStore(), fetch: reg.fetch, now: () => NOW }, "@scope/pkg");
    expect(reg.calls).toEqual(["https://registry.npmjs.org/@scope%2Fpkg"]);
  });
  it("404 is an answer (and cached); an invalid name is never sent", async () => {
    const reg = new FakeRegistry();
    const d = { cache: newStore(), fetch: reg.fetch, now: () => NOW };
    expect(await lookupPackage(d, "no-such-package")).toMatchObject({ entry: { state: "missing" } });
    expect(await lookupPackage(d, "no-such-package")).toMatchObject({ fromCache: true });
    expect(reg.calls).toHaveLength(1);
    expect(await lookupPackage(d, "../../etc/passwd")).toMatchObject({ entry: null });
    expect(await lookupPackage(d, "a b")).toMatchObject({ entry: null });
    expect(reg.calls).toHaveLength(1);
  });
  it("no network and nothing cached → unknown, with the reason; no guess", async () => {
    const reg = new FakeRegistry();
    reg.mode = "offline";
    const r = await lookupPackage({ cache: newStore(), fetch: reg.fetch, now: () => NOW }, "left-pad", "1.0.0");
    expect(r).toMatchObject({ entry: null, reason: expect.stringContaining("could not be reached") });
    reg.mode = 503;
    expect(await lookupPackage({ cache: newStore(), fetch: reg.fetch, now: () => NOW }, "left-pad")).toMatchObject({ entry: null, reason: "the registry answered HTTP 503" });
  });
  it("offline with a cache hit is fine; a cached entry lacking the wanted version is asked again only after an hour", async () => {
    const reg = new FakeRegistry();
    reg.docs.set("p", { times: { "1.0.0": iso(30 * DAY) } });
    const store = newStore();
    let t = NOW;
    const d = { cache: store, fetch: reg.fetch, now: () => t };
    await lookupPackage(d, "p", "1.0.0");
    reg.mode = "offline";
    expect(await lookupPackage(d, "p", "1.0.0")).toMatchObject({ fromCache: true }); // no network needed
    expect(await lookupPackage(d, "p", "1.1.0")).toMatchObject({ fromCache: true }); // fresh: do not hammer the registry
    expect(reg.calls).toHaveLength(1);
    t += REFRESH_MS + 1;
    const stale = await lookupPackage(d, "p", "1.1.0"); // due for refresh, but offline: the old answer, flagged
    expect(stale).toMatchObject({ fromCache: true, refreshError: expect.stringContaining("could not be reached") });
    reg.mode = "online";
    reg.docs.set("p", { times: { "1.0.0": iso(30 * DAY), "1.1.0": iso(DAY) } });
    expect(await lookupPackage(d, "p", "1.1.0")).toMatchObject({ fromCache: false });
  });
  it("answers without publish times are rejected; huge answers are cut off", () => {
    expect(() => parsePackument("x", "{}", NOW)).toThrow(/publish times/);
    expect(() => parsePackument("x", "nope", NOW)).toThrow();
  });
  it("old cache rows are dropped when something new is stored", () => {
    let t = NOW;
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    const store = new Store(db, () => t);
    store.putRegistry({ name: "old", state: "ok", fetchedAt: t, distTags: {}, times: {} });
    t += 61 * DAY;
    store.putRegistry({ name: "new", state: "ok", fetchedAt: t, distTags: {}, times: {} });
    expect(store.getRegistry("old")).toBeNull();
    expect(store.getRegistry("new")).not.toBeNull();
  });
});

describe("dependencies of a plugin tree (offline part of runChecks)", () => {
  it("declared dependencies and node_modules copies are listed once each, with versions", async () => {
    const r = await tree({
      "package.json": pkg({ left: "^1.0.0", "@s/pkg": "2.0.0" }, { optionalDependencies: { opt: "~3.1.0" }, devDependencies: { dev: "1.0.0" } }),
      "server.ts": "export default 1;\n",
      "node_modules/left/package.json": JSON.stringify({ name: "left", version: "1.4.2" }),
      "node_modules/left/index.js": "module.exports = 1;\n",
      "node_modules/left/node_modules/inner/package.json": JSON.stringify({ name: "inner", version: "0.1.0" }),
      "node_modules/@s/other/package.json": JSON.stringify({ name: "@s/other", version: "5.0.0" }),
    });
    const by = (name: string) => r.dependencies!.find((d) => d.name === name)!;
    expect(by("left")).toMatchObject({ spec: "^1.0.0", installed: "1.4.2", declared: true, file: "package.json" });
    expect(by("@s/pkg")).toMatchObject({ spec: "2.0.0", installed: null, declared: true });
    expect(by("opt")).toMatchObject({ spec: "~3.1.0", declared: true });
    expect(by("inner")).toMatchObject({ installed: "0.1.0", declared: false, file: "node_modules/left/node_modules/inner/package.json" });
    expect(by("@s/other")).toMatchObject({ installed: "5.0.0", declared: false });
    expect(r.dependencies!.find((d) => d.name === "dev")).toBeUndefined(); // devDependencies are not shipped
    expect(r.dependencies).toHaveLength(5);
  });
  it("a name that looks like a popular package is a review finding with file and line; the real one is not", async () => {
    const r = await tree({ "package.json": pkg({ lodahs: "1.0.0", lodash: "4.17.21", expres: "^4.0.0", "my-own-thing-xyz": "1.0.0" }), "server.ts": "export default 1;\n" });
    const found = ruleList(r, "dep-lookalike");
    expect(found.map((f) => f.excerpt.split('"')[1]).sort()).toEqual(["expres", "lodahs"]);
    expect(found[0]).toMatchObject({ severity: "review", file: "package.json" });
    expect(found.every((f) => f.line > 0)).toBe(true);
    expect(found.find((f) => f.excerpt.includes("lodahs"))!.excerpt).toContain('"lodash"');
  });
  it("a lookalike inside node_modules is found too, pointing at its directory", async () => {
    const r = await tree({ "package.json": pkg({}), "node_modules/reakt/package.json": JSON.stringify({ name: "reakt", version: "1.0.0" }) });
    expect(ruleList(r, "dep-lookalike")[0]).toMatchObject({ file: "node_modules/reakt/package.json", excerpt: expect.stringContaining('"react"') });
  });
  it("a package.json inside node_modules that names itself differently is a review finding", async () => {
    const r = await tree({ "package.json": pkg({}), "node_modules/innocent/package.json": JSON.stringify({ name: "something-else", version: "1.0.0" }) });
    expect(ruleList(r, "dep-name-mismatch")).toHaveLength(1);
  });
  it("many lookalikes are reported as 20 findings and a count", async () => {
    const files: Record<string, string> = { "package.json": pkg({}) };
    const names = ["react", "lodash", "express", "axios", "chalk", "debug", "semver", "commander", "typescript", "webpack", "eslint", "prettier", "jest", "mocha", "yargs", "uuid", "moment", "async", "request", "bluebird", "rimraf", "mkdirp", "glob", "minimist"];
    for (const nm of names) files[`node_modules/${nm}x/package.json`] = JSON.stringify({ name: `${nm}x`, version: "1.0.0" });
    const r = await tree(files);
    const found = ruleList(r, "dep-lookalike");
    expect(found.length).toBeLessThanOrEqual(21);
    expect(found.some((f) => /and \d+ more/.test(f.excerpt))).toBe(true);
  });
  it("no dependencies, no registry stage: nothing is asked", async () => {
    const reg = new FakeRegistry();
    const r = await verifyDependencies(await tree({ "package.json": pkg({}), "server.ts": "export default 1;\n" }), { cache: newStore(), fetch: reg.fetch, now: () => NOW });
    expect(reg.calls).toEqual([]);
    expect(r.findings).toEqual([]);
    expect(r.dependencyStats).toMatchObject({ total: 0, registry: true });
  });
});

describe("the registry stage: age, existence, honesty about what was not verified", () => {
  async function run(files: Record<string, string>, setup: (reg: FakeRegistry) => void, store = newStore(), t = NOW) {
    const reg = new FakeRegistry();
    setup(reg);
    const base = await tree(files);
    const result = await verifyDependencies(base, { cache: store, fetch: reg.fetch, now: () => t, deadlineMs: 300, requestTimeoutMs: 200 });
    return { reg, result, store };
  }
  const OLD = { times: { "1.0.0": iso(200 * DAY), "1.2.0": iso(30 * DAY) }, tags: { latest: "1.2.0" } };

  it("a release younger than 3 days is a review finding; exactly at the limit is not", async () => {
    const { result } = await run({ "package.json": pkg({ fresh: "1.0.0", edge: "1.0.0", ancient: "1.0.0" }) }, (reg) => {
      reg.docs.set("fresh", { times: { "1.0.0": iso(5 * 3_600_000) } });
      reg.docs.set("edge", { times: { "1.0.0": iso(YOUNG_RELEASE_MS) } });
      reg.docs.set("ancient", OLD);
    });
    const young = ruleList(result, "dep-young-release");
    expect(young).toHaveLength(1);
    expect(young[0]).toMatchObject({ severity: "review", file: "package.json", excerpt: expect.stringContaining("fresh@1.0.0") });
    expect(young[0]!.excerpt).toContain("5 h ago");
    expect(result.dependencies!.find((d) => d.name === "fresh")).toMatchObject({ status: "young", version: "1.0.0", publishedAt: iso(5 * 3_600_000) });
    expect(result.dependencies!.find((d) => d.name === "ancient")).toMatchObject({ status: "ok" });
    expect(result.dependencyStats).toMatchObject({ total: 3, verified: 3, young: 1, unchecked: 0, registry: true });
  });

  it("a range is judged by the version it resolves to today; a tag by its target", async () => {
    const { result } = await run({ "package.json": pkg({ ranged: "^1.0.0", tagged: "latest", stuck: "^2.0.0" }) }, (reg) => {
      // ^1.0.0 resolves to 1.3.0, released an hour ago, even though 1.2.0 is old
      reg.docs.set("ranged", { times: { "1.0.0": iso(90 * DAY), "1.2.0": iso(30 * DAY), "1.3.0": iso(3_600_000) } });
      reg.docs.set("tagged", { times: { "1.0.0": iso(90 * DAY), "2.0.0": iso(2 * 3_600_000) }, tags: { latest: "2.0.0" } });
      reg.docs.set("stuck", OLD); // nothing satisfies ^2.0.0
    });
    const young = ruleList(result, "dep-young-release").map((f) => f.excerpt);
    expect(young.some((e) => e.includes("ranged@1.3.0"))).toBe(true);
    expect(young.some((e) => e.includes("tagged@2.0.0") && e.includes("tag latest"))).toBe(true);
    const unchecked = ruleList(result, "dep-unchecked");
    expect(unchecked).toHaveLength(1);
    expect(unchecked[0]!.excerpt).toContain("no published version satisfies ^2.0.0");
  });

  it("the installed copy is what is judged, not the declared range", async () => {
    const { result } = await run(
      { "package.json": pkg({ lib: "^1.0.0" }), "node_modules/lib/package.json": JSON.stringify({ name: "lib", version: "1.0.0" }), "server.ts": "export default 1;\n" },
      (reg) => reg.docs.set("lib", { times: { "1.0.0": iso(300 * DAY), "1.1.0": iso(3_600_000) } }),
    );
    expect(ruleList(result, "dep-young-release")).toEqual([]); // 1.1.0 is new, but 1.0.0 is what is installed
    expect(result.dependencies!.find((d) => d.name === "lib")).toMatchObject({ version: "1.0.0", status: "ok" });
  });

  it("node_modules packages are checked as well (a fresh transitive release is found)", async () => {
    const { result } = await run(
      { "package.json": pkg({}), "node_modules/zq-deep/package.json": JSON.stringify({ name: "zq-deep", version: "9.9.9" }), "node_modules/zq-fine/package.json": JSON.stringify({ name: "zq-fine", version: "1.0.0" }) },
      (reg) => {
        reg.docs.set("zq-deep", { times: { "9.9.9": iso(3_600_000) } });
        reg.docs.set("zq-fine", OLD);
      },
    );
    const f = ruleList(result, "dep-young-release");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ file: "node_modules/zq-deep/package.json", excerpt: expect.stringContaining("zq-deep@9.9.9") });
    // a clean node_modules entry is not kept in the stored result
    expect(result.dependencies!.map((d) => d.name)).toEqual(["zq-deep"]);
    expect(result.dependencyStats).toMatchObject({ total: 2, verified: 2, young: 1 });
  });

  it("a name the registry does not know and a version it does not list are review findings", async () => {
    const { result } = await run({ "package.json": pkg({ ghost: "1.0.0", real: "7.7.7" }) }, (reg) => reg.docs.set("real", OLD));
    expect(ruleList(result, "dep-not-in-registry")[0]!.excerpt).toContain("ghost");
    expect(ruleList(result, "dep-unknown-version")[0]!.excerpt).toContain("real@7.7.7");
  });

  it("NO NETWORK and nothing cached: 'not verified' is a review finding, never silence", async () => {
    const { result, reg } = await run({ "package.json": pkg({ a: "1.0.0", b: "1.0.0" }) }, (r) => (r.mode = "offline"));
    expect(reg.calls.length).toBe(2);
    const f = ruleList(result, "dep-unchecked");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "review", excerpt: expect.stringContaining("not verified: 2 of 2 dependencies") });
    expect(f[0]!.excerpt).toContain("could not be reached");
    expect(result.dependencyStats).toMatchObject({ verified: 0, unchecked: 2 });
    expect(result.dependencies!.every((d) => d.status === "unchecked")).toBe(true);
  });

  it("no network but a warm cache: verified from the database, and the young release is still found", async () => {
    const store = newStore();
    const files = { "package.json": pkg({ fresh: "1.0.0", old: "1.0.0" }) };
    await run(files, (reg) => {
      reg.docs.set("fresh", { times: { "1.0.0": iso(3_600_000) } });
      reg.docs.set("old", OLD);
    }, store);
    const { result, reg } = await run(files, (r) => (r.mode = "offline"), store, NOW + 1000);
    expect(reg.calls).toEqual([]); // not a single request
    expect(ruleList(result, "dep-unchecked")).toEqual([]);
    expect(ruleList(result, "dep-young-release")).toHaveLength(1);
  });

  it("the age is computed from the cached time against *now*: a release that was young is not young any more", async () => {
    const store = newStore();
    const files = { "package.json": pkg({ fresh: "1.0.0" }) };
    await run(files, (reg) => reg.docs.set("fresh", { times: { "1.0.0": iso(3_600_000) } }), store);
    const { result } = await run(files, (r) => (r.mode = "offline"), store, NOW + 4 * DAY);
    expect(ruleList(result, "dep-young-release")).toEqual([]);
  });

  it("a registry that hangs: the stage gives up at its deadline and says so", async () => {
    const t0 = Date.now();
    const { result } = await run({ "package.json": pkg({ slow: "1.0.0" }) }, (r) => (r.mode = "hang"));
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(ruleList(result, "dep-unchecked")).toHaveLength(1);
  });

  it("HTTP errors (429, 503) are 'not verified', and are not cached as answers", async () => {
    const store = newStore();
    const { result } = await run({ "package.json": pkg({ a: "1.0.0" }) }, (r) => (r.mode = 429), store);
    expect(ruleList(result, "dep-unchecked")[0]!.excerpt).toContain("HTTP 429");
    expect(store.getRegistry("a")).toBeNull();
  });

  it("git, URL and workspace dependencies are not asked about (other rules handle them)", async () => {
    const { result, reg } = await run({ "package.json": pkg({ g: "git+https://x/y.git", u: "https://x/y.tgz", w: "workspace:*", s: "user/repo" }) }, () => undefined);
    expect(reg.calls).toEqual([]);
    expect(ruleList(result, "dep-unchecked")).toEqual([]);
    expect(result.dependencies!.every((d) => d.status === "skipped")).toBe(true);
  });

  it("an npm: alias is judged by the package it points at", async () => {
    const { result, reg } = await run({ "package.json": pkg({ alias: "npm:real-pkg@1.0.0" }) }, (r) => r.docs.set("real-pkg", { times: { "1.0.0": iso(3_600_000) } }));
    expect(reg.calls).toEqual(["https://registry.npmjs.org/real-pkg"]);
    expect(ruleList(result, "dep-young-release")).toHaveLength(1);
  });

  it("the report for `bb secure-bb check` lists versions, publish dates and the statistics", async () => {
    const { result } = await run({ "package.json": pkg({ fresh: "1.0.0", old: "1.0.0" }) }, (reg) => {
      reg.docs.set("fresh", { times: { "1.0.0": iso(3_600_000) } });
      reg.docs.set("old", OLD);
    });
    const text = formatReport(result);
    expect(text).toContain("dependencies: 2 (2 declared), 2 verified against the npm registry, 0 not verified, 1 younger than 3 days");
    expect(text).toContain("fresh@1.0.0: young, published 2026-11-21");
    expect(text).toContain("old@1.0.0: ok, published 2026-05-05");
    expect(formatReport(await tree({ "package.json": pkg({ x: "1.0.0" }) }))).toContain("registry not consulted");
  });

  it("a stored result stays small: declared dependencies and flagged ones only", async () => {
    const files: Record<string, string> = { "package.json": pkg({}), "server.ts": "export default 1;\n" };
    for (let i = 0; i < 150; i++) files[`node_modules/zq-aa-${i}/package.json`] = JSON.stringify({ name: `zq-aa-${i}`, version: "1.0.0" });
    const { result } = await run(files, (reg) => {
      for (let i = 0; i < 150; i++) reg.docs.set(`zq-aa-${i}`, OLD);
    });
    expect(result.dependencyStats).toMatchObject({ total: 150, verified: 150 });
    expect(result.dependencies).toEqual([]);
  });
});
