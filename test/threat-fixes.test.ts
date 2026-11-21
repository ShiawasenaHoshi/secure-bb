// Tests for the fixes from the plugin threat model (secure-bb-threat-fixes.md, items 1–10). One describe block per item.
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import plugin from "../server.js";
import { ALIVE_INTERVAL_MS, Alive, GAP_THRESHOLD_MS } from "../src/alive.js";
import { SessionProof } from "../src/approval.js";
import { checkPathRefusal, checkSummary } from "../src/checkpath.js";
import { runChecks } from "../src/checks/index.js";
import { assess, type Probe } from "../src/detect.js";
import { Gate, GateError, type HookCtx } from "../src/gate.js";
import { cursorCommand } from "../src/scan/commands.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { classifyItem } from "../src/taint/classify.js";
import { githubSlug } from "../src/taint/repos.js";
import { T } from "../src/text.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";
import { hashTree } from "../src/tree.js";
import { CLEAN } from "./support/checks.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-tf-")));
chmodSync(root, 0o755); // the privacy rule of `check` must not see the test directory itself as private
const T0 = 1_800_000_000_000;

function tree(name: string, files: Record<string, string>): string {
  const dir = join(root, name);
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  for (const [f, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    writeFileSync(join(dir, f), body);
  }
  return dir;
}
const ctx = (dir: string, hash: string): HookCtx => ({ pluginId: "demo", version: "1.0.0", source: `path:${dir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: dir, contentHash: hash, trigger: "install" });
const rulesOf = async (code: string, name = `t${Math.random().toString(36).slice(2)}`) => {
  const r = await runChecks(tree(name, { "server.ts": code }));
  return { blocks: r.findings.filter((f) => f.severity === "block").map((f) => f.rule), kinds: r.capabilities.map((c) => c.kind), all: r.findings.map((f) => `${f.severity}:${f.rule}`) };
};

/** A gate with a registered second factor; `code()` is a fresh code for the current step, `tick()` moves to the next step. */
async function registered(over: Partial<ConstructorParameters<typeof Gate>[0]> = {}) {
  const h = newGate(over);
  const { secret } = await h.gate.beginRegistration({ attended: true, caller: "test" });
  const code = () => hotp(base32Decode(secret), stepAt(h.clock.t));
  h.gate.confirmRegistration(code());
  const tick = () => void (h.clock.t += 31_000);
  tick();
  return { ...h, code, tick };
}

function newGate(over: Partial<ConstructorParameters<typeof Gate>[0]> = {}) {
  const db = new Database(":memory:");
  for (const stmt of MIGRATIONS) db.exec(stmt);
  const clock = { t: T0 };
  const store = new Store(db, () => clock.t);
  const gate = new Gate({
    store,
    now: () => clock.t,
    threads: { ancestors: async () => [], descendants: async () => [] },
    thirdPartyRunning: async () => [],
    externalTotpFile: null,
    snapshotsRoot: join(root, "snapshots"),
    unsafeDirs: async () => [],
    ...over,
  });
  return { db, store, gate, clock };
}

// ---- 1. F2: database access is a capability; ATTACH / extensions are a block ---------------------------------------------
describe("1. F2: the database handle is a capability, ATTACH and extensions are blocks", () => {
  it("attack fixture: a plugin with no capabilities that ATTACHes another plugin's database is a block (and the gate rejects it)", async () => {
    const dir = join(here, "fixtures", "attack-attach");
    const r = await runChecks(dir);
    expect(r.findings.filter((f) => f.severity === "block").map((f) => f.rule)).toContain("sqlite-attach");
    // none of the old capability kinds: the attack looks "clean" to the old safe class
    expect(r.capabilities.map((c) => c.kind).filter((k) => k !== "database")).toEqual([]);
    expect(r.capabilities.map((c) => c.kind)).toContain("database");

    const { gate } = newGate();
    const d = await gate.decide(ctx(dir, "sha256:attack"));
    expect(d.action).toBe("reject");
  });

  it("bb.storage.database() alone is the `database` capability, outside the safe class", async () => {
    const r = await rulesOf("export default (bb) => { const db = bb.storage.database(); db.exec('CREATE TABLE IF NOT EXISTS t (a)'); };");
    expect(r.kinds).toEqual(["database"]);
    expect(r.blocks).toEqual([]);
  });

  it("the handle is seen through an alias, a destructuring and an unreadable key", async () => {
    expect((await rulesOf("export default (bb) => { const s = bb.storage; return s.database(); };")).kinds).toContain("database");
    expect((await rulesOf("export default (bb) => { const { database } = bb.storage; return database(); };")).kinds).toContain("database");
    const dyn = await rulesOf("export default (bb, k) => bb.storage[k]();");
    expect(dyn.kinds).toContain("database");
    expect(dyn.all).toContain("review:dynamic-access");
  });

  it("ATTACH, VACUUM INTO, load_extension, .loadExtension and PRAGMA assignments are blocks, however the string is built", async () => {
    expect((await rulesOf("export default (db) => db.exec(\"ATTACH DATABASE '/x/y.db' AS s\");")).blocks).toContain("sqlite-attach");
    expect((await rulesOf("export default (db, p) => db.exec(`attach '${p}' as s`);")).blocks).toContain("sqlite-attach");
    expect((await rulesOf("export default (db, p) => db.exec(\"ATT\" + \"ACH '\" + p + \"' AS s\");")).blocks).toContain("sqlite-attach");
    expect((await rulesOf("export default (db) => db.exec(\"VACUUM INTO '/tmp/copy.db'\");")).blocks).toContain("sqlite-vacuum-into");
    expect((await rulesOf("export default (db) => db.prepare(\"SELECT load_extension('/tmp/x.dylib')\").get();")).blocks).toContain("sqlite-extension");
    expect((await rulesOf("export default (db) => db.loadExtension('/tmp/x.dylib');")).blocks).toContain("sqlite-extension");
    expect((await rulesOf("export default (db) => db['load' + 'Extension']('/tmp/x.dylib');")).blocks).toContain("sqlite-extension");
    expect((await rulesOf("export default (db) => db.exec('PRAGMA s.user_version = 3');")).blocks).toContain("sqlite-pragma");
    expect((await rulesOf("export default (db) => db.exec('PRAGMA writable_schema = 1');")).blocks).toContain("sqlite-pragma");
    expect((await rulesOf("export default (db) => db.pragma('s.journal_mode = off');")).blocks).toContain("sqlite-pragma");
  });

  it("ordinary SQL of a plugin's own database is not a block", async () => {
    const r = await rulesOf("export default (bb) => { const db = bb.storage.database(); db.exec('PRAGMA journal_mode = WAL'); db.exec('CREATE TABLE IF NOT EXISTS t (a)'); return db.prepare('PRAGMA table_info(t)').all(); };");
    expect(r.blocks).toEqual([]);
    expect(r.kinds).toEqual(["database"]);
  });

  it("node:sqlite is a database capability; v8, diagnostics_channel, async_hooks, inspector, vm, worker_threads are dynamic code, none is a plain built-in", async () => {
    expect((await rulesOf("import { DatabaseSync } from 'node:sqlite';\nexport default DatabaseSync;")).kinds).toEqual(["database"]);
    for (const mod of ["v8", "diagnostics_channel", "async_hooks", "inspector", "vm", "worker_threads"]) {
      const r = await rulesOf(`import m from 'node:${mod}';\nexport default m;`);
      expect(r.kinds, mod).toEqual(["dynamic_code"]);
      expect(r.all.filter((x) => x.endsWith(":unknown-builtin")), mod).toEqual([]);
    }
  });

  it("without any of the above the plugin is still clean (the safe class is not emptied by the new rules)", async () => {
    const r = await rulesOf("import { join } from 'node:path';\nexport default (bb) => join('a', 'b');");
    expect(r).toMatchObject({ blocks: [], kinds: [] });
  });
});

// ---- 2. F7: the safe class is not passed without a touch by default --------------------------------------------------------
describe("2. F7: automatic pass of the safe class is off by default and turned on only with a code", () => {
  async function snapshot(h: { store: Store }, n: number) {
    const dir = join(root, "snapshots", "demo", `s${n}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: `1.0.${n}` }));
    writeFileSync(join(dir, "server.ts"), `export default () => ${n};\n`);
    const proposal = h.store.addProposal({ pluginId: "demo", localHash: await hashTree(dir), snapshotDir: dir, threadId: "T1", windowId: null });
    return { dir, proposal };
  }

  it("the default policy has it off", async () => {
    const { store } = newGate();
    expect(store.policy().autoSafe).toBe(false);
  });

  it("a clean snapshot with no capabilities is held for a touch, and the reason says why", async () => {
    const h = await registered({ runChecks: async () => CLEAN });
    const s = await snapshot(h, 1);
    const d = await h.gate.decide(ctx(s.dir, "sha256:safe1"));
    expect(d.action).toBe("wait");
    expect(h.store.listQueue()[0]!.reason).toBe(T.autoSafeOff);
    expect(h.store.activeApproval("sha256:safe1")).toBeNull();
    // a touch still approves it
    h.gate.approveQueue(h.store.listQueue()[0]!.id, h.code());
    expect(h.store.activeApproval("sha256:safe1")).toMatchObject({ via: "touch" });
  });

  it("turning it on needs a code; then the clean snapshot passes by itself; turning it off needs none", async () => {
    const h = await registered({ runChecks: async () => CLEAN });
    expect(() => h.gate.setPolicy({ autoSafe: true }, undefined)).toThrow(GateError);
    expect(() => h.gate.setPolicy({ autoSafe: true }, "000000")).toThrow(/invalid/);
    expect(h.store.policy().autoSafe).toBe(false);
    h.gate.setPolicy({ autoSafe: true }, h.code());
    expect(h.store.policy().autoSafe).toBe(true);
    const s = await snapshot(h, 2);
    expect(await h.gate.decide(ctx(s.dir, "sha256:safe2"))).toEqual({ action: "proceed" });
    expect(h.store.activeApproval("sha256:safe2")).toMatchObject({ via: "auto" });
    h.gate.setPolicy({ autoSafe: false }, undefined);
    expect(h.store.policy().autoSafe).toBe(false);
    const s3 = await snapshot(h, 3);
    expect((await h.gate.decide(ctx(s3.dir, "sha256:safe3"))).action).toBe("wait");
  });

  it("the page warns when it is switched on (the warning text says the server code runs in the gate's process)", () => {
    expect(T.autoSafeWarning).toMatch(/процесс/);
    expect(readFileSync(join(here, "..", "app.tsx"), "utf8")).toContain("T.autoSafeWarning");
  });
});

// ---- 3. F6: registration from the page and the external secret file ------------------------------------------------------
describe("3. F6: registering from the page is flagged; from stage 3 the missing external secret file is a shortcoming", () => {
  const probe = (env: Record<string, string>): Probe => ({
    hookRegistered: true,
    env: { BB_PLUGIN_ACTIVATION_GUARDS: "secure-bb", ...env },
    serverUid: 501,
    agentUid: 502,
    accountState: "signed-in",
    builtins: {},
    connectHold: { exists: false, serverCanDelete: null },
    bind: { address: null, loopbackOnly: null },
    apiAuth: "unknown",
    thirdParty: [],
    telemetryConfigured: null,
  });

  it("stage 3 without BB_SECURE_BB_TOTP_FILE: a bad check, listed under what is missing", () => {
    const a = assess(probe({}));
    expect(a.stage).toBe(3);
    expect(a.checks.find((c) => c.id === "totp-file")).toMatchObject({ state: "bad" });
    expect(a.missing).toContain(T.totpFile.missing);
  });

  it("stage 3 with the file: ok, nothing missing about it", () => {
    const a = assess(probe({ BB_SECURE_BB_TOTP_FILE: "/etc/secure-bb/totp.secret" }));
    expect(a.checks.find((c) => c.id === "totp-file")).toMatchObject({ state: "ok" });
    expect(a.missing).not.toContain(T.totpFile.missing);
  });

  it("below stage 3 it is only a warning, and not repeated under 'missing'", () => {
    const a = assess({ ...probe({}), env: {} });
    expect(a.stage).toBe(1);
    expect(a.checks.find((c) => c.id === "totp-file")).toMatchObject({ state: "warn" });
    expect(a.missing).not.toContain(T.totpFile.missing);
  });

  it("the registration card on the page carries the warning and names the file variable", () => {
    expect(T.totpFile.registerWarning).toContain("BB_SECURE_BB_TOTP_FILE");
    expect(T.totpFile.registerWarning).toMatch(/Любой из них/);
    expect(readFileSync(join(here, "..", "app.tsx"), "utf8")).toContain("T.totpFile.registerWarning");
  });
});

// ---- 4. F8: tightening needs no code and ignores the block -----------------------------------------------------------------
describe("4. F8: closing a window, revoking, switching a module off, rollback on, closing the session: no code, not blocked", () => {
  async function blocked() {
    const h = await registered();
    // a version that is approved, with an open window, and a held entry
    h.store.addApproval({ contentHash: "sha256:v1", pluginId: "demo", version: "1.0.0", source: "path:/x", sourceKind: "path", gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, threadId: "T1" });
    const w = h.store.insertWindow({ pluginId: "demo", threadId: "T1", scope: "tree", mode: "sliding", sizeSec: 1800, capSec: 14400, openedAt: h.clock.t, expiresAt: h.clock.t + 1_800_000, hardExpiresAt: h.clock.t + 14_400_000, caps: [] });
    // five wrong codes: every touch is blocked for an hour
    for (let i = 0; i < 5; i++) expect(() => h.gate.touch("attack", "000000")).toThrow();
    expect(h.gate.blockedUntil()).toBeGreaterThan(h.clock.t);
    expect(() => h.gate.touch("anything", h.code())).toThrow(/blocked|too many/); // even the right code
    return { ...h, w };
  }

  it("a window can be closed while touches are blocked", async () => {
    const h = await blocked();
    h.gate.closeWindow(h.w.id);
    expect(h.gate.openWindows()).toEqual([]);
  });

  it("an approval can be revoked while touches are blocked", async () => {
    const h = await blocked();
    h.gate.revoke(h.store.activeApproval("sha256:v1")!.id);
    expect(h.store.activeApproval("sha256:v1")).toBeNull();
  });

  it("widening is still blocked: approving, opening a window and widening the policy need a code", async () => {
    const h = await blocked();
    expect(() => h.gate.setPolicy({ windowMin: 60 }, h.code())).toThrow(/blocked|too many/);
  });

  it("the AI scan and the sentinel can be switched off without a code; switching on needs one", async () => {
    const h = await registered();
    h.gate.setAiSettings({ enabled: true, autoFreeze: true }, h.code());
    h.gate.setAiSettings({ enabled: false }, undefined);
    expect(h.store.aiSettings().enabled).toBe(false);
    expect(() => h.gate.setAiSettings({ enabled: true }, undefined)).toThrow(GateError);
  });

  it("closing a session needs nothing and says nothing about whether there was one", async () => {
    const h = await registered({ thirdPartyRunning: async () => [] });
    const { token } = await h.gate.openSession(h.code());
    h.gate.closeSessions("locked");
    expect(() => h.gate.touch("x", h.gate.proofFor("queue.dismiss", { session: token }))).toThrow(GateError);
  });

  it("over RPC: window.close, approval.revoke and watch.window.close take no code at all", async () => {
    const { bb, harness } = createFakePluginHost({
      pluginId: "secure-bb",
      sdk: { plugins: { list: async () => ({ plugins: [] }), disable: async () => ({}) }, system: { config: async () => ({}) }, threads: {} } as never,
    } as never);
    await plugin(bb);
    for (const [name, input] of [["window.close", { windowId: 1 }], ["approval.revoke", { approvalId: 1 }], ["watch.window.close", { windowId: 1 }]] as const) {
      // no such window / approval: a refusal about that, never about a code
      await expect(harness.behavior.callRpc(name, input), name).rejects.toThrow(/no such/);
    }
    await expect(harness.behavior.callRpc("window.close", { windowId: 1, code: "123456" })).rejects.toThrow(); // the schema no longer takes one
  });
});

// ---- 5. F9: `check` ------------------------------------------------------------------------------------------------------------
describe("5. F9: `check` refuses bb's data and private directories, and tells an agent only a summary", () => {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0;

  it("a directory inside bb's data directory is refused, so is the data directory itself", () => {
    const data = tree("bbdata", { "plugins/x/data.db": "secret" });
    chmodSync(data, 0o755);
    expect(checkPathRefusal(data, { dataDir: data, serverUid: uid })).toMatch(/data directory/);
    expect(checkPathRefusal(join(data, "plugins", "x"), { dataDir: data, serverUid: uid })).toMatch(/data directory/);
    expect(checkPathRefusal(join(data, ".."), { dataDir: data, serverUid: uid })).toBeNull(); // the parent is not inside it
  });

  it("a directory owned by the server's user with mode 700 is refused, one with 755 is not", () => {
    const priv = tree("private-700", { "a.js": "x" });
    chmodSync(priv, 0o700);
    expect(checkPathRefusal(priv, { dataDir: null, serverUid: uid })).toMatch(/private to the server user/);
    chmodSync(priv, 0o755);
    expect(checkPathRefusal(priv, { dataDir: null, serverUid: uid })).toBeNull();
  });

  it("a private parent counts too (a subdirectory of a 700 directory is not reachable by others)", () => {
    const outer = tree("outer-700", { "inner/a.js": "x" });
    chmodSync(join(outer, "inner"), 0o755);
    chmodSync(outer, 0o700);
    expect(checkPathRefusal(join(outer, "inner"), { dataDir: null, serverUid: uid })).toMatch(/private to the server user/);
    chmodSync(outer, 0o755);
  });

  it("a directory that belongs to someone else is not refused by the privacy rule", () => {
    const priv = tree("other-owner", { "a.js": "x" });
    chmodSync(priv, 0o700);
    expect(checkPathRefusal(priv, { dataDir: null, serverUid: uid + 1 })).toBeNull();
    chmodSync(priv, 0o755);
  });

  it("the summary has the verdict and counts but no rule, file, line, excerpt, host or capability name", async () => {
    const r = await runChecks(tree("summary", { "index.js": "export const s = JSON.stringify(process.env);\nfetch('https://secret-host.example');\n" }));
    const text = checkSummary(r);
    expect(text).toMatch(/^check: stopped; 1 block/);
    expect(text).not.toMatch(/env-dump|index\.js|secret-host|network|fetch|:1/);
    expect(checkSummary({ findings: [], capabilities: [], stats: r.stats })).toMatch(/^check: clean; 0 block, 0 review, 0 capabilities/);
  });

  it("through the CLI: the data directory is refused with a plain message (and a journal record), a normal directory gets the summary", async () => {
    const data = tree("cli-data", { "gate/data.db": "secret" });
    chmodSync(data, 0o755);
    const { bb, harness } = createFakePluginHost({
      pluginId: "secure-bb",
      dataDir: data,
      sdk: { plugins: { list: async () => ({ plugins: [] }) }, system: { config: async () => ({}) }, threads: {} } as never,
    } as never);
    await plugin(bb);
    const refused = await harness.behavior.runCli(["check", join(data, "gate")]);
    expect(refused.exitCode).toBe(1);
    expect(refused.stderr).toContain("cannot be checked from here");
    expect(refused.stderr).not.toMatch(/data directory|private|bbdata|cli-data/);
    const ok = tree("cli-plain", { "index.js": "export default 1;\n" });
    chmodSync(ok, 0o755);
    const res = await harness.behavior.runCli(["check", ok]);
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toMatch(/^check: clean/);
  });
});

// ---- 6. F10: pollution ---------------------------------------------------------------------------------------------------------
describe("6. F10: pollution cannot be dodged with an interpreter one-liner, a lookalike address or a trusted repository's issues", () => {
  const cmd = (command: string, trusted: string[] = []) => classifyItem({ type: "commandExecution", command, status: "completed" }, trusted);
  const MINE = ["me/my-plugin", "myorg/*"];

  it("node -e / python -c / perl -e / ruby -e with a network call or a URL literal taint", () => {
    for (const c of [
      `node -e "fetch('https://example.org').then(r => r.text())"`,
      `node -e "require('https').get('https://example.org')"`,
      `node --input-type=module -e "await fetch(process.argv[1])" https://example.org`,
      `python3 -c "import urllib.request as u; u.urlopen('https://example.org')"`,
      `python -c "import requests; requests.get(url)"`,
      `perl -e 'use LWP::Simple; get("http://example.org")'`,
      `ruby -e "require 'open-uri'; URI.open('https://example.org')"`,
      `cd /w && node -e "fetch('https://example.org'); console.log(1)"`,
    ])
      expect(cmd(c)?.kind, c).toBe("web");
  });

  it("the same interpreters without a network call do not taint", () => {
    for (const c of [`node -e "console.log(1 + 1)"`, `python3 -c "print(sum(range(10)))"`, `perl -e 'print 1'`, "node script.js", "python3 build.py --out dist"]) expect(cmd(c), c).toBeNull();
  });

  it("curl / wget taint whatever the address looks like (a variable, a file)", () => {
    for (const c of [`curl "$URL"`, `U=https://x.test; curl "$U" -o a`, "wget -i urls.txt", "sudo curl -s $X", "/usr/bin/curl $A"]) expect(cmd(c)?.kind, c).toBe("web");
    expect(cmd("echo curl is a tool")).toBeNull();
  });

  it("github.com is recognised only as the host of the address", () => {
    expect(githubSlug("https://github.com/Me/My-Plugin.git")).toBe("me/my-plugin");
    expect(githubSlug("git@github.com:me/my-plugin.git")).toBe("me/my-plugin");
    expect(githubSlug("ssh://git@github.com/me/my-plugin")).toBe("me/my-plugin");
    for (const bad of ["https://evil.tld/github.com/me/my-plugin", "https://github.com.evil.tld/me/my-plugin", "https://github.com@evil.tld/me/my-plugin", "https://evil.tld/?u=github.com/me/my-plugin", "git@evil.tld:github.com/me/my-plugin", "https://notgithub.com/me/my-plugin"])
      expect(githubSlug(bad), bad).toBeNull();
  });

  it("a clone from a lookalike address of a trusted repository taints", () => {
    expect(cmd("git clone https://github.com/me/my-plugin.git", MINE)).toBeNull();
    for (const c of ["git clone https://evil.tld/github.com/me/my-plugin", "git clone https://github.com.evil.tld/me/my-plugin", "git clone https://github.com@evil.tld/me/my-plugin"])
      expect(cmd(c, MINE)?.kind, c).toBe("repo");
  });

  it("issues, pull requests and comments taint even in a trusted repository", () => {
    for (const c of [
      "gh issue view 3 --repo me/my-plugin",
      "gh issue list -R me/my-plugin",
      "gh pr view 5 --comments --repo me/my-plugin",
      "gh pr view 5 -R myorg/tool",
      "gh pr diff 5 -R myorg/tool",
      "gh pr checkout 5 --repo me/my-plugin",
      "gh api repos/me/my-plugin/issues/3/comments",
      "gh api repos/me/my-plugin/pulls/5",
    ])
      expect(cmd(c, MINE)?.kind, c).toBe("repo");
    // what stays trusted: the repository's own contents
    expect(cmd("gh repo clone me/my-plugin", MINE)).toBeNull();
    expect(cmd("gh api repos/me/my-plugin/contents/README.md", MINE)).toBeNull();
  });
});

// ---- 7. X3: a mark of life and an alarm for a gap -------------------------------------------------------------------------------
describe("7. X3: the gate leaves a trace when it was off", () => {
  function alive(safe: { v: boolean | null } = { v: false }) {
    const { store, clock } = newGate();
    const a = new Alive({ store, now: () => clock.t, safeMode: async () => safe.v });
    return { store, clock, a, safe };
  }

  it("the first start is a record but not an alarm", async () => {
    const h = alive();
    expect(await h.a.start()).toBeNull();
    expect(h.store.listLog(10).map((l) => l.kind)).toContain("gate.start");
    expect(h.a.view().gaps).toEqual([]);
  });

  it("a restart within the threshold is not an alarm; a gap longer than it is, with from, to and the journal record", async () => {
    const h = alive();
    await h.a.start();
    await h.a.beat();
    h.clock.t += ALIVE_INTERVAL_MS;
    await h.a.beat();
    const lastBeat = h.clock.t;
    h.clock.t += GAP_THRESHOLD_MS - 1000;
    expect(await h.a.start()).toBeNull();
    h.clock.t += GAP_THRESHOLD_MS + 5 * 60_000;
    const alarm = await h.a.start();
    expect(alarm).toMatchObject({ from: expect.any(Number), ms: GAP_THRESHOLD_MS + 5 * 60_000 });
    expect(alarm!.to - alarm!.from).toBe(alarm!.ms);
    expect(lastBeat).toBeLessThan(alarm!.to);
    expect(h.store.listLog(20).filter((l) => l.kind === "gate.gap")).toHaveLength(1);
    expect(h.a.view().gaps[0]).toMatchObject({ ms: alarm!.ms, stopped: false });
    expect(h.store.verifyJournal().ok).toBe(true);
  });

  it("a stop followed by a long gap says it was an orderly stop (disabled), and the alarm stays on the page for a week", async () => {
    const h = alive();
    await h.a.start();
    await h.a.beat();
    h.a.stop();
    h.clock.t += 10 * 60_000;
    const alarm = await h.a.start();
    expect(alarm).toMatchObject({ stopped: true });
    h.clock.t += 6 * 24 * 3_600_000;
    expect(h.a.view().gaps).toHaveLength(1);
    h.clock.t += 2 * 24 * 3_600_000;
    expect(h.a.view().gaps).toHaveLength(0);
  });

  it("safe-mode on at start is recorded and shown; switched on or off while running is recorded too", async () => {
    const h = alive({ v: true });
    await h.a.start();
    expect(h.store.listLog(10).map((l) => l.kind)).toContain("safe-mode.on");
    expect(h.a.view()).toMatchObject({ safeMode: true, safeModeSeen: true });
    h.safe.v = false;
    await h.a.beat();
    expect(h.store.listLog(10)[0]!.kind).toBe("safe-mode.off");
    h.safe.v = true;
    await h.a.beat();
    expect(h.store.listLog(3).map((l) => l.kind)).toContain("safe-mode.on");
  });

  it("an unreadable safe-mode is not recorded as either state", async () => {
    const h = alive({ v: null });
    await h.a.start();
    expect(h.store.listLog(10).filter((l) => l.kind.startsWith("safe-mode"))).toEqual([]);
    expect(h.a.view().safeMode).toBeNull();
  });

  it("through the server entry: the background loop writes the mark and the overview carries the view", async () => {
    const { bb, harness } = createFakePluginHost({
      pluginId: "secure-bb",
      sdk: { plugins: { list: async () => ({ plugins: [] }) }, system: { config: async () => ({}) }, threads: {} } as never,
    } as never);
    await plugin(bb);
    const ov = (await harness.behavior.callRpc("overview", null)) as { alive: { lastBeat: number | null; gaps: unknown[] } };
    expect(ov.alive.lastBeat).toBeTypeOf("number");
    expect(ov.alive.gaps).toEqual([]);
    expect(readFileSync(join(here, "..", "app.tsx"), "utf8")).toContain("<AliveAlarm");
  });
});

// ---- 8. AI scan: enabling only with a code; cursor-agent in a sandbox -------------------------------------------------------------
describe("8. the AI scan is enabled only with a code, and cursor-agent runs with --sandbox enabled", () => {
  it("every way of turning something on needs a code (nothing leaves for the cloud without one)", async () => {
    const h = await registered();
    for (const patch of [{ enabled: true }, { autoFreeze: true }, { autoExternal: true }, { second: true, secondModel: "gpt-5" }, { freezePlugin: { id: "demo", on: true } }]) {
      expect(() => h.gate.setAiSettings(patch, undefined), JSON.stringify(patch)).toThrow(GateError);
    }
    expect(() => h.gate.setAiSettings({ enabled: true }, "000000")).toThrow(/invalid/);
    expect(h.store.aiSettings()).toMatchObject({ enabled: false, autoFreeze: false, autoExternal: false, second: false, freezePlugins: [] });
    h.gate.setAiSettings({ enabled: true }, h.code());
    expect(h.store.aiSettings().enabled).toBe(true);
  });

  it("changing the second model while it is on is also a code (a different vendor gets the code)", async () => {
    const h = await registered();
    h.gate.setAiSettings({ enabled: true, second: true, secondModel: "gpt-5" }, h.code());
    h.tick();
    expect(() => h.gate.setAiSettings({ secondModel: "gemini-3" }, undefined)).toThrow(GateError);
    h.gate.setAiSettings({ secondModel: "gemini-3" }, h.code());
    expect(h.store.aiSettings().secondModel).toBe("gemini-3");
  });

  it("the cursor-agent command has --sandbox enabled, before the model, in ask mode", () => {
    const b = cursorCommand({ prompt: "p", cwd: "/empty", model: "gpt-5", server: {} });
    if (!b.ok) throw new Error(b.unavailable);
    expect(b.spec.args).toEqual(["-p", "--trust", "--mode", "ask", "--sandbox", "enabled", "--model", "gpt-5"]);
  });
});

// ---- 9. revoke: every approval of the version ----------------------------------------------------------------------------------
describe("9. revoke withdraws every approval of the version, by content hash and by reviewed-source hash", () => {
  const add = (store: Store, over: Partial<Parameters<Store["addApproval"]>[0]>) =>
    store.addApproval({ contentHash: "sha256:x", pluginId: "demo", version: "1.0.0", source: "path:/x", sourceKind: "path", gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, threadId: "T1", ...over });

  it("the row before the build and the row after it (other core hash, same source hash) both go; another version stays", async () => {
    const { store, gate } = newGate();
    const before = add(store, { contentHash: "sha256:before-build", localHash: "sha256:src1", via: "touch" });
    const after = add(store, { contentHash: "sha256:after-build", localHash: "sha256:src1", via: "pin" });
    const other = add(store, { contentHash: "sha256:v2", localHash: "sha256:src2", version: "2.0.0", via: "touch" });
    const sameHashOtherPlugin = add(store, { contentHash: "sha256:o", pluginId: "other", localHash: "sha256:src1" });
    gate.revoke(before.id);
    expect(store.activeApproval("sha256:before-build")).toBeNull();
    expect(store.activeApproval("sha256:after-build")).toBeNull();
    expect(store.activeApproval("sha256:v2")?.id).toBe(other.id);
    expect(store.activeApproval("sha256:o")?.id).toBe(sameHashOtherPlugin.id);
    expect(store.listLog(5).find((l) => l.kind === "revoked")!.detail).toMatchObject({ approvals: 2 });
    void after;
  });

  it("the row without a source hash is found by its core hash; the siblings of the same core hash go too", async () => {
    const { store, gate } = newGate();
    const a = add(store, { contentHash: "sha256:same", localHash: null });
    gate.revoke(a.id);
    expect(store.activeApproval("sha256:same")).toBeNull();
  });

  it("the snapshots with that source hash lose their pin, so they are held again", async () => {
    const { store, gate } = newGate();
    const dir = tree("pinned-snapshot", { "server.ts": "export default 1;\n" });
    const proposal = store.addProposal({ pluginId: "demo", localHash: "sha256:src9", snapshotDir: dir, threadId: "T1", windowId: null });
    store.markProposalLoaded(proposal.id);
    store.approveProposal(proposal.id);
    const row = add(store, { contentHash: "sha256:c9", localHash: "sha256:src9" });
    gate.revoke(row.id);
    expect(store.getProposal(proposal.id)).toMatchObject({ loadedAt: null, touchApprovedAt: null });
  });

  it("a touch approval keeps the reviewed-source hash of its proposal, so a later revoke finds the siblings", async () => {
    const h = await registered({ runChecks: async () => ({ ...CLEAN, capabilities: [{ kind: "network", detail: [], sites: [] }] }) });
    const dir = join(root, "snapshots", "demo", `r-${Math.random().toString(36).slice(2)}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: "1.0.0" }));
    writeFileSync(join(dir, "server.ts"), "export default 1;\n");
    const localHash = await hashTree(dir);
    h.store.addProposal({ pluginId: "demo", localHash, snapshotDir: dir, threadId: "T1", windowId: null });
    await h.gate.decide(ctx(dir, "sha256:t1"));
    h.gate.approveQueue(h.store.listQueue()[0]!.id, h.code());
    expect(h.store.activeApproval("sha256:t1")).toMatchObject({ via: "touch", localHash });
  });
});

// ---- 10. a session does not survive a third-party plugin ----------------------------------------------------------------------------
describe("10. an open session is closed when a third-party plugin starts running", () => {
  it("the session works, then a plugin starts, then it is closed and its token is useless", async () => {
    const running: string[] = [];
    const h = await registered({ thirdPartyRunning: async () => [...running] });
    const { token } = await h.gate.openSession(h.code());
    expect(h.gate.proofFor("queue.dismiss", { session: token })).toBeInstanceOf(SessionProof);
    expect(() => h.gate.touch("t", h.gate.proofFor("queue.dismiss", { session: token }))).not.toThrow();

    expect(await h.gate.closeSessionsForThirdParty()).toEqual([]); // nobody runs: nothing to do
    expect(h.store.unclosedSessions()).toHaveLength(1);

    running.push("nosy");
    expect(await h.gate.closeSessionsForThirdParty()).toEqual(["nosy"]);
    expect(h.store.unclosedSessions()).toHaveLength(0);
    expect(() => h.gate.touch("t", h.gate.proofFor("queue.dismiss", { session: token }))).toThrow(/invalid or expired session|invalid/);
    expect(h.store.listLog(10).find((l) => l.kind === "session.close")!.detail).toMatchObject({ reason: expect.stringContaining("nosy") });
  });

  it("with no session open it does nothing and does not ask who runs", async () => {
    let asked = 0;
    const running: string[] = [];
    const h = await registered({ thirdPartyRunning: async () => (asked++, [...running]) });
    running.push("nosy");
    asked = 0;
    expect(await h.gate.closeSessionsForThirdParty()).toEqual([]);
    expect(asked).toBe(0);
  });

  it("a new session cannot be opened while one runs (as before)", async () => {
    const running: string[] = [];
    const h = await registered({ thirdPartyRunning: async () => [...running] });
    running.push("nosy");
    await expect(h.gate.openSession(h.code())).rejects.toThrow(/third-party plugins/);
  });
});
