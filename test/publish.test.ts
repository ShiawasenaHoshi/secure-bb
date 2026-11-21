// Stage 4: publishing a frozen version to the plugins monorepo. Real `git` against a local bare
// repository (file://): no network, no real token ever leaves the process.
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Gate, GateError } from "../src/gate.js";
import { propose } from "../src/propose.js";
import { Publisher } from "../src/publish/publisher.js";
import { PUBLISH_TOKEN_FILE_ENV } from "../src/publish/types.js";
import { checkBranch, checkRepoUrl } from "../src/publish/validate.js";
import { runProcess } from "../src/scan/process.js";
import type { CommandSpec, ProcessRunner } from "../src/scan/commands.js";
import { MIGRATIONS, Store } from "../src/store.js";
import { base32Decode, hotp, stepAt } from "../src/totp.js";
import { hashTree } from "../src/tree.js";
import { NETWORKED } from "./support/checks.js";

const TOKEN = "ghp_TESTTOKEN0123456789abcdefghijklmnop";
const PLAIN_ENV = { PATH: process.env.PATH ?? "", HOME: "/nonexistent", LC_ALL: "C", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };
const sh = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, env: PLAIN_ENV, encoding: "utf8" }).trim();

interface Call {
  spec: CommandSpec;
  homeEntries: string[] | null;
  askpass: string | null;
}

class Env {
  t = 1_800_000_000_000;
  root = realpathSync(mkdtempSync(join(tmpdir(), "sbb-pub-")));
  snapshots = join(this.root, "snapshots");
  bare = join(this.root, "plugins.git");
  tokenFile = join(this.root, "token");
  store: Store;
  gate: Gate;
  publisher: Publisher;
  calls: Call[] = [];
  /** Before a command is run (lets a test move the remote under the publisher's feet). */
  before: ((spec: CommandSpec) => void) | null = null;
  tokenPath: string | null = this.tokenFile;
  code!: () => string;
  private n = 0;

  constructor() {
    mkdirSync(this.snapshots);
    mkdirSync(this.bare);
    sh(this.bare, "init", "-q", "--bare");
    sh(this.bare, "symbolic-ref", "HEAD", "refs/heads/main");
    writeFileSync(this.tokenFile, `${TOKEN}\n`, { mode: 0o600 });
    const db = new Database(":memory:");
    for (const s of MIGRATIONS) db.exec(s);
    this.store = new Store(db, () => this.t);
    this.publisher = null as unknown as Publisher;
    this.gate = new Gate({
      store: this.store,
      now: () => this.t,
      threads: { ancestors: async () => [], descendants: async () => [] },
      thirdPartyRunning: async () => [],
      externalTotpFile: null,
      snapshotsRoot: this.snapshots,
      unsafeDirs: async () => [],
      runChecks: async () => NETWORKED,
      publishAllowFile: true,
      onFreeze: (id, pin) => this.publisher.onFreeze(id, pin),
    });
    this.rebuild();
  }
  rebuild(): void {
    const run: ProcessRunner = (spec) => {
      this.before?.(spec);
      const home = spec.env.HOME;
      const askpass = spec.env.GIT_ASKPASS;
      this.calls.push({ spec, homeEntries: home && existsSync(home) ? readdirSync(home) : null, askpass: askpass && existsSync(askpass) ? readFileSync(askpass, "utf8") : null });
      return runProcess(spec);
    };
    this.publisher = new Publisher({ store: this.store, now: () => this.t, run, tokenFile: this.tokenPath, snapshotsRoot: this.snapshots, allowFile: true });
  }
  async register(): Promise<void> {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    this.code = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(this.code());
    this.t += 31_000;
  }
  enable(opts: { onApprove?: boolean } = {}): void {
    this.store.setPublishSettings({ enabled: true, repoUrl: `file://${this.bare}`, branch: "main", onApprove: opts.onApprove ?? false });
  }
  /** A snapshot as `propose` makes it: a directory under snapshots/<id>/<hash>, a proposal row and an approval. */
  async snapshot(id: string, version: string, files: Record<string, string> = {}, o: { approve?: boolean } = {}): Promise<{ dir: string; localHash: string; proposalId: number }> {
    const src = join(this.root, "src", `${id}-${version}-${this.n++}`);
    mkdirSync(src, { recursive: true });
    writeFileSync(join(src, "package.json"), JSON.stringify({ name: `bb-plugin-${id}`, version, bb: { server: "./server.ts" } }));
    writeFileSync(join(src, "server.ts"), `export default () => "${id} ${version}";\n`);
    for (const [f, body] of Object.entries(files)) {
      mkdirSync(join(src, f, ".."), { recursive: true });
      writeFileSync(join(src, f), body);
    }
    const localHash = await hashTree(src);
    const dir = join(this.snapshots, id, localHash);
    mkdirSync(join(this.snapshots, id), { recursive: true });
    execFileSync("cp", ["-R", src, dir]);
    const proposal = this.store.addProposal({ pluginId: id, localHash, snapshotDir: dir, threadId: "T1", windowId: null });
    if (o.approve !== false) {
      this.store.addApproval({ contentHash: `sha256:${id}${version}${this.n}`, pluginId: id, version, source: `path:${dir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, via: "window", windowId: 1, threadId: "T1", localHash });
    }
    return { dir, localHash, proposalId: proposal.id };
  }
  clone(): string {
    const dir = join(this.root, `clone-${this.n++}`);
    sh(this.root, "clone", "-q", this.bare, dir);
    return dir;
  }
  plugin(name: string, version = "1.0.0"): string {
    const dir = join(this.root, "plugins", name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `bb-plugin-${name}`, version, bb: { server: "./server.ts" } }));
    writeFileSync(join(dir, "server.ts"), "export default () => {};\n");
    return dir;
  }
  cleanup(): void {
    rmSync(this.root, { recursive: true, force: true });
  }
}

let e: Env;
beforeEach(() => {
  e = new Env();
});
afterEach(() => e.cleanup());

describe("what is published", () => {
  it("puts the snapshot into <id>/ (no dist, node_modules, .git), commits '<id>@<version> frozen <hash>' and tags <id>-v<version>", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.2.3", { "src/a.ts": "export const a = 1;\n", "dist/bundle.js": "built", "node_modules/x/index.js": "dep", "src/node_modules/y.js": "nested", ".git/config": "x" });
    const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "manual" });
    expect(out.row).toMatchObject({ status: "published", version: "1.2.3", tag: "demo-v1.2.3" });

    const c = e.clone();
    expect(sh(c, "log", "-1", "--format=%s")).toBe(`demo@1.2.3 frozen ${s.localHash}`);
    expect(sh(c, "rev-parse", "demo-v1.2.3^{commit}")).toBe(sh(c, "rev-parse", "HEAD"));
    expect(out.row!.commit).toBe(sh(c, "rev-parse", "HEAD"));
    const files = sh(c, "ls-files").split("\n").sort();
    expect(files).toEqual(["demo/package.json", "demo/server.ts", "demo/src/a.ts"]);
    expect(readFileSync(join(c, "demo/src/a.ts"), "utf8")).toBe("export const a = 1;\n");
    expect(sh(c, "log", "-1", "--format=%an <%ae>")).toBe("secure-bb <secure-bb@localhost>");
    expect(sh(c, "branch", "--show-current")).toBe("main");
    expect(e.store.listLog(5).map((l) => l.kind)).toContain("publish.ok");
  });

  it("several plugins share the repository, each in its own directory; a new version is a new commit and a new tag", async () => {
    e.enable();
    const a = await e.snapshot("alpha", "1.0.0");
    const b = await e.snapshot("beta", "0.1.0");
    const a2 = await e.snapshot("alpha", "1.1.0", { "extra.ts": "1\n" });
    for (const s of [a, b, a2]) {
      const r = (await e.publisher.publish({ pluginId: s.dir.includes("alpha") ? "alpha" : "beta", localHash: s.localHash, trigger: "freeze" })).row!;
      expect([r.status, r.detail]).toEqual(["published", expect.any(String)]);
    }
    const c = e.clone();
    expect(sh(c, "ls-files").split("\n").filter((f) => f.endsWith("package.json")).sort()).toEqual(["alpha/package.json", "beta/package.json"]);
    expect(readFileSync(join(c, "alpha/package.json"), "utf8")).toContain("1.1.0");
    expect(sh(c, "tag", "--list").split("\n").sort()).toEqual(["alpha-v1.0.0", "alpha-v1.1.0", "beta-v0.1.0"]);
    expect(sh(c, "rev-list", "--count", "HEAD")).toBe("3");
  });

  it("an older tag keeps pointing at the old content", async () => {
    e.enable();
    const a = await e.snapshot("alpha", "1.0.0");
    const a2 = await e.snapshot("alpha", "1.1.0", { "extra.ts": "1\n" });
    await e.publisher.publish({ pluginId: "alpha", localHash: a.localHash, trigger: "freeze" });
    await e.publisher.publish({ pluginId: "alpha", localHash: a2.localHash, trigger: "freeze" });
    const c = e.clone();
    expect(sh(c, "ls-tree", "-r", "--name-only", "alpha-v1.0.0").split("\n")).not.toContain("alpha/extra.ts");
    expect(sh(c, "ls-tree", "-r", "--name-only", "alpha-v1.1.0").split("\n")).toContain("alpha/extra.ts");
  });

  it("publishes a symlink that stays inside the tree as a link", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0", { "real.txt": "x\n" });
    symlinkSync("real.txt", join(s.dir, "link.txt"));
    // the snapshot's bytes changed: register it again as the reviewed source
    const hash = await hashTree(s.dir);
    const p = e.store.addProposal({ pluginId: "demo", localHash: hash, snapshotDir: s.dir, threadId: "T1", windowId: null });
    e.store.approveProposal(p.id);
    const out = await e.publisher.publish({ pluginId: "demo", localHash: hash, trigger: "manual" });
    expect(out.row!.status).toBe("published");
    expect(sh(e.clone(), "ls-files", "-s", "demo/link.txt")).toMatch(/^120000 /);
  });
});

describe("repeating and conflicts", () => {
  it("the same source is not pushed twice", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    const again = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "manual" });
    expect(again.row!.status).toBe("unchanged");
    expect(sh(e.clone(), "rev-list", "--count", "HEAD")).toBe("1");
  });

  it("already in the repository (state lost): recognised by the tag's commit message, nothing is pushed", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    e.store = e.store; // same repository, a fresh history of attempts
    (e.store as unknown as { db: Database.Database }).db.exec("DELETE FROM publications");
    const again = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "manual" });
    expect(again.row).toMatchObject({ status: "unchanged", tag: "demo-v1.0.0" });
    expect(sh(e.clone(), "rev-list", "--count", "HEAD")).toBe("1");
  });

  it("a version number that already exists with other content is refused: tags are never moved", async () => {
    e.enable();
    const a = await e.snapshot("demo", "1.0.0");
    const b = await e.snapshot("demo", "1.0.0", { "changed.ts": "1\n" });
    await e.publisher.publish({ pluginId: "demo", localHash: a.localHash, trigger: "freeze" });
    const out = await e.publisher.publish({ pluginId: "demo", localHash: b.localHash, trigger: "freeze" });
    expect(out.row!.status).toBe("failed");
    expect(out.row!.detail).toContain("поднимите версию");
    const c = e.clone();
    expect(sh(c, "log", "-1", "--format=%s", "demo-v1.0.0")).toContain(a.localHash);
    expect(sh(c, "rev-list", "--count", "HEAD")).toBe("1");
  });

  it("the branch moved while publishing: fetches again and pushes on top (no force)", async () => {
    e.enable();
    const first = await e.snapshot("alpha", "1.0.0");
    await e.publisher.publish({ pluginId: "alpha", localHash: first.localHash, trigger: "freeze" });
    const b = await e.snapshot("beta", "1.0.0");
    let moved = false;
    e.before = (spec) => {
      if (spec.args[0] !== "push" || moved) return;
      moved = true;
      const other = e.clone();
      writeFileSync(join(other, "someone-else.txt"), "x\n");
      sh(other, "add", "-A");
      execFileSync("git", ["-c", "user.name=o", "-c", "user.email=o@x", "commit", "-q", "-m", "other"], { cwd: other, env: PLAIN_ENV });
      sh(other, "push", "-q", "origin", "HEAD:main");
    };
    const out = await e.publisher.publish({ pluginId: "beta", localHash: b.localHash, trigger: "freeze" });
    expect(out.row!.status).toBe("published");
    const c = e.clone();
    expect(sh(c, "ls-files").split("\n")).toEqual(expect.arrayContaining(["alpha/package.json", "beta/package.json", "someone-else.txt"]));
    expect(sh(c, "rev-list", "--count", "HEAD")).toBe("3");
  });

  it("a new branch is created when the repository has none", async () => {
    e.store.setPublishSettings({ enabled: true, repoUrl: `file://${e.bare}`, branch: "frozen", onApprove: false });
    const s = await e.snapshot("demo", "1.0.0");
    expect((await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" })).row!.status).toBe("published");
    expect(sh(e.bare, "branch", "--list")).toContain("frozen");
  });
});

describe("only our own, only what was reviewed", () => {
  it("a plugin without a snapshot of ours (third-party, installed another way) is never published", async () => {
    e.enable();
    e.store.addApproval({ contentHash: "sha256:foreign", pluginId: "foreign", version: "9.9.9", source: "npm:foreign", sourceKind: "npm", gitCommit: null, npmIntegrity: "x", via: "pin", windowId: null, threadId: null });
    const pin = e.store.latestApproval("foreign")!;
    e.publisher.onFreeze("foreign", pin);
    expect((await e.publisher.publishPinned("foreign")).row).toBeNull();
    // a hash the store has no snapshot for
    const out = await e.publisher.publish({ pluginId: "foreign", localHash: "f".repeat(64), trigger: "freeze" });
    expect(out.row).toMatchObject({ status: "skipped" });
    expect(out.row!.detail).toContain("не наш плагин");
    expect(sh(e.bare, "for-each-ref")).toBe("");
  });

  it("a proposal nobody approved is not published", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0", {}, { approve: false });
    const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    expect(out.row!.status).toBe("skipped");
    expect(sh(e.bare, "for-each-ref")).toBe("");
  });

  it("a revoked approval is not published", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    e.store.revokeApproval(e.store.latestApproval("demo")!.id);
    expect((await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "manual" })).row!.status).toBe("skipped");
  });

  it("a snapshot changed after review fails the hash check and nothing leaves", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    writeFileSync(join(s.dir, "server.ts"), "export default () => fetch('https://evil.example');\n");
    const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    expect(out.row).toMatchObject({ status: "failed" });
    expect(out.row!.detail).toContain("хеш не совпал");
    expect(sh(e.bare, "for-each-ref")).toBe("");
    expect(e.calls.filter((c) => c.spec.env.SECURE_BB_PUBLISH_TOKEN)).toHaveLength(0);
  });

  it("a snapshot outside our snapshots directory is refused", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    const elsewhere = join(e.root, "elsewhere");
    execFileSync("cp", ["-R", s.dir, elsewhere]);
    e.store.addProposal({ pluginId: "demo", localHash: s.localHash, snapshotDir: elsewhere, threadId: null, windowId: null });
    const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    expect(out.row!.status).toBe("failed");
    expect(out.row!.detail).toContain("вне каталога снимков");
  });

  it("secrets in the snapshot stop the publication (the report names the rule and the file, not the text)", async () => {
    e.enable();
    const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n";
    const s = await e.snapshot("demo", "1.0.0", { "deploy/key.pem": key, "notes.md": `push with ${TOKEN}\n` });
    const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    expect(out.row!.status).toBe("failed");
    expect(out.row!.detail).toContain("private-key в deploy/key.pem");
    expect(out.row!.detail).toContain("push-token в notes.md");
    expect(JSON.stringify(out.row)).not.toContain(TOKEN);
    expect(sh(e.bare, "for-each-ref")).toBe("");
  });

  it("publishing is off: nothing happens and nothing is recorded", async () => {
    const s = await e.snapshot("demo", "1.0.0");
    e.publisher.onFreeze("demo", e.store.latestApproval("demo"));
    await e.publisher.idle();
    expect((await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "manual" })).row).toBeNull();
    expect(e.store.listPublications()).toEqual([]);
    expect(e.calls).toEqual([]);
  });

  it("not configured on the server (no token file variable): says so, runs no git", async () => {
    e.enable();
    e.tokenPath = null;
    e.rebuild();
    expect(e.publisher.state()).toBe("not-configured");
    const s = await e.snapshot("demo", "1.0.0");
    const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    expect(out.row).toMatchObject({ status: "skipped" });
    expect(out.row!.detail).toContain(`публикация не настроена`);
    expect(out.row!.detail).toContain(PUBLISH_TOKEN_FILE_ENV);
    expect(e.calls).toEqual([]);
  });

  it("an unreadable or empty token file fails before any git command", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    e.tokenPath = join(e.root, "missing");
    e.rebuild();
    expect((await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" })).row!.detail).toContain("не читается");
    writeFileSync(e.tokenFile, "\n");
    e.tokenPath = e.tokenFile;
    e.rebuild();
    expect((await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "manual" })).row!.detail).toContain("нет токена");
    expect(e.calls).toEqual([]);
  });
});

describe("how git is run and where the token goes", () => {
  it("the token is only in the environment of the commands that touch the remote: never argv, address, database or journal", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    expect(out.row!.status).toBe("published");
    expect(e.calls.length).toBeGreaterThan(6);
    for (const c of e.calls) {
      expect(c.spec.file).toBe("git"); // no shell
      expect(JSON.stringify(c.spec.args)).not.toContain(TOKEN);
      expect(c.spec.args.join(" ")).not.toMatch(/@.*localhost|https?:\/\/[^ ]*@/);
      expect(c.spec.stdin).toBe("");
      expect(Object.entries(c.spec.env).filter(([k, v]) => v.includes(TOKEN)).map(([k]) => k)).toEqual(c.spec.env.SECURE_BB_PUBLISH_TOKEN ? ["SECURE_BB_PUBLISH_TOKEN"] : []);
      expect(c.askpass).not.toContain(TOKEN); // the script only reads the variable
    }
    const withToken = e.calls.filter((c) => c.spec.env.SECURE_BB_PUBLISH_TOKEN === TOKEN).map((c) => c.spec.args[0]);
    expect(withToken).toEqual(["ls-remote", "push"]); // empty remote: nothing to fetch
    expect(e.calls.filter((c) => !c.spec.env.SECURE_BB_PUBLISH_TOKEN).map((c) => c.spec.args[0])).toEqual(expect.arrayContaining(["init", "commit", "tag", "add"]));
    // nowhere else
    const dump = JSON.stringify((e.store as unknown as { db: Database.Database }).db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().flatMap((t) => (e.store as unknown as { db: Database.Database }).db.prepare(`SELECT * FROM ${(t as { name: string }).name}`).all()));
    expect(dump).not.toContain(TOKEN);
  });

  it("git gets no prompt, no user config, no hooks, an empty HOME and a short protocol list", async () => {
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    for (const c of e.calls) {
      const env = c.spec.env;
      expect(env.GIT_TERMINAL_PROMPT).toBe("0");
      expect(env.GIT_CONFIG_NOSYSTEM).toBe("1");
      expect(env.GIT_CONFIG_GLOBAL).toBe("/dev/null");
      expect(env.GIT_ALLOW_PROTOCOL).toBe("https:file"); // tests only; the server's default is "https"
      expect(env.HOME.startsWith(realpathSync(tmpdir()))).toBe(true);
      expect(c.homeEntries).toEqual([]); // empty
      const cfg = Object.fromEntries(Array.from({ length: Number(env.GIT_CONFIG_COUNT) }, (_, i) => [env[`GIT_CONFIG_KEY_${i}`]!, env[`GIT_CONFIG_VALUE_${i}`]!]));
      expect(cfg).toMatchObject({ "core.hooksPath": "/dev/null", "commit.gpgsign": "false", "http.followRedirects": "false", "credential.helper": "" });
      // nothing of the server's environment
      expect(Object.keys(env).filter((k) => !/^(PATH|HOME|XDG_CONFIG_HOME|LANG|LC_ALL|GIT_.*|SECURE_BB_PUBLISH_TOKEN)$/.test(k))).toEqual([]);
    }
    expect(e.calls.every((c) => c.spec.cwd.startsWith(realpathSync(tmpdir())))).toBe(true);
    expect(existsSync(e.calls[0]!.spec.env.HOME)).toBe(false); // the throwaway directory is gone
  });

  it("the production default allows https only", async () => {
    const p = new Publisher({ store: e.store, now: () => e.t, run: async () => ({ kind: "spawn-failed", errno: "ENOENT", message: "x" }), tokenFile: e.tokenFile, snapshotsRoot: e.snapshots });
    e.enable();
    const s = await e.snapshot("demo", "1.0.0");
    const out = await p.publish({ pluginId: "demo", localHash: s.localHash, trigger: "manual" });
    expect(out.row!.detail).toContain("git не найден");
  });

  it("the user's own git configuration and hooks are not used", async () => {
    e.enable();
    const home = join(e.root, "userhome");
    const hooks = join(e.root, "userhooks");
    mkdirSync(hooks, { recursive: true });
    writeFileSync(join(hooks, "pre-commit"), `#!/bin/sh\ntouch ${join(e.root, "HOOK-RAN")}\n`, { mode: 0o755 });
    chmodSync(join(hooks, "pre-commit"), 0o755);
    writeFileSync(join(hooks, "reference-transaction"), `#!/bin/sh\ntouch ${join(e.root, "HOOK-RAN")}\n`, { mode: 0o755 });
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, ".gitconfig"), `[core]\n\thooksPath = ${hooks}\n[user]\n\tname = Mallory\n\temail = mallory@example.com\n[commit]\n\tgpgsign = true\n[url "file:///nowhere/"]\n\tinsteadOf = file://\n`);
    const saved = { HOME: process.env.HOME, XDG: process.env.XDG_CONFIG_HOME };
    process.env.HOME = home;
    try {
      const s = await e.snapshot("demo", "1.0.0");
      const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
      expect(out.row!.status).toBe("published");
    } finally {
      process.env.HOME = saved.HOME;
    }
    expect(existsSync(join(e.root, "HOOK-RAN"))).toBe(false);
    expect(sh(e.clone(), "log", "-1", "--format=%an")).toBe("secure-bb");
  });

  it("a push that is refused reports git's words with the token and credentials removed", async () => {
    e.store.setPublishSettings({ enabled: true, repoUrl: `file://${e.root}/does-not-exist.git`, branch: "main", onApprove: false });
    const s = await e.snapshot("demo", "1.0.0");
    const out = await e.publisher.publish({ pluginId: "demo", localHash: s.localHash, trigger: "freeze" });
    expect(out.row!.status).toBe("failed");
    expect(out.row!.detail).toMatch(/git ls-remote/);
    expect(JSON.stringify(out.row)).not.toContain(TOKEN);
    expect(e.store.listLog(3).map((l) => l.kind)).toContain("publish.fail");
  });
});

describe("settings", () => {
  beforeEach(async () => {
    await e.register();
  });

  it("enabling, the address and the branch need a code; turning off does not", () => {
    expect(() => e.gate.setPublishSettings({ repoUrl: "file:///x.git" }, undefined)).toThrow(GateError);
    e.gate.setPublishSettings({ repoUrl: `file://${e.bare}` }, e.code());
    expect(e.store.publishSettings()).toMatchObject({ repoUrl: `file://${e.bare}`, enabled: false });
    e.t += 31_000;
    expect(() => e.gate.setPublishSettings({ enabled: true }, undefined)).toThrow(/кода/);
    expect(() => e.gate.setPublishSettings({ enabled: true }, "000000")).toThrow();
    e.gate.setPublishSettings({ enabled: true }, e.code());
    expect(e.store.publishSettings().enabled).toBe(true);
    e.t += 31_000;
    expect(() => e.gate.setPublishSettings({ branch: "other" }, undefined)).toThrow();
    expect(() => e.gate.setPublishSettings({ onApprove: true }, undefined)).toThrow();
    e.gate.setPublishSettings({ onApprove: true }, e.code());
    // narrowing is free
    e.gate.setPublishSettings({ onApprove: false }, undefined);
    e.gate.setPublishSettings({ enabled: false }, undefined);
    expect(e.store.publishSettings()).toMatchObject({ enabled: false, onApprove: false });
    const kinds = e.store.listLog(20).filter((l) => l.kind === "publish.settings");
    expect(kinds.length).toBe(5);
  });

  it("a replayed code is refused", () => {
    const code = e.code();
    e.gate.setPublishSettings({ repoUrl: `file://${e.bare}` }, code);
    expect(() => e.gate.setPublishSettings({ branch: "x" }, code)).toThrow();
  });

  it("cannot be enabled without an address", () => {
    expect(() => e.gate.setPublishSettings({ enabled: true }, e.code())).toThrow(/адрес/);
  });

  it("addresses: https only, no credentials, no query; file:// only where the server was built to allow it", () => {
    const ok = (u: string) => checkRepoUrl(u).ok;
    expect(ok("https://github.com/o/bb-plugins.git")).toBe(true);
    expect(ok("http://github.com/o/r.git")).toBe(false);
    expect(ok("ssh://git@github.com/o/r.git")).toBe(false);
    expect(ok("git@github.com:o/r.git")).toBe(false);
    expect(ok("https://user:pw@github.com/o/r.git")).toBe(false);
    expect(ok("https://ghp_abc@github.com/o/r.git")).toBe(false);
    expect(ok("https://github.com/o/r.git?token=x")).toBe(false);
    expect(ok("https://github.com/o/r.git#x")).toBe(false);
    expect(ok("https://github.com")).toBe(false);
    expect(ok("--upload-pack=touch /tmp/x")).toBe(false);
    expect(ok("https://github.com/o/r .git")).toBe(false);
    expect(ok("file:///tmp/r.git")).toBe(false);
    expect(checkRepoUrl("file:///tmp/r.git", { allowFile: true }).ok).toBe(true);
    const prod = new Gate({ store: e.store, now: () => e.t, threads: { ancestors: async () => [], descendants: async () => [] }, thirdPartyRunning: async () => [], externalTotpFile: null, snapshotsRoot: e.snapshots });
    expect(() => prod.setPublishSettings({ repoUrl: "file:///tmp/r.git" }, "123456")).toThrow(/https/);
  });

  it("branches: plain names only", () => {
    for (const b of ["main", "frozen", "release/2026", "a.b_c-d"]) expect(checkBranch(b)).toBeNull();
    for (const b of ["", "-x", "--force", "a..b", "a b", "a;b", "x/", "x.lock", "$(id)", "refs/../x"]) expect(checkBranch(b)).not.toBeNull();
  });

  it("the settings live in the database and contain no secret", () => {
    e.gate.setPublishSettings({ repoUrl: `file://${e.bare}`, branch: "main" }, e.code());
    const rows = (e.store as unknown as { db: Database.Database }).db.prepare("SELECT key, value FROM policy WHERE key LIKE 'publish.%'").all() as Array<{ key: string; value: string }>;
    expect(rows.map((r) => r.key).sort()).toEqual(["publish.branch", "publish.enabled", "publish.on_approve", "publish.repo_url"]);
  });
});

describe("when it runs: freeze, close, approval", () => {
  /** propose → window → installed and loaded by the hook, as the real flow does. */
  async function windowedPlugin(name: string, threadId = "T1") {
    await e.register();
    const deps = {
      gate: e.gate,
      store: e.store,
      snapshotsRoot: e.snapshots,
      invokerIsServerMachine: async () => true,
      install: async () => ({ id: name, version: "1.0.0", status: "running", statusDetail: null }),
      changed: () => undefined,
    };
    const dir = e.plugin(name);
    await propose(deps, { path: dir, cwd: undefined, threadId });
    e.gate.openWindow(e.store.listQueue()[0]!.id, e.code());
    await propose(deps, { path: dir, cwd: undefined, threadId });
    const p = e.store.proposalByDir(join(e.snapshots, name, await hashTree(dir)))!;
    await e.gate.decide({ pluginId: name, version: "1.0.0", source: `path:${p.snapshotDir}`, sourceKind: "path", gitCommit: null, npmIntegrity: null, rootDir: p.snapshotDir, contentHash: `sha256:core-${name}`, trigger: "install" });
    return { p, dir, deps };
  }

  it("a window that runs out freezes the pinned version and publishes it", async () => {
    e.enable();
    const { p } = await windowedPlugin("demo");
    expect(e.store.listPublications()).toEqual([]); // not before the freeze
    e.t += 31 * 60_000;
    expect(e.gate.sweep()).toBe(1);
    await e.publisher.idle();
    const rows = e.store.listPublications();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ pluginId: "demo", version: "1.0.0", status: "published", trigger: "freeze", localHash: p.localHash });
    const c = e.clone();
    expect(sh(c, "log", "-1", "--format=%s")).toBe(`demo@1.0.0 frozen ${p.localHash}`);
    expect(e.store.listLog(30).some((l) => l.kind === "publish.ok" && l.pluginId === "demo")).toBe(true);
  });

  it("closing the window by hand freezes it too", async () => {
    e.enable();
    await windowedPlugin("demo");
    e.t += 31_000;
    e.gate.closeWindow(e.gate.openWindows()[0]!.id);
    await e.publisher.idle();
    expect(e.store.listPublications()[0]).toMatchObject({ status: "published", trigger: "freeze" });
  });

  it("with publishing off a freeze publishes nothing", async () => {
    await windowedPlugin("demo");
    e.t += 31 * 60_000;
    e.gate.sweep();
    await e.publisher.idle();
    expect(e.store.listPublications()).toEqual([]);
  });

  it("approval by code publishes only when the option is on, and only what a human approved", async () => {
    await e.register();
    const deps = { gate: e.gate, store: e.store, snapshotsRoot: e.snapshots, invokerIsServerMachine: async () => true, install: async () => ({ id: "demo", version: "1.0.0", status: "running", statusDetail: null }), changed: () => undefined };
    await propose(deps, { path: e.plugin("demo"), cwd: undefined, threadId: "T1" });
    const q = e.store.listQueue()[0]!;
    e.enable({ onApprove: false });
    let res = e.gate.approveQueue(q.id, e.code());
    e.publisher.onApproved(res.proposalId);
    await e.publisher.idle();
    expect(e.store.listPublications()).toEqual([]);

    await propose(deps, { path: e.plugin("other"), cwd: undefined, threadId: "T1" });
    e.t += 31_000;
    const q2 = e.store.listQueue().find((x) => x.pluginId === "other")!;
    e.enable({ onApprove: true });
    res = e.gate.approveQueue(q2.id, e.code());
    e.publisher.onApproved(res.proposalId);
    await e.publisher.idle();
    expect(e.store.listPublications()).toHaveLength(1);
    expect(e.store.listPublications()[0]).toMatchObject({ pluginId: "other", status: "published", trigger: "approve" });
    expect(sh(e.clone(), "tag", "--list")).toBe("other-v1.0.0");
  });

  it("a hook-only approval (no proposal: not our snapshot) never publishes", () => {
    e.enable({ onApprove: true });
    e.publisher.onApproved(null);
    expect(e.store.listPublications()).toEqual([]);
  });

  it("a crash mid-push leaves no 'running' attempt behind after a restart", () => {
    e.store.insertPublication({ pluginId: "demo", version: "1.0.0", localHash: "a".repeat(64), trigger: "freeze", repoUrl: "x", branch: "main" });
    expect(e.store.interruptRunningPublications()).toBe(1);
    expect(e.store.listPublications()[0]).toMatchObject({ status: "failed" });
  });
});

describe("replacing a version", () => {
  it("a file the new version dropped is gone from the directory", async () => {
    e.enable();
    const a = await e.snapshot("alpha", "1.0.0", { "old.ts": "1\n" });
    const a2 = await e.snapshot("alpha", "1.1.0");
    await e.publisher.publish({ pluginId: "alpha", localHash: a.localHash, trigger: "freeze" });
    await e.publisher.publish({ pluginId: "alpha", localHash: a2.localHash, trigger: "freeze" });
    const c = e.clone();
    expect(sh(c, "ls-files").split("\n")).not.toContain("alpha/old.ts");
    expect(sh(c, "ls-tree", "-r", "--name-only", "alpha-v1.0.0").split("\n")).toContain("alpha/old.ts");
  });
});
