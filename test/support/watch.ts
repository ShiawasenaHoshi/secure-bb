// Fake bb for the config watchdog: a mutable world the tests change like an agent would.
import Database from "better-sqlite3";
import { Gate } from "../../src/gate.js";
import { MIGRATIONS, Store } from "../../src/store.js";
import { base32Decode, hotp, stepAt } from "../../guard/src/totp.ts";
import type { InstalledPluginLite } from "../../src/probe.js";
import type { SkillLite, WatchSource } from "../../src/watch/collect.js";
import { Watchdog, type WatchActions } from "../../src/watch/watchdog.js";
import { NETWORKED } from "./checks.js";

const plugin = (id: string, enabled: boolean): InstalledPluginLite => ({
  id,
  provenance: "builtin",
  enabled,
  status: enabled ? "running" : "disabled",
  version: "0.1.0",
  source: `builtin:${id}`,
  rootDir: `/builtin/${id}`,
});

export class FakeBb implements WatchSource {
  builtins: Record<string, boolean | null> = { connect: false, "connect-next": false, "bb-account": false, mcp: false, "bb-ai": false, "push-notifications": false, "browser-automation": null, "account-pool": false };
  account: "signed-in" | "signed-out" | "unknown" = "signed-out";
  hold: boolean | null = true;
  catalogs = [{ name: "bb-official", source: "path:/b", subdirectory: null as string | null }];
  instructionsText = "be careful";
  projectList = [{ id: "proj_a", name: "A" }];
  skillList: Record<string, SkillLite[]> = { proj_a: [{ id: "s1", name: "mine", scope: "bb-user", pluginId: null, manageable: true }] };
  revisions: Record<string, string> = { s1: "rev1" };
  machineVars: string[] = ["GH_TOKEN"];
  projectVars: Record<string, string[]> = { proj_a: [] };
  hostList = [{ id: "host_1", name: "laptop", maxPermissionMode: "full" }];
  permModes: Record<string, string | null> = { proj_a: "accept-edits" };
  providers: Record<string, Record<string, unknown>> = {
    "provider-claude-code": { sandboxEnabled: true, fullAccessApprovalsEnabled: false, chromeEnabled: false, artifactsEnabled: false },
    "provider-acp": { customAgents: "" },
  };
  exps: Record<string, boolean> = { serverMove: false };
  safe = false;
  envSetups: Record<string, string | null> = { proj_a: null };
  /** sources that throw, by method name */
  broken = new Set<string>();

  private guard(name: string): void {
    if (this.broken.has(name)) throw new Error(`${name} is unavailable`);
  }
  async listPlugins() {
    this.guard("listPlugins");
    return Object.entries(this.builtins).filter(([, v]) => v !== null).map(([id, v]) => plugin(id === "mcp" ? "bb--mcp" : id === "connect-next" ? "bb--connect-next" : id, v === true));
  }
  async accountState() {
    this.guard("accountState");
    return this.account;
  }
  connectHoldExists() {
    return this.hold;
  }
  async marketplaces() {
    this.guard("marketplaces");
    return this.catalogs;
  }
  async instructions() {
    this.guard("instructions");
    return this.instructionsText;
  }
  async projects() {
    this.guard("projects");
    return this.projectList;
  }
  async skills(projectId: string) {
    this.guard("skills");
    return this.skillList[projectId] ?? [];
  }
  async skillRevision(_p: string, skillId: string) {
    return this.revisions[skillId] ?? "none";
  }
  async machineEnv() {
    this.guard("machineEnv");
    return this.machineVars;
  }
  async projectEnv(projectId: string) {
    this.guard("projectEnv");
    return this.projectVars[projectId] ?? [];
  }
  async hosts() {
    this.guard("hosts");
    return this.hostList;
  }
  async projectPermissionMode(projectId: string) {
    return this.permModes[projectId] ?? null;
  }
  async providerSettings(pluginId: string) {
    this.guard("providerSettings");
    return this.providers[pluginId] ?? {};
  }
  async experiments() {
    return this.exps;
  }
  async safeMode() {
    return this.safe;
  }
  async envSetup(projectId: string) {
    this.guard("envSetup");
    return this.envSetups[projectId] ?? null;
  }

  calls: string[] = [];
  failActions = false;
  actions: WatchActions = {
    disablePlugin: async (id) => {
      this.calls.push(`disable ${id}`);
      if (this.failActions) throw new Error("disable refused");
      this.builtins[id.replace(/^bb--/, "")] = false;
    },
    deleteEnv: async (scope, projectId, name) => {
      this.calls.push(`delete-env ${scope} ${projectId ?? "-"} ${name}`);
      if (this.failActions) throw new Error("delete refused");
      if (scope === "machine") this.machineVars = this.machineVars.filter((n) => n !== name);
      else this.projectVars[projectId!] = (this.projectVars[projectId!] ?? []).filter((n) => n !== name);
    },
    restoreInstructions: async (text) => {
      this.calls.push("restore-instructions");
      if (this.failActions) throw new Error("restore refused");
      this.instructionsText = text;
    },
  };
}

export class WatchHarness {
  t = 1_800_000_000_000;
  bb = new FakeBb();
  store: Store;
  gate: Gate;
  watch: Watchdog;
  code!: () => string;
  constructor() {
    const db = new Database(":memory:");
    for (const stmt of MIGRATIONS) db.exec(stmt);
    this.store = new Store(db, () => this.t);
    this.gate = new Gate({
      store: this.store,
      now: () => this.t,
      threads: { ancestors: async () => [], descendants: async () => [] },
      thirdPartyRunning: async () => [],
      externalTotpFile: null,
      snapshotsRoot: "/nonexistent", unsafeDirs: async () => [],
      runChecks: async () => NETWORKED,
    });
    this.watch = new Watchdog({
      store: this.store,
      now: () => this.t,
      source: this.bb,
      actions: this.bb.actions,
      touch: (purpose, code) => this.gate.touch(purpose, code),
    });
  }
  /** Registers TOTP and returns a generator of fresh codes. */
  async register(): Promise<void> {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    const gen = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(gen());
    this.t += 31_000;
    this.code = () => {
      const c = gen();
      return c;
    };
  }
  /** A fresh code: every touch consumes a 30 s step, so move to the next one first. */
  fresh(): string {
    this.t += 31_000;
    return this.code();
  }
  minutes(n: number): void {
    this.t += n * 60_000;
  }
  async approved(): Promise<void> {
    await this.register();
    await this.watch.acceptAll(this.code());
  }
}
