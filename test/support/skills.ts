// A fake bb with skills that have files: a mutable world the tests change like an agent would.
import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { Gate } from "../../src/gate.js";
import { SkillGuard } from "../../src/skills/guard.js";
import { SkillReader } from "../../src/skills/reader.js";
import { SkillStore } from "../../src/skills/store.js";
import type { SkillFileSource, SkillRef } from "../../src/skills/types.js";
import { MIGRATIONS, Store } from "../../src/store.js";
import { base32Decode, hotp, stepAt } from "../../src/totp.js";
import type { SkillLite } from "../../src/watch/collect.js";
import { Watchdog } from "../../src/watch/watchdog.js";
import { NETWORKED } from "./checks.js";
import { FakeBb } from "./watch.js";

export const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

export interface FakeSkill extends SkillLite {
  files: Record<string, string>;
}

/** FakeBb whose skills have files; the whole-skill hash comes from the same reader the guard uses. */
export class SkillsBb extends FakeBb {
  skillsById: Record<string, FakeSkill> = {};
  /** paths that cannot be read, `skillId/path` */
  unreadable = new Set<string>();
  removeCalls: string[] = [];
  removeFails = false;
  listCalls = 0;
  reader!: SkillReader;
  truncatedFor = new Set<string>();
  /** Plugin ids that are built-in (so their skills are bb's own). */
  builtinPluginIds = new Set<string>(["bb-guide"]);

  constructor() {
    super();
    this.skillList = { proj_a: [] };
    this.revisions = {};
  }

  /** Adds or replaces a skill (global user skills are listed by every project). */
  put(id: string, name: string, files: Record<string, string>, extra: Partial<SkillLite> = {}): FakeSkill {
    const s: FakeSkill = { id, name, scope: "bb-user", pluginId: null, manageable: true, registrySkillId: null, ...extra, files: { ...files } };
    this.skillsById[id] = s;
    this.sync();
    return s;
  }
  edit(id: string, path: string, content: string | null): void {
    const s = this.skillsById[id]!;
    if (content === null) delete s.files[path];
    else s.files[path] = content;
  }
  drop(id: string): void {
    delete this.skillsById[id];
    this.sync();
  }
  private sync(): void {
    this.skillList = { proj_a: Object.values(this.skillsById).map(({ files: _f, ...lite }) => lite) };
  }

  override async skillRevision(projectId: string, skillId: string): Promise<string> {
    const ref = { key: "", id: skillId, projectId, name: "", scope: "", pluginId: null, manageable: false, registrySkillId: null };
    return (await this.reader.snapshot(ref)).hash;
  }

  source: SkillFileSource = {
    listFiles: async (ref: SkillRef) => {
      this.listCalls++;
      if (this.broken.has("skillFiles")) throw new Error("skill files unavailable");
      const s = this.skillsById[ref.id];
      if (!s) throw new Error("Skill not found");
      return { files: Object.keys(s.files), truncated: this.truncatedFor.has(ref.id) };
    },
    readFile: async (ref: SkillRef, path: string) => {
      const s = this.skillsById[ref.id];
      const content = s?.files[path];
      if (content === undefined || this.unreadable.has(`${ref.id}/${path}`)) throw new Error("HTTP 413 file_too_large");
      return { content, revision: sha(content) };
    },
    remove: async (ref: SkillRef) => {
      this.removeCalls.push(ref.id);
      if (this.removeFails) throw new Error("HTTP 403 forbidden");
      this.drop(ref.id);
    },
  };
}

export class SkillsHarness {
  t = 1_800_000_000_000;
  bb = new SkillsBb();
  store: Store;
  gate: Gate;
  guard: SkillGuard;
  skillStore: SkillStore;
  watch: Watchdog;
  code!: () => string;
  constructor() {
    const db = new Database(":memory:");
    for (const stmt of MIGRATIONS) db.exec(stmt);
    this.store = new Store(db, () => this.t);
    this.skillStore = new SkillStore(db, () => this.t);
    this.gate = new Gate({
      store: this.store,
      now: () => this.t,
      threads: { ancestors: async () => [], descendants: async () => [] },
      thirdPartyRunning: async () => [],
      externalTotpFile: null,
      snapshotsRoot: "/nonexistent",
      unsafeDirs: async () => [],
      runChecks: async () => NETWORKED,
    });
    const reader = new SkillReader(this.bb.source);
    this.bb.reader = reader;
    this.guard = new SkillGuard({
      store: this.store,
      skills: this.skillStore,
      reader,
      source: this.bb.source,
      builtinPlugins: async () => this.bb.builtinPluginIds,
      now: () => this.t,
      touch: (purpose, code) => this.gate.touch(purpose, code),
    });
    this.watch = new Watchdog({
      store: this.store,
      now: () => this.t,
      source: this.bb,
      actions: this.bb.actions,
      touch: (purpose, code) => this.gate.touch(purpose, code),
      skills: this.guard,
    });
  }
  async register(): Promise<void> {
    const { secret } = await this.gate.beginRegistration({ attended: true, caller: "test" });
    const gen = () => hotp(base32Decode(secret), stepAt(this.t));
    this.gate.confirmRegistration(gen());
    this.t += 31_000;
    this.code = gen;
  }
  fresh(): string {
    this.t += 31_000;
    return this.code();
  }
  minutes(n: number): void {
    this.t += n * 60_000;
  }
  /** The first scan: whatever is there is the state before the module. */
  async start(): Promise<void> {
    await this.register();
    await this.watch.scan();
  }
}

export const CLEAN_SKILL = { "SKILL.md": "---\nname: tidy\ndescription: tidy things\n---\n\n# Tidy\n\nKeep things tidy.\n" };
