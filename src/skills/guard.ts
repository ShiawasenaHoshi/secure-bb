// The skills guard (stage 6, spec §6/§7, threat model 8.3).
//
// bb has no core hook for installing skills, so this works "after the fact": every scan of the config watchdog hands
// over the skills bb lists. Each skill is read completely (every file through bb's API) and hashed. A hash that is
// pinned passes. A new or changed one is checked (code: the plugin checks; text: the skill rules) and decided by code:
//   block  -> the skill is removed at once (bb allows it for user and project skills); what it contained is recorded;
//             where bb does not allow removal, or the skill was there before the module: an alarm
//   review -> kept in the skills queue on the page until a code
//   clean  -> accepted if it comes from a trusted registry source, or inside an open configuration window on "skills"
//             (the window is the watchdog's); otherwise it waits in the queue like a review
// bb's own skills (built-in, and those of built-in plugins) are only pinned: never blocked, never queued.
import type { Proof } from "../approval.js";
import type { Store } from "../store.js";
import { isTrustedRepo, normalizePattern } from "../taint/repos.js";
import { decide, inspectSkill, SKILL_RULES_VERSION, summarize } from "./inspect.js";
import type { SkillReader } from "./reader.js";
import { OPEN_STATES, type SkillStore } from "./store.js";
import { REMOVABLE_SCOPES, type SkillCheck, type SkillFileSource, type SkillQueueRow, type SkillRef, type SkillSnapshot, type Verdict } from "./types.js";

export class SkillError extends Error {
  constructor(
    readonly code: "invalid" | "not_found" | "conflict",
    message: string,
  ) {
    super(message);
  }
}

export interface GuardDeps {
  store: Store;
  skills: SkillStore;
  reader: SkillReader;
  source: Pick<SkillFileSource, "remove">;
  /** Ids of the built-in plugins (their skills are bb's own). */
  builtinPlugins: () => Promise<Set<string>>;
  now: () => number;
  /** A touch: throws unless `code` is a fresh valid TOTP code. */
  touch: (purpose: string, code: Proof) => void;
  log?: (message: string) => void;
}

export interface EvalInput {
  refs: SkillRef[];
  /** Every source that lists skills was read: only then can a missing skill be called gone. */
  complete: boolean;
  /** The configuration trust window on "skills" that is open now, if any. */
  skillsWindow: number | null;
}

export interface EvalResult {
  verdicts: Map<string, Verdict>;
  /** New queue rows, removals and alarms made by this pass. */
  raised: number;
  /** Skills accepted by an open window (so it can slide). */
  viaWindow: number[];
}

/** What bb's API cannot show of a skill: said on the page, never silently skipped. */
export const SKILL_BLIND: string[] = [
  "API bb не показывает скрытые файлы и каталоги скилла (имя с точкой) и ссылки: их содержимое не хешируется и не проверяется",
  "Бит «исполняемый» у файлов API не отдаёт: скрипт определяется по расширению и shebang",
  "Скилл, установленный «из реестра», помечен файлом рядом со скиллом; метка не доказывает происхождение — доверенный источник ослабляет ступень, а не заменяет проверки",
];

export interface SkillQueueView extends Omit<SkillQueueRow, "removedFiles"> {
  removed: Array<{ path: string; size: number }> | null;
  /** Whether bb lets the skill be removed (a person can do it from the page). */
  removable: boolean;
}

export interface SkillsView {
  baselineAt: number | null;
  lastScanAt: number | null;
  pinned: { total: number; builtin: number; baseline: number; approved: number };
  open: SkillQueueView[];
  recent: SkillQueueView[];
  trusted: string[];
  blind: string[];
  unchecked: string[];
}

const META_BASELINE = "skills_baseline_at";
const META_LAST = "skills_last_scan";

const removable = (ref: Pick<SkillRef, "scope" | "manageable">): boolean => ref.manageable && REMOVABLE_SCOPES.includes(ref.scope);

/** `github.com/owner/repo/skill` or `owner/repo/skill` -> `owner/repo`; null for other hosts. */
export function registrySlug(registrySkillId: string | null): string | null {
  if (!registrySkillId) return null;
  const parts = registrySkillId.toLowerCase().split("/").filter(Boolean);
  if (parts[0] === "github.com") parts.shift();
  if (parts.length < 3 || parts[0]!.includes(".")) return null;
  return `${parts[0]}/${parts[1]}`;
}

export class SkillGuard {
  private verdicts = new Map<string, Verdict>();
  private refs = new Map<string, SkillRef>();
  private unchecked = new Set<string>();

  constructor(private readonly d: GuardDeps) {}

  private get skills(): SkillStore {
    return this.d.skills;
  }

  // ---- reading the verdicts ---------------------------------------------------------------------------------------------
  verdict(key: string): Verdict | null {
    return this.verdicts.get(key) ?? null;
  }
  /** What the watchdog may take into its snapshot without a touch: content that is pinned or only pinned (bb's own). */
  isAccepted(key: string): boolean {
    const v = this.verdicts.get(key);
    return v === "ok" || v === "approved" || v === "builtin";
  }
  baselineAt(): number | null {
    const v = this.d.store.getMeta(META_BASELINE);
    return v === null ? null : Number(v);
  }

  isTrustedSource(registrySkillId: string | null): boolean {
    const slug = registrySlug(registrySkillId);
    return slug !== null && isTrustedRepo(slug, this.skills.trustedSources());
  }

  view(): SkillsView {
    const pins = this.skills.pins();
    const toView = (r: SkillQueueRow): SkillQueueView => {
      const { removedFiles, ...rest } = r;
      return { ...rest, removed: removedFiles ? removedFiles.map((f) => ({ path: f.path, size: f.content?.length ?? 0 })) : null, removable: removable({ scope: r.scope, manageable: true }) };
    };
    const last = this.d.store.getMeta(META_LAST);
    return {
      baselineAt: this.baselineAt(),
      lastScanAt: last === null ? null : Number(last),
      pinned: { total: pins.length, builtin: pins.filter((p) => p.kind === "builtin").length, baseline: pins.filter((p) => p.kind === "baseline").length, approved: pins.filter((p) => p.kind === "approved").length },
      open: this.skills.openRows().map(toView),
      recent: this.skills.recentRows(30).map(toView),
      trusted: this.skills.trustedSources(),
      blind: SKILL_BLIND,
      unchecked: [...this.unchecked].sort(),
    };
  }

  /** What was removed, as it was (page only). */
  removedContent(id: number): Array<{ path: string; content: string | null }> {
    const row = this.skills.getRow(id);
    if (!row || !row.removedFiles) throw new SkillError("not_found", `no removed skill in entry #${id}`);
    return row.removedFiles;
  }

  /** Call before each reading of bb: the skills read since are not reused. */
  beginScan(): void {
    this.d.reader.beginScan();
  }

  // ---- the pass ---------------------------------------------------------------------------------------------------------
  async evaluate(input: EvalInput): Promise<EvalResult> {
    const out: EvalResult = { verdicts: new Map(), raised: 0, viaWindow: [] };
    this.refs = new Map(input.refs.map((r) => [r.key, r]));
    this.unchecked = new Set();
    let builtin: Set<string> | null = null;
    try {
      builtin = await this.d.builtinPlugins();
    } catch (err) {
      this.d.log?.(`skills: built-in plugins not listed: ${err instanceof Error ? err.message : String(err)}`);
    }
    const baselineMode = this.baselineAt() === null;

    for (const ref of input.refs) {
      const isBuiltin = ref.scope === "bb-builtin" || (ref.scope === "plugin" && ref.pluginId !== null && builtin?.has(ref.pluginId) === true);
      if (ref.scope === "plugin" && builtin === null) {
        out.verdicts.set(ref.key, "unchecked");
        this.unchecked.add(ref.key);
        continue;
      }
      let snap: SkillSnapshot;
      try {
        snap = await this.d.reader.snapshot(ref);
      } catch (err) {
        // Not being able to read is not an all-clear and not a finding: nothing is accepted for this skill this time.
        out.verdicts.set(ref.key, "unchecked");
        this.unchecked.add(ref.key);
        this.d.log?.(`skills: ${ref.key} not read: ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      const v = await this.one(ref, snap, { isBuiltin, baselineMode, skillsWindow: input.skillsWindow, out });
      out.verdicts.set(ref.key, v);
    }

    if (input.complete) {
      // A skill that is gone leaves no pin (a later one with the same name is new) and closes its open entry.
      for (const pin of this.skills.pins()) {
        if (this.refs.has(pin.key)) continue;
        this.skills.deletePin(pin.key);
        this.d.store.log("skills.gone", null, pin.hash, { key: pin.key, name: pin.name, scope: pin.scope });
      }
      for (const row of this.skills.openRows()) {
        if (this.refs.has(row.key)) continue;
        this.skills.resolve(row.id, "gone", "scan", "скилл исчез");
        this.d.store.log("skills.gone", null, row.hash, { key: row.key, name: row.name, entry: row.id });
      }
    }
    // The baseline is the first complete listing. A skill that could not be read then is not baselined: it is new content later.
    if (baselineMode && input.complete) {
      this.d.store.setMeta(META_BASELINE, String(this.d.now()));
      this.d.store.log("skills.baseline", null, null, { skills: input.refs.length, pinned: this.skills.pins().length, flagged: this.skills.openRows().length });
    }
    this.d.store.setMeta(META_LAST, String(this.d.now()));
    this.verdicts = out.verdicts;
    return out;
  }

  private async one(ref: SkillRef, snap: SkillSnapshot, ctx: { isBuiltin: boolean; baselineMode: boolean; skillsWindow: number | null; out: EvalResult }): Promise<Verdict> {
    const pin = this.skills.pin(ref.key);
    const files = snap.files.length;
    const base = { key: ref.key, skillId: ref.id, name: ref.name, scope: ref.scope, projectId: ref.projectId, hash: snap.hash };

    // bb's own skills: a pin, nothing else.
    if (ctx.isBuiltin) {
      if (!pin || pin.hash !== snap.hash) {
        this.skills.putPin({ ...base, kind: "builtin", via: "builtin", files });
        this.d.store.log("skills.pin", null, snap.hash, { key: ref.key, kind: "builtin", before: pin?.hash ?? null });
      }
      return "builtin";
    }

    const open = this.skills.openRow(ref.key);
    if (pin && pin.hash === snap.hash) {
      if (open) this.skills.resolve(open.id, "approved", "pin", "содержимое снова совпадает с одобренным");
      return pin.kind === "baseline" ? "ok" : "approved";
    }
    // The same content under the same rules: nothing to decide again. Under newer rules the entry is checked afresh below.
    if (open && open.hash === snap.hash && open.rulesVersion === SKILL_RULES_VERSION) {
      this.skills.touchRow(open.id);
      return open.state === "alarm" ? "alarm" : "held";
    }

    // New or changed content: check it.
    let check: SkillCheck | null = null;
    let decision: "clean" | "review" | "block";
    let reason: string;
    try {
      check = await inspectSkill(snap);
      decision = decide(check);
      reason = summarize(check);
    } catch (err) {
      decision = "review";
      reason = `проверка не удалась: ${err instanceof Error ? err.message : String(err)}`;
    }
    const source = ref.registrySkillId;
    const when = pin ? "изменён" : "новый";

    if (decision === "block") {
      ctx.out.raised++;
      return this.block(ref, snap, check, reason, { ...ctx, base, open });
    }
    if (decision === "review") {
      ctx.out.raised += this.hold(base, "review", reason, check, source, ctx.baselineMode, open);
      this.d.store.log("skills.hold", null, snap.hash, { key: ref.key, why: "review", when });
      return "held";
    }

    // Clean.
    const trusted = this.isTrustedSource(source);
    const viaWindow = ctx.skillsWindow !== null;
    if (ctx.baselineMode && !pin) return this.accept(base, files, "baseline", "baseline", open, ctx.out, null);
    if (trusted) return this.accept(base, files, "approved", "trusted-source", open, ctx.out, null);
    if (viaWindow) return this.accept(base, files, "approved", `window:${ctx.skillsWindow}`, open, ctx.out, ctx.skillsWindow);
    ctx.out.raised += this.hold(base, "review", `${when} скилл: проверки чисты, но источник не доверенный и окно «скиллы» закрыто`, check, source, false, open);
    this.d.store.log("skills.hold", null, snap.hash, { key: ref.key, why: "clean-untrusted", when });
    return "held";
  }

  private accept(base: { key: string; skillId: string; name: string; scope: string; projectId: string; hash: string }, files: number, kind: "approved" | "baseline", via: string, open: SkillQueueRow | null, out: EvalResult, windowId: number | null): Verdict {
    this.skills.putPin({ ...base, kind, via, files });
    if (open) this.skills.resolve(open.id, "approved", via, null);
    this.d.store.log("skills.pin", null, base.hash, { key: base.key, kind, via });
    if (windowId !== null) out.viaWindow.push(windowId);
    return kind === "baseline" ? "ok" : "approved";
  }

  /** Creates or follows the open row. Returns 1 when a new row appeared. */
  private hold(base: { key: string; skillId: string; name: string; scope: string; projectId: string; hash: string }, decision: "review" | "block", reason: string, check: SkillCheck | null, source: string | null, preexisting: boolean, open: SkillQueueRow | null): number {
    const state = decision === "block" ? "alarm" : "held";
    if (open) {
      this.skills.retarget(open.id, { skillId: base.skillId, hash: base.hash, decision, state, reason, check, source });
      return 0;
    }
    this.skills.insertRow({ ...base, decision, state, reason, check, source, preexisting });
    return 1;
  }

  private async block(ref: SkillRef, snap: SkillSnapshot, check: SkillCheck | null, reason: string, ctx: { baselineMode: boolean; base: { key: string; skillId: string; name: string; scope: string; projectId: string; hash: string }; open: SkillQueueRow | null }): Promise<Verdict> {
    const { base, open } = ctx;
    const source = ref.registrySkillId;
    const contents = snap.files.map((f) => ({ path: f.path, content: f.content }));
    // Before the module's first scan the skill was already working for the agents: the first pass only shows it.
    if (ctx.baselineMode) {
      this.hold(base, "block", reason, check, source, true, open);
      this.d.store.log("skills.alarm", null, snap.hash, { key: ref.key, why: "block-preexisting", reason });
      return "alarm";
    }
    if (!removable(ref)) {
      this.hold(base, "block", reason, check, source, false, open);
      const row = this.skills.openRow(ref.key)!;
      this.skills.setNote(row.id, `bb не позволяет удалить скилл области «${ref.scope}»: тревога, убрать нужно вручную`);
      this.d.store.log("skills.alarm", null, snap.hash, { key: ref.key, why: "block-not-removable", scope: ref.scope, reason });
      return "alarm";
    }
    // What was there is written down first, then the skill is removed.
    const same = this.skills.rowByHash(ref.key, snap.hash);
    let id: number;
    if (open) {
      this.skills.retarget(open.id, { skillId: base.skillId, hash: base.hash, decision: "block", state: "alarm", reason, check, source });
      id = open.id;
    } else if (same && same.state === "removed") {
      this.skills.retarget(same.id, { skillId: base.skillId, hash: base.hash, decision: "block", state: "alarm", reason, check, source });
      id = same.id;
    } else {
      id = this.skills.insertRow({ ...base, decision: "block", state: "alarm", reason, check, source, preexisting: false }).id;
    }
    this.skills.setRemoved(id, contents);
    try {
      await this.d.source.remove(ref);
      this.skills.resolve(id, "removed", "auto", "скилл удалён: найден жёсткий признак");
      this.d.store.log("skills.remove", null, snap.hash, { key: ref.key, name: ref.name, scope: ref.scope, entry: id, files: contents.length, reason });
      return "removed";
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.skills.setNote(id, `удалить не удалось: ${msg}`);
      this.d.store.log("skills.alarm", null, snap.hash, { key: ref.key, why: "remove-failed", message: msg, reason });
      this.d.log?.(`skills: could not remove ${ref.key}: ${msg}`);
      return "alarm";
    }
  }

  // ---- people ------------------------------------------------------------------------------------------------------------
  /** One queue entry (the batch approval looks at it before and after the code). */
  entry(id: number): SkillQueueRow | null {
    return this.skills.getRow(id);
  }

  /** Accepts the queued content (a touch). A block needs `acknowledgeBlock`. */
  async approve(id: number, code: Proof, opts: { acknowledgeBlock?: boolean } = {}): Promise<{ note: string }> {
    const row = this.skills.getRow(id);
    if (!row) throw new SkillError("not_found", `no entry #${id} in the skills queue`);
    if (row.state !== "held" && row.state !== "alarm" && row.state !== "removed") throw new SkillError("conflict", `entry #${id} is already ${row.state}`);
    if (row.decision === "block" && opts.acknowledgeBlock !== true) throw new SkillError("invalid", "the checks found a hard sign: confirm that you accept this skill anyway");
    this.d.touch("skills.approve", code);
    const base = { key: row.key, skillId: row.skillId, name: row.name, scope: row.scope, projectId: row.projectId, hash: row.hash };
    if (row.state === "removed") {
      // The skill is gone: its content hash is accepted, so installing the same content again passes.
      this.skills.putPin({ ...base, kind: "approved", via: "touch-after-block", files: row.check?.stats.files ?? 0 });
      this.skills.resolve(id, "approved", "touch", "хеш одобрен: тот же скилл можно поставить снова");
      this.d.store.log("skills.approve", null, row.hash, { key: row.key, entry: id, after: "removed" });
      return { note: "approved the content hash; the skill can be installed again" };
    }
    const ref = this.refs.get(row.key);
    if (!ref) throw new SkillError("conflict", "the skill is not listed any more; wait for the next scan");
    this.d.reader.beginScan();
    const snap = await this.d.reader.snapshot(ref);
    if (snap.hash !== row.hash) throw new SkillError("conflict", "the skill changed since it was queued; it will be checked again, then approve the new content");
    this.skills.putPin({ ...base, kind: "approved", via: "touch", files: snap.files.length });
    this.skills.resolve(id, "approved", "touch", null);
    this.d.store.log("skills.approve", null, row.hash, { key: row.key, entry: id, decision: row.decision });
    this.verdicts.set(row.key, "approved");
    return { note: "approved" };
  }

  /** Removes a queued skill by hand (no code: this only makes bb safer). */
  async removeQueued(id: number): Promise<void> {
    const row = this.skills.getRow(id);
    if (!row || (row.state !== "held" && row.state !== "alarm")) throw new SkillError("not_found", `no waiting entry #${id}`);
    const ref = this.refs.get(row.key);
    if (!ref) throw new SkillError("conflict", "the skill is not listed any more");
    if (!removable(ref)) throw new SkillError("conflict", `bb does not allow removing a skill of scope ${ref.scope}`);
    this.d.reader.beginScan();
    const snap = await this.d.reader.snapshot(ref);
    this.skills.setRemoved(id, snap.files.map((f) => ({ path: f.path, content: f.content })));
    await this.d.source.remove(ref);
    this.skills.resolve(id, "removed", "manual", "удалён человеком");
    this.d.store.log("skills.remove", null, snap.hash, { key: row.key, entry: id, by: "person" });
  }

  setTrustedSource(change: { add?: string; remove?: string }, code: string): string[] {
    if ((change.add === undefined) === (change.remove === undefined)) throw new SkillError("invalid", "give exactly one of add / remove");
    const pattern = normalizePattern((change.add ?? change.remove)!);
    if (pattern === null) throw new SkillError("invalid", "a trusted source is `owner/repo` or `owner/*` (github.com)");
    this.d.touch("skills.trusted", code);
    const changed = change.add !== undefined ? this.skills.addTrustedSource(pattern) : this.skills.removeTrustedSource(pattern);
    this.d.store.log(change.add !== undefined ? "skills.trusted.add" : "skills.trusted.remove", null, null, { pattern, changed });
    return this.skills.trustedSources();
  }

  openCount(): number {
    return this.skills.openRows().filter((r) => OPEN_STATES.includes(r.state)).length;
  }
}
