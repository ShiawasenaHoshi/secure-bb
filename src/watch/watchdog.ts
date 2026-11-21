// The config watchdog (spec §7) and the configuration trust window (spec §6).
//
// Once a minute and on `config-changed` / `plugins-changed`, the current state of
// bb is compared with the approved snapshot. A difference is a "drift":
//   - inside an open configuration window, on an object the window covers: accepted
//     into the snapshot, no touch (sliding windows extend);
//   - otherwise it is shown, and, only if the human switched rollback on and a safe
//     undo exists (disable a built-in plugin, delete a new env variable, restore the
//     instructions), undone.
// The snapshot itself is only ever changed by a touch (TOTP) or by a window.
import type { Proof } from "../approval.js";
import type { SkillGuard } from "../skills/guard.js";
import type { TaintAssessment } from "../taint/monitor.js";
import { collect, type WatchSource } from "./collect.js";
import { diffSnapshot, type Difference } from "./diff.js";
import {
  isWindowScope,
  SCOPE_LABEL,
  type Category,
  type ConfigWindowRow,
  type Drift,
  type Item,
  type Observation,
  type Rollback,
  type Unobserved,
  type WindowScope,
} from "./model.js";
import { GateError } from "../gate.js";
import type { Store } from "../store.js";

export interface WatchActions {
  disablePlugin(pluginId: string): Promise<void>;
  deleteEnv(scope: "machine" | "project", projectId: string | null, name: string): Promise<void>;
  restoreInstructions(text: string): Promise<void>;
}

export interface WatchDeps {
  store: Store;
  now: () => number;
  source: WatchSource;
  actions: WatchActions;
  /** A touch: throws unless `code` is a fresh valid TOTP code. Provided by the gate. */
  touch: (purpose: string, code: Proof) => void;
  /** Stage 6: the skills guard. Absent: skills are only compared by their hash, as before. */
  skills?: SkillGuard;
  log?: (message: string) => void;
}

export class WatchError extends Error {
  constructor(
    readonly code: "invalid" | "not_found" | "conflict",
    message: string,
  ) {
    super(message);
  }
}

export interface ConfigWindowView {
  id: number;
  scopes: WindowScope[];
  scopeLabels: string[];
  mode: "sliding" | "fixed";
  openedAt: number;
  expiresAt: number;
  hardExpiresAt: number;
  remainingSec: number;
}

export interface WatchView {
  /** Null until a human accepted the first snapshot with a code. */
  baselineAt: number | null;
  rollbackEnabled: boolean;
  lastScanAt: number | null;
  observedCount: number;
  byCategory: Partial<Record<Category, number>>;
  failed: Unobserved[];
  /** Not read because there is nothing to read here (e.g. a project without a local folder). */
  notApplicable: Unobserved[];
  blind: Unobserved[];
  drifts: Drift[];
  windows: ConfigWindowView[];
}

const META_BASELINE = "watch_baseline_at";
const META_ROLLBACK = "watch_rollback";
const META_LAST_SCAN = "watch_last_scan";

export const isCfgOpen = (w: ConfigWindowRow, now: number): boolean => w.closedAt === null && now < w.expiresAt && now < w.hardExpiresAt;

export interface ScanResult {
  /** Drifts newly recorded this scan. */
  found: number;
  accepted: number;
  rolledBack: number;
  rollbackFailed: number;
}

export class Watchdog {
  private last: Observation | null = null;
  private running = false;
  private again = false;

  constructor(private readonly d: WatchDeps) {}

  private get store(): Store {
    return this.d.store;
  }
  private get now(): number {
    return this.d.now();
  }

  // ---- state -------------------------------------------------------------
  baselineAt(): number | null {
    const v = this.store.getMeta(META_BASELINE);
    return v === null ? null : Number(v);
  }
  rollbackEnabled(): boolean {
    return this.store.getMeta(META_ROLLBACK) === "1";
  }

  view(): WatchView {
    this.sweep();
    const byCategory: Partial<Record<Category, number>> = {};
    for (const i of this.last?.items ?? []) byCategory[i.category] = (byCategory[i.category] ?? 0) + 1;
    return {
      baselineAt: this.baselineAt(),
      rollbackEnabled: this.rollbackEnabled(),
      lastScanAt: this.last?.at ?? (this.store.getMeta(META_LAST_SCAN) === null ? null : Number(this.store.getMeta(META_LAST_SCAN))),
      observedCount: this.last?.items.length ?? 0,
      byCategory,
      failed: this.last?.failed ?? [],
      notApplicable: this.last?.notApplicable ?? [],
      blind: this.last?.blind ?? [],
      drifts: this.store.listDrifts(60),
      windows: this.openWindows().map((w) => this.windowView(w)),
    };
  }

  // ---- windows -----------------------------------------------------------
  openWindows(): ConfigWindowRow[] {
    return this.store.unclosedCfgWindows().filter((w) => isCfgOpen(w, this.now));
  }

  windowView(w: ConfigWindowRow): ConfigWindowView {
    return {
      id: w.id,
      scopes: w.scopes,
      scopeLabels: w.scopes.map((s) => SCOPE_LABEL[s]),
      mode: w.mode,
      openedAt: w.openedAt,
      expiresAt: w.expiresAt,
      hardExpiresAt: w.hardExpiresAt,
      remainingSec: Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - this.now) / 1000)),
    };
  }

  /** Marks expired windows closed: the snapshot stays as the last accepted state. */
  sweep(): number {
    let n = 0;
    for (const w of this.store.unclosedCfgWindows()) {
      if (isCfgOpen(w, this.now)) continue;
      this.store.closeCfgWindow(w.id, w.expiresAt >= w.hardExpiresAt ? "ceiling" : "expired", Math.min(w.expiresAt, w.hardExpiresAt));
      this.store.log("watch.window.freeze", null, null, { windowId: w.id, scopes: w.scopes, note: "снимок зафиксирован" });
      n++;
    }
    return n;
  }

  /**
   * Pollution (spec §6): a configuration window is not tied to a thread (bb does not say which thread changed
   * a setting), so it covers all of bb: if any thread has read untrusted content since it opened, it is closed.
   * Returns how many windows were closed. A read failure leaves the window open (it is closed on the next pass that can read).
   */
  async taintSweep(assess: (since: number) => Promise<TaintAssessment>): Promise<number> {
    let n = 0;
    for (const w of this.openWindows()) {
      let verdict: TaintAssessment;
      try {
        verdict = await assess(w.openedAt);
      } catch (err) {
        this.d.log?.(`taint check of configuration window #${w.id} failed: ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      if (verdict.state !== "tainted") continue;
      this.store.closeCfgWindow(w.id, "tainted");
      this.store.log("watch.window.taint", null, null, { windowId: w.id, scopes: w.scopes, kinds: verdict.kinds, threads: verdict.threads.slice(0, 10), lines: verdict.lines.slice(0, 5), note: "снимок зафиксирован" });
      n++;
    }
    return n;
  }

  /** Opens a configuration window on the chosen objects. Needs a touch. */
  async openWindow(scopes: string[], code: Proof): Promise<ConfigWindowRow> {
    const chosen = [...new Set(scopes)];
    if (chosen.length === 0) throw new WatchError("invalid", "choose at least one object the window is opened on");
    const bad = chosen.filter((s) => !isWindowScope(s));
    if (bad.length > 0) throw new WatchError("invalid", `a configuration window cannot be opened on: ${bad.join(", ")}`);
    if (this.baselineAt() === null) throw new WatchError("conflict", "there is no approved snapshot yet; accept the current configuration first");
    this.d.touch("watch.window.open", code);
    // What changed before the window opened is not "in the window": record it (and roll it back, if that is on) first.
    await this.scan();
    this.sweep();
    for (const old of this.store.unclosedCfgWindows()) this.store.closeCfgWindow(old.id, "reopened");
    const policy = this.store.policy();
    const now = this.now;
    const hard = now + policy.cfgCapMin * 60_000;
    const w = this.store.insertCfgWindow({
      scopes: chosen as WindowScope[],
      mode: policy.cfgMode,
      sizeSec: policy.cfgWindowMin * 60,
      capSec: policy.cfgCapMin * 60,
      openedAt: now,
      expiresAt: Math.min(now + policy.cfgWindowMin * 60_000, hard),
      hardExpiresAt: hard,
    });
    this.store.log("watch.window.open", null, null, { windowId: w.id, scopes: w.scopes, mode: w.mode, sizeSec: w.sizeSec });
    return w;
  }

  /** Closes a window by hand (a touch). Changes made until now are taken first. */
  /** Closing a window only tightens: no code, and the block after wrong codes does not apply (threat model F8). */
  async closeWindow(windowId: number): Promise<void> {
    const w = this.store.getCfgWindow(windowId);
    if (!w || w.closedAt !== null) throw new WatchError("not_found", "no such open configuration window");
    if (isCfgOpen(w, this.now)) await this.scan();
    this.store.closeCfgWindow(windowId, "closed");
    this.store.log("watch.window.close", null, null, { windowId, scopes: w.scopes });
  }

  private slide(w: ConfigWindowRow): void {
    if (w.mode !== "sliding") return;
    const next = Math.min(this.now + w.sizeSec * 1000, w.hardExpiresAt);
    if (next > w.expiresAt) {
      this.store.setCfgWindowExpiry(w.id, next);
      this.store.log("watch.window.slide", null, null, { windowId: w.id });
    }
  }

  // ---- the scan ----------------------------------------------------------
  /** One reading of bb. Skills are read afresh (the reader's memo is per reading). */
  private observe(): Promise<Observation> {
    this.d.skills?.beginScan();
    return collect(this.d.source, () => this.now);
  }

  /** Coalesces overlapping triggers (events come in bursts). */
  async scan(): Promise<ScanResult> {
    if (this.running) {
      this.again = true;
      return { found: 0, accepted: 0, rolledBack: 0, rollbackFailed: 0 };
    }
    this.running = true;
    const total: ScanResult = { found: 0, accepted: 0, rolledBack: 0, rollbackFailed: 0 };
    try {
      do {
        this.again = false;
        const r = await this.scanOnce();
        total.found += r.found;
        total.accepted += r.accepted;
        total.rolledBack += r.rolledBack;
        total.rollbackFailed += r.rollbackFailed;
      } while (this.again);
    } finally {
      this.running = false;
    }
    return total;
  }

  private isRollbackable(diff: Difference): boolean {
    const rb = diff.item?.rollback;
    if (!rb || diff.kind === "removed") return false;
    if (rb.kind === "restore-instructions") return this.store.getBlob("instructions") !== null;
    return true;
  }

  private coveringWindow(diff: Difference, drift: Drift): ConfigWindowRow | null {
    for (const w of this.openWindows()) {
      // Only what happened after the window opened is "in the window".
      if ((w.scopes as string[]).includes(diff.category) && drift.firstSeen >= w.openedAt) return w;
    }
    return null;
  }

  private async scanOnce(): Promise<ScanResult> {
    const out: ScanResult = { found: 0, accepted: 0, rolledBack: 0, rollbackFailed: 0 };
    this.sweep();
    const obs = await this.observe();
    this.last = obs;
    this.store.setMeta(META_LAST_SCAN, String(obs.at));

    // Skills (stage 6): checked and decided by the guard, whether or not a configuration snapshot was approved.
    if (this.d.skills && obs.skillRefs) {
      const complete = !obs.failed.some((f) => f.source === "skills" || f.source.startsWith("skills:") || f.source === "projects");
      const win = this.openWindows().find((w) => w.scopes.includes("skills")) ?? null;
      try {
        const r = await this.d.skills.evaluate({ refs: obs.skillRefs, complete, skillsWindow: win?.id ?? null });
        out.found += r.raised;
        for (const id of new Set(r.viaWindow)) {
          const w = this.store.getCfgWindow(id);
          if (w) this.slide(w);
        }
      } catch (err) {
        this.d.log?.(`skills guard failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (this.baselineAt() === null) return out; // nothing approved yet: show, do not judge

    const diffs = diffSnapshot(this.store.listSnapshot(), obs);
    const live = new Set(diffs.map((x) => x.key));

    // A drift that vanished by itself (or was undone by hand) is closed.
    for (const open of this.store.unresolvedDrifts()) {
      if (!live.has(open.key) && !this.isUnobservedKey(open, obs)) this.store.resolveDrift(open.id, "reverted", "значение снова совпадает с одобренным");
    }

    for (const diff of diffs) {
      const rollbackable = this.isRollbackable(diff);
      let drift = this.store.openDrift(diff.key);
      if (drift && drift.after === diff.after && drift.kind === diff.kind) {
        this.store.touchDrift(drift.id);
      } else if (drift) {
        this.store.updateDrift(drift.id, { kind: diff.kind, label: diff.label, after: diff.after, rollbackable });
        drift = this.store.getDrift(drift.id)!;
      } else {
        drift = this.store.insertDrift({ key: diff.key, category: diff.category, source: diff.source, kind: diff.kind, label: diff.label, before: diff.before, after: diff.after, rollbackable });
        this.store.log("watch.drift", null, null, { key: diff.key, kind: diff.kind, category: diff.category, before: diff.before, after: diff.after });
        out.found++;
      }

      // A skill is taken into the snapshot by a window only if the guard accepted its content (checks clean).
      const skillOk = diff.category !== "skills" || !this.d.skills || diff.kind === "removed" || this.d.skills.isAccepted(diff.key);
      const w = skillOk ? this.coveringWindow(diff, drift) : null;
      if (w) {
        this.applyToSnapshot(diff.key, obs, "window");
        this.store.resolveDrift(drift.id, "accepted-window", `окно #${w.id}`);
        this.store.log("watch.accept.window", null, null, { key: diff.key, windowId: w.id });
        this.slide(w);
        out.accepted++;
        continue;
      }
      if (this.rollbackEnabled() && rollbackable && diff.item?.rollback) {
        const ok = await this.rollback(drift, diff.item.rollback);
        if (ok) out.rolledBack++;
        else out.rollbackFailed++;
      }
    }
    return out;
  }

  private isUnobservedKey(d: Drift, obs: Observation): boolean {
    return obs.failed.some((f) => d.source === f.source || d.source.startsWith(`${f.source}:`));
  }

  // ---- rollback ----------------------------------------------------------
  private async rollback(drift: Drift, rb: Rollback): Promise<boolean> {
    try {
      if (rb.kind === "disable-plugin") await this.d.actions.disablePlugin(rb.pluginId);
      else if (rb.kind === "delete-env") await this.d.actions.deleteEnv(rb.scope, rb.projectId, rb.name);
      else {
        const text = this.store.getBlob("instructions");
        if (text === null) throw new Error("approved instruction text is not stored");
        await this.d.actions.restoreInstructions(text);
      }
      this.store.resolveDrift(drift.id, "rolled-back", rollbackNote(rb));
      this.store.log("watch.rollback", null, null, { key: drift.key, action: rb.kind });
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.store.failRollback(drift.id, `откат не удался: ${msg}`);
      this.store.log("watch.rollback.failed", null, null, { key: drift.key, action: rb.kind, message: msg });
      this.d.log?.(`rollback of ${drift.key} failed: ${msg}`);
      return false;
    }
  }

  // ---- snapshot ----------------------------------------------------------
  private applyToSnapshot(key: string, obs: Observation, via: string): void {
    const item = obs.items.find((i) => i.key === key);
    if (!item) {
      this.store.deleteSnapshot(key);
      if (key === "instructions") this.store.putBlob("instructions", "");
      return;
    }
    this.putItem(item, obs, via);
  }

  private putItem(item: Item, obs: Observation, via: string): void {
    this.store.putSnapshot({ key: item.key, category: item.category, source: item.source, label: item.label, value: item.value, via });
    if (item.key === "instructions" && obs.instructionsText !== null) this.store.putBlob("instructions", obs.instructionsText);
  }

  /** The first snapshot, or a full re-approval: everything observed right now becomes the approved state. */
  async acceptAll(code: Proof): Promise<{ items: number }> {
    this.d.touch("watch.baseline", code);
    const obs = await this.observe();
    this.last = obs;
    const isFailed = (source: string) => obs.failed.some((f) => source === f.source || source.startsWith(`${f.source}:`));
    const keys = new Set(obs.items.map((i) => i.key));
    for (const row of this.store.listSnapshot()) if (!keys.has(row.key) && !isFailed(row.source)) this.store.deleteSnapshot(row.key);
    for (const item of obs.items) this.putItem(item, obs, "touch");
    for (const open of this.store.unresolvedDrifts()) if (!isFailed(open.source)) this.store.resolveDrift(open.id, "accepted-touch", "принят целиком");
    this.store.setMeta(META_BASELINE, String(this.now));
    this.store.log("watch.baseline", null, null, { items: obs.items.length, unobserved: obs.failed.map((f) => f.source) });
    return { items: obs.items.length };
  }

  /** Accepts one drift as the new approved value (a touch). */
  async acceptDrift(driftId: number, code: Proof, expect?: { after: string | null }): Promise<void> {
    const drift = this.requireOpen(driftId);
    this.d.touch("watch.accept", code);
    const obs = await this.observe();
    this.last = obs;
    if (expect) {
      // A list was shown with this value: what is observed now must be that value, or the person approved something else.
      const now = diffSnapshot(this.store.listSnapshot(), obs).find((x) => x.key === drift.key);
      if ((now?.after ?? null) !== expect.after) throw new WatchError("conflict", "the value changed after the list was shown; it was not accepted");
    }
    this.applyToSnapshot(drift.key, obs, "touch");
    this.store.resolveDrift(drift.id, "accepted-touch", "принято человеком");
    this.store.log("watch.accept.touch", null, null, { key: drift.key });
  }

  /** Undoes one drift now (a touch), whether or not automatic rollback is on. */
  async rollbackDrift(driftId: number, code: Proof): Promise<void> {
    const drift = this.requireOpen(driftId);
    if (!drift.rollbackable) throw new WatchError("invalid", "no safe rollback exists for this change; accept it or fix it by hand");
    this.d.touch("watch.rollback", code);
    const obs = await this.observe();
    this.last = obs;
    const diff = diffSnapshot(this.store.listSnapshot(), obs).find((x) => x.key === drift.key);
    const rb = diff?.item?.rollback;
    if (!diff || !rb) {
      this.store.resolveDrift(drift.id, "reverted", "уже совпадает с одобренным");
      return;
    }
    if (!(await this.rollback(drift, rb))) throw new WatchError("conflict", this.store.getDrift(drift.id)?.note ?? "rollback failed");
  }

  private requireOpen(id: number): Drift {
    const d = this.store.getDrift(id);
    if (!d) throw new WatchError("not_found", `no difference #${id}`);
    if (d.status !== "open" && d.status !== "rollback-failed") throw new WatchError("conflict", `difference #${id} is already ${d.status}`);
    return d;
  }

  /** Rollback is off by default. Switching it on only tightens (no code, threat model F8); switching it off needs a touch. */
  setRollback(enabled: boolean, code?: string): void {
    const turnsOff = !enabled && this.store.getMeta(META_ROLLBACK) === "1";
    if (turnsOff) {
      if (code === undefined) throw new GateError("invalid_code", "turning the rollback off needs a code");
      this.d.touch("watch.rollback.mode", code);
    }
    this.store.setMeta(META_ROLLBACK, enabled ? "1" : "0");
    this.store.log("watch.rollback.mode", null, null, { enabled });
  }
}

function rollbackNote(rb: Rollback): string {
  switch (rb.kind) {
    case "disable-plugin":
      return `выключен плагин ${rb.pluginId}`;
    case "delete-env":
      return `удалена переменная ${rb.name}${rb.projectId ? ` (проект ${rb.projectId})` : " (машина)"}`;
    case "restore-instructions":
      return "возвращены одобренные инструкции";
  }
}
