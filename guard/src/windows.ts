// Trust windows (open, close, expire, sweep), the window policy and the troubleshooting mode: everything about time that other layers read.
// Whether a version passes by a window is decide.ts (`windowRefuses`); here a window only exists, slides and ends.
import { guardPolicyWidens } from "./policy.ts";
import { GuardError, MAX_TROUBLESHOOT_MIN, type Policy, type WindowRow, type Raw, windowOf, pluginIdOf, intOf, type Proof, factorDetail } from "./guard-types.ts";
import { FactorGuard } from "./factor.ts";

export class WindowGuard extends FactorGuard {
  // ---- windows ------------------------------------------------------------
  protected unclosedWindows(): WindowRow[] {
    return (this.db.prepare(`SELECT * FROM windows WHERE closed_at IS NULL`).all() as Raw[]).map(windowOf);
  }
  protected openWindowOf(pluginId: string): WindowRow | null {
    const now = this.now();
    return this.unclosedWindows().find((w) => w.pluginId === pluginId && now < w.expiresAt && now < w.hardExpiresAt) ?? null;
  }
  protected closeWindowInner(w: WindowRow, reason: string, at = this.now()): void {
    this.db.prepare(`UPDATE windows SET closed_at = ?, closed_reason = ? WHERE id = ? AND closed_at IS NULL`).run(at, reason, w.id);
    const pin = this.db.prepare(`SELECT version, content_hash FROM approvals WHERE plugin_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1`).get(w.pluginId) as { version: string; content_hash: string } | undefined;
    // The last approved version stays pinned: the next one needs a new window.
    this.log(reason === "expired" || reason === "ceiling" ? "window.freeze" : "window.close", w.pluginId, pin?.content_hash ?? null, { windowId: w.id, reason, pinnedVersion: pin?.version ?? null });
  }
  protected sweepInner(): number {
    let n = 0;
    const now = this.now();
    for (const w of this.unclosedWindows()) {
      if (now < w.expiresAt && now < w.hardExpiresAt) continue;
      this.closeWindowInner(w, w.expiresAt >= w.hardExpiresAt ? "ceiling" : "expired", Math.min(w.expiresAt, w.hardExpiresAt));
      n++;
    }
    for (const r of this.db.prepare(`SELECT id, expires_at, hard_expires_at FROM sessions WHERE closed_at IS NULL`).all() as Array<{ id: number; expires_at: number; hard_expires_at: number }>) {
      if (now < Number(r.expires_at) && now < Number(r.hard_expires_at)) continue;
      this.closeSessionInner(Number(r.id), "expired");
      n++;
    }
    this.flushPasskeyFails("", {}, true);
    // Troubleshooting mode returns by itself.
    const until = Number(this.meta("troubleshoot_until") ?? 0);
    if (until > 0 && until <= now) {
      this.setMeta("troubleshoot_until", "0");
      this.log("troubleshoot.end", null, null, { reason: "expired", at: until });
      n++;
    }
    return n;
  }
  /** Background pass: closes windows whose time is up and journals the freeze. */
  sweep(): number {
    return this.tx(() => this.sweepInner());
  }
  /**
   * Opens a window on a plugin id with a touch. Inside it a version is approved without a touch only if it passes `windowRefuses` (no hard sign, no right beyond the
   * base, nothing for review; a window bound to a thread also needs the plugin's pulse): not "any version".
   */
  openWindow(raw: Record<string, unknown>): WindowRow {
    const pluginId = pluginIdOf(raw.pluginId);
    const policy = this.policy();
    const minutes = raw.minutes === undefined ? policy.windowMin : intOf(raw.minutes, "minutes", 1, 1440);
    if (minutes > policy.capMin) throw new GuardError("invalid", `a window is at most ${policy.capMin} minutes (the ceiling)`);
    const factor = this.verifyFactor(`window.open:${pluginId}`, this.normalizeAction({ op: "open-window", pluginId, minutes, ...(raw.scope !== undefined ? { scope: raw.scope } : {}) }), raw);
    return this.tx(() => {
      this.sweepInner();
      for (const old of this.unclosedWindows()) if (old.pluginId === pluginId) this.closeWindowInner(old, "reopened");
      const now = this.now();
      const hard = now + policy.capMin * 60_000;
      // What the person saw when opening it: the rights of the newest version of this plugin that waits.
      const held = this.db.prepare(`SELECT rights FROM queue WHERE plugin_id = ? AND status = 'held' AND rights IS NOT NULL ORDER BY id DESC LIMIT 1`).get(pluginId) as { rights: string } | undefined;
      const info = this.db
        .prepare(`INSERT INTO windows (plugin_id, size_sec, cap_sec, mode, opened_at, expires_at, hard_expires_at, scope, base_rights) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(pluginId, minutes * 60, policy.capMin * 60, policy.mode, now, Math.min(now + minutes * 60_000, hard), hard, raw.scope === "tree" || raw.scope === "thread" ? raw.scope : "all", held?.rights ?? null);
      const w = windowOf(this.db.prepare(`SELECT * FROM windows WHERE id = ?`).get(Number(info.lastInsertRowid)) as Raw);
      this.log("window.open", pluginId, null, { windowId: w.id, minutes, mode: w.mode, ceilingMin: policy.capMin, ...factorDetail(factor) });
      return w;
    });
  }
  /** Closing only tightens: no code. */
  closeWindow(raw: Record<string, unknown>): { closed: number } {
    return this.tx(() => {
      const open = this.unclosedWindows();
      let targets: WindowRow[];
      if (raw.windowId !== undefined) {
        const id = intOf(raw.windowId, "windowId", 1, Number.MAX_SAFE_INTEGER);
        targets = open.filter((w) => w.id === id);
      } else {
        const pluginId = pluginIdOf(raw.pluginId);
        targets = open.filter((w) => w.pluginId === pluginId);
      }
      if (targets.length === 0) throw new GuardError("not_found", "no such open window");
      for (const w of targets) this.closeWindowInner(w, "closed");
      return { closed: targets.length };
    });
  }
  /** Widening (a longer window, a higher ceiling, sliding instead of fixed) needs a code; narrowing does not. */
  setPolicy(patch: Partial<Policy>, proof: Proof): Policy {
    const cur = this.policy();
    const next: Policy = { ...cur };
    if (patch.windowMin !== undefined) next.windowMin = intOf(patch.windowMin, "windowMin", 1, 1440);
    if (patch.capMin !== undefined) next.capMin = intOf(patch.capMin, "capMin", 1, 1440);
    if (patch.mode !== undefined) {
      if (patch.mode !== "sliding" && patch.mode !== "fixed") throw new GuardError("invalid", "mode is sliding or fixed");
      next.mode = patch.mode;
    }
    if (next.windowMin > next.capMin) throw new GuardError("invalid", "the window size cannot exceed the ceiling");
    const widens = guardPolicyWidens(cur, next);
    const factor = widens ? this.verifyFactor("policy", this.normalizeAction({ op: "policy", patch }), proof) : null;
    return this.tx(() => {
      this.setMeta("policy", JSON.stringify(next));
      this.log("policy", null, null, { from: cur, to: next, touched: widens, ...(factor ? factorDetail(factor) : {}) });
      return next;
    });
  }
  // ---- troubleshooting mode (console + a code; the guard has no off switch) ----------------------------------------------------
  /** Until when the guard passes everything and writes every decision down; 0: off. */
  troubleshootUntil(): number {
    const until = Number(this.meta("troubleshoot_until") ?? 0);
    return until > this.now() ? until : 0;
  }
  /**
   * Console only (there is no op for it on the socket): a code is spent, the guard passes everything for `minutes`, writes each decision into the
   * journal and returns by itself. It does not switch the guard off: approvals, windows, touches and the journal work as always.
   */
  troubleshootStart(minutes: unknown, code: unknown): { until: number; minutes: number } {
    const m = intOf(minutes, "minutes", 1, MAX_TROUBLESHOOT_MIN);
    this.verifyCode("troubleshoot", code);
    return this.tx(() => {
      const until = this.now() + m * 60_000;
      this.setMeta("troubleshoot_until", String(until));
      this.troubleshootPasses = [];
      this.log("troubleshoot.start", null, null, { minutes: m, until, via: "console" });
      return { until, minutes: m };
    });
  }
  /** Console only: back to normal now. Tightening: no code. */
  troubleshootStop(): boolean {
    return this.tx(() => {
      if (this.troubleshootUntil() === 0) return false;
      this.setMeta("troubleshoot_until", "0");
      this.log("troubleshoot.end", null, null, { reason: "stopped", via: "console" });
      return true;
    });
  }
}
