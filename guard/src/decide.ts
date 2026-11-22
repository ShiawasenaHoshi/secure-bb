// What the guard says when the core asks: `decide` / `hold` / `evaluate` (the guard reads a version itself), the window rule (`windowRefuses`) and the source rule (`sourceVerdict`).
// It reads the layers below and writes the queue and approvals through them; it never checks a factor itself.
import { realpathSync } from "node:fs";
import { sep } from "node:path";
import { readTree, TreeRefused } from "./tree-read.ts";
import { brief, grown, hardFlags, identityOf, levelOf, rightsOf, type ReasonKind, type Rights, windowAllows } from "./trust.ts";
import { MAX_TROUBLESHOOT_PASSES_PER_MIN, PLUGIN_ALIVE_MS, WINDOW_PAUSED_NOTE, type DecideInput, type Decision, type WindowRow, type Raw, approvalOf, type Evaluation, MAX_CONCURRENT_EVALS, MAX_EVALS_PER_MINUTE } from "./guard-types.ts";
import { QueueGuard } from "./queue.ts";

export class DecideGuard extends QueueGuard {
  /** What the guard's OWN reading says about a version, whatever check a hold stopped at: the hard flags (null: not read) and whether the hash did not match. */
  protected factsOf(req: DecideInput, ev: Evaluation | null): { blocks: string[] | null; mismatch: boolean } {
    if (ev?.ok === true && ev.hash === req.contentHash) return { blocks: ev.blocks, mismatch: false };
    return { blocks: null, mismatch: (ev?.ok === true && ev.hash !== req.contentHash) || (ev?.ok === false && ev.mismatch === true) };
  }
  /** The reason as a fact: a hash mismatch and a hard flag outrank the check a hold stopped at (`verdictKind`). */
  protected kindOf(f: { blocks: string[] | null; mismatch: boolean }, verdictKind: ReasonKind): ReasonKind {
    return f.mismatch ? "mismatch" : f.blocks !== null && f.blocks.length > 0 ? "block" : verdictKind;
  }
  /**
   * Holds a version for a human, by request of the plugin's hook (tightening: no code). Unlike a hold made by `decide`, a window does not lift it:
   * only a human's approval does. Needed because the hook knows things the guard cannot (a new capability inside a window), and the core may not
   * ask the guard at all once a hook has held the version.
   */
  hold(raw: Record<string, unknown>, ev: Evaluation | null = null): { requestId: number | null } {
    const req = this.parseDecide(raw);
    return this.tx(() => {
      this.sweepInner();
      // Already approved by a human or imported: nothing to hold (a window's approval is withdrawn by `revoke` first).
      if (this.activeApproval(req.pluginId, req.contentHash, req.source)) return { requestId: null };
      // Rejected by the person: no new entry (the rejection stands until «Вернуть»).
      if (this.isRejected(req.pluginId, req.contentHash)) {
        this.logRepeatReject(req.pluginId, req.contentHash, req.version);
        return { requestId: null };
      }
      // From the hook only what tightens is taken: `stop`. Its findings are not believed: the block is what the guard's own reading found (none read: unknown, which counts as a block).
      const f = this.factsOf(req, ev);
      return { requestId: this.upsertHeld(req, raw.stop === true, { rights: ev?.ok && ev.hash === req.contentHash ? ev.rights : null, note: null, kind: this.kindOf(f, "other"), blocks: f.blocks }).id };
    });
  }
  /** `hold` with the guard's own reading of the version first (as `decideChecked` does for a decision). */
  async holdChecked(raw: Record<string, unknown>): Promise<{ requestId: number | null }> {
    const req = this.parseDecide(raw);
    return this.hold(raw, await this.evaluate(req));
  }
  // ---- the plugin's pulse ------------------------------------------------------------------------------------
  protected pluginBeatAt = 0;
  /** The plugin says it runs (a light call every few seconds). Only memory: after a restart of the guard the plugin is "not alive" until its next call. */
  beat(): { ok: true } {
    this.pluginBeatAt = this.now();
    return { ok: true };
  }
  /** The plugin called within PLUGIN_ALIVE_MS. Whoever can reach the socket can call, so this only decides what a window needs; it never lets anything in by itself. */
  pluginAlive(): boolean {
    return this.pluginBeatAt > 0 && this.now() - this.pluginBeatAt <= PLUGIN_ALIVE_MS;
  }
  /**
   * An open window lets a version in only if the same stands as when the plugin runs. The pulse decides ONE thing: the thread scope (only the plugin knows
   * the threads), so a window bound to a thread pauses without it. Whoever reaches the socket can fake a pulse, so everything the guard can read itself it
   * checks always: the version was read and its hash matched, no hard flag, no right beyond the last approved version and the one the window was opened from, nothing for review (`windowAllows`).
   * No base to compare with: held. Null: the window may let it in.
   */
  protected windowRefuses(w: WindowRow, req: DecideInput, ev: Evaluation | null): { note: string; stop: boolean; kind: ReasonKind } | null {
    if (w.scope !== "all" && !this.pluginAlive()) return { note: WINDOW_PAUSED_NOTE, stop: false, kind: "other" };
    if (ev === null) return { note: "окно: права версии не посчитаны", stop: false, kind: "other" };
    if (!ev.ok) return { note: `окно: ${ev.reason}`, stop: false, kind: ev.mismatch === true ? "mismatch" : "other" };
    if (ev.hash !== req.contentHash) return { note: "окно: хеш каталога не совпал с хешем из запроса", stop: false, kind: "mismatch" };
    if (ev.blocks.length > 0) return { note: `жёсткий флаг: ${brief(ev.blocks)}`, stop: true, kind: "block" };
    const base = this.windowBase(w, req);
    if (base === null) return { note: "окно: нет одобренной версии или версии, с которой открыто окно, для сравнения прав", stop: false, kind: "first" };
    const v = windowAllows(base, ev.rights);
    if (v.newTokens.length > 0) return { note: `новое право: ${brief(v.newTokens)}`, stop: true, kind: "growth" };
    if (v.reviews.length > 0) return { note: `проверки требуют ревью: ${brief(v.reviews)}`, stop: true, kind: "growth" };
    return null;
  }
  /** What the window may carry without being asked: the last approved version of the plugin (same source first) together with the version it was opened from. */
  protected windowBase(w: WindowRow, req: DecideInput): Rights | null {
    const ident = identityOf(req.sourceKind, req.source, req.rootDir);
    const q = `SELECT * FROM approvals WHERE plugin_id = ? AND revoked_at IS NULL AND rights IS NOT NULL`;
    const row = ((ident ? this.db.prepare(`${q} AND source_id = ? ORDER BY id DESC LIMIT 1`).get(req.pluginId, ident.id) : undefined) ?? this.db.prepare(`${q} ORDER BY id DESC LIMIT 1`).get(req.pluginId)) as Raw | undefined;
    const parts: Rights[] = [];
    if (row) parts.push(approvalOf(row).rights!);
    if (w.baseRights) parts.push(w.baseRights);
    if (parts.length === 0) return null;
    return { tokens: [...new Set(parts.flatMap((p) => p.tokens))].sort(), review: [...new Set(parts.flatMap((p) => p.review))].sort() };
  }
  /**
   * What the core asks before it loads a plugin. Holds when nothing a human decided covers it. `ev`: what the guard itself read in the version's
   * directory (see `evaluate`); with it, a version of a trusted source whose rights did not grow passes by itself (`sourceVerdict`).
   */
  decide(raw: Record<string, unknown>, ev: Evaluation | null = null): Decision {
    const req = this.parseDecide(raw);
    return this.tx(() => {
      this.sweepInner();
      // Troubleshooting mode: everything passes, and every decision is a record (what it would have been is in it). Nothing is approved and nothing is queued.
      if (this.troubleshootUntil() > 0) {
        const wouldHave = this.coveringApproval(req) ? "approval" : this.openWindowOf(req.pluginId) ? "window" : "wait";
        const now = this.now();
        this.troubleshootPasses = this.troubleshootPasses.filter((t) => t > now - 60_000);
        // Every pass is journaled: past the limit the guard holds instead of passing without a record.
        if (this.troubleshootPasses.length >= MAX_TROUBLESHOOT_PASSES_PER_MIN) return { action: "wait", reason: "held by secure-bb guard: troubleshooting mode records too many decisions", requestId: null } as const;
        this.troubleshootPasses.push(now);
        this.log("troubleshoot.pass", req.pluginId, req.contentHash, { version: req.version, source: req.source, sourceKind: req.sourceKind, rootDir: req.rootDir, trigger: req.trigger, wouldHave });
        return { action: "proceed", via: "troubleshoot" } as const;
      }
      if (this.coveringApproval(req)) return { action: "proceed", via: "approval" } as const;

      // Rejected by the person and not brought back: "no", no new queue entry (the core keeps the plugin off), one journal line an hour per version.
      // Before windows and the source rule: a window or a trusted source must not undo what the person said "no" to; «Вернуть» does.
      if (this.isRejected(req.pluginId, req.contentHash)) {
        this.logRepeatReject(req.pluginId, req.contentHash, req.version);
        return { action: "reject", message: "secure-bb: версия отклонена вами; чтобы вернуть, нажмите «Вернуть» в Карантине" } as const;
      }

      // A stop survives a rejection: dismiss needs no code, so a process that can reach the guard could otherwise clear the stop and let the window in.
      const stopped = this.isStopped(req.pluginId, req.contentHash);
      const w = stopped ? null : this.openWindowOf(req.pluginId);
      const refused = w ? this.windowRefuses(w, req, ev) : null;
      if (w && refused) {
        const f = this.factsOf(req, ev);
        const h = this.upsertHeld(req, refused.stop, { rights: ev?.ok && ev.hash === req.contentHash ? ev.rights : null, note: refused.note, kind: this.kindOf(f, refused.kind), blocks: f.blocks });
        this.log("window.refused", req.pluginId, req.contentHash, { windowId: w.id, version: req.version, scope: w.scope, note: refused.note, ...(refused.stop ? { stop: true } : {}) });
        return h.id === null ? ({ action: "wait", reason: "held by secure-bb guard: too many new holds", requestId: null } as const) : ({ action: "wait", reason: `held by secure-bb guard: review #${h.id}`, requestId: h.id } as const);
      }
      if (w) {
        const a = this.addApproval({ contentHash: req.contentHash, pluginId: req.pluginId, version: req.version, source: req.source, sourceKind: req.sourceKind, rootDir: req.rootDir, gitCommit: null, npmIntegrity: null, via: "window", windowId: w.id, rights: ev?.ok && ev.hash === req.contentHash ? ev.rights : null, why: "в открытом окне доверия: окно пропускает версии, пока не просят нового" });
        this.db.prepare(`UPDATE windows SET uses = uses + 1 WHERE id = ?`).run(w.id);
        if (w.mode === "sliding") {
          const next = Math.min(this.now() + w.sizeSec * 1000, w.hardExpiresAt);
          if (next > w.expiresAt) this.db.prepare(`UPDATE windows SET expires_at = ? WHERE id = ?`).run(next, w.id);
        }
        this.resolveQueue(req.pluginId, req.contentHash, "approved");
        this.log("approved.window", req.pluginId, req.contentHash, { approval: a.id, windowId: w.id, version: req.version, source: req.source, sourceKind: req.sourceKind, ...this.learning({ rights: a.rights }) });
        return { action: "proceed", via: "window" } as const;
      }

      const verdict = this.sourceVerdict(req, ev, stopped);
      if (verdict.pass) {
        const a = this.addApproval({ contentHash: req.contentHash, pluginId: req.pluginId, version: req.version, source: req.source, sourceKind: req.sourceKind, rootDir: req.rootDir, gitCommit: null, npmIntegrity: null, via: "source", windowId: null, rights: verdict.rights, why: String(verdict.detail.why ?? "прошла сама: источник и права те же") });
        this.resolveQueue(req.pluginId, req.contentHash, "approved");
        this.log("approved.source", req.pluginId, req.contentHash, { approval: a.id, version: req.version, source: req.source, sourceKind: req.sourceKind, ...verdict.detail, ...this.learning({ rights: a.rights }) });
        return { action: "proceed", via: "source" } as const;
      }

      const f = this.factsOf(req, ev);
      const h = this.upsertHeld(req, stopped, { rights: ev?.ok && ev.hash === req.contentHash ? ev.rights : null, note: verdict.note, kind: this.kindOf(f, verdict.kind), blocks: f.blocks });
      return h.id === null ? ({ action: "wait", reason: "held by secure-bb guard: too many new holds", requestId: null } as const) : ({ action: "wait", reason: `held by secure-bb guard: review #${h.id}`, requestId: h.id } as const);
    });
  }
  /** `decide` with the guard's own reading of the version first (the checks run outside the transaction, within a time budget). */
  async decideChecked(raw: Record<string, unknown>): Promise<Decision> {
    const req = this.parseDecide(raw);
    if (this.coveringApproval(req) || this.troubleshootUntil() > 0) return this.decide(raw);
    return this.decide(raw, await this.evaluate(req));
  }
  /**
   * The guard reads the version's directory ITSELF: what the plugin says about its own rights is not looked at (annotate is for display only).
   * Fails closed: a directory that cannot be read, is not where the source says, or checks that fail or run out of time → `ok: false`.
   * Checks are limited (two at a time, thirty a minute): whoever can reach the socket must not be able to make the guard read without end.
   */
  async evaluate(req: DecideInput): Promise<Evaluation> {
    const ident = identityOf(req.sourceKind, req.source, req.rootDir);
    if (ident === null) return { ok: false, reason: "источник не назван (не github и не каталог на диске)" };
    let dir: string;
    try {
      dir = realpathSync(req.rootDir);
      if (ident.kind === "path") {
        if (dir !== realpathSync(ident.id.slice(5))) return { ok: false, reason: "каталог версии не тот, что назван источником" };
      } else if (!this.trustCfg.pluginsRoots.some((r) => this.within(dir, r))) {
        return { ok: false, reason: this.trustCfg.pluginsRoots.length === 0 ? "у сторожа не задан каталог плагинов (--plugins-root)" : "каталог версии вне каталогов плагинов ядра" };
      }
    } catch (err) {
      return { ok: false, reason: `каталог не прочитан: ${this.errText(err)}` };
    }
    const now = this.now();
    this.evalTimes = this.evalTimes.filter((t) => t > now - 60_000);
    if (this.evalsRunning >= MAX_CONCURRENT_EVALS || this.evalTimes.length >= MAX_EVALS_PER_MINUTE) return { ok: false, reason: "сторож занят чтением других версий, повторите позже" };
    this.evalTimes.push(now);
    this.evalsRunning++;
    let timer: NodeJS.Timeout | undefined;
    // ONE pass: the guard reads the directory once, hashes what it read the way the core does, and the checks run on a private copy of those same bytes.
    // The hash must be the request's: otherwise the request is about other code than the directory shows (a forged `decide`), and nothing is approved.
    const work = (async (): Promise<Evaluation> => {
      let tree;
      try {
        tree = await readTree(dir, this.trustCfg.treeLimits);
      } catch (err) {
        return { ok: false, reason: err instanceof TreeRefused ? `каталог не прочитан: ${err.message}` : `каталог не прочитан: ${this.errText(err)}` };
      }
      try {
        if (tree.hash !== req.contentHash) return { ok: false, reason: "хеш каталога, посчитанный сторожем, не совпал с хешем из запроса", mismatch: true };
        const res = await this.trustCfg.checks(tree.dir, { pluginId: req.pluginId });
        // The clock stopped the flow analysis: its result is not finished and counts for no right. The version is held; the next evaluation tries again.
        if (res.flowsTimedOut) return { ok: false, reason: "проверка не успела: анализ потока данных остановлен по времени, повторите позже" };
        return { ok: true, hash: tree.hash, rights: rightsOf(res), blocks: hardFlags(res).map((f) => `${f.rule} ${f.file}${f.line ? `:${f.line}` : ""}`) };
      } finally {
        await tree.cleanup().catch(() => undefined);
      }
    })().finally(() => {
      // The slot is freed when the work ends, not when the budget does: a slow directory must not pile up readers.
      this.evalsRunning--;
    });
    try {
      return await Promise.race([work, new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Error("проверки не уложились во время")), this.trustCfg.budgetMs)))]);
    } catch (err) {
      work.catch(() => undefined);
      return { ok: false, reason: `проверки не выполнены: ${this.errText(err)}` };
    } finally {
      clearTimeout(timer);
    }
  }
  protected within = (path: string, root: string): boolean => {
    try {
      const r = realpathSync(root);
      return path === r || path.startsWith(r.endsWith(sep) ? r : r + sep);
    } catch {
      return false;
    }
  };
  protected errText = (err: unknown): string => (err instanceof Error ? err.message : String(err)).slice(0, 200);
  protected sourceVerdict(req: DecideInput, ev: Evaluation | null, stopped: boolean): { pass: true; rights: Rights; detail: Record<string, unknown> } | { pass: false; note: string | null; kind: ReasonKind } {
    const no = (note: string | null, kind: ReasonKind = "other") => ({ pass: false as const, note, kind });
    if (stopped) return no(null, "other"); // the plugin's own check stopped this version for a human: its reason is in the queue already
    // A critical difference in the agents' settings is open: an agent that may be swapped must not carry a version of an "own" plugin through. Only a human's decision lets it in.
    if (this.criticalAgentsOpen()) return no("открыта критичная тревога по настройкам агентов: версии сами не проходят, пока вы её не разберёте");
    const mode = this.trustMode();
    const ident = identityOf(req.sourceKind, req.source, req.rootDir);
    const { level, entry } = levelOf(ident, this.mySources(), this.trustCfg.known);
    if (mode === "strict") return no("режим «Строгий»: каждая версия ждёт вас", "strict");
    if (level === "unknown") return no(ident === null ? "источник нельзя назвать своим (не github и не каталог на диске)" : "неизвестный источник", "unknown-source");
    if (ev === null) return no("права версии не посчитаны");
    if (!ev.ok) return no(ev.reason, ev.mismatch === true ? "mismatch" : "other");
    if (ev.hash !== req.contentHash) return no("хеш каталога не совпал с хешем из запроса", "mismatch");
    const base = this.db
      .prepare(`SELECT * FROM approvals WHERE plugin_id = ? AND source_id = ? AND revoked_at IS NULL AND rights IS NOT NULL ORDER BY id DESC LIMIT 1`)
      .get(req.pluginId, ident!.id) as Raw | undefined;
    if (!base) return no("нет одобренной версии этого плагина из этого источника", "first");
    if (ev.blocks.length > 0) return no(`жёсткий флаг: ${brief(ev.blocks)}`, "block");
    const baseline = approvalOf(base);
    const g = grown(baseline.rights!, ev.rights);
    if (g.tokens.length > 0) return no(`новое право: ${brief(g.tokens)}`, "growth");
    if (g.review.length > 0) return no(`новое замечание проверок: ${brief(g.review)}`, "growth");
    const levelText = level === "own" ? "свой источник" : "известный источник";
    return { pass: true, rights: ev.rights, detail: { why: `прошла сама: ${levelText}, права те же`, level, entry, mode, baseline: { approval: baseline.id, version: baseline.version, source: baseline.sourceId }, rights: ev.rights.tokens.length } };
  }
}
