// The agent watch, the guard's side: scanning the agents' files, the drifts found, accepting and rejecting them.
// Putting a file back and the parts of a settings file are agents-apply.ts.
import { lstatSync } from "node:fs";
import { basename } from "node:path";
import { sha256 } from "./passkey.ts";
import { analyze as analyzeAgents, maskSecrets, unifiedDiff, type Change } from "./agents-rules.ts";
import { scan as scanAgents, type FileKind, type ScanResult } from "./agents-scan.ts";
import { viewPart } from "./json-parts.ts";
import { GuardError, type Raw, type AgentsConfig, factorDetail } from "./guard-types.ts";
import { DecideGuard } from "./decide.ts";

/** Agent watch: a scan asked for over the socket runs at most once in this time; the differences kept open; ids in one touch. */
export const AGENTS_SCAN_GAP_MS = 10_000;

export const MAX_OPEN_DRIFTS = 1000;

/** Is a file that the walk did not see really gone (ENOENT), or can it not be looked at (no access)? Anything else: leave it alone. */
export function fileGone(path: string): "gone" | "denied" | "present" {
  try {
    lstatSync(path);
    return "present";
  } catch (e) {
    const code = (e as { code?: string }).code;
    return code === "ENOENT" || code === "ENOTDIR" ? "gone" : code === "EACCES" || code === "EPERM" ? "denied" : "present";
  }
}

export const rootKindOf = (cfg: AgentsConfig, root: string): string => (root === cfg.home ? "global" : cfg.extraRoots.includes(root) ? "extra" : "workspace");


export class AgentsWatchGuard extends DecideGuard {
  agentsEnabled(): boolean {
    return this.agents !== null;
  }
  /** One pass over the files. `force` skips the rate limit (the timer of `serve` and tests); a request is served at most once in AGENTS_SCAN_GAP_MS. */
  agentsScan(opts: { force?: boolean } = {}): { scanned: boolean; throttled: boolean; at: number } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const t = this.now();
    if (!opts.force && this.lastAgentsScan !== 0 && t - this.lastAgentsScan < AGENTS_SCAN_GAP_MS) return { scanned: false, throttled: true, at: this.lastAgentsScan };
    this.lastAgentsScan = t;
    const res = scanAgents({ home: this.agents.home, extraRoots: this.agents.extraRoots, ...(this.agents.limits ? { limits: this.agents.limits } : {}), deny: [this.secretDir, this.headDir, ...(this.agents.deny ?? [])], ...(this.agents.hooks ? { hooks: this.agents.hooks } : {}) });
    this.tx(() => this.reconcileAgents(res));
    return { scanned: true, throttled: false, at: t };
  }
  protected reconcileAgents(res: ScanResult): void {
    const now = this.now();
    const first = this.meta("agents_first_scan") === null;
    const baseline = new Map((this.db.prepare(`SELECT * FROM agent_baseline`).all() as Raw[]).map((r) => [String(r.path), r]));
    const open = new Map((this.db.prepare(`SELECT * FROM agent_drifts WHERE status = 'open'`).all() as Raw[]).map((r) => [String(r.path), r]));
    const alarms = [...res.alarms];
    const fresh: Array<{ id: number; path: string; rel: string; rootKind: string; root: string; cls: string; change: string; reasons: string[] }> = [];
    const counts = { added: 0, changed: 0, removed: 0, critical: 0, instructions: 0, other: 0 };
    let openCount = open.size;
    let capped = false;

    const close = (d: Raw, status: "reverted" | "superseded"): void => {
      this.db.prepare(`UPDATE agent_drifts SET status = ?, resolved_at = ? WHERE id = ?`).run(status, now, Number(d.id));
      open.delete(String(d.path));
      openCount--;
    };
    const create = (o: { path: string; root: string; rootKind: string; rel: string; kind: FileKind; change: Change; prev: string | null; oldSha: string | null; next: string | null; newSha: string | null; size: number | null; mtime: number | null }): void => {
      if (openCount >= MAX_OPEN_DRIFTS) {
        capped = true;
        return;
      }
      let a = analyzeAgents({ rel: o.rel, kind: o.kind, change: o.change, next: o.next, prev: o.prev });
      if (o.change !== "removed" && o.next === null) {
        // Too large to keep or to read in full: it cannot be judged, which is itself the reason (a config is held to the strict side).
        a = o.kind === "instructions" ? { cls: "instructions", reasons: [], findings: [{ rule: "too-large", severity: "review", file: o.rel, line: 0, excerpt: "файл слишком велик, чтобы разобрать его целиком" }] } : { cls: "critical", reasons: ["файл слишком велик для разбора: проверить вручную"], findings: [] };
      }
      const diff = o.change === "removed" ? unifiedDiff(o.prev, null) : o.next === null || (o.change === "changed" && o.prev === null && o.oldSha !== null) ? "(содержимое слишком велико для показа)" : unifiedDiff(o.prev, o.next);
      const info = this.db
        .prepare(`INSERT INTO agent_drifts (path, root, root_kind, rel, kind, change, class, reasons, findings, old_sha, new_sha, new_size, new_mtime, diff, new_content, initial, status, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`)
        .run(o.path, o.root, o.rootKind, o.rel, o.kind, o.change, a.cls, JSON.stringify(a.reasons), JSON.stringify(a.findings), o.oldSha, o.newSha, o.size, o.mtime, diff, o.next, first ? 1 : 0, now, now);
      openCount++;
      counts[o.change]++;
      counts[a.cls]++;
      if (a.cls === "critical" && !first) fresh.push({ id: Number(info.lastInsertRowid), path: o.path, rel: o.rel, rootKind: o.rootKind, root: o.root, cls: a.cls, change: o.change, reasons: a.reasons });
    };

    for (const o of res.observed.values()) {
      const b = baseline.get(o.path);
      const d = open.get(o.path);
      if (b && String(b.sha256) === o.sha256) {
        if (d) close(d, "reverted");
        continue;
      }
      const change: Change = b ? "changed" : "added";
      if (d && String(d.new_sha) === o.sha256 && String(d.change) === change) {
        this.db.prepare(`UPDATE agent_drifts SET last_seen = ? WHERE id = ?`).run(now, Number(d.id));
        continue;
      }
      if (d) close(d, "superseded");
      create({ path: o.path, root: o.root, rootKind: o.rootKind, rel: o.rel, kind: o.kind, change, prev: b ? ((b.content as string | null) ?? null) : null, oldSha: b ? String(b.sha256) : null, next: o.content, newSha: o.sha256, size: o.size, mtime: Math.round(o.mtimeMs) });
    }

    // A baseline file that was not seen has gone only if the file system says so; a file the walk did not reach (a limit) or cannot open is not "removed".
    for (const [path, b] of baseline) {
      if (res.observed.has(path)) continue;
      const gone = fileGone(path);
      if (gone === "denied") {
        // One alarm for the directory that cannot be entered says it all; each file under it would only repeat it.
        if (!alarms.some((a) => path.startsWith(`${a.path}/`))) alarms.push({ path, kind: "unreadable", error: "EACCES" });
        continue;
      }
      if (gone !== "gone") continue;
      const d = open.get(path);
      if (d && String(d.change) === "removed") {
        this.db.prepare(`UPDATE agent_drifts SET last_seen = ? WHERE id = ?`).run(now, Number(d.id));
        continue;
      }
      if (d) close(d, "superseded");
      create({ path, root: String(b.root), rootKind: rootKindOf(this.agents!, String(b.root)), rel: String(b.rel), kind: String(b.kind) as FileKind, change: "removed", prev: (b.content as string | null) ?? null, oldSha: String(b.sha256), next: null, newSha: null, size: null, mtime: null });
    }
    // An addition that disappeared before anybody looked: nothing to decide any more.
    for (const [path, d] of open) if (!res.observed.has(path) && !baseline.has(path) && String(d.change) === "added" && fileGone(path) === "gone") close(d, "reverted");

    // ---- consequences (v1: signals) ----
    if (first) this.log("agents.first-scan", null, null, { files: res.observed.size, roots: res.roots, drifts: counts.added });
    else if (counts.added + counts.changed + counts.removed > 0) this.log("agents.drift", null, null, { ...counts });
    if (fresh.length > 0) {
      // A critical change closes the windows of trust, as pollution does (the plugin also marks the thread whose working directory it is).
      let closed = 0;
      for (const w of this.unclosedWindows()) (this.closeWindowInner(w, "agents-critical"), closed++);
      for (const f of fresh.slice(0, 20)) this.log("agents.critical", null, null, { drift: f.id, path: f.path, rel: f.rel, rootKind: f.rootKind, change: f.change, reasons: f.reasons.slice(0, 5), windowsClosed: closed });
    }
    if (capped) this.log("agents.flood", null, null, { limit: MAX_OPEN_DRIFTS });

    // ---- alarms and notes: remembered for the page; a change in the set of alarms is journaled ----
    const sig = alarms.map((a) => `${a.path}\0${a.error}`).sort().join("\n");
    if (sig !== (this.meta("agents_alarm_sig") ?? "")) {
      this.setMeta("agents_alarm_sig", sig);
      this.log(alarms.length > 0 ? "agents.alarm" : "agents.alarm.clear", null, null, { count: alarms.length, paths: alarms.slice(0, 10).map((a) => ({ path: a.path, error: a.error })) });
    }
    const notes = capped ? [...res.notes, { kind: "limit", text: `открытых расхождений больше ${MAX_OPEN_DRIFTS}: новые не записываются, пока их не рассмотрят` }] : res.notes;
    this.setMeta("agents_last", JSON.stringify({ at: now, files: res.observed.size, roots: res.roots, alarms: alarms.slice(0, 100), notes: notes.slice(0, 50) }));
    if (first) this.setMeta("agents_first_scan", String(now));
    this.db.prepare(`DELETE FROM agent_drifts WHERE status != 'open' AND id NOT IN (SELECT id FROM agent_drifts ORDER BY id DESC LIMIT 2000)`).run();
  }
  /** What the page reads: the differences, the alarms, the notes. No secret: the diff and the excerpts are masked, the stored content never leaves. */
  agentsState(): Record<string, unknown> {
    if (this.agents === null) return { enabled: false };
    const last = ((): Record<string, unknown> | null => {
      const raw = this.meta("agents_last");
      try {
        return raw === null ? null : (JSON.parse(raw) as Record<string, unknown>);
      } catch {
        return null;
      }
    })();
    const view = (r: Raw): Record<string, unknown> => ({
      id: Number(r.id),
      path: String(r.path),
      root: String(r.root),
      rootKind: String(r.root_kind),
      rootName: basename(String(r.root)),
      rel: String(r.rel),
      kind: String(r.kind),
      change: String(r.change),
      class: String(r.class),
      reasons: JSON.parse(String(r.reasons)) as string[],
      findings: (JSON.parse(String(r.findings)) as Array<Record<string, unknown>>).map((f) => ({ ...f, excerpt: maskSecrets(String(f.excerpt ?? "")) })),
      oldSha: r.old_sha === null ? null : String(r.old_sha).slice(0, 16),
      newSha: r.new_sha === null ? null : String(r.new_sha).slice(0, 16),
      size: r.new_size === null ? null : Number(r.new_size),
      mtime: r.new_mtime === null ? null : Number(r.new_mtime),
      diff: String(r.diff),
      initial: Number(r.initial) === 1,
      status: String(r.status),
      firstSeen: Number(r.first_seen),
      lastSeen: Number(r.last_seen),
      resolvedAt: r.resolved_at === null ? null : Number(r.resolved_at),
      rejected: r.rejected_at !== null && r.rejected_at !== undefined,
      rejectedAt: r.rejected_at === null || r.rejected_at === undefined ? null : Number(r.rejected_at),
      // What «Вернуть как было» would do, or why it cannot be done (the page shows the manual way then).
      ...(String(r.status) === "open" ? { restorable: ((p) => (p.ok ? { ok: true, action: p.action } : { ok: false, reason: p.reason }))(this.restorePlan(r)) } : {}),
      // A settings file's difference split by the path inside the JSON (null: it cannot be split; the whole file is the only choice).
      ...(String(r.status) === "open" ? { parts: this.partsOf(r)?.map(viewPart) ?? null } : {}),
    });
    const rank = `CASE class WHEN 'critical' THEN 0 WHEN 'instructions' THEN 1 ELSE 2 END`;
    const open = (this.db.prepare(`SELECT * FROM agent_drifts WHERE status = 'open' ORDER BY ${rank}, id DESC LIMIT 500`).all() as Raw[]).map(view);
    const recent = (this.db.prepare(`SELECT * FROM agent_drifts WHERE status != 'open' ORDER BY id DESC LIMIT 20`).all() as Raw[]).map(view);
    const baselineFiles = (this.db.prepare(`SELECT COUNT(*) AS n FROM agent_baseline`).get() as { n: number }).n;
    const total = (this.db.prepare(`SELECT COUNT(*) AS n FROM agent_drifts WHERE status = 'open'`).get() as { n: number }).n;
    return {
      enabled: true,
      home: this.agents.home,
      extraRoots: this.agents.extraRoots,
      restoreConfigured: this.agents.restore !== undefined,
      lastScanAt: (last?.at as number | undefined) ?? null,
      scannedFiles: (last?.files as number | undefined) ?? 0,
      roots: (last?.roots as number | undefined) ?? 0,
      baselineFiles,
      // The first baseline: the first scan's differences, until a human accepts them as they are.
      initial: { pending: open.filter((d) => d.initial === true).length, baselineAt: this.meta("agents_first_scan") === null ? null : Number(this.meta("agents_first_scan")) },
      openTotal: total,
      drifts: open,
      recent,
      alarms: (last?.alarms as unknown[] | undefined) ?? [],
      notes: (last?.notes as unknown[] | undefined) ?? [],
      kept: this.keptParts(),
    };
  }

  // ---- putting a file back (design: secure-bb-agent-rollback-design.md) ----------------------------------------------------------
  // The guard only reads the agents' files. Writing is the job of the restore helper (restore.ts), a service of the agents' user whose socket only
  // the guard's user reaches. What the helper is told to write is the guard's OWN baseline, chosen by the id of a difference — never anything the
  // caller sends. A touch is needed (a code or a passkey, a session does not cover it): a harmful process of the bb user must not be able to
  // roll the owner's lawful changes back again and again.
  /**
   * «Это не я — отклонить»: marks open differences as rejected. Tightening, so no code: nothing goes into the baseline, the difference stays open
   * (the alarm, the polluted thread and the closed windows stay until the file itself is fixed), and the journal gets a record. The guard itself only reads the agents' files; putting one back is
   * «Вернуть как было» (`agentsRestore`, a touch), accepting is also possible later, with a touch.
   */
  agentsReject(raw: Record<string, unknown>): { rejected: number } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const ids = this.agentIds(raw.ids);
    return this.tx(() => {
      const rows = this.openDrifts(ids);
      const now = this.now();
      let n = 0;
      for (const r of rows) {
        if (r.rejected_at !== null && r.rejected_at !== undefined) continue;
        this.db.prepare(`UPDATE agent_drifts SET rejected_at = ? WHERE id = ?`).run(now, Number(r.id));
        n++;
      }
      this.log("agents.reject", null, null, { count: n, drifts: rows.slice(0, 50).map((r) => ({ id: Number(r.id), path: String(r.path), change: String(r.change), class: String(r.class) })) });
      return { rejected: n };
    });
  }
  /** Accepts differences into the baseline. A touch (a code or a passkey signature over exactly these ids), like `approve`. */
  agentsAccept(raw: Record<string, unknown>): { accepted: number } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const ids = this.agentIds(raw.ids);
    // Everything that can be checked without a code is checked first, so that a spent code is not wasted on a refusal.
    this.criticalAlone(this.openDrifts(ids));
    const factor = this.verifyFactor("agents.accept", this.normalizeAction({ op: "agents-accept", ids }), raw);
    return this.tx(() => {
      const rows = this.openDrifts(ids);
      const now = this.now();
      for (const r of rows) {
        if (String(r.change) === "removed") this.db.prepare(`DELETE FROM agent_baseline WHERE path = ?`).run(String(r.path));
        else
          this.db
            .prepare(`INSERT INTO agent_baseline (path, root, rel, kind, sha256, size, content, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET root = excluded.root, rel = excluded.rel, kind = excluded.kind, sha256 = excluded.sha256, size = excluded.size, content = excluded.content, accepted_at = excluded.accepted_at`)
            .run(String(r.path), String(r.root), String(r.rel), String(r.kind), String(r.new_sha), Number(r.new_size ?? 0), (r.new_content as string | null) ?? null, now);
        this.db.prepare(`UPDATE agent_drifts SET status = 'accepted', resolved_at = ? WHERE id = ?`).run(now, Number(r.id));
      }
      const by = (c: string): number => rows.filter((r) => String(r.class) === c).length;
      this.log("agents.accept", null, null, { count: rows.length, critical: by("critical"), instructions: by("instructions"), other: by("other"), initial: rows.filter((r) => Number(r.initial) === 1).length, drifts: rows.slice(0, 50).map((r) => ({ id: Number(r.id), path: String(r.path), change: String(r.change), class: String(r.class) })), ...factorDetail(factor) });
      return { accepted: rows.length };
    });
  }
}
