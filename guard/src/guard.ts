// The guard's decisions. Pure logic over the database and an injected clock: no sockets here (server.ts),
// no terminal here (cli.ts). Everything that changes state happens in one transaction together with its
// journal record, and the journal head file is rewritten right after the commit.
//
// Two kinds of requests (design doc, "Сокет и протокол"):
//  - without a secret (any process of the bb user can send them, including a harmful plugin, so they may
//    decide nothing a human has not already decided): decide, state, lookup, annotate, close-window, revoke, dismiss (held entries only);
//  - with a touch (a TOTP code): approve, open-window, policy, touch.
// The TOTP secret is only ever written by `sbb-guard totp-register` on the console, and is never returned
// by anything in this file. A touch is either a TOTP code or a passkey signature over a challenge the guard issued for exactly
// that action (see "Passkeys" below); passkeys are registered only through the console (`sbb-guard passkey-enroll`).
//
// This file is the front: `Guard` is the class everyone knows, built from layers (guard-base.ts → agents-plan.ts → guard-actions.ts → factor.ts → windows.ts → queue.ts → decide.ts → agents-watch.ts
// → agents-apply.ts), each below the next and calling only what is below it. What it adds itself is `state()`, the one view that reads every layer.

import { readHead } from "./journal.ts";
import { type QueueRow, type Raw, approvalOf, queueOf, windowOf } from "./guard-types.ts";
import { AgentsApplyGuard } from "./agents-apply.ts";

// Approval sessions: the numbers, the table of what a session covers and `isRoutineAction` are in session-rules.ts (the plugin takes them from there).
export { SESSION_CAP_MS, SESSION_IDLE_MS, ROUTINE_TOUCH_PURPOSES, isRoutineAction } from "./session-rules.ts";
export { GuardError, HOUR_MS, MAX_FAILURES, PASSKEY_FAIL_LOG_EVERY_MS, BATCH_TTL_MS, MAX_TROUBLESHOOT_MIN, ENROLL_WINDOW_MS, SETUP_CHECK_PURPOSE, CHALLENGE_TTL_MS, PLUGIN_ALIVE_MS, WINDOW_PAUSED_NOTE, DEFAULT_POLICY, str, pluginIdOf, hashOf, intOf } from "./guard-types.ts";
export { AGENTS_SCAN_GAP_MS } from "./agents-watch.ts";
export type { GuardErrorCode, Policy, DecideInput, Decision, ApprovalRow, QueueRow, WindowRow, GuardOptions, TrustConfig, Evaluation, AgentsConfig, Proof, Factor, PasskeyRow, ImportItem } from "./guard-types.ts";

export class Guard extends AgentsApplyGuard {
  state(): Record<string, unknown> {
    const now = this.now();
    const rows = <T>(sql: string, map: (r: Raw) => T, ...args: Array<string | number>): T[] => (this.db.prepare(sql).all(...args) as Raw[]).map(map);
    const notes = new Map((this.db.prepare(`SELECT content_hash, ts, findings FROM annotations`).all() as Array<{ content_hash: string; ts: number; findings: string }>).map((a) => [a.content_hash, a]));
    const withNotes = (q: QueueRow) => {
      const a = notes.get(q.contentHash);
      // Supplied by the plugin, which a harmful plugin can lie through: shown as "unverified", never used to decide.
      return { ...q, annotation: a ? { ts: a.ts, findings: JSON.parse(a.findings) as unknown, verified: false } : null };
    };
    const head = readHead(this.db);
    const blockedUntil = this.blockedUntil();
    return {
      now,
      totp: { registered: this.totpRegistered(), disabled: this.totpDisabled(), blockedUntil },
      sessions: this.openSessions().map((r) => ({ id: Number(r.id), openedAt: Number(r.opened_at), expiresAt: Number(r.expires_at), hardExpiresAt: Number(r.hard_expires_at), uses: Number(r.uses) })),
      troubleshoot: this.troubleshootUntil() > 0 ? { until: this.troubleshootUntil() } : null,
      maintenance: this.maintenanceWindows(),
      passkeys: {
        rpId: this.rp.rpId,
        origin: this.rp.origin,
        keys: this.listPasskeys()
          .filter((k) => k.state === "active")
          .map((k) => ({ id: k.id, label: k.label, createdAt: k.createdAt, lastUsedAt: k.lastUsedAt, aaguid: k.aaguid })),
        enrollmentOpen: this.openEnrollment() !== undefined,
      },
      policy: this.policy(),
      trust: this.trustState(),
      queue: rows(`SELECT * FROM queue ORDER BY (status = 'held') DESC, id DESC LIMIT 100`, queueOf).map(withNotes),
      approvals: rows(`SELECT * FROM approvals WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 500`, approvalOf),
      revoked: rows(`SELECT * FROM approvals WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC LIMIT 20`, approvalOf),
      windows: this.unclosedWindows()
        .filter((w) => now < w.expiresAt && now < w.hardExpiresAt)
        .map((w) => ({ ...w, remainingSec: Math.max(0, Math.floor((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000)) })),
      closedWindows: rows(`SELECT * FROM windows WHERE closed_at IS NOT NULL ORDER BY id DESC LIMIT 10`, windowOf),
      journal: {
        head: head ? { id: head.id, hash: head.hash } : null,
        recent: (this.db.prepare(`SELECT id, ts, kind, plugin_id, content_hash, detail FROM journal ORDER BY id DESC LIMIT 200`).all() as Raw[]).map((r) => ({
          id: Number(r.id),
          ts: Number(r.ts),
          kind: String(r.kind),
          pluginId: (r.plugin_id as string | null) ?? null,
          contentHash: (r.content_hash as string | null) ?? null,
          detail: r.detail === null ? null : (JSON.parse(String(r.detail)) as unknown),
        })),
      },
    };
  }
}
