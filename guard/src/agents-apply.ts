// Putting the agents' files back: restore, and the parts of a settings file («Оставить» / «Вернуть» / «Отозвать»).
// The scan and the list of differences are agents-watch.ts; the touch for each action is checked in factor.ts.
import { sha256 } from "./passkey.ts";
import { applyPathChange } from "./restore.ts";
import { helperUp, sendRestore } from "./restore-client.ts";
import { applyForward, partAction, partRestorable, rollbackDanger, type JsonPart } from "./json-parts.ts";
import { GuardError, sha256hex, type Raw, str, intOf, factorDetail } from "./guard-types.ts";
import { AgentsWatchGuard } from "./agents-watch.ts";

export class AgentsApplyGuard extends AgentsWatchGuard {
  /**
   * «Вернуть как было»: a fresh touch, then the helper puts the baseline's file back (or removes a file the baseline does not have), then the file
   * is looked at again at once, so that the alarm goes by itself. Everything is in the journal: what was, what became, who touched.
   */
  async agentsRestore(raw: Record<string, unknown>): Promise<{ restored: true; action: "write" | "delete" | "json"; result: string; resolved: boolean; path: string; rel: string }> {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const socket = this.agents.restore?.socket;
    const id = intOf(raw.id, "id", 1, Number.MAX_SAFE_INTEGER);
    // Everything that can be checked without a code is checked first, so that a spent code is not wasted on a refusal.
    const [before] = this.openDrifts([id]);
    const plan0 = this.restorePlan(before!);
    if (!plan0.ok) throw new GuardError("no_restore", plan0.reason);
    if (!(await helperUp(socket!, this.agents.restore?.timeoutMs))) throw new GuardError("unavailable", "помощник отката не отвечает (служба sbb-restore не запущена или сокет недоступен): ничего не записано, код не потрачен");
    const factor = this.verifyFactor("agents.restore", this.normalizeAction({ op: "agents-restore", id }), raw);
    // The difference may have moved on while we waited for the helper: what is done is what the baseline says NOW, for a difference that is still open.
    const [d] = this.openDrifts([id]);
    const plan = this.restorePlan(d!);
    if (!plan.ok) throw new GuardError("no_restore", plan.reason);
    const path = String(d!.path);
    const timeoutMs = this.agents.restore?.timeoutMs;
    const detail: Record<string, unknown> = { drift: id, path, rel: String(d!.rel), kind: String(d!.kind), change: String(d!.change), class: String(d!.class), action: plan.action, was: d!.new_sha === null || d!.new_sha === undefined ? null : String(d!.new_sha).slice(0, 16), becomes: plan.action === "delete" ? null : plan.sha.slice(0, 16) };
    let ans: Awaited<ReturnType<typeof sendRestore>>;
    if (plan.action === "json") {
      // One section at a time, each by its own key and each from the baseline's view; the first refusal stops the rest.
      detail.sections = plan.ops!.map((o) => o.key.slice(1, -1).join("") || "mcpServers");
      ans = { ok: true, result: "written" };
      for (const o of plan.ops!) {
        ans = await sendRestore(socket!, o.value === null ? { op: "restore-json-key", path, key: o.key, sha256: o.sha, delete: true } : { op: "restore-json-key", path, key: o.key, sha256: o.sha, value: o.value }, timeoutMs);
        if (!ans.ok) break;
      }
    } else ans = await sendRestore(socket!, plan.action === "delete" ? { path, sha256: plan.sha, delete: true } : { path, sha256: plan.sha, content: plan.content! }, timeoutMs);
    if (!ans.ok) {
      this.tx(() => this.log("agents.restore.fail", null, null, { ...detail, error: ans.code, message: ans.message.slice(0, 200), ...factorDetail(factor) }));
      throw new GuardError(ans.code === "unavailable" ? "unavailable" : "restore_failed", ans.code === "unavailable" ? "помощник отката не ответил: файл не изменён" : `помощник отказал: ${ans.message}`);
    }
    // Looked at again at once (not at the pace of the timer).
    this.agentsScan({ force: true });
    const now = this.db.prepare(`SELECT status FROM agent_drifts WHERE id = ?`).get(id) as { status: string } | undefined;
    const resolved = now !== undefined && now.status !== "open";
    this.tx(() => this.log("agents.restore", null, null, { ...detail, result: ans.result, resolved, ...factorDetail(factor) }));
    return { restored: true, action: plan.action, result: ans.result, resolved, path, rel: String(d!.rel) };
  }
  /**
   * A difference of a settings file that is left with no part: the file says the same as the approved text, only written another way (a final newline,
   * the order of keys). Nothing is left to decide, so it is recorded as the approved text and closed — never an alarm that has nothing in it.
   */
  protected settleSemantic(path: string): void {
    const d = this.db.prepare(`SELECT * FROM agent_drifts WHERE path = ? AND status = 'open'`).get(path) as Raw | undefined;
    if (!d) return;
    const parts = this.partsOf(d);
    if (parts === null || parts.length > 0) return;
    this.tx(() => {
      const now = this.now();
      this.db
        .prepare(`INSERT INTO agent_baseline (path, root, rel, kind, sha256, size, content, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET sha256 = excluded.sha256, size = excluded.size, content = excluded.content, accepted_at = excluded.accepted_at`)
        .run(String(d.path), String(d.root), String(d.rel), String(d.kind), String(d.new_sha), Number(d.new_size ?? 0), String(d.new_content), now);
      this.db.prepare(`UPDATE agent_drifts SET status = 'reverted', resolved_at = ? WHERE id = ?`).run(now, Number(d.id));
    });
  }
  /**
   * «Отозвать» a part that was kept: it goes out of the file (the helper, for this one path) and out of the approved text. Tightening, so no code. What was kept
   * is only what the owner chose with a touch; taking it back needs none, as taking back a window or an approval needs none.
   */
  async agentsRevokeKept(raw: Record<string, unknown>): Promise<{ revoked: true; inFile: boolean }> {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const socket = this.agents.restore?.socket;
    if (socket === undefined) throw new GuardError("no_restore", "помощник отката не настроен у сторожа: вернуть можно только вручную");
    const id = intOf(raw.id, "id", 1, Number.MAX_SAFE_INTEGER);
    const k = this.db.prepare(`SELECT * FROM agent_kept WHERE id = ? AND revoked_at IS NULL`).get(id) as Raw | undefined;
    if (!k) throw new GuardError("not_found", `no kept change #${id}`);
    const part = JSON.parse(String(k.part)) as JsonPart;
    const path = String(k.path);
    if (!partRestorable(part)) throw new GuardError("no_restore", "эту часть помощник не возвращает: вернуть можно только вручную");
    if (!(await helperUp(socket, this.agents.restore?.timeoutMs))) throw new GuardError("unavailable", "помощник отката не отвечает (служба sbb-restore не запущена или сокет недоступен): ничего не записано");
    // Taking back a kept ban (deny, ask, the sandbox) weakens the agent: a fresh touch, as for any other weakening.
    const revokeDanger = rollbackDanger(part);
    const factor = revokeDanger === null ? null : this.verifyFactor("agents.revokeKept", this.normalizeAction({ op: "agents-revoke-kept", id }), raw);
    this.agentsScan({ force: true });
    // The file as the guard sees it now: the open difference's hash, or the approved one when the file is as approved.
    const open = this.db.prepare(`SELECT * FROM agent_drifts WHERE path = ? AND status = 'open'`).get(path) as Raw | undefined;
    const base = this.db.prepare(`SELECT * FROM agent_baseline WHERE path = ?`).get(path) as Raw | undefined;
    const fileSha = open ? (open.new_sha === null ? null : String(open.new_sha)) : base ? String(base.sha256) : null;
    const back = partAction(part, "rollback");
    let inFile = false;
    if (fileSha !== null) {
      const ans = await sendRestore(socket, { op: "restore-json-path", path, fileSha256: fileSha, pointer: part.path, action: back.action, ...(back.action === "delete" ? {} : { value: back.value }) }, this.agents.restore?.timeoutMs);
      if (!ans.ok) {
        this.tx(() => this.log("agents.revoke-kept.fail", null, null, { kept: id, path, part: part.path.join("."), error: ans.code, message: ans.message.slice(0, 200) }));
        if (ans.code === "stale") throw new GuardError("conflict", "the file changed since it was shown: look again");
        throw new GuardError(ans.code === "unavailable" ? "unavailable" : "restore_failed", ans.code === "unavailable" ? "помощник отката не ответил: файл не изменён" : `помощник отказал: ${ans.message}`);
      }
      inFile = ans.result !== "absent";
    }
    this.tx(() => {
      // Out of the approved text too, or the file (without it) would show as a difference of its own.
      if (base) {
        const text = (base.content as string | null) ?? null;
        if (text !== null && sha256hex(text) === String(base.sha256)) {
          const doc = ((): Record<string, unknown> | null => {
            try {
              const v = JSON.parse(text) as unknown;
              return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
            } catch {
              return null;
            }
          })();
          if (doc) {
            applyPathChange(doc, part.path, back.action, back.value);
            const next = `${JSON.stringify(doc, null, 2)}\n`;
            this.db.prepare(`UPDATE agent_baseline SET sha256 = ?, size = ?, content = ?, accepted_at = ? WHERE path = ?`).run(sha256hex(next), Buffer.byteLength(next, "utf8"), next, this.now(), path);
          }
        }
      }
      this.db.prepare(`UPDATE agent_kept SET revoked_at = ? WHERE id = ?`).run(this.now(), id);
      this.log("agents.revoke-kept", null, null, { kept: id, path, rel: String(k.rel), part: part.path.join("."), kind: part.kind, inFile, ...(factor ? factorDetail(factor) : {}) });
    });
    this.agentsScan({ force: true });
    this.settleSemantic(path);
    return { revoked: true, inFile };
  }
  /**
   * «Вернуть» one part: the helper takes this one change out of the file and leaves the rest. Tightening (what comes back is the approved state), so no
   * code. Only a part of an OPEN difference, only on a path the helper edits, and only against the file the page showed (`fileSha`) — the helper checks
   * the hash of the whole file again, so that a change that came in between is never overwritten.
   */
  async agentsRollbackPart(raw: Record<string, unknown>): Promise<{ restored: true; resolved: boolean; remaining: number; path: string; rel: string }> {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const socket = this.agents.restore?.socket;
    if (socket === undefined) throw new GuardError("no_restore", "помощник отката не настроен у сторожа: вернуть можно только вручную");
    const id = intOf(raw.id, "id", 1, Number.MAX_SAFE_INTEGER);
    const partId = str(raw.partId, "partId", 16, 16);
    const fileSha = str(raw.fileSha, "fileSha", 16, 16);
    // The file as it is right now (not as it was at the last timer).
    this.agentsScan({ force: true });
    const { drift: d, part, danger } = this.partOf(id, partId, fileSha);
    if (!partRestorable(part)) throw new GuardError("no_restore", "эту часть помощник не возвращает: вернуть можно только весь файл");
    if (!(await helperUp(socket, this.agents.restore?.timeoutMs))) throw new GuardError("unavailable", "помощник отката не отвечает (служба sbb-restore не запущена или сокет недоступен): ничего не записано");
    // Without a code only a tightening: when the result makes the agent more dangerous (a rule the owner removed comes back, a ban goes), a fresh touch is needed.
    const backDanger = rollbackDanger(part);
    const factor = backDanger === null ? null : this.verifyFactor("agents.rollbackPart", this.normalizeAction({ op: "agents-rollback-part", id, partId, fileSha }), raw);
    const a = partAction(part, "rollback");
    const path = String(d.path);
    const fileSha256 = String(d.new_sha);
    const ans = await sendRestore(socket, { op: "restore-json-path", path, fileSha256, pointer: part.path, action: a.action, ...(a.action === "delete" ? {} : { value: a.value }) }, this.agents.restore?.timeoutMs);
    const detail = { drift: id, path, rel: String(d.rel), part: part.path.join("."), kind: part.kind, action: a.action, danger: danger !== null, backDanger: backDanger !== null, ...(factor ? factorDetail(factor) : {}), was: fileSha256.slice(0, 16) };
    if (!ans.ok) {
      this.tx(() => this.log("agents.rollback-part.fail", null, null, { ...detail, error: ans.code, message: ans.message.slice(0, 200) }));
      // The file is not the one the part was worked out from: nothing was written and the page draws again.
      if (ans.code === "stale") throw new GuardError("conflict", "the file changed since it was shown: look again");
      throw new GuardError(ans.code === "unavailable" ? "unavailable" : "restore_failed", ans.code === "unavailable" ? "помощник отката не ответил: файл не изменён" : `помощник отказал: ${ans.message}`);
    }
    this.agentsScan({ force: true });
    this.settleSemantic(path);
    // Resolved: nothing of this file is left to decide.
    const rest = this.db.prepare(`SELECT * FROM agent_drifts WHERE path = ? AND status = 'open'`).get(path) as Raw | undefined;
    const remaining = rest ? (this.partsOf(rest)?.length ?? 1) : 0;
    const resolved = rest === undefined;
    this.tx(() => this.log("agents.rollback-part", null, null, { ...detail, result: ans.result, resolved, remaining }));
    return { restored: true, resolved, remaining, path, rel: String(d.rel) };
  }
  /**
   * «Оставить» one part: it goes into the approved text of the file; the rest stays a difference. A touch: a code or a key for a part that makes the agent
   * more dangerous (bypass, a shell or network permission, a hook, `env`…), and for the rest a session is enough. Nothing is written to the agents' file.
   */
  agentsKeepPart(raw: Record<string, unknown>): { kept: true; accepted: boolean; remaining: number; danger: boolean } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const id = intOf(raw.id, "id", 1, Number.MAX_SAFE_INTEGER);
    const partId = str(raw.partId, "partId", 16, 16);
    const fileSha = str(raw.fileSha, "fileSha", 16, 16);
    this.agentsScan({ force: true });
    // Everything that can be checked without a code is checked first, so that a spent code is not wasted on a refusal.
    const first = this.partOf(id, partId, fileSha);
    const dangerous = first.danger !== null;
    if (raw.danger !== undefined && raw.danger !== dangerous) throw new GuardError("conflict", "the part is not what the page showed: look again");
    const factor = this.verifyFactor("agents.keepPart", this.normalizeAction({ op: "agents-keep-part", id, partId, fileSha, danger: dangerous }), raw);
    const result = this.tx(() => {
      // Again, inside the transaction: the difference may have moved while the code was being checked.
      const { drift: d, part, parts } = this.partOf(id, partId, fileSha);
      const base = this.baselineText(d);
      const approved = base === undefined ? null : applyForward(base, part);
      if (approved === null) throw new GuardError("no_restore", "этот файл нельзя разобрать по частям: принять можно только целиком");
      const now = this.now();
      const done = parts.length === 1;
      // The last part: the file as it is becomes the approved one (what is kept is exactly what was seen). Otherwise a new approved text with this part in it.
      const content = done ? String(d.new_content) : approved;
      const sha = done ? String(d.new_sha) : sha256hex(content);
      this.db
        .prepare(`INSERT INTO agent_baseline (path, root, rel, kind, sha256, size, content, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET root = excluded.root, rel = excluded.rel, kind = excluded.kind, sha256 = excluded.sha256, size = excluded.size, content = excluded.content, accepted_at = excluded.accepted_at`)
        .run(String(d.path), String(d.root), String(d.rel), String(d.kind), sha, Buffer.byteLength(content, "utf8"), content, now);
      // The old difference is closed; the next look at the file makes the difference that is left (or finds none).
      this.db.prepare(`UPDATE agent_drifts SET status = ?, resolved_at = ? WHERE id = ?`).run(done ? "accepted" : "superseded", now, id);
      this.db.prepare(`INSERT INTO agent_kept (path, rel, part, danger, kept_at) VALUES (?, ?, ?, ?, ?)`).run(String(d.path), String(d.rel), JSON.stringify(part), first.danger === null ? null : first.danger.slice(0, 300), now);
      this.log("agents.keep-part", null, null, { drift: id, path: String(d.path), rel: String(d.rel), part: part.path.join("."), kind: part.kind, danger: dangerous, reason: first.danger === null ? null : first.danger.slice(0, 200), remaining: parts.length - 1, ...factorDetail(factor) });
      return { accepted: done, remaining: parts.length - 1 };
    });
    // The file is looked at again at once: what is left of the difference is drawn from the new approved text.
    this.agentsScan({ force: true });
    this.settleSemantic(first.path);
    return { kept: true, accepted: result.accepted, remaining: result.remaining, danger: dangerous };
  }
}
