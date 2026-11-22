// The queue of held versions and the approvals made from it: record, approve, dismiss, revoke, batch, trust lists, import.
// The decision on a request that arrives is decide.ts; this layer only keeps and changes what was decided.
import { randomBytes } from "node:crypto";
import { identityOf, liftBlock, MAX_SOURCES, MODE_RANK, normalizeEntry, TRUST_MODES, type ReasonKind, type Rights, type TrustMode } from "./trust.ts";
import { GuardError, HOUR_MS, BATCH_TTL_MS, MAX_PENDING_BATCHES, MAX_BATCH_ITEMS, sha256hex, MAX_HOLDS_PER_HOUR, MAX_QUEUE_ROWS, MAX_ANNOTATIONS, MAX_FINDINGS_BYTES, type DecideInput, type ApprovalRow, type QueueRow, type Raw, touchWhy, approvalOf, queueOf, str, pluginIdOf, hashOf, intOf, type Proof, factorDetail, type ImportItem, type NewApproval } from "./guard-types.ts";
import { WindowGuard } from "./windows.ts";

export class QueueGuard extends WindowGuard {
  // ---- approvals ----------------------------------------------------------
  /**
   * An approval of this version that covers the request. One made by the source rule is bound to (plugin, hash, source): it counts only for a
   * caller that names the same source (a hash alone does not say where the code came from), so without a source it never counts.
   */
  protected activeApproval(pluginId: string, contentHash: string, source: string | null = null): ApprovalRow | null {
    const rows = this.db.prepare(`SELECT * FROM approvals WHERE content_hash = ? AND plugin_id = ? AND revoked_at IS NULL ORDER BY id DESC`).all(contentHash, pluginId) as Raw[];
    return rows.map(approvalOf).find((a) => a.via !== "source" || (source !== null && a.source === source)) ?? null;
  }
  protected addApproval(i: NewApproval): ApprovalRow {
    const sourceId = identityOf(i.sourceKind, i.source)?.id ?? null;
    const rights = i.rights ?? null;
    const info = this.db
      .prepare(`INSERT INTO approvals (content_hash, plugin_id, version, source, source_kind, git_commit, npm_integrity, via, window_id, approved_at, source_id, rights, why) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(i.contentHash, i.pluginId, i.version, i.source, i.sourceKind, i.gitCommit, i.npmIntegrity, i.via, i.windowId, this.now(), sourceId, rights === null ? null : JSON.stringify(rights), i.why ?? null);
    return { ...i, rights, sourceId, why: i.why ?? null, id: Number(info.lastInsertRowid), approvedAt: this.now(), revokedAt: null };
  }
  protected resolveQueue(pluginId: string, contentHash: string, status: "approved" | "dismissed"): void {
    // Approving a version also undoes an earlier rejection of it by the person («Вернуть»); a rejection itself touches held entries only.
    const from = status === "approved" ? "('held', 'dismissed')" : "('held')";
    this.db.prepare(`UPDATE queue SET status = ? WHERE content_hash = ? AND plugin_id = ? AND status IN ${from}`).run(status, contentHash, pluginId);
  }
  /** A version the person rejected (dismissed) and has not brought back: no approval covers it. The core asks again at every start; the answer is "no" without a new entry. */
  protected isRejected(pluginId: string, contentHash: string): boolean {
    return this.db.prepare(`SELECT 1 FROM queue WHERE content_hash = ? AND plugin_id = ? AND status = 'dismissed' LIMIT 1`).get(contentHash, pluginId) !== undefined;
  }
  /** The repeated question about a rejected version goes to the journal once an hour per version, not at every ask. */
  protected logRepeatReject(pluginId: string, contentHash: string, version: string): void {
    const key = `rejected_logged:${pluginId}:${contentHash}`;
    if (Number(this.meta(key) ?? 0) > this.now() - HOUR_MS) return;
    this.setMeta(key, String(this.now()));
    this.log("reject.repeat", pluginId, contentHash, { version, note: "версия отклонена вами; плагин остаётся выключенным, пока вы не нажмёте «Вернуть» в Карантине" });
  }
  protected parseDecide(raw: Record<string, unknown>): DecideInput {
    return {
      pluginId: pluginIdOf(raw.pluginId),
      version: str(raw.version, "version", 128),
      contentHash: hashOf(raw.contentHash),
      rootDir: str(raw.rootDir, "rootDir", 4096),
      source: str(raw.source, "source", 2048),
      sourceKind: str(raw.sourceKind, "sourceKind", 64),
      trigger: str(raw.trigger, "trigger", 64),
    };
  }
  /** A version a window does not lift: some entry of it was kept with stop=1 and is held or was dismissed. Only a code (approve) lifts it. */
  protected isStopped(pluginId: string, contentHash: string): boolean {
    return this.db.prepare(`SELECT 1 FROM queue WHERE content_hash = ? AND plugin_id = ? AND status IN ('held', 'dismissed') AND stop = 1`).get(contentHash, pluginId) !== undefined;
  }
  /** The held entry of a version (made if there was none, unless too many were made this hour). `stop`: a window does not lift this hold. */
  protected upsertHeld(req: DecideInput, stop: boolean, why: { rights: Rights | null; note: string | null; kind?: ReasonKind | null; blocks?: string[] | null } = { rights: null, note: null }): { id: number | null; created: boolean } {
    const held = this.db.prepare(`SELECT * FROM queue WHERE content_hash = ? AND plugin_id = ? AND status = 'held' ORDER BY id DESC LIMIT 1`).get(req.contentHash, req.pluginId) as Raw | undefined;
    const rightsJson = why.rights === null ? null : JSON.stringify(why.rights);
    const blocksJson = why.blocks === null || why.blocks === undefined ? null : JSON.stringify(why.blocks);
    const kind = why.kind ?? null;
    if (held) {
      // The note and the rights are the guard's own latest reading; a call that could not read keeps the earlier one.
      this.db.prepare(`UPDATE queue SET last_seen = ?, seen_count = seen_count + 1, version = ?, source = ?, source_kind = ?, root_dir = ?, trigger = ?, stop = MAX(stop, ?), note = COALESCE(?, note), rights = COALESCE(?, rights), blocks = COALESCE(?, blocks), reason_kind = CASE WHEN reason_kind = 'mismatch' THEN reason_kind ELSE COALESCE(?, reason_kind) END WHERE id = ?`).run(this.now(), req.version, req.source, req.sourceKind, req.rootDir, req.trigger, stop ? 1 : 0, why.note, rightsJson, blocksJson, kind, Number(held.id));
      return { id: Number(held.id), created: false };
    }
    // A process that can talk to the guard must not be able to fill it: a flood of new holds is not recorded (one record says so).
    const recent = (this.db.prepare(`SELECT COUNT(*) AS n FROM queue WHERE first_seen > ?`).get(this.now() - HOUR_MS) as { n: number }).n;
    if (recent >= MAX_HOLDS_PER_HOUR) {
      if (Number(this.meta("flood_logged") ?? 0) < this.now() - HOUR_MS) {
        this.setMeta("flood_logged", String(this.now()));
        this.log("queue.flood", null, null, { limit: MAX_HOLDS_PER_HOUR });
      }
      return { id: null, created: false };
    }
    const info = this.db
      .prepare(`INSERT INTO queue (content_hash, plugin_id, version, source, source_kind, root_dir, trigger, status, first_seen, last_seen, stop, note, rights, blocks, reason_kind) VALUES (?, ?, ?, ?, ?, ?, ?, 'held', ?, ?, ?, ?, ?, ?, ?)`)
      .run(req.contentHash, req.pluginId, req.version, req.source, req.sourceKind, req.rootDir, req.trigger, this.now(), this.now(), stop ? 1 : 0, why.note, rightsJson, blocksJson, kind);
    const id = Number(info.lastInsertRowid);
    this.db.prepare(`DELETE FROM queue WHERE status != 'held' AND status != 'dismissed' AND id NOT IN (SELECT id FROM queue ORDER BY id DESC LIMIT ?)`).run(MAX_QUEUE_ROWS);
    this.log("hold", req.pluginId, req.contentHash, { review: id, version: req.version, trigger: req.trigger, source: req.source, sourceKind: req.sourceKind, ...(why.note !== null ? { note: why.note } : {}), ...(stop ? { stop: true } : {}) });
    return { id, created: true };
  }
  /** An approval that covers this request. One made by the source rule covers only the source it was made for (the hash alone does not say where the code came from). */
  protected coveringApproval(req: DecideInput): ApprovalRow | null {
    return this.activeApproval(req.pluginId, req.contentHash, req.source);
  }
  /** Read-only: is this version approved, is a window open, what is its queue entry. For the plugin's own hook. */
  lookup(raw: Record<string, unknown>): {
    approved: boolean;
    /** Who approved it: a window approval is the one a hook that holds the version for its own reasons withdraws (revoke, no code). */
    approval: { id: number; via: string; windowId: number | null } | null;
    window: { id: number; expiresAt: number; hardExpiresAt: number; mode: string; sizeSec: number } | null;
    requestId: number | null;
    /** Troubleshooting mode is on until this time (the plugin's hook passes too, and says so); 0: off. */
    troubleshootUntil: number;
    /** The person rejected this version and has not brought it back. */
    rejected: boolean;
  } {
    const pluginId = pluginIdOf(raw.pluginId);
    const contentHash = hashOf(raw.contentHash);
    const w = this.openWindowOf(pluginId);
    const a = this.activeApproval(pluginId, contentHash);
    const q = this.db.prepare(`SELECT id FROM queue WHERE content_hash = ? AND plugin_id = ? AND status = 'held' ORDER BY id DESC LIMIT 1`).get(contentHash, pluginId) as { id: number } | undefined;
    return {
      approved: a !== null,
      approval: a ? { id: a.id, via: a.via, windowId: a.windowId } : null,
      window: w ? { id: w.id, expiresAt: w.expiresAt, hardExpiresAt: w.hardExpiresAt, mode: w.mode, sizeSec: w.sizeSec } : null,
      requestId: q ? Number(q.id) : null,
      troubleshootUntil: this.troubleshootUntil(),
      rejected: a === null && this.isRejected(pluginId, contentHash),
    };
  }
  /** Check results of the plugin are attached to a queue entry. For display only: nothing here changes a decision. */
  annotate(raw: Record<string, unknown>): { ok: true } {
    let hash: string;
    if (raw.requestId !== undefined) {
      const q = this.db.prepare(`SELECT content_hash FROM queue WHERE id = ?`).get(intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER)) as { content_hash: string } | undefined;
      if (!q) throw new GuardError("not_found", "no such request");
      hash = q.content_hash;
    } else hash = hashOf(raw.contentHash);
    const text = JSON.stringify(raw.findings ?? null);
    if (text === undefined || Buffer.byteLength(text) > MAX_FINDINGS_BYTES) throw new GuardError("invalid", `findings must be JSON of at most ${MAX_FINDINGS_BYTES} bytes`);
    this.tx(() => {
      this.db.prepare(`INSERT INTO annotations (content_hash, ts, findings) VALUES (?, ?, ?) ON CONFLICT(content_hash) DO UPDATE SET ts = excluded.ts, findings = excluded.findings`).run(hash, this.now(), text);
      this.db.prepare(`DELETE FROM annotations WHERE content_hash NOT IN (SELECT content_hash FROM annotations ORDER BY ts DESC LIMIT ?)`).run(MAX_ANNOTATIONS);
    });
    return { ok: true };
  }
  /**
   * What the guard itself refuses about lifting a stop, before any touch is spent: a hash that did not match is never approved (the request may be about
   * other code than the directory shows), and in Strict mode nothing is lifted. `acknowledgeBlock` is the page's word for "I accept the risk".
   */
  protected assertLiftable(q: QueueRow, acknowledgeBlock: boolean): void {
    // By the guard's facts (trust.ts `liftBlock`): the hash mismatch, a hard flag found by its own reading, or a version it did not read at all.
    const lift = liftBlock(q, this.trustMode());
    if (lift.never) throw new GuardError("invalid", "the directory's hash did not match the request's: this version is never approved, with or without acknowledgeBlock (reinstall the plugin from its source)");
    if (acknowledgeBlock && this.trustMode() === "strict") throw new GuardError("invalid", "режим «Строгий»: остановку обойти нельзя (acknowledgeBlock отклонён сторожем); сначала ослабьте режим");
    if (lift.needsAck && !acknowledgeBlock)
      throw new GuardError("invalid", lift.why === "unread" ? "the guard did not read this version, so a hard flag may be there: it is approved only with acknowledgeBlock and a fresh touch (a session does not cover it)" : "this version has a hard flag: it is approved only with acknowledgeBlock and a fresh touch (a session does not cover it)");
  }
  /**
   * Approves a held version with a touch (a session also covers it, unless `acknowledgeBlock` lifts a stop: that is always a fresh touch, and
   * never in Strict mode). The code is checked first, in the same transaction as the approval.
   */
  approve(raw: Record<string, unknown>): { approval: ApprovalRow } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    if (raw.acknowledgeBlock !== undefined && typeof raw.acknowledgeBlock !== "boolean") throw new GuardError("invalid", "acknowledgeBlock is true or false");
    const ack = raw.acknowledgeBlock === true;
    const q = this.heldRequest(id, true);
    this.assertLiftable(q, ack);
    const factor = this.verifyFactor(`approve:${q.pluginId}`, this.normalizeAction({ op: "approve", requestId: id, ...(ack ? { acknowledgeBlock: true } : {}) }), raw);
    return this.tx(() => {
      const a = this.addApproval({ contentHash: q.contentHash, pluginId: q.pluginId, version: q.version, source: q.source, sourceKind: q.sourceKind, gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, rights: q.rights, why: touchWhy(q.note) });
      this.resolveQueue(q.pluginId, q.contentHash, "approved");
      // The record says what exactly was approved: after the fact, this is what the owner reads.
      this.log("approved.touch", q.pluginId, q.contentHash, { approval: a.id, review: q.id, version: q.version, source: q.source, sourceKind: q.sourceKind, rootDir: q.rootDir, ...(ack ? { acknowledgeBlock: true } : {}), ...factorDetail(factor) });
      return { approval: a };
    });
  }
  /**
   * «Вернуть и доверять источнику»: ONE operation, ONE touch, ONE journal record — the version is approved and its source (as the guard names it
   * from the queue entry, not from the request) goes into "my sources". Never a session (adding a source is always a fresh touch), never a stop.
   */
  approveAndTrust(raw: Record<string, unknown>): { approval: ApprovalRow; entry: string; mySources: string[] } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    const q = this.heldRequest(id, true);
    this.assertLiftable(q, false);
    const action = this.normalizeAction({ op: "approve-trust", requestId: id });
    const entry = action.entry as string;
    const cur = this.mySources();
    if (!cur.includes(entry) && cur.length + 1 > MAX_SOURCES) throw new GuardError("invalid", `at most ${MAX_SOURCES} sources`);
    const factor = this.verifyFactor(`approve-trust:${q.pluginId}`, action, raw);
    return this.tx(() => {
      const a = this.addApproval({ contentHash: q.contentHash, pluginId: q.pluginId, version: q.version, source: q.source, sourceKind: q.sourceKind, gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, rights: q.rights, why: touchWhy(q.note) });
      this.resolveQueue(q.pluginId, q.contentHash, "approved");
      const next = cur.includes(entry) ? cur : [...cur, entry].sort();
      this.setMeta("my_sources", JSON.stringify(next));
      this.log("approved.trust", q.pluginId, q.contentHash, { approval: a.id, review: q.id, version: q.version, source: q.source, sourceKind: q.sourceKind, rootDir: q.rootDir, trustedSource: entry, sourceWasTrusted: cur.includes(entry), ...factorDetail(factor) });
      return { approval: a, entry, mySources: next };
    });
  }
  // ---- batch: the list is fixed here before the touch ---------------------------------------------------------------------
  protected batchHash(items: Array<{ kind: string; id: number; fingerprint: string }>): string {
    const canon = items.map((i) => [i.kind, i.id, i.fingerprint] as const).sort((a, b) => (a[0] === b[0] ? a[1] - b[1] : a[0] < b[0] ? -1 : 1));
    return sha256hex(JSON.stringify(canon));
  }
  /** What a held version is right now, as the guard sees it: if any part differs when the touch arrives, the version is not approved. */
  protected queueFingerprint(q: QueueRow): string {
    const stop = (this.db.prepare(`SELECT stop FROM queue WHERE id = ?`).get(q.id) as { stop: number } | undefined)?.stop ?? 0;
    return sha256hex(JSON.stringify([q.pluginId, q.version, q.contentHash, q.source, q.sourceKind, q.rootDir, stop, q.blocks, q.reasonKind]));
  }
  /**
   * `batch-prepare {items: [{kind, id, fingerprint?, label?}]}`: fixes the list. `queue` items are the guard's own held versions: the guard computes
   * their fingerprint and label itself (what the caller says about them is ignored), and leaves out the ones that cannot go into a list (a hash that did
   * not match, a hard flag: blocks are lifted one by one). `skill` and `drift` items belong to the plugin: the guard keeps what the plugin said about
   * them, only to bind the touch to them. Nothing is approved here.
   */
  batchPrepare(raw: Record<string, unknown>): { batchId: string; setHash: string; expiresAt: number; items: Array<{ kind: string; id: number; label: string; fingerprint: string }>; skipped: Array<{ kind: string; id: number; reason: string }> } {
    if (!Array.isArray(raw.items) || raw.items.length === 0 || raw.items.length > MAX_BATCH_ITEMS) throw new GuardError("invalid", `items is a list of 1..${MAX_BATCH_ITEMS} entries`);
    const seen = new Set<string>();
    const items: Array<{ kind: string; id: number; label: string; fingerprint: string }> = [];
    const skipped: Array<{ kind: string; id: number; reason: string }> = [];
    for (const r of raw.items as unknown[]) {
      if (typeof r !== "object" || r === null || Array.isArray(r)) throw new GuardError("invalid", "an item is an object");
      const it = r as Record<string, unknown>;
      if (it.kind !== "queue" && it.kind !== "skill" && it.kind !== "drift") throw new GuardError("invalid", "kind is queue, skill or drift");
      const id = intOf(it.id, "id", 1, Number.MAX_SAFE_INTEGER);
      if (seen.has(`${it.kind}:${id}`)) continue;
      seen.add(`${it.kind}:${id}`);
      if (it.kind === "queue") {
        const row = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(id) as Raw | undefined;
        const q = row ? queueOf(row) : null;
        if (!q || q.status !== "held") skipped.push({ kind: "queue", id, reason: "уже не ждёт решения" });
        else if (liftBlock(q, this.trustMode()).never) skipped.push({ kind: "queue", id, reason: "хеш не совпал: одобрить нельзя" });
        else if (liftBlock(q, this.trustMode()).needsAck) skipped.push({ kind: "queue", id, reason: liftBlock(q, this.trustMode()).why === "unread" ? "сторож не читал версию, жёсткий признак возможен: снимается отдельно, свежим касанием" : "жёсткий флаг: снимается отдельно, свежим касанием" });
        else items.push({ kind: "queue", id, label: `${q.pluginId}@${q.version}`, fingerprint: this.queueFingerprint(q) });
      } else {
        items.push({ kind: it.kind, id, label: str(it.label ?? `${it.kind} #${id}`, "label", 200), fingerprint: str(it.fingerprint, "fingerprint", 128, 1) });
      }
    }
    if (items.length === 0) throw new GuardError("invalid", `nothing in the list can be approved together${skipped.length > 0 ? `: ${skipped.map((s) => `${s.kind} #${s.id} — ${s.reason}`).join("; ")}` : ""}`);
    const setHash = this.batchHash(items);
    return this.tx(() => {
      const now = this.now();
      this.db.prepare(`DELETE FROM batches WHERE expires_at < ? OR used_at IS NOT NULL AND used_at < ?`).run(now, now - HOUR_MS);
      if ((this.db.prepare(`SELECT COUNT(*) AS n FROM batches WHERE used_at IS NULL`).get() as { n: number }).n >= MAX_PENDING_BATCHES) throw new GuardError("conflict", "too many lists are waiting; use or let them expire first");
      const batchId = randomBytes(12).toString("hex");
      const expiresAt = now + BATCH_TTL_MS;
      this.db.prepare(`INSERT INTO batches (id, set_hash, items, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`).run(batchId, setHash, JSON.stringify(items), now, expiresAt);
      this.log("batch.prepare", null, null, { batch: batchId, setHash, items: items.map((i) => `${i.kind}#${i.id}`) });
      return { batchId, setHash, expiresAt, items, skipped };
    });
  }
  protected loadBatch(raw: Record<string, unknown>): { id: string; setHash: string; items: Array<{ kind: string; id: number; label: string; fingerprint: string }> } {
    const id = str(raw.batchId, "batchId", 64, 1);
    const shown = str(raw.setHash, "setHash", 64, 64);
    const row = this.db.prepare(`SELECT * FROM batches WHERE id = ?`).get(id) as Raw | undefined;
    if (!row) throw new GuardError("not_found", "no such list; prepare it again");
    if (row.used_at !== null) throw new GuardError("conflict", "this list was already approved");
    if (this.now() >= Number(row.expires_at)) throw new GuardError("conflict", "the list expired; prepare it again");
    const items = JSON.parse(String(row.items)) as Array<{ kind: string; id: number; label: string; fingerprint: string }>;
    // What the person saw (the hash they confirm), what is stored, and what the stored items add up to: all the same, or nothing.
    if (shown !== String(row.set_hash) || this.batchHash(items) !== String(row.set_hash)) throw new GuardError("conflict", "the list does not match the one that was shown; prepare it again");
    return { id, setHash: String(row.set_hash), items };
  }
  /**
   * `batch-approve {batchId, setHash, code | passkey | session}`: ONE touch for the whole stored list (the touch names the list's id and hash, never items;
   * a passkey signature is bound to that pair). Each `queue` item is approved only if it is still what it was when the list was shown. `skill` and
   * `drift` items are returned as `local`: the plugin approves its own, now that the touch was accepted.
   */
  batchApprove(raw: Record<string, unknown>): { results: Array<{ kind: string; id: number; label: string; ok: boolean; local: boolean; note: string }> } {
    const b = this.loadBatch(raw);
    const factor = this.verifyFactor("batch.approve", this.normalizeAction({ op: "batch-approve", batchId: b.id, setHash: b.setHash }), raw);
    return this.tx(() => {
      const spent = this.db.prepare(`UPDATE batches SET used_at = ? WHERE id = ? AND used_at IS NULL`).run(this.now(), b.id);
      if (Number(spent.changes) !== 1) throw new GuardError("conflict", "this list was already approved");
      this.log("batch.approve", null, null, { batch: b.id, setHash: b.setHash, items: b.items.map((i) => `${i.kind}#${i.id}`), ...factorDetail(factor) });
      const results: Array<{ kind: string; id: number; label: string; ok: boolean; local: boolean; note: string }> = [];
      for (const it of b.items) {
        if (it.kind !== "queue") {
          results.push({ kind: it.kind, id: it.id, label: it.label, ok: true, local: true, note: "касание принято; одобряет плагин" });
          continue;
        }
        const row = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(it.id) as Raw | undefined;
        const q = row ? queueOf(row) : null;
        if (!q || q.status !== "held" || this.queueFingerprint(q) !== it.fingerprint || liftBlock(q, this.trustMode()).never || liftBlock(q, this.trustMode()).needsAck) {
          results.push({ kind: "queue", id: it.id, label: it.label, ok: false, local: false, note: "изменилось после показа списка: не одобрено, посмотрите заново" });
          continue;
        }
        const a = this.addApproval({ contentHash: q.contentHash, pluginId: q.pluginId, version: q.version, source: q.source, sourceKind: q.sourceKind, gitCommit: null, npmIntegrity: null, via: "touch", windowId: null, rights: q.rights, why: touchWhy(q.note) });
        this.resolveQueue(q.pluginId, q.contentHash, "approved");
        this.log("approved.touch", q.pluginId, q.contentHash, { approval: a.id, review: q.id, version: q.version, source: q.source, sourceKind: q.sourceKind, rootDir: q.rootDir, batch: b.id, ...factorDetail(factor) });
        results.push({ kind: "queue", id: it.id, label: it.label, ok: true, local: false, note: "одобрено" });
      }
      return { results };
    });
  }
  /** Drops a held entry: tightening (the version stays unapproved), so no code and no block after wrong codes, like revoke. Held entries only; the journal gets a record. */
  dismiss(raw: Record<string, unknown>): { ok: true } {
    const id = intOf(raw.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
    const q = this.heldRequest(id);
    return this.tx(() => {
      const stop = (this.db.prepare(`SELECT stop FROM queue WHERE id = ?`).get(q.id) as { stop: number } | undefined)?.stop === 1;
      this.resolveQueue(q.pluginId, q.contentHash, "dismissed");
      this.log("dismissed", q.pluginId, q.contentHash, { review: q.id, version: q.version, ...(stop ? { stop: true } : {}) });
      // A stop means the plugin's hook saw something the window must not wave through (a new capability, a tainted tree).
      // Rejecting it does not lift the stop (see isStopped), and the plugin's window is closed too: tightening, journaled.
      if (stop) for (const w of this.unclosedWindows()) if (w.pluginId === q.pluginId) this.closeWindowInner(w, "dismissed-stop");
      return { ok: true } as const;
    });
  }
  /**
   * Withdraws approvals: tightening, so no code and no block after wrong codes (whoever can call the guard must not
   * be able to keep the owner from revoking). By approval id: every approval of that version goes. By plugin id: all of them, and its windows.
   */
  revoke(raw: Record<string, unknown>): { revoked: number } {
    return this.tx(() => {
      let rows: ApprovalRow[];
      if (raw.approvalId !== undefined) {
        const a = this.db.prepare(`SELECT * FROM approvals WHERE id = ? AND revoked_at IS NULL`).get(intOf(raw.approvalId, "approvalId", 1, Number.MAX_SAFE_INTEGER)) as Raw | undefined;
        if (!a) throw new GuardError("not_found", "no such active approval");
        rows = (this.db.prepare(`SELECT * FROM approvals WHERE content_hash = ? AND plugin_id = ? AND revoked_at IS NULL`).all(String(a.content_hash), String(a.plugin_id)) as Raw[]).map(approvalOf);
      } else {
        const pluginId = pluginIdOf(raw.pluginId);
        rows = (this.db.prepare(`SELECT * FROM approvals WHERE plugin_id = ? AND revoked_at IS NULL`).all(pluginId) as Raw[]).map(approvalOf);
        for (const w of this.unclosedWindows()) if (w.pluginId === pluginId) this.closeWindowInner(w, "revoked");
        if (rows.length === 0) throw new GuardError("not_found", "no active approvals of this plugin");
      }
      for (const a of rows) {
        this.db.prepare(`UPDATE approvals SET revoked_at = ? WHERE id = ?`).run(this.now(), a.id);
        this.log("revoked", a.pluginId, a.contentHash, { approval: a.id, version: a.version });
      }
      return { revoked: rows.length };
    });
  }
  /** Weakening the mode (Strict → Detailed → Simple) is a touch; the same or a stricter one is not. */
  setTrustMode(modeIn: unknown, proof: Proof): TrustMode {
    if (typeof modeIn !== "string" || !TRUST_MODES.includes(modeIn as TrustMode)) throw new GuardError("invalid", "mode is simple, detailed or strict");
    const mode = modeIn as TrustMode;
    const cur = this.trustMode();
    if (mode === cur) return cur;
    const weakens = MODE_RANK[mode] < MODE_RANK[cur];
    const factor = weakens ? this.verifyFactor("trust.mode", this.normalizeAction({ op: "trust-mode", mode }), proof) : null;
    return this.tx(() => {
      this.setMeta("trust_mode", mode);
      this.log("trust.mode", null, null, { from: cur, to: mode, touched: weakens, ...(factor ? factorDetail(factor) : {}) });
      return mode;
    });
  }
  /** Adding "my sources" is a touch (it widens what passes by itself). Entries already in the list need none. `migrated`: from the plugin's old list of trusted repositories. */
  addSources(raw: Record<string, unknown>): { mySources: string[]; added: string[] } {
    const entries = this.entriesOf(raw.entries);
    const cur = this.mySources();
    const fresh = entries.filter((e) => !cur.includes(e));
    if (fresh.length === 0) return { mySources: cur, added: [] };
    if (cur.length + fresh.length > MAX_SOURCES) throw new GuardError("invalid", `at most ${MAX_SOURCES} sources`);
    const factor = this.verifyFactor("sources.add", this.normalizeAction({ op: "sources-add", entries: fresh }), raw);
    return this.tx(() => {
      const next = [...cur, ...fresh].sort();
      this.setMeta("my_sources", JSON.stringify(next));
      this.log("sources.add", null, null, { entries: fresh, ...(raw.migrated === true ? { migrated: "trusted repositories of the plugin" } : {}), ...factorDetail(factor) });
      return { mySources: next, added: fresh };
    });
  }
  /** Removing one only tightens: no touch, and not blocked after wrong codes. Versions already approved stay approved; later ones are asked about. */
  removeSource(raw: Record<string, unknown>): { mySources: string[] } {
    const e = normalizeEntry(raw.entry);
    if (e === null) throw new GuardError("invalid", "entry is github:owner/name, github:owner/* or path:/dir");
    return this.tx(() => {
      const cur = this.mySources();
      if (!cur.includes(e)) throw new GuardError("not_found", "this source is not in the list");
      const next = cur.filter((x) => x !== e);
      this.setMeta("my_sources", JSON.stringify(next));
      this.log("sources.remove", null, null, { entry: e });
      return { mySources: next };
    });
  }
  // ---- migration ------------------------------------------------------------------------------------------
  /** Console only. Adds approvals exported by the plugin; skips what is already approved. Returns what was added. */
  importApprovals(items: ImportItem[], fileDigest: string): { added: number; skipped: number } {
    return this.tx(() => {
      let added = 0;
      let skipped = 0;
      for (const i of items) {
        if (this.activeApproval(i.pluginId, i.contentHash)) {
          skipped++;
          continue;
        }
        const a = this.addApproval({ ...i, via: "import", windowId: null });
        this.resolveQueue(i.pluginId, i.contentHash, "approved");
        this.log("approved.import", i.pluginId, i.contentHash, { approval: a.id, version: i.version, source: i.source, sourceKind: i.sourceKind, originalApprovedAt: i.approvedAt, file: fileDigest });
        added++;
      }
      this.log("import", null, null, { file: fileDigest, added, skipped });
      return { added, skipped };
    });
  }
}
