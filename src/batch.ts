// Batch approval (docs: secure-bb-approval-ux.md §2): "approve the selected" — ONE code for the whole list.
//
// The list is fixed on the server BEFORE any code is entered: `prepare` stores the items with a fingerprint of what each one is right
// now, and returns a hash of the whole set. `approve` takes only the id of that stored list and the hash, never the items, so
// nothing can be added or swapped between what the person saw and what the code confirms. And an item that changed after
// it was shown (a new content hash, a new value) is not approved: it is reported as changed.
import { randomBytes } from "node:crypto";
import { setHash, type BatchItem, type BatchKind } from "./approval.js";
import type { ListProof, Proof } from "./approval.js";
import { GateError } from "./errors.js";
import type { BatchPrepared, BatchResult } from "./batch-types.js";
import type { GuardBatchPrepared, GuardBatchResult, GuardProof } from "./guardlink.js";
import type { Store } from "./store.js";

export const BATCH_TTL_MS = 10 * 60_000;
const MAX_PENDING = 20;

/** What an item is right now. `skip`: it cannot go into a list (and why); null: it is gone or not waiting any more. */
export type Described = { fingerprint: string; label: string; detail: string } | { skip: string } | null;

export interface BatchSource {
  describe(id: number): Promise<Described> | Described;
  /** Approves one item. The code was accepted for the whole list already; `mark` says so. Returns a short note; throws when it cannot. */
  approve(id: number, mark: ListProof): Promise<string>;
  /** Guard mode: the guard approved this item itself (it is the guard's own, a held version); what the plugin does after an approval (rechecks, the page). */
  afterGuard?(id: number): Promise<void> | void;
}

/**
 * Guard mode: the list is fixed AT THE GUARD before the touch, and the touch (a code, a signature bound to the list, or a session) is spent there, once,
 * on the guard's own copy. Versions the guard holds are approved by the guard; the plugin's own items (skills, differences) are approved here afterwards.
 */
export interface GuardBatch {
  prepare(items: Array<{ kind: BatchKind; id: number; fingerprint: string; label: string }>): Promise<GuardBatchPrepared>;
  approve(batchId: string, setHash: string, proof: GuardProof): Promise<GuardBatchResult[]>;
  /** The mark that says the guard accepted the touch (the plugin's own items are approved under it). */
  mark(): ListProof;
}

export interface BatchDeps {
  store: Store;
  now: () => number;
  sources: Record<BatchKind, BatchSource>;
  /** Checks the proof once and returns the mark (the gate). */
  approveList: (purpose: string, proof: Proof) => ListProof;
  guard?: GuardBatch;
}

const isSkip = (d: Described): d is { skip: string } => d !== null && "skip" in d;

export class BatchService {
  constructor(private readonly d: BatchDeps) {}

  async prepare(requested: Array<{ kind: BatchKind; id: number }>): Promise<BatchPrepared> {
    const { store } = this.d;
    const now = this.d.now();
    if (store.pruneBatches(now) >= MAX_PENDING) throw new GateError("conflict", "too many lists are waiting; use or let them expire first");
    const seen = new Set<string>();
    const items: BatchItem[] = [];
    const shown: BatchPrepared["items"] = [];
    const skipped: BatchPrepared["skipped"] = [];
    for (const r of requested) {
      const key = `${r.kind}:${r.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const d = await this.d.sources[r.kind].describe(r.id);
      if (d === null) skipped.push({ kind: r.kind, id: r.id, reason: "уже не ждёт решения" });
      else if (isSkip(d)) skipped.push({ kind: r.kind, id: r.id, reason: d.skip });
      else {
        items.push({ kind: r.kind, id: r.id, fingerprint: d.fingerprint, label: d.label });
        shown.push({ kind: r.kind, id: r.id, label: d.label, detail: d.detail });
      }
    }
    if (items.length === 0) throw new GateError("invalid", `nothing in the list can be approved together${skipped.length > 0 ? `: ${skipped.map((s) => `${s.kind} #${s.id} — ${s.reason}`).join("; ")}` : ""}`);
    if (this.d.guard) {
      // The guard fixes the list (and reads its own versions itself: what it says of them wins). What it leaves out is told to the person.
      const g = await this.d.guard.prepare(items.map((i) => ({ kind: i.kind, id: i.id, fingerprint: i.fingerprint, label: i.label })));
      const kept = g.items.map((i) => ({ kind: i.kind, id: i.id, fingerprint: i.fingerprint, label: i.label }));
      store.insertBatch({ id: g.batchId, setHash: g.setHash, items: JSON.stringify(kept), createdAt: now, expiresAt: g.expiresAt });
      store.log("batch.prepare", null, null, { batch: g.batchId, setHash: g.setHash, items: kept.map((i) => `${i.kind}#${i.id}`), at: "guard" });
      const detail = new Map(shown.map((i) => [`${i.kind}:${i.id}`, i.detail]));
      return {
        batchId: g.batchId,
        setHash: g.setHash,
        expiresAt: g.expiresAt,
        items: g.items.map((i) => ({ kind: i.kind, id: i.id, label: i.label, detail: detail.get(`${i.kind}:${i.id}`) ?? "" })),
        skipped: [...skipped, ...g.skipped.map((x) => ({ kind: x.kind as BatchKind, id: x.id, reason: x.reason }))],
      };
    }
    const hash = setHash(items);
    const id = randomBytes(12).toString("hex");
    const expiresAt = now + BATCH_TTL_MS;
    store.insertBatch({ id, setHash: hash, items: JSON.stringify(items), createdAt: now, expiresAt });
    store.log("batch.prepare", null, null, { batch: id, setHash: hash, items: items.map((i) => `${i.kind}#${i.id}`) });
    return { batchId: id, setHash: hash, expiresAt, items: shown, skipped };
  }

  /** Guard mode: the guard checks the touch against ITS copy of the list and approves its own versions; then this plugin's own items follow. */
  async approveGuarded(batchId: string, shownHash: string, proof: GuardProof): Promise<BatchResult[]> {
    const { store } = this.d;
    const guard = this.d.guard;
    if (!guard) throw new GateError("invalid", "not in guard mode");
    const row = store.getBatch(batchId);
    if (!row) throw new GateError("not_found", "no such list; prepare it again");
    if (row.usedAt !== null) throw new GateError("conflict", "this list was already approved");
    if (this.d.now() >= row.expiresAt) throw new GateError("conflict", "the list expired; prepare it again");
    const items = JSON.parse(row.items) as BatchItem[];
    if (shownHash !== row.setHash || setHash(items) !== row.setHash) throw new GateError("conflict", "the list does not match the one that was shown; prepare it again");
    const hash = row.setHash;
    const done = await guard.approve(batchId, hash, proof);
    if (!store.useBatch(batchId, this.d.now())) throw new GateError("conflict", "this list was already approved");
    store.log("batch.approve", null, null, { batch: batchId, setHash: hash, items: items.map((i) => `${i.kind}#${i.id}`), at: "guard" });
    const mark = guard.mark();
    const results: BatchResult[] = [];
    for (const r of done) {
      const item = items.find((i) => i.kind === r.kind && i.id === r.id);
      const src = this.d.sources[r.kind as BatchKind];
      if (!item || !r.ok) {
        results.push({ kind: r.kind as BatchKind, id: r.id, label: r.label, ok: false, note: r.note });
        continue;
      }
      if (!r.local) {
        // Approved by the guard already.
        try {
          await src.afterGuard?.(r.id);
        } catch {
          /* the approval stands; a failed refresh is not a failed approval */
        }
        results.push({ kind: r.kind as BatchKind, id: r.id, label: r.label, ok: true, note: r.note });
        continue;
      }
      try {
        const now = await src.describe(r.id);
        if (now === null || isSkip(now) || now.fingerprint !== item.fingerprint) {
          results.push({ kind: item.kind, id: item.id, label: item.label, ok: false, note: "изменилось после показа списка: не одобрено, посмотрите заново" });
          continue;
        }
        results.push({ kind: item.kind, id: item.id, label: item.label, ok: true, note: await src.approve(r.id, mark) });
      } catch (err) {
        results.push({ kind: item.kind, id: item.id, label: item.label, ok: false, note: err instanceof Error ? err.message : String(err) });
      }
    }
    store.log("batch.done", null, null, { batch: batchId, ok: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length });
    return results;
  }

  async approve(batchId: string, shownHash: string, proof: Proof): Promise<BatchResult[]> {
    const { store } = this.d;
    const row = store.getBatch(batchId);
    if (!row) throw new GateError("not_found", "no such list; prepare it again");
    if (row.usedAt !== null) throw new GateError("conflict", "this list was already approved");
    if (this.d.now() >= row.expiresAt) throw new GateError("conflict", "the list expired; prepare it again");
    const items = JSON.parse(row.items) as BatchItem[];
    // What the person saw (the hash they confirm), what the server stored, and what the stored items add up to: all the same, or nothing.
    if (shownHash !== row.setHash || setHash(items) !== row.setHash) throw new GateError("conflict", "the list does not match the one that was shown; prepare it again");
    // The one code (or session) for the whole list; a wrong one leaves the list as it was.
    const mark = this.d.approveList("batch", proof);
    if (!store.useBatch(batchId, this.d.now())) throw new GateError("conflict", "this list was already approved");
    store.log("batch.approve", null, null, { batch: batchId, setHash: row.setHash, items: items.map((i) => `${i.kind}#${i.id}`) });
    const results: BatchResult[] = [];
    for (const item of items) {
      const src = this.d.sources[item.kind];
      try {
        const now = await src.describe(item.id);
        if (now === null || isSkip(now) || now.fingerprint !== item.fingerprint) {
          results.push({ kind: item.kind, id: item.id, label: item.label, ok: false, note: "изменилось после показа списка: не одобрено, посмотрите заново" });
          continue;
        }
        results.push({ kind: item.kind, id: item.id, label: item.label, ok: true, note: await src.approve(item.id, mark) });
      } catch (err) {
        results.push({ kind: item.kind, id: item.id, label: item.label, ok: false, note: err instanceof Error ? err.message : String(err) });
      }
    }
    store.log("batch.done", null, null, { batch: batchId, ok: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length });
    return results;
  }
}
