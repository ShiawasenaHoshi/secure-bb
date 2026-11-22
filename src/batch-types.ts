// What a batch approval returns to the page: the list as it was fixed, and the outcome of each item. A leaf module (the RPC contract names these types).
import type { BatchKind } from "./approval.js";

export interface BatchPrepared {
  batchId: string;
  /** The hash the person confirms (the page shows its beginning next to the list). */
  setHash: string;
  expiresAt: number;
  items: Array<{ kind: BatchKind; id: number; label: string; detail: string }>;
  skipped: Array<{ kind: BatchKind; id: number; reason: string }>;
}
export interface BatchResult {
  kind: BatchKind;
  id: number;
  label: string;
  ok: boolean;
  note: string;
}
