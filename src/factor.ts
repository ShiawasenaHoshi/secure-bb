// How an approval was confirmed, told as it was. The approval rows say `via: "touch"` for any confirmation of the person; the guard's journal knows the factor
// (a code, a key — which one — or an open session). The page says what the journal says, and where it cannot know, it does not claim a touch.

export interface FactorUsed {
  via: "totp" | "passkey" | "session";
  /** The label of the key that was touched. */
  key?: string;
}

export interface JournalLike {
  kind: string;
  detail: unknown;
}

/** The factor the guard recorded for an approval (the record that names it: `approved.touch`, `approved.trust`, …). Null: no such record (it is older than the list). */
export function factorOfApproval(approvalId: number, recent: JournalLike[]): FactorUsed | null {
  for (const r of recent) {
    const d = (r.detail !== null && typeof r.detail === "object" ? r.detail : {}) as Record<string, unknown>;
    if (d.approval !== approvalId) continue;
    if (d.via === "totp" || d.via === "passkey" || d.via === "session") return { via: d.via, ...(typeof d.key === "string" && d.key !== "" ? { key: d.key } : {}) };
  }
  return null;
}

/** «кодом» / «касанием (ключ MacBook)» / «в открытой сессии». */
export function factorWords(f: FactorUsed): string {
  if (f.via === "totp") return "кодом";
  if (f.via === "session") return "в открытой сессии";
  return f.key ? `касанием (ключ ${f.key})` : "касанием";
}

interface ApprovalLike {
  id: number;
  via: string;
  why?: string | null;
}

/**
 * The approval with its «why» rewritten to say how the person confirmed. Only an approval made by the person (`via: "touch"`) is touched; a window, a source or a
 * pin keeps its words. With a guard, the factor comes from its journal, and when the journal does not have the record the text says «вы подтвердили» and nothing
 * more; without a guard, the confirmation of the plugin's own gate is a code.
 */
export function truthfulApproval<T extends ApprovalLike>(a: T, ctx: { guardMode: boolean; recent: JournalLike[] }): T {
  if (a.via !== "touch") return a;
  const m = /^(?:вы, )?касанием(?:: ([\s\S]*))?$/.exec(a.why ?? "касанием");
  if (!m) return a;
  const f = ctx.guardMode ? factorOfApproval(a.id, ctx.recent) : ({ via: "totp" } as FactorUsed);
  const head = f ? `вы, ${factorWords(f)}` : "вы подтвердили";
  return { ...a, why: m[1] ? `${head}: ${m[1]}` : head };
}
