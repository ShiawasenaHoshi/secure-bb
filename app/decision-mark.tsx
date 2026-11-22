// One click after a decision: «ложная тревога» / «правда было опасно» / «не знаю» (and a one-line reason when a version was revoked). Optional; it decides nothing.
import { useState } from "react";
import type { Overview } from "../src/overview";
import { MARKABLE_KINDS, MARK_LABEL, MARK_REVOKE_REASON, type MarkKey } from "../src/ux";
import { useCodeAction } from "./code";
import { type Rpc } from "./touch";
import { btn, input, muted, Msg } from "./ui";

type Rec = NonNullable<Overview["guard"]>["recent"][number];

/** The latest mark of a record, from the journal's recent records (a mark is a record of its own: `decision.mark`). */
export function markOf(recent: Rec[], id: number): { mark: MarkKey; reason: string | null } | null {
  const hit = recent.find((r) => r.kind === "decision.mark" && (r.detail as { record?: number } | null)?.record === id);
  const d = hit?.detail as { mark?: string; reason?: string } | null | undefined;
  return d?.mark && d.mark in MARK_LABEL ? { mark: d.mark as MarkKey, reason: d.reason ?? null } : null;
}

export function DecisionMark({ r, recent, rpc, refetch }: { r: Rec; recent: Rec[]; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const [reason, setReason] = useState("");
  if (!MARKABLE_KINDS.includes(r.kind)) return null;
  const given = markOf(recent, r.id);
  const send = (mark: MarkKey) => void act.run(async () => { await rpc.call("decision.mark", { record: r.id, mark, ...(reason.trim() ? { reason: reason.trim() } : {}) } as never); });
  return (
    <span className="ml-2 inline-flex flex-wrap items-center gap-1 font-sans" data-secure-bb-mark={r.id}>
      {given ? <span className={muted}>отметка: {MARK_LABEL[given.mark]}{given.reason ? ` · ${given.reason}` : ""}</span> : null}
      {r.kind === "revoked" ? <input className={`${input} w-56 font-sans tracking-normal`} maxLength={200} value={reason} placeholder={MARK_REVOKE_REASON} onChange={(e) => setReason(e.target.value)} /> : null}
      {(Object.keys(MARK_LABEL) as MarkKey[]).map((k) => (
        <button key={k} className={btn} disabled={act.busy} onClick={() => send(k)} data-secure-bb-mark-button={k}>{MARK_LABEL[k]}</button>
      ))}
      <Msg error={act.error} />
    </span>
  );
}
