import { useState } from "react";
import type { Overview } from "../src/overview";
import { useCodeAction } from "./code";
import { type Rpc } from "./touch";
import { ProofField, ProofNotes } from "./confirm";
import { useProof } from "./proof";
import { card, btn, btnPrimary, input, muted, Msg } from "./ui";

/** "Approve the selected": the list is fixed on the server and shown with its hash BEFORE the code; one code approves the whole list. */
export type BatchKindUi = "queue" | "skill" | "drift";

export function BatchCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const [picked, setPicked] = useState<string[]>([]);
  const [prepared, setPrepared] = useState<Awaited<ReturnType<Rpc["call"]>> | null>(null);
  const [results, setResults] = useState<Array<{ kind: string; id: number; label: string; ok: boolean; note: string }> | null>(null);
  const proof = useProof(ov, rpc);
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const candidates: Array<{ key: string; kind: BatchKindUi; id: number; label: string }> = [
    ...ov.queue.filter((q) => q.status === "held").map((q) => ({ key: `queue:${q.id}`, kind: "queue" as const, id: q.id, label: `версия ${q.pluginId}@${q.version}` })),
    ...ov.skills.open.map((q) => ({ key: `skill:${q.id}`, kind: "skill" as const, id: q.id, label: `скилл ${q.name} (${q.scope})` })),
    ...ov.watch.drifts.filter((d) => d.status === "open" || d.status === "rollback-failed").map((d) => ({ key: `drift:${d.id}`, kind: "drift" as const, id: d.id, label: `расхождение: ${d.label}` })),
  ];
  const prep = prepared as null | { batchId: string; setHash: string; expiresAt: number; items: Array<{ kind: string; id: number; label: string; detail: string }>; skipped: Array<{ kind: string; id: number; reason: string }> };
  if (candidates.length < 2 && !prep && !results) return null;
  const toggle = (k: string) => setPicked((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]));
  const reset = () => { setPrepared(null); proof.clearDraft(); };
  return (
    <div className={card}>
      <h3 className="font-semibold">Пакетное одобрение</h3>
      {!prep ? (
        <>
          <p className={muted}>Отметьте, что одобрить разом: одно {ov.guard ? "касание" : "подтверждение"} на весь список. Список фиксируется {ov.guard ? "у сторожа" : "на сервере"} до касания; элементы с блоком проверок в пакет не входят.</p>
          <ul className="mt-2 space-y-1">
            {candidates.map((c) => (
              <li key={c.key}><label className="flex items-center gap-2"><input type="checkbox" checked={picked.includes(c.key)} onChange={() => toggle(c.key)} /> {c.label} <span className={`text-xs ${muted}`}>#{c.id}</span></label></li>
            ))}
          </ul>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button className={btn} disabled={act.busy || picked.length === 0 || !registered} onClick={() => void act.run(async () => {
              setResults(null);
              const items = picked.map((k) => ({ kind: k.split(":")[0] as BatchKindUi, id: Number(k.split(":")[1]) }));
              setPrepared((await rpc.call("batch.prepare", { items })) as never);
            })}>
              Показать список ({picked.length})
            </button>
            <button className={btn} onClick={() => setPicked(candidates.map((c) => c.key))}>Выбрать всё</button>
          </div>
        </>
      ) : (
        <>
          <p className="mt-1">Будет одобрено ({prep.items.length}) — список зафиксирован, хеш набора <span className="font-mono">{prep.setHash.slice(0, 12)}</span>:</p>
          <ul className="mt-1 list-disc pl-5">
            {prep.items.map((i) => <li key={`${i.kind}${i.id}`}>{i.label} <span className={`text-xs ${muted}`}>({i.kind} #{i.id}{i.detail ? ` · ${i.detail}` : ""})</span></li>)}
          </ul>
          {prep.skipped.length > 0 ? (
            <div className="mt-1">
              <p className={muted}>Не вошли (одобряются по одному):</p>
              <ul className="list-disc pl-5 text-xs">{prep.skipped.map((i) => <li key={`${i.kind}${i.id}`}>{i.kind} #{i.id}: {i.reason}</li>)}</ul>
            </div>
          ) : null}
          <p className={`mt-1 text-xs ${muted}`}>Список действует 10 минут и одобряется один раз. Если что-то изменится до касания, это не будет одобрено.</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <ProofField proof={proof} routine />
            <button className={btnPrimary} disabled={act.busy || !proof.ready({ routine: true })} onClick={() => void act.run(async () => {
              // One touch for the whole list: the touch is for this list's id and hash (the guard holds the list), never for items.
              const r = await proof.run({ kind: "batch.approve", batchId: prep.batchId, setHash: prep.setHash }, (p) => rpc.call("batch.approve", { batchId: prep.batchId, setHash: prep.setHash, ...p } as never), { routine: true });
              setResults(r.results);
              setPicked([]);
              reset();
              return { note: `Одобрено: ${r.results.filter((x) => x.ok).length} из ${r.results.length}` };
            })}>
              Одобрить список ({prep.items.length})
            </button>
            <button className={btn} onClick={reset}>Отмена</button>
          </div>
          <ProofNotes proof={proof} />
        </>
      )}
      {results ? <ul className="mt-2 list-disc pl-5 text-xs">{results.map((r) => <li key={`${r.kind}${r.id}`} className={r.ok ? muted : "text-destructive"}>{r.label}: {r.ok ? "одобрено" : "не одобрено"} — {r.note}</li>)}</ul> : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}
