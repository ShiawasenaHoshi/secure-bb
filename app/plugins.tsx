import { useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview, PluginView } from "../src/overview";
import type { CheckResult } from "../src/checks/types";
import { approvedByText, launchProblem } from "../src/ux";
import { truthfulApproval } from "../src/factor";
import { useApproval } from "./approval";
import { ChecksView } from "./checks";
import { useCodeAction, CodeField } from "./code";
import { type Rpc } from "./touch";
import { ProofField, ProofNotes } from "./confirm";
import { useProof } from "./proof";
import { ScanResultView, PublicationLine, ScanButton } from "./scan";
import { card, btn, input, muted, Fold, useNow, Msg } from "./ui";
import { windowLine } from "./windows";

/** «Открыть окно на N мин» on the plugin's row, or the reason there is none. */
export function PluginWindowOpen({ p, ov, rpc, refetch }: { p: PluginView; ov: Overview; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc);
  if (!p.windowOpen.available) return p.windowOpen.note ? <p className={`text-xs ${muted}`}>{p.windowOpen.note}</p> : null;
  return (
    <div className="mt-1">
      <div className="flex flex-wrap items-center gap-2">
        <ProofField proof={proof} routine />
        <button className={btn} disabled={act.busy || !proof.ready({ routine: true })} onClick={() => void act.run(async () => { await proof.run({ kind: "window.open", pluginId: p.id } as never, (x) => rpc.call("window.open", { pluginId: p.id, ...x } as never), { routine: true }); })}>
          Открыть окно на {ov.policy.windowMin} мин
        </button>
      </div>
      <p className={`text-xs ${muted}`}>Пока окно открыто, новые версии {p.id} из того же треда проходят без вопросов; новое право всё равно спросит.</p>
      <ProofNotes proof={proof} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

export function PluginRow({ p, ov, rpc, refetch, registered, checks }: { p: PluginView; ov: Overview; checks: Record<string, CheckResult>; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void; registered: boolean }) {
  const now = useNow();
  const factorCtx = { guardMode: ov.guard?.connected === true, recent: ov.guard?.recent ?? [] };
  const ap = useApproval();
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const remaining = p.window ? Math.max(0, Math.ceil((Math.min(p.window.expiresAt, p.window.hardExpiresAt) - now) / 1000)) : 0;
  return (
    <div className={card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{p.id} <span className={muted}>{p.version} · {p.status}</span></h3>
        <span className={muted}>
          {p.pin ? `${p.frozenPin ? "закреплена при заморозке" : "пин"}: ${p.pin.version} (${approvedByText(truthfulApproval(p.pin, factorCtx), now)})` : p.unreviewedBaseline ? "стоял до secure-bb, не проверялся" : "не одобрен"}
        </span>
      </div>
      {launchProblem(p) && p.pin ? <p className="mt-1 font-semibold text-destructive" role="alert">{launchProblem(p)}</p> : null}
      <p className={muted}>{p.window ? windowLine(p.window, remaining) : "окно закрыто"}</p>
      {!p.window ? <PluginWindowOpen p={p} ov={ov} rpc={rpc} refetch={refetch} /> : null}
      {p.pin ? <ChecksView id={`plugin-${p.id}`} result={checks[p.pin.contentHash]} /> : null}
      <PublicationLine ov={ov} pluginId={p.id} version={p.pin?.version ?? null} rpc={rpc} refetch={refetch} />
      <ScanResultView scan={ov.ai.pluginScans[p.id]} enabled={ov.ai.settings.enabled} other={ov.ai.pluginScans[p.id] ? (ov.ai.pluginScans[p.id]!.current ? "это закреплённая версия" : "не закреплённая версия") : undefined} />
      {ov.ai.settings.enabled ? (
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <ScanButton ov={ov} target={{ pluginId: p.id }} rpc={rpc} refetch={refetch} />
          <label className="flex items-center gap-1 text-xs">
            <input type="checkbox" checked={ov.ai.settings.freezePlugins.includes(p.id)} disabled={act.busy || (!ov.ai.settings.freezePlugins.includes(p.id) && (!registered || code.length !== 6))} onChange={(e) => void act.run(async () => { await rpc.call("ai.settings", { freezePlugin: { id: p.id, on: e.target.checked }, ...(code.length === 6 ? { code } : {}) }); setCode(""); })} />
            автоскан при заморозке этого плагина{ov.ai.settings.freezePlugins.includes(p.id) ? "" : " (включить — с кодом)"}
          </label>
          {registered && !ov.ai.settings.freezePlugins.includes(p.id) ? <CodeField value={code} onChange={setCode} /> : null}
        </div>
      ) : null}
      {p.history.length > 1 ? (
        <Fold id={`plugin-${p.id}-history`} className="mt-1" summary={`История (${p.history.length})`}>
          <ul className="mt-1 list-disc pl-5">
            {p.history.map((h) => (
              <li key={h.id}>{h.version} · {approvedByText(truthfulApproval(h, factorCtx), now)}</li>
            ))}
          </ul>
        </Fold>
      ) : null}
      {p.pin ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {p.pin ? (
            <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("approval.revoke", { approvalId: p.pin!.id }); })}>
              Отозвать (без кода)
            </button>
          ) : null}
        </div>
      ) : null}
      <Msg error={act.error} />
    </div>
  );
}
