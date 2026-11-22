import { useState } from "react";
import type { Overview } from "../src/overview";
import type { PasskeyAssertion } from "../src/guardlink";
import { EXCEPTIONS_EMPTY, EXCEPTIONS_HELP, RESET_NOTE, exceptionRows, exceptionsHeadline, type ExceptionRow, FREQ_SETTING_LABEL, REVOKE_CODE_NOTE, resetConfirmText, resetRows } from "../src/ux";
import { useDraftCode, useCodeAction, CodeField, type Rpc, usePasskey, touchFor } from "./code";
import { TrustCard } from "./guard";
import { card, btn, input, muted, btnDanger, when, useNow, Msg, Section } from "./ui";

export function ExceptionsTab({ ov, rpc, refetch, freqOff, onFreqOff }: { ov: Overview; rpc: Rpc; refetch: () => void; freqOff: boolean; onFreqOff: (off: boolean) => void }) {
  const now = useNow();
  const act = useCodeAction(refetch);
  const [day, setDay] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [code, setCode] = useDraftCode("exceptions");
  const pk = usePasskey(ov);
  const input = {
    windows: ov.windows.map((w) => ({ id: w.id, pluginId: w.pluginId, openedAt: w.openedAt, remainingSec: Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000)) })),
    cfgWindows: ov.watch.windows.map((w) => ({ id: w.id, openedAt: w.openedAt, scopeLabels: w.scopeLabels, remainingSec: Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000)) })),
    approvals: ov.plugins.flatMap((p) => p.history.map((a) => ({ ...a, pluginId: p.id }))),
    sources: ov.guard?.trust?.mySources ?? [],
    kept: ov.agents?.state?.kept ?? [],
  };
  const all = exceptionRows(input, now);
  const rows = day ? exceptionRows(input, now, true) : all;
  // «Отозвать» of any kind only tightens: no code. Each calls the rpc that is its own.
  const revoke = async (r: ExceptionRow, proof: { code?: string; passkey?: PasskeyAssertion } = {}): Promise<void> => {
    switch (r.revoke.kind) {
      case "window":
        await rpc.call("window.close", { windowId: r.revoke.id as number });
        break;
      case "cfgWindow":
        await rpc.call("watch.window.close", { windowId: r.revoke.id as number });
        break;
      case "approval":
        await rpc.call("approval.revoke", { approvalId: r.revoke.id as number });
        break;
      case "source":
        await rpc.call("trust.remove", { entry: r.revoke.id as string } as never);
        break;
      case "kept":
        await rpc.call("agents.revokeKept", { id: r.revoke.id as number, ...proof });
        break;
    }
  };
  const reset = () =>
    void act.run(async () => {
      // All of it only tightens: no touch. The mode stays (weakening it takes a touch, so a reset must not do it either).
      // Only what tightens: a kept ban would weaken the agent when taken back, so it stays for a code of its own.
      for (const r of resetRows(all)) await revoke(r);
      setConfirm(false);
      return { note: "Сброшено: окна закрыты, одобрения и оставленные изменения отозваны, «мои источники» очищены. Режим не менялся." };
    });
  return (
    <div className="space-y-4">
      {ov.guard ? <TrustCard ov={ov} rpc={rpc} refetch={refetch} /> : <div className={`${card} ${muted}`}>Режимы и «мои источники» есть только у сторожа решений.</div>}
      <Section title={exceptionsHeadline(all.length)}>
        <p className={`text-xs ${muted}`}>{EXCEPTIONS_HELP}</p>
        <label className="flex items-center gap-2"><input type="checkbox" checked={day} onChange={(e) => setDay(e.target.checked)} /> только за последние 24 часа</label>
        {rows.length === 0 ? <div className={`${card} ${muted}`}>{EXCEPTIONS_EMPTY}</div> : (
          <ul className="space-y-1" data-secure-bb-exceptions>
            {rows.map((r) => (
              <li key={r.key} className={`${card} flex flex-wrap items-center justify-between gap-2`} data-exception={r.kind}>
                <span className="min-w-0 flex-1">
                  <span className="break-words">{r.title}</span>
                  {r.detail ? <span className={`block text-xs ${muted}`}>{r.detail}</span> : null}
                </span>
                {r.needsCode === null ? (
                  <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await revoke(r); return { note: "Отозвано." }; })}>Отозвать</button>
                ) : (
                  <span className="flex basis-full flex-wrap items-center gap-2">
                    <span className="text-xs font-semibold text-red-800 dark:text-red-300">{REVOKE_CODE_NOTE} {r.needsCode}</span>
                    {pk.has ? <button className={btnDanger} disabled={act.busy || pk.problem !== null} onClick={() => void act.run(async () => { const t = await touchFor(rpc, { kind: "agents.revokeKept", ids: [r.revoke.id as number] }, () => undefined); if (!t) throw new Error("касание не требуется"); await revoke(r, { passkey: t.passkey }); return { note: "Отозвано." }; })}>Отозвать касанием</button> : null}
                    {!pk.keyOnly ? <><CodeField value={code} onChange={setCode} /><button className={btnDanger} disabled={act.busy || code.length !== 6} onClick={() => void act.run(async () => { await revoke(r, { code }); setCode(""); return { note: "Отозвано." }; })}>Отозвать кодом</button></> : null}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
        <Msg error={act.error} ok={act.ok} />
      </Section>
      <Section title="Подсказки">
        <label className="flex items-center gap-2" data-secure-bb-freq-setting><input type="checkbox" checked={!freqOff} onChange={(e) => onFreqOff(!e.target.checked)} /> {FREQ_SETTING_LABEL}</label>
      </Section>
      <Section title="Сбросить к умолчаниям">
        <div className={card}>
          <p>{RESET_NOTE}</p>
          {confirm ? (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="font-semibold">{resetConfirmText(all)}</span>
              <button className={btnDanger} disabled={act.busy} onClick={reset}>Да, сбросить</button>
              <button className={btn} onClick={() => setConfirm(false)}>Нет</button>
            </div>
          ) : <button className={`${btn} mt-2`} onClick={() => setConfirm(true)}>Сбросить к умолчаниям…</button>}
        </div>
      </Section>
    </div>
  );
}

// ---- first run --------------------------------------------------------------------------------------------------------------
