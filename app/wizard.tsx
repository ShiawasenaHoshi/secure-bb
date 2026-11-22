import { useState } from "react";
import type { Overview } from "../src/overview";
import type { TrustMode } from "../src/guardlink";
import { MODE_DESCRIPTIONS, MODE_NAMES } from "../src/ux";
import { friendlySource, WIZARD_SOURCES_TEXT, secondFactorText } from "../src/ux";
import { useCodeAction, type Rpc } from "./code";
import { useProof, ProofField, ProofNotes } from "./confirm";
import { card, btn, btnPrimary, input, muted, Msg } from "./ui";

/** Three screens: the mode, "my sources", the second factor. Shown once (the page remembers that it was closed: a convenience, not a security fact). */
export function Wizard({ ov, rpc, refetch, onClose }: { ov: Overview; rpc: Rpc; refetch: () => void; onClose: () => void }) {
  const t = ov.guard?.trust ?? null;
  const [step, setStep] = useState(0);
  const [mode, setMode] = useState<TrustMode>(t?.mode ?? "simple");
  const [picked, setPicked] = useState<string[]>([]);
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc);
  if (!t) return null;
  const suggestions = ov.sourceSuggestions.filter((s) => !t.mySources.includes(s));
  const keys = ov.guard?.passkey?.keys ?? [];
  const second = ov.totp.state === "locked" || ov.totp.state === "external" || keys.length > 0;
  return (
    <div className={card} data-secure-bb-wizard={step}>
      <div className="flex items-baseline justify-between gap-2">
        <h2 className="text-base font-semibold">Первый запуск · шаг {step + 1} из 3</h2>
        <button className={btn} onClick={onClose}>Пропустить</button>
      </div>
      {step === 0 ? (
        <div className="mt-2 space-y-2">
          <p>Как строго проверять плагины? Это можно поменять потом.</p>
          {(["simple", "detailed", "strict"] as const).map((m) => (
            <label key={m} className="flex items-start gap-2">
              <input type="radio" name="sbb-mode" className="mt-1" checked={mode === m} onChange={() => setMode(m)} />
              <span><b>{MODE_NAMES[m]}</b>{m === "simple" ? " (рекомендуется)" : ""}<br /><span className={muted}>{MODE_DESCRIPTIONS[m]}</span></span>
            </label>
          ))}
          <div className="flex flex-wrap items-center gap-2">
            {mode !== t.mode ? <ProofField proof={proof} /> : null}
            <button className={btnPrimary} disabled={act.busy || (mode !== t.mode && !proof.ready())} onClick={() => void act.run(async () => { if (mode !== t.mode) await proof.run({ kind: "trust.mode", trustMode: mode }, (p) => rpc.call("trust.mode", { mode, ...p } as never)); setStep(1); })}>Дальше</button>
          </div>
        </div>
      ) : null}
      {step === 1 ? (
        <div className="mt-2 space-y-2">
          <p>{WIZARD_SOURCES_TEXT}</p>
          {suggestions.length === 0 ? <p className={muted}>Подходящих источников у установленных плагинов не нашлось. Свои можно добавить позже на вкладке «Исключения и доверие».</p> : suggestions.map((s) => (
            <label key={s} className="flex items-center gap-2"><input type="checkbox" checked={picked.includes(s)} onChange={(e) => setPicked(e.target.checked ? [...picked, s] : picked.filter((x) => x !== s))} /><span className="text-sm">{friendlySource(s)}</span></label>
          ))}
          <div className="flex flex-wrap items-center gap-2">
            {picked.length > 0 ? <ProofField proof={proof} /> : null}
            <button className={btnPrimary} disabled={act.busy || (picked.length > 0 && !proof.ready())} onClick={() => void act.run(async () => { if (picked.length > 0) await proof.run({ kind: "trust.add", entries: picked }, (p) => rpc.call("trust.add", { entries: picked, ...p } as never)); setStep(2); })}>{picked.length > 0 ? "Добавить и дальше" : "Пропустить"}</button>
            <button className={btn} onClick={() => setStep(0)}>Назад</button>
          </div>
        </div>
      ) : null}
      {step === 2 ? (
        <div className="mt-2 space-y-2">
          <p>Второй фактор подтверждает ваши решения: без него одобрить нельзя.</p>
          <p className={second ? "text-green-700 dark:text-green-400" : "font-semibold text-red-700 dark:text-red-400"}>{secondFactorText({ codes: ov.totp.state === "locked" || ov.totp.state === "external", keys: keys.length })}</p>
          {second ? null : <p>На машине со сторожем выполните <span className="font-mono">sbb-guard setup</span>: мастер сам подключит коды или ключ, напечатает ссылку для этой страницы и проверит касание. Если такой команды в вашей сборке ещё нет, используйте <span className="font-mono">sudo sbb-guard passkey-enroll</span>, а затем вернитесь сюда.</p>}
          <div className="flex flex-wrap gap-2">
            <button className={btnPrimary} onClick={onClose}>Готово</button>
            <button className={btn} onClick={() => setStep(1)}>Назад</button>
          </div>
        </div>
      ) : null}
      <ProofNotes proof={proof} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}
