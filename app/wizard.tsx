import { useState } from "react";
import type { Overview } from "../src/overview";
import type { TrustMode } from "../src/guardlink";
import { MODE_DESCRIPTIONS, MODE_NAMES } from "../src/ux";
import { friendlySource, WIZARD_SOURCES_TEXT, secondFactorText } from "../src/ux";
import { useCodeAction, type Rpc } from "./code";
import { useProof, ProofField } from "./confirm";
import { MODE_RANK_UI, ModePicker } from "./mode-picker";
import { muted, Msg } from "./ui";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Switch } from "../components/ui/switch";
import { cn } from "../lib/utils";

/** Three screens: the mode, "my sources", the second factor. Shown once (the page remembers that it was closed: a convenience, not a security fact). */
export function Wizard({ ov, rpc, refetch, onClose, startStep = 0 }: { ov: Overview; rpc: Rpc; refetch: () => void; onClose: () => void; startStep?: number }) {
  const t = ov.guard?.trust ?? null;
  const [step, setStep] = useState(startStep);
  const [mode, setMode] = useState<TrustMode>(t?.mode ?? "simple");
  const [picked, setPicked] = useState<string[]>([]);
  const act = useCodeAction(refetch);
  const proof = useProof(ov, rpc, "wizard");
  if (!t) return null;
  const suggestions = ov.sourceSuggestions.filter((s) => !t.mySources.includes(s));
  const keys = ov.guard?.passkey?.keys ?? [];
  const second = ov.totp.state === "locked" || ov.totp.state === "external" || keys.length > 0;
  const next = () =>
    void act.run(async () => {
      if (mode !== t.mode) {
        const weaker = MODE_RANK_UI[mode] < MODE_RANK_UI[t.mode];
        await proof.run({ kind: "trust.mode", trustMode: mode }, (p) => rpc.call("trust.mode", { mode, ...p } as never), { optional: true, what: `Режим «${MODE_NAMES[mode]}»`, detail: weaker ? `Защита станет слабее: ${MODE_DESCRIPTIONS[mode]}` : MODE_DESCRIPTIONS[mode] });
      }
      setStep(1);
    });
  const addSources = () =>
    void act.run(async () => {
      if (picked.length > 0) await proof.run({ kind: "trust.add", entries: picked }, (p) => rpc.call("trust.add", { entries: picked, ...p } as never), { what: `Добавить источники: ${picked.length}`, detail: picked.map(friendlySource).join("; ") });
      setStep(2);
    });
  return (
    <Card className="space-y-3 p-4 text-sm" data-secure-bb-wizard={step}>
      <div className="flex items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold">Первый запуск</h2>
          <p className={`text-xs ${muted}`} data-secure-bb-wizard-step>шаг {step + 1} из 3</p>
        </div>
        <Button size="sm" variant="ghost" onClick={onClose}>Пропустить</Button>
      </div>
      <div className="flex gap-1" aria-hidden>
        {[0, 1, 2].map((i) => (
          <span key={i} className={cn("h-1 flex-1 rounded-full", i <= step ? "bg-foreground" : "bg-muted")} />
        ))}
      </div>
      {step === 0 ? (
        <div className="space-y-3">
          <p>Как строго проверять плагины? Это можно поменять потом.</p>
          <ModePicker value={mode} onChange={setMode} disabled={act.busy} />
          <ProofField proof={proof} />
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" disabled={act.busy || !proof.registered && mode !== t.mode} onClick={next}>Дальше</Button>
          </div>
        </div>
      ) : null}
      {step === 1 ? (
        <div className="space-y-3">
          <p>{WIZARD_SOURCES_TEXT}</p>
          {suggestions.length === 0 ? <p className={muted}>Подходящих источников у установленных плагинов не нашлось. Свои можно добавить позже на вкладке «Доверие и исключения».</p> : suggestions.map((s) => (
            <label key={s} className="flex items-center gap-2">
              <Switch checked={picked.includes(s)} onCheckedChange={(on) => setPicked(on ? [...picked, s] : picked.filter((x) => x !== s))} aria-label={friendlySource(s)} />
              <span className="text-sm">{friendlySource(s)}</span>
            </label>
          ))}
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" disabled={act.busy || (picked.length > 0 && !proof.ready())} onClick={addSources}>{picked.length > 0 ? "Добавить и дальше" : "Дальше"}</Button>
            <Button size="sm" variant="ghost" onClick={() => setStep(0)}>Назад</Button>
          </div>
        </div>
      ) : null}
      {step === 2 ? (
        <div className="space-y-3">
          <p>Второй фактор подтверждает ваши решения: без него одобрить нельзя.</p>
          <p className={second ? "" : "font-medium text-destructive"}>{secondFactorText({ codes: ov.totp.state === "locked" || ov.totp.state === "external", keys: keys.length })}</p>
          {second ? null : <p>На машине со сторожем выполните <span className="font-mono">sbb-guard setup</span>: мастер сам подключит коды или ключ, напечатает ссылку для этой страницы и проверит касание. Если такой команды в вашей сборке ещё нет, используйте <span className="font-mono">sudo sbb-guard passkey-enroll</span>, а затем вернитесь сюда.</p>}
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={onClose}>Готово</Button>
            <Button size="sm" variant="ghost" onClick={() => setStep(1)}>Назад</Button>
          </div>
        </div>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </Card>
  );
}
