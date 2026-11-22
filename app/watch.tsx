import { useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { CATEGORY_LABEL, WINDOW_SCOPES, SCOPE_LABEL } from "../src/watch/model";
import type { Drift, WindowScope } from "../src/watch/model";
import { useApproval, RoutineCode } from "./approval";
import { useCodeAction, CodeField } from "./code";
import { card, btn, btnPrimary, input, muted, when, Fold, Msg } from "./ui";

export const driftStatus: Record<Drift["status"], string> = {
  open: "открыто",
  "rollback-failed": "откат не удался",
  "rolled-back": "откатано",
  "accepted-window": "принято окном",
  "accepted-touch": "принято вами",
  reverted: "вернулось",
};

export function DriftRow({ d, registered, rpc, refetch }: { d: Drift; registered: boolean; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const ap = useApproval();
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const isOpen = d.status === "open" || d.status === "rollback-failed";
  const change = d.kind === "added" ? `новое: ${d.after}` : d.kind === "removed" ? `пропало (было: ${d.before})` : `${d.before} → ${d.after}`;
  return (
    <div className={`${card} ${isOpen ? "border-yellow-500/60" : ""}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{d.label}</h3>
        <span className={muted}>{driftStatus[d.status]} · {when(d.firstSeen)}</span>
      </div>
      <p className="break-all">{CATEGORY_LABEL[d.category]}: {change}</p>
      {d.note ? <p className={muted}>{d.note}</p> : null}
      {isOpen && registered ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} />
          <button className={btn} disabled={act.busy || !ap.ready(code)} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("watch.accept", { id: d.id, ...proof })); setCode(""); })}>
            Принять
          </button>
          {d.rollbackable ? (
            <button className={btn} disabled={act.busy || !ap.ready(code)} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("watch.rollback", { id: d.id, ...proof })); setCode(""); })}>
              Откатить
            </button>
          ) : (
            <span className={`text-xs ${muted}`}>безопасного отката нет</span>
          )}
        </div>
      ) : null}
      <Msg error={act.error} />
    </div>
  );
}

export function WatchSection({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const w = ov.watch;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const [code, setCode] = useState("");
  const [scopes, setScopes] = useState<WindowScope[]>([]);
  const act = useCodeAction(refetch);
  const open = w.drifts.filter((d) => d.status === "open" || d.status === "rollback-failed");
  const settled = w.drifts.filter((d) => d.status !== "open" && d.status !== "rollback-failed");
  const toggle = (s: WindowScope) => setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const ap = useApproval();
  const need = code.length !== 6 || act.busy || !registered; // dangerous: a fresh code only
  const needRoutine = !ap.ready(code) || act.busy || !registered; // routine: a code or the session
  return (
    <div className="space-y-3">
      <div className={card}>
        <p>
          {w.baselineAt === null ? (
            <b>Эталон не принят: сторож только показывает, что видит, и ничего не оценивает.</b>
          ) : (
            <>Эталон принят {when(w.baselineAt)}.</>
          )}{" "}
          Проверка раз в минуту и по событиям{w.lastScanAt ? `; последняя — ${when(w.lastScanAt)}, объектов: ${w.observedCount}` : ""}.
        </p>
        <p className={`mt-1 ${muted}`}>
          Пока агенты работают от того же пользователя (ступени 0–2) и API без токенов, агент может вернуть изменение обратно: это сигнализация, не замок.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} />
          <button className={btnPrimary} disabled={needRoutine} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("watch.acceptAll", { ...proof })); setCode(""); return { note: `Эталон принят, объектов: ${r.items}` }; })}>
            {w.baselineAt === null ? "Принять текущую конфигурацию как эталон" : "Принять всё текущее как эталон"}
          </button>
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("watch.scan"); })}>
            Проверить сейчас
          </button>
        </div>
        {!registered ? <p className={`mt-2 ${muted}`}>Сначала зарегистрируйте второй фактор.</p> : null}
        <Msg error={act.error} ok={act.ok} />
      </div>

      <div className={card}>
        <h3 className="font-semibold">Откат: {w.rollbackEnabled ? "включён" : "выключен"}</h3>
        <p className={muted}>
          Откатывает только безопасное и только вне окна: выключает включённый встроенный плагин из списка, удаляет новую переменную окружения, возвращает инструкции. Остальное только показывается.
          Включить можно без кода (это ужесточение), выключить — только кодом.
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {w.rollbackEnabled ? <CodeField value={code} onChange={setCode} /> : null}
          <button className={btn} disabled={act.busy || (w.rollbackEnabled && need)} onClick={() => void act.run(async () => { await rpc.call("watch.rollbackMode", { enabled: !w.rollbackEnabled, ...(w.rollbackEnabled ? { code } : {}) }); setCode(""); })}>
            {w.rollbackEnabled ? "Выключить откат" : "Включить откат"}
          </button>
        </div>
      </div>

      <div className={card}>
        <h3 className="font-semibold">Окно доверия «конфигурация»</h3>
        <p className={muted}>
          Изменения выбранного в окне принимаются в эталон без кода; по умолчанию 10 минут, скользящее. Вход в аккаунт, потолки разрешений, настройки провайдеров, эксперименты и safe-mode окном не принимаются.
        </p>
        <div className="mt-2 flex flex-wrap gap-3">
          {WINDOW_SCOPES.map((s) => (
            <label key={s} className="flex items-center gap-1">
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggle(s)} /> {SCOPE_LABEL[s]}
            </label>
          ))}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} />
          <button className={btnPrimary} disabled={needRoutine || scopes.length === 0 || w.baselineAt === null} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("watch.window.open", { scopes, ...proof })); setCode(""); setScopes([]); })}>
            Открыть окно
          </button>
        </div>
      </div>

      <h3 className="font-semibold">Расхождения ({open.length})</h3>
      {open.length === 0 ? <div className={`${card} ${muted}`}>Открытых расхождений нет.</div> : open.map((d) => <DriftRow key={d.id} d={d} registered={registered} rpc={rpc} refetch={refetch} />)}
      {settled.length > 0 ? (
        <Fold id="watch-settled" summaryClassName={`cursor-pointer ${muted}`} summary={`Лента (${settled.length})`}>
          <div className="mt-2 space-y-2">{settled.map((d) => <DriftRow key={d.id} d={d} registered={registered} rpc={rpc} refetch={refetch} />)}</div>
        </Fold>
      ) : null}

      {w.failed.length > 0 ? (
        <div className={`${card} border-yellow-500/60`}>
          <h4 className="font-medium">Не удалось прочитать сейчас (здесь расхождения не оцениваются)</h4>
          <ul className="list-disc pl-5">{w.failed.map((f) => <li key={f.source} className="break-all"><span className="font-mono">{f.source}</span>: {f.reason}</li>)}</ul>
        </div>
      ) : null}
      {w.notApplicable.length > 0 ? (
        <div className={card}>
          <h4 className="font-medium">Не применимо (читать нечего)</h4>
          <ul className="list-disc pl-5">{w.notApplicable.map((f) => <li key={f.source} className="break-all"><span className="font-mono">{f.source}</span>: {f.reason}</li>)}</ul>
        </div>
      ) : null}
      <Fold id="watch-blind" className={card} summaryClassName="cursor-pointer font-medium" summary={`Что не наблюдается вообще (${w.blind.length})`}>
        <ul className="mt-2 list-disc pl-5">{w.blind.map((b) => <li key={b.source}>{b.reason}</li>)}</ul>
      </Fold>
    </div>
  );
}
