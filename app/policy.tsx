import { useEffect, useState } from "react";
import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview } from "../src/overview";
import { T } from "../src/text";
import { buildPolicyChange, buildPolicySetInput, buildPolicyTouchQuery } from "../src/rpc-input";
import { useCodeAction, CodeField, usePasskey, TouchNote, touchFor } from "./code";
import { card, btn, btnPrimary, input, muted, Msg } from "./ui";

export function PolicyCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const p = ov.policy;
  const [windowMin, setWindowMin] = useState(String(p.windowMin));
  const [capMin, setCapMin] = useState(String(p.capMin));
  const [mode, setMode] = useState<"sliding" | "fixed">(p.mode);
  const [scope, setScope] = useState<"tree" | "thread">(p.scope);
  const [cfgWindowMin, setCfgWindowMin] = useState(String(p.cfgWindowMin));
  const [cfgCapMin, setCfgCapMin] = useState(String(p.cfgCapMin));
  const [cfgMode, setCfgMode] = useState<"sliding" | "fixed">(p.cfgMode);
  const [autoSafe, setAutoSafe] = useState(p.autoSafe);
  const [flowDowngrade, setFlowDowngrade] = useState(p.flowDowngrade);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const pk = usePasskey(ov);
  const [touching, setTouching] = useState<string | null>(null);
  useEffect(() => {
    setAutoSafe(p.autoSafe);
    setFlowDowngrade(p.flowDowngrade);
    setWindowMin(String(p.windowMin));
    setCapMin(String(p.capMin));
    setMode(p.mode);
    setScope(p.scope);
    setCfgWindowMin(String(p.cfgWindowMin));
    setCfgCapMin(String(p.cfgCapMin));
    setCfgMode(p.cfgMode);
  }, [p.windowMin, p.capMin, p.mode, p.scope, p.cfgWindowMin, p.cfgCapMin, p.cfgMode, p.autoSafe, p.flowDowngrade]);
  return (
    <div className={card}>
      <h3 className="font-semibold">Окна доверия: настройки</h3>
      <p className={muted}>Хранятся в базе secure-bb, не в настройках плагина. Расширять (больше размер или потолок, скользящее, дерево) — с кодом; сужать — без.</p>
      <div className="mt-2 grid gap-2 sm:grid-cols-2">
        <label className="flex items-center justify-between gap-2">Размер окна, мин
          <input className={input} inputMode="numeric" value={windowMin} onChange={(e) => setWindowMin(e.target.value.replace(/\D/g, ""))} />
        </label>
        <label className="flex items-center justify-between gap-2">Потолок, мин
          <input className={input} inputMode="numeric" value={capMin} onChange={(e) => setCapMin(e.target.value.replace(/\D/g, ""))} />
        </label>
        <label className="flex items-center justify-between gap-2">Режим
          <select className={input} value={mode} onChange={(e) => setMode(e.target.value as "sliding" | "fixed")}>
            <option value="sliding">скользящее</option>
            <option value="fixed">фиксированное</option>
          </select>
        </label>
        <label className="flex items-center justify-between gap-2">Охват
          <select className={input} value={scope} onChange={(e) => setScope(e.target.value as "tree" | "thread")}>
            <option value="tree">тред и всё дерево</option>
            <option value="thread">только этот тред</option>
          </select>
        </label>
        <label className="flex items-center justify-between gap-2">Окно «конфигурация», мин
          <input className={input} inputMode="numeric" value={cfgWindowMin} onChange={(e) => setCfgWindowMin(e.target.value.replace(/\D/g, ""))} />
        </label>
        <label className="flex items-center justify-between gap-2">Потолок «конфигурации», мин
          <input className={input} inputMode="numeric" value={cfgCapMin} onChange={(e) => setCfgCapMin(e.target.value.replace(/\D/g, ""))} />
        </label>
        <label className="flex items-center justify-between gap-2">Режим «конфигурации»
          <select className={input} value={cfgMode} onChange={(e) => setCfgMode(e.target.value as "sliding" | "fixed")}>
            <option value="sliding">скользящее</option>
            <option value="fixed">фиксированное</option>
          </select>
        </label>
      </div>
      <label className="mt-3 flex items-start gap-2">
        <input type="checkbox" className="mt-1" checked={flowDowngrade} onChange={(e) => setFlowDowngrade(e.target.checked)} />
        <span>Снижать уровень карточки, если проверки не нашли, куда уходит прочитанное (<span className="font-mono">flow.downgrade</span>)</span>
      </label>
      <p className={`mt-1 ${muted}`}>Выключено: «по коду никуда не отправляет» говорится, но карточка плагина с сетью остаётся красной, как раньше. Включение ослабляет защиту — с кодом или касанием.</p>
      {ov.guard ? (
        <p className={`mt-3 ${muted}`}>Размер, потолок и режим окна хранит сторож (расширять — с кодом, он проверит его сам). Окно доверия нужно для плагинов не из «моих источников». Версия плагина из «моих источников» проходит и без окна, пока не просит новых прав; новое право и всё остальное ждёт вашего касания.</p>
      ) : (
        <>
          <label className="mt-3 flex items-start gap-2">
            <input type="checkbox" className="mt-1" checked={autoSafe} onChange={(e) => setAutoSafe(e.target.checked)} />
            <span>Автопропуск версий без возможностей (без касания)</span>
          </label>
          <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">{T.autoSafeWarning}</p>
        </>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {pk.has ? <span className={muted}>касание или код:</span> : null}
        {pk.keyOnly ? null : <CodeField value={code} onChange={setCode} />}
        <button
          className={btnPrimary}
          disabled={act.busy || (pk.has && pk.problem !== null && pk.keyOnly)}
          onClick={() =>
            void act.run(async () => {
              // Guard mode has no "safe class passes": autoSafe is not sent there (bb rejects undefined fields in an RPC input).
              const change = buildPolicyChange({ autoSafe: ov.guard ? undefined : autoSafe, windowMin, capMin, mode, scope, cfgWindowMin, cfgCapMin, cfgMode, flowDowngrade });
              // With a key and no code typed: the touch (if the change widens anything; a narrowing needs none).
              const t = pk.has && code.length !== 6 ? await touchFor(rpc, buildPolicyTouchQuery(change), (d) => setTouching(`Подтвердите касанием. Сторож: «${d}»`)) : null;
              await rpc.call("policy.set", buildPolicySetInput(change, t ? { passkey: t.passkey } : code.length === 6 ? { code } : {}) as never);
              setCode("");
              setTouching(null);
              return t ? { note: `Сохранено касанием. Сторож описал действие так: «${t.description}».` } : undefined;
            })
          }
        >
          {pk.has && code.length !== 6 ? "Сохранить (касанием, если расширяет)" : "Сохранить"}
        </button>
      </div>
      {pk.has && pk.problem ? <p className="mt-1 text-destructive">{pk.problem}</p> : null}
      <TouchNote text={touching} />
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

export function TrustedRepos({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [pattern, setPattern] = useState("");
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const run = (change: { add: string } | { remove: string }) =>
    void act.run(async () => {
      const r = await rpc.call("trusted.set", { ...change, code });
      setCode("");
      setPattern("");
      return r;
    });
  return (
    <div className={card}>
      <p>
        Свои репозитории (github.com): <span className="font-mono">owner/name</span> или <span className="font-mono">owner/*</span>. <span className="font-mono">git clone/fetch/pull/ls-remote</span> по их адресу и вызовы <span className="font-mono">gh</span> с <span className="font-mono">--repo</span> или адресом такого репозитория не загрязняют тред. <span className="font-mono">gh</span> без явного репозитория загрязняет. Список пуст по умолчанию; менять — только с кодом. Изменение действует на события, прочитанные после него.
      </p>
      {ov.trustedRepos.length === 0 ? <p className={`mt-2 ${muted}`}>Список пуст: любой clone/fetch по адресу загрязняет.</p> : (
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {ov.trustedRepos.map((r) => (
            <li key={r} className="flex items-center gap-2">
              {r}
              <button className={btn} disabled={act.busy || code.length !== 6 || !registered} onClick={() => run({ remove: r })}>Убрать</button>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="rounded border border-border bg-transparent px-2 py-1 font-mono text-xs" placeholder="owner/name или owner/*" value={pattern} onChange={(e) => setPattern(e.target.value)} />
        <CodeField value={code} onChange={setCode} />
        <button className={btnPrimary} disabled={act.busy || code.length !== 6 || pattern.trim() === "" || !registered} onClick={() => run({ add: pattern })}>Добавить</button>
      </div>
      <Msg error={act.error} />
    </div>
  );
}
