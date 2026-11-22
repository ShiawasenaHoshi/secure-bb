import { useEffect, useState } from "react";
import type { Overview } from "../src/overview";
import { OUTCOME_LABEL, firedText, verdictText } from "../src/sentinel/view";
import type { QuestionView } from "../src/sentinel/view";
import type { FeedRow } from "../src/sentinel/types";
import { defined } from "../src/rpc-input";
import { useCodeAction, CodeField, type Rpc } from "./code";
import { card, btn, input, muted, when, Fold, Msg } from "./ui";

export function FeedItem({ row, riskThreshold }: { row: FeedRow; riskThreshold: number }) {
  const fired = firedText(row);
  return (
    <li className="rounded-md border border-border p-2">
      <div className={`text-xs ${muted}`}>{when(row.ts)} · тред {row.threadId} · {row.providerId}{row.windowPlugin ? ` · окно: ${row.windowPlugin}` : ""}</div>
      <div className="font-mono text-xs break-all"><b>{row.tool}</b>{row.args ? ` — ${row.args}` : ""}</div>
      {row.task ? <div className={`text-xs ${muted}`}>задача: {row.task}</div> : <div className={`text-xs ${muted}`}>задача треда не найдена</div>}
      <div className={row.status === "not_scored" ? muted : fired ? "text-destructive" : ""}>{verdictText(row, riskThreshold)}</div>
      <div className={`text-xs ${muted}`}>человек: {OUTCOME_LABEL[row.outcome]}{row.outcomeAt ? ` (${when(row.outcomeAt)})` : ""}</div>
    </li>
  );
}

export function QuestionEditor({ q, rpc, refetch }: { q: QuestionView; rpc: Rpc; refetch: () => void }) {
  const [text, setText] = useState(q.instructions);
  const [threshold, setThreshold] = useState(String(q.threshold ?? ""));
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  useEffect(() => setText(q.instructions), [q.instructions]);
  useEffect(() => setThreshold(String(q.threshold ?? "")), [q.threshold]);
  const save = (patch: Record<string, unknown>) => void act.run(async () => { await rpc.call("sentinel.settings", defined({ ...patch, code }) as never); setCode(""); return { note: "Сохранено." }; });
  return (
    <Fold id={`sentinel-q-${q.id}`} className="rounded-md border border-border p-2" summary={`${q.label}${q.threshold !== null ? ` · порог ${q.threshold}` : ""}${q.edited ? " · изменён" : ""}`}>
      <div className="mt-2 space-y-2">
        <textarea className="w-full rounded-md border border-border bg-background p-2 text-xs" rows={4} value={text} onChange={(e) => setText(e.target.value)} />
        {q.threshold !== null ? (
          <label className="flex items-center gap-2">Порог срабатывания (0–1)
            <input className={`${input} w-20 tracking-normal`} value={threshold} onChange={(e) => setThreshold(e.target.value)} />
          </label>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <CodeField value={code} onChange={setCode} />
          <button className={btn} disabled={act.busy || code.length !== 6 || text === q.instructions} onClick={() => save({ instruction: { id: q.id, text } })}>Сохранить вопрос</button>
          {q.edited ? <button className={btn} disabled={act.busy || code.length !== 6} onClick={() => save({ instruction: { id: q.id, text: "" } })}>Вернуть исходный</button> : null}
          {q.threshold !== null ? <button className={btn} disabled={act.busy || code.length !== 6 || Number(threshold) === q.threshold || threshold.trim() === "" || !(Number(threshold) >= 0 && Number(threshold) <= 1)} onClick={() => save({ threshold: { id: q.id, value: Number(threshold) } })}>Сохранить порог</button> : null}
        </div>
        <Msg error={act.error} ok={act.ok} />
      </div>
    </Fold>
  );
}

export function SentinelSection({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const v = ov.sentinel;
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const set = (patch: Record<string, unknown>) => void act.run(async () => { await rpc.call("sentinel.settings", defined({ ...patch, code }) as never); setCode(""); });
  return (
    <div className="space-y-2">
      <div className={card}>
        <h3 className="font-semibold">Дозор на Jev — только наблюдение</h3>
        <p className={muted}>
          Выключен по умолчанию. Включённый, на каждую карточку одобрения (все провайдеры) в треде с открытым окном доверия задаёт решателю десять вопросов-категорий и оценку риска и пишет ответ в ленту.
          <b> На карточки он не отвечает</b>: до ступени 5 на карточку может ответить сам агент через API, поэтому решение дозора было бы декорацией. Что попало в запрос, маскируется кодом: секреты скрываются, аргументы сокращаются, но задача треда и действие уходят в облако. Ошибка, таймаут или лимит — запись «не оценено».
          Любое изменение — только с кодом.
        </p>
        <div className="mt-2 space-y-1">
          <label className="flex items-center gap-2">Провайдер Jev (ключ должен быть от него)
            <select className="rounded-md border border-border bg-background px-2 py-1" value={v.settings.provider} disabled={act.busy || code.length !== 6} onChange={(e) => set({ provider: e.target.value })}>
              <option value="typesafe">typesafe (api.typesafe.ai)</option>
              <option value="openrouter">openrouter</option>
            </select>
          </label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={v.settings.enabled} disabled={act.busy || code.length !== 6} onChange={(e) => set({ enabled: e.target.checked })} /> Дозор включён</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={v.settings.allThreads} disabled={act.busy || code.length !== 6} onChange={(e) => set({ allThreads: e.target.checked })} /> Следить во всех тредах, а не только с открытым окном доверия</label>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <CodeField value={code} onChange={setCode} />
          <span className={muted}>Введите код, затем нажмите на переключатель.</span>
        </div>
        <p className={`mt-2 ${muted}`}>
          Решатель: {v.solver}{v.keyConfigured ? " · ключ задан" : " · ключ не задан (BB_SECURE_BB_JEV_KEY_FILE): карточки будут записаны как «не оценено»"} · таймаут {Math.round(v.settings.timeoutMs / 1000)} с · не больше {v.settings.maxPerMinute} запросов в минуту
        </p>
        <Msg error={act.error} ok={act.ok} />
      </div>
      <div className={card}>
        <h3 className="font-semibold">Лента дозора ({v.feed.length})</h3>
        {v.feed.length === 0 ? <p className={muted}>Пока пусто.</p> : <ul className="mt-2 space-y-2">{v.feed.map((r) => <FeedItem key={r.id} row={r} riskThreshold={v.settings.riskThreshold} />)}</ul>}
      </div>
      <Fold id="sentinel-questions" className={card} summaryClassName="cursor-pointer font-semibold" summary={`Вопросы и пороги (${v.questions.length})`}>
        <div className="mt-2 space-y-2">{v.questions.map((q) => <QuestionEditor key={q.id} q={q} rpc={rpc} refetch={refetch} />)}</div>
      </Fold>
    </div>
  );
}
