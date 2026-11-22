import { useEffect, useState } from "react";
import type { Overview } from "../src/overview";
import type { ScanView } from "../src/scan/view";
import { defined } from "../src/rpc-input";
import { aiScanEmptyText } from "../src/ux";
import { scanHeadText } from "../src/cardview";
import { useCodeAction, CodeField } from "./code";
import { type Rpc } from "./touch";
import { card, btn, input, muted, when, Fold, Msg } from "./ui";

export const MODEL_STATUS: Record<string, string> = { clean: "чисто", flag: "флаг", refusal: "отказ", invalid: "невалидный ответ", timeout: "таймаут", error: "ошибка", unavailable: "недоступна" };

type ModelView = ScanView["models"][number];

function ModelReport({ m }: { m: ModelView }) {
  return (
    <div className="mt-1">
      <h4 className="font-medium">{m.label} — {MODEL_STATUS[m.status] ?? m.status}</h4>
      {m.report ? (
        <div className={muted}>
          <p>{m.report.summary}</p>
          <p>Совпадает с описанием: {m.report.matchesDescription ? "да" : "нет"}{m.report.descriptionNote ? ` — ${m.report.descriptionNote}` : ""}</p>
          {m.report.capabilities.length > 0 ? <ul className="list-disc pl-5">{m.report.capabilities.map((c, i) => <li key={i}>{c.kind}: {c.detail} ({c.file}{c.line ? `:${c.line}` : ""})</li>)}</ul> : null}
          {m.report.dataFlows.length > 0 ? <ul className="list-disc pl-5">{m.report.dataFlows.map((f, i) => <li key={i}>{f.from} → {f.to} ({f.file}{f.line ? `:${f.line}` : ""}){f.note ? ` — ${f.note}` : ""}</li>)}</ul> : null}
        </div>
      ) : <p className={muted}>{m.detail}</p>}
    </div>
  );
}

function ModelsFold({ scan }: { scan: ScanView }) {
  if (!scan.models.some((m) => m.report)) return null;
  return (
    <Fold id={`scan-${scan.id}-models`} className="mt-1" summary="Что нашли модели">
      {scan.models.map((m) => <ModelReport key={m.model} m={m} />)}
      <p className={muted}>Отправлено файлов: {scan.files}, {scan.chars} знаков (без комментариев). Модели одобрить версию не могут.</p>
    </Fold>
  );
}

/** Result of a scan next to the version it belongs to: not run / clean (date, models) / flags (what and where). */
export function ScanResultView({ scan, other, enabled }: { scan: ScanView | undefined; other?: string; enabled: boolean }) {
  if (!scan) return <p className={`mt-1 ${muted}`}>{aiScanEmptyText(enabled)}</p>;
  const silent = scan.models.filter((m) => m.status === "unavailable");
  return (
    <div className="mt-1">
      <p className={scan.status === "suspect" ? "font-semibold text-destructive" : muted}>ИИ-скан #{scan.id}, версия {scan.version}: {scanHeadText(scan, when)}{other ? ` · ${other}` : ""}</p>
      {scan.flags.length > 0 ? <ul className="list-disc pl-5 text-destructive">{scan.flags.map((f, i) => <li key={i}>{f}</li>)}</ul> : null}
      {silent.length > 0 ? <p className={muted}>Не отвечала: {silent.map((m) => `${m.label} (${m.detail})`).join("; ")}</p> : null}
      <ModelsFold scan={scan} />
    </div>
  );
}

export const PUBLISH_STATE: Record<string, string> = {
  off: "публикация выключена",
  "no-address": "публикация включена, но адрес репозитория не задан",
  "not-configured": "публикация не настроена: на сервере не задана переменная BB_SECURE_BB_PUBLISH_TOKEN_FILE",
  ready: "публикация готова",
};

export const PUBLISH_STATUS: Record<string, string> = { running: "идёт", published: "опубликовано", unchanged: "уже было опубликовано", failed: "ошибка", skipped: "пропущено" };

/** Where this version of this plugin went (or why it did not): the result of the last attempts, with the reason. */
export function PublicationLine({ ov, pluginId, version, rpc, refetch }: { ov: Overview; pluginId: string; version: string | null; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const mine = ov.publish.recent.filter((r) => r.pluginId === pluginId && (version === null || r.version === version || r.version === "—"));
  const last = mine[0];
  if (!ov.publish.settings.enabled && !last) return null;
  return (
    <div className="mt-1 text-xs">
      {last ? (
        <p className={last.status === "failed" ? "text-destructive" : muted}>
          Публикация {last.version}: {PUBLISH_STATUS[last.status] ?? last.status}
          {last.commit ? ` · коммит ${last.commit.slice(0, 10)}` : ""}{last.tag ? ` · тег ${last.tag}` : ""} · {when(last.finishedAt ?? last.startedAt)}
          {last.detail && last.status !== "published" ? ` — ${last.detail}` : ""}
        </p>
      ) : (
        <p className={muted}>Публикация: ещё не было ({PUBLISH_STATE[ov.publish.state]}).</p>
      )}
      {ov.publish.state === "ready" && version ? (
        <button className={`${btn} mt-1`} disabled={act.busy} onClick={() => void act.run(async () => { const r = await rpc.call("publish.run", { pluginId }); return { note: r.note }; })}>
          Опубликовать закреплённую версию
        </button>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

export function PublishCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const cur = ov.publish.settings;
  const [url, setUrl] = useState(cur.repoUrl);
  const [branch, setBranch] = useState(cur.branch);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  useEffect(() => setUrl(cur.repoUrl), [cur.repoUrl]);
  useEffect(() => setBranch(cur.branch), [cur.branch]);
  const set = (patch: Record<string, unknown>) =>
    void act.run(async () => {
      await rpc.call("publish.settings", defined({ ...patch, ...(code.length === 6 ? { code } : {}) }) as never);
      setCode("");
    });
  return (
    <div className={card}>
      <h3 className="font-semibold">Публикация замороженных версий (необязательный модуль)</h3>
      <p className={muted}>
        При заморозке окна secure-bb кладёт снимок плагина в git-репозиторий: каталог <code>&lt;id&gt;/</code>, коммит «id@версия frozen хеш», тег <code>id-vверсия</code>. Только наши плагины (снимки через propose). Включение, смена адреса и ветки — с кодом. Токен в настройках не хранится: путь к файлу задаёт переменная окружения сервера <code>BB_SECURE_BB_PUBLISH_TOKEN_FILE</code>.
      </p>
      <p className="mt-1">{PUBLISH_STATE[ov.publish.state]}</p>
      <div className="mt-2 space-y-1">
        <label className="flex items-center justify-between gap-2">Адрес (https)
          <input className={`${input} w-72 tracking-normal`} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/owner/bb-plugins.git" />
        </label>
        <label className="flex items-center justify-between gap-2">Ветка
          <input className={`${input} w-48 tracking-normal`} value={branch} onChange={(e) => setBranch(e.target.value)} />
        </label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={cur.enabled} disabled={act.busy || cur.repoUrl === ""} onChange={(e) => set({ enabled: e.target.checked })} /> Публиковать при заморозке окна</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={cur.onApprove} disabled={act.busy || !cur.enabled} onChange={(e) => set({ onApprove: e.target.checked })} /> Также при одобрении версии кодом</label>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {registered ? <CodeField value={code} onChange={setCode} /> : <span className={muted}>Второй фактор ещё не зарегистрирован.</span>}
        <button className={btn} disabled={act.busy || (url === cur.repoUrl && branch === cur.branch)} onClick={() => set({ repoUrl: url, branch })}>Сохранить адрес и ветку</button>
      </div>
      {ov.publish.recent.length > 0 ? (
        <Fold id="publish-recent" className="mt-1" summary={`Последние публикации (${ov.publish.recent.length})`}>
          <ul className="mt-1 list-disc pl-5">
            {ov.publish.recent.slice(0, 15).map((r) => (
              <li key={r.id} className={r.status === "failed" ? "text-destructive" : undefined}>
                {r.pluginId}@{r.version} · {PUBLISH_STATUS[r.status] ?? r.status} · {when(r.startedAt)}{r.detail ? ` — ${r.detail}` : ""}
              </li>
            ))}
          </ul>
        </Fold>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

export function ScanButton({ ov, target, rpc, refetch }: { ov: Overview; target: { pluginId: string } | { queueId: number }; rpc: Rpc; refetch: () => void }) {
  const act = useCodeAction(refetch);
  if (!ov.ai.settings.enabled) return null;
  return (
    <>
      <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("ai.scan", target); return { note: "Скан запущен: он идёт несколько минут." }; })}>
        Сканировать
      </button>
      <Msg error={act.error} ok={act.ok} />
    </>
  );
}

export function AiCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const ai = ov.ai;
  const [code, setCode] = useState("");
  const [model, setModel] = useState(ai.settings.secondModel);
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  useEffect(() => setModel(ai.settings.secondModel), [ai.settings.secondModel]);
  const set = (patch: Record<string, unknown>) =>
    void act.run(async () => {
      await rpc.call("ai.settings", defined({ ...patch, ...(code.length === 6 ? { code } : {}) }) as never);
      setCode("");
    });
  const box = (label: string, key: "enabled" | "autoFreeze" | "autoExternal" | "second", dependsOnModule = true) => (
    <label className="flex items-center gap-2">
      <input type="checkbox" checked={ai.settings[key]} disabled={act.busy || (dependsOnModule && !ai.settings.enabled)} onChange={(e) => set({ [key]: e.target.checked })} /> {label}
    </label>
  );
  return (
    <div className={card}>
      <h3 className="font-semibold">ИИ-скан плагинов (необязательный модуль)</h3>
      <p className={muted}>
        Выключен по умолчанию. Включённый, отправляет код плагина (без комментариев) в облако моделей. Модели только добавляют подозрение: одобрить версию они не могут. Включать — только с кодом (код плагина уходит в облако); выключать — без кода.
      </p>
      <div className="mt-2 space-y-1">
        {box("Модуль включён (кнопка «Сканировать»)", "enabled", false)}
        {box("Автоскан при заморозке (все плагины; отдельные — у плагина)", "autoFreeze")}
        {box("Автоскан внешних (каждая версия до решения)", "autoExternal")}
        {box("Вторая модель (cursor-agent, другой вендор, параллельно)", "second")}
        <label className="flex items-center justify-between gap-2">Имя второй модели (не Anthropic)
          <input className={`${input} w-48 tracking-normal`} value={model} onChange={(e) => setModel(e.target.value)} placeholder="например gpt-5" />
        </label>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {registered ? <CodeField value={code} onChange={setCode} /> : <span className={muted}>Код нужен для включения; второй фактор ещё не зарегистрирован.</span>}
        <button className={btn} disabled={act.busy || model === ai.settings.secondModel} onClick={() => set({ secondModel: model })}>Сохранить имя модели</button>
      </div>
      <p className={`mt-2 ${muted}`}>
        Claude: {ai.availability.claude.mode === "unavailable" ? "недоступен — " : ""}{ai.availability.claude.detail}
        {ai.availability.cursor ? ` · cursor-agent: ${ai.availability.cursor.found ? "" : "недоступен — "}${ai.availability.cursor.detail}` : ""}
      </p>
      {ai.recent.length > 0 ? (
        <Fold id="ai-recent" className="mt-1" summary={`Последние сканы (${ai.recent.length})`}>
          {ai.recent.map((r) => <ScanResultView key={r.id} scan={r} other={r.trigger} enabled={ai.settings.enabled} />)}
        </Fold>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}
