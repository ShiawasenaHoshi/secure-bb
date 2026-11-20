// secure-bb — frontend: the secure-bb page (the plugin gate is a section of it) and an always-visible banner
// for open trust windows. Plain React + host theme tokens; no vendored UI,
// no third-party code (this bundle runs in bb's origin, so it stays minimal).
import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { definePluginApp, useRealtime, useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "./server";
import type { Overview, PluginView, WindowView } from "./src/overview";
import type { QueueRow } from "./src/store";
import type { CheckResult } from "./src/checks/types";
import type { ConfigWindowView } from "./src/watch/watchdog";
import { CATEGORY_LABEL, WINDOW_SCOPES, SCOPE_LABEL } from "./src/watch/model";
import type { Drift, WindowScope } from "./src/watch/model";

// ---------------------------------------------------------------- helpers --

const card = "rounded-lg border border-border bg-card p-4 text-sm text-card-foreground";
const btn =
  "rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted disabled:opacity-50";
const btnPrimary =
  "rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50";
const input = "w-28 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm tracking-widest";
const muted = "text-muted-foreground";

const minutes = (sec: number): string => (sec < 60 ? `${sec} с` : `${Math.ceil(sec / 60)} мин`);
const when = (ms: number): string => new Date(ms).toLocaleString();

function useOverview() {
  const rpc = useRpc<SecureBbRpc>();
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refetch = useCallback(() => {
    rpc.call("overview").then(
      (ov) => {
        setData(ov);
        setError(null);
      },
      (e: unknown) => setError(e instanceof Error ? e.message : String(e)),
    );
  }, [rpc]);
  useEffect(() => {
    refetch();
    const timer = setInterval(refetch, 20_000);
    return () => clearInterval(timer);
  }, [refetch]);
  useRealtime("changed", refetch);
  return { rpc, data, error, refetch };
}

/** Counts down locally between refetches. */
function useNow(): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

function Msg({ error, ok }: { error?: string | null; ok?: string | null }) {
  if (error) return <p className="mt-2 text-sm text-destructive">{error}</p>;
  if (ok) return <p className={`mt-2 text-sm ${muted}`}>{ok}</p>;
  return null;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h2 className="text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

/** A one-shot action that needs a fresh TOTP code. */
function useCodeAction(refetch: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    setOk(null);
    try {
      const res = (await fn()) as { note?: string } | undefined;
      if (res?.note) setOk(res.note);
      refetch();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, ok, run };
}

function CodeField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <input
      className={input}
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={6}
      placeholder="код"
      aria-label="Код из приложения-аутентификатора"
      value={value}
      onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 6))}
    />
  );
}

// ------------------------------------------------------------ window bar ---

function windowLine(w: WindowView, remainingSec: number): string {
  const subs = w.scope === "tree" && w.subthreads > 0 ? ` и ${w.subthreads} сабтредов` : "";
  const only = w.scope === "thread" ? " (только этот тред)" : "";
  return `Окно доверия: плагин ${w.pluginId} из треда ${w.threadId}${subs}${only} — ещё ${minutes(remainingSec)}`;
}

function cfgWindowLine(w: ConfigWindowView, remainingSec: number): string {
  return `Окно доверия: ${w.scopeLabels.join(", ")} — ещё ${minutes(remainingSec)}`;
}

function WindowRows({ windows, cfgWindows, rpc, refetch }: { windows: WindowView[]; cfgWindows: ConfigWindowView[]; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const now = useNow();
  const act = useCodeAction(refetch);
  const [code, setCode] = useState("");
  const [closing, setClosing] = useState<number | null>(null);
  const [closingCfg, setClosingCfg] = useState<number | null>(null);
  if (windows.length === 0 && cfgWindows.length === 0) return null;
  return (
    <div className="space-y-2">
      {cfgWindows.map((w) => {
        const remaining = Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000));
        return (
          <div key={`cfg-${w.id}`} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">{cfgWindowLine(w, remaining)}</span>
            {closingCfg === w.id ? (
              <>
                <CodeField value={code} onChange={setCode} />
                <button
                  className={btnPrimary}
                  disabled={act.busy || code.length !== 6}
                  onClick={() =>
                    void act.run(async () => {
                      await rpc.call("watch.window.close", { windowId: w.id, code });
                      setCode("");
                      setClosingCfg(null);
                    })
                  }
                >
                  Закрыть
                </button>
              </>
            ) : (
              <button className={btn} onClick={() => setClosingCfg(w.id)}>
                Закрыть
              </button>
            )}
          </div>
        );
      })}
      {windows.map((w) => {
        const remaining = Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000));
        return (
          <div key={w.id} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">{windowLine(w, remaining)}</span>
            {closing === w.id ? (
              <>
                <CodeField value={code} onChange={setCode} />
                <button
                  className={btnPrimary}
                  disabled={act.busy || code.length !== 6}
                  onClick={() =>
                    void act.run(async () => {
                      await rpc.call("window.close", { windowId: w.id, code });
                      setCode("");
                      setClosing(null);
                    })
                  }
                >
                  Закрыть
                </button>
              </>
            ) : (
              <button className={btn} onClick={() => setClosing(w.id)}>
                Закрыть
              </button>
            )}
          </div>
        );
      })}
      <Msg error={act.error} />
    </div>
  );
}

/** Always-on-screen strip: open windows are never hidden. */
function WindowOverlay() {
  const { rpc, data, refetch } = useOverview();
  if (!data || (data.windows.length === 0 && data.watch.windows.length === 0)) return null;
  return (
    <div className="pointer-events-auto fixed bottom-3 left-3 z-50 max-w-[min(32rem,calc(100vw-1.5rem))] rounded-lg border border-border bg-card p-2 shadow-lg" data-secure-bb-banner>
      <WindowRows windows={data.windows} cfgWindows={data.watch.windows} rpc={rpc} refetch={refetch} />
    </div>
  );
}

// ---------------------------------------------------------------- sections --

const dot: Record<string, string> = { ok: "bg-green-500", warn: "bg-yellow-500", bad: "bg-red-500", unknown: "bg-gray-400" };

function StageCard({ ov }: { ov: Overview }) {
  const a = ov.assessment;
  const names = ["Ступень 0 — обычный bb", "Ступень 1 — bb с хуком", "Ступень 2 — гейт обязателен", "Ступень 3 — агенты отдельно", "Ступень 4 — сеть закрыта", "Ступень 5 — аутентификация API"];
  return (
    <div className={card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-lg font-semibold">{names[a.stage]}</h3>
        <span className={muted}>{ov.hookRegistered ? "проверка до загрузки кода" : "режим «после факта»"}</span>
      </div>
      {a.honest.map((h) => (
        <p key={h} className="mt-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 p-2">
          {h}
        </p>
      ))}
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div>
          <h4 className="font-medium">Что защищено</h4>
          <ul className="list-disc pl-5">{a.protects.map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
        <div>
          <h4 className="font-medium">Чего нет</h4>
          {a.missing.length === 0 ? <p className={muted}>—</p> : <ul className="list-disc pl-5">{a.missing.map((p) => <li key={p}>{p}</li>)}</ul>}
        </div>
      </div>
      <p className="mt-3"><span className="font-medium">Следующий шаг: </span>{a.nextStep}</p>
      <details className="mt-3">
        <summary className="cursor-pointer font-medium">Проверки</summary>
        <ul className="mt-2 space-y-1.5">
          {a.checks.map((c) => (
            <li key={c.id} className="flex gap-2">
              <span className={`mt-1.5 size-2.5 shrink-0 rounded-full ${dot[c.state]}`} aria-label={c.state} />
              <span><span className="font-medium">{c.label}.</span> {c.detail}</span>
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

function Registration({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [qr, setQr] = useState<{ secret: string; uri: string; matrix: boolean[][] } | null>(null);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const state = ov.totp.state;

  if (state === "locked") return <div className={card}>✓ Второй фактор (TOTP) зарегистрирован. Секрет больше нигде не показывается.</div>;
  if (state === "external") return <div className={card}>✓ Секрет TOTP берётся из внешнего файла (BB_SECURE_BB_TOTP_FILE).</div>;
  if (state === "external-broken") return <div className={`${card} border-destructive`}>Задан BB_SECURE_BB_TOTP_FILE, но файл не читается или в нём нет секрета. Одобрения невозможны.</div>;

  const blockedByPlugins = ov.thirdPartyRunning.length > 0;
  return (
    <div className={`${card} border-2 border-destructive`}>
      <h3 className="text-base font-semibold text-destructive">Зарегистрируйте второй фактор сейчас</h3>
      {ov.totp.pendingUnattended && qr === null ? (
        <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">
          Регистрация была начата не с этой страницы (кто — см. журнал). Её нельзя подтвердить: нажмите «Начать заново» и сканируйте новый код.
        </p>
      ) : null}
      <p className="mt-1">
        Без неё одобрить плагин нельзя. Сделайте это сразу: до регистрации любой процесс на этой машине (в том числе агент) может её начать раньше вас.
      </p>
      {blockedByPlugins ? (
        <div className="mt-2">
          <p className="text-destructive">Выключите сторонние плагины — их код интерфейса увидел бы QR-код:</p>
          <ul className="list-disc pl-5 font-mono">{ov.thirdPartyRunning.map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
      ) : null}
      {qr === null ? (
        <button
          className={`${btnPrimary} mt-3`}
          disabled={act.busy || blockedByPlugins}
          onClick={() => void act.run(async () => { await rpc.call("page.ping"); setQr(await rpc.call("totp.begin")); })}
        >
          {state === "pending" ? "Начать заново" : "Показать QR-код"}
        </button>
      ) : (
        <div className="mt-3 space-y-3">
          <QrSvg matrix={qr.matrix} />
          <p>Отсканируйте в приложении-аутентификаторе или введите ключ вручную:</p>
          <p className="break-all font-mono text-base">{qr.secret}</p>
          <div className="flex items-center gap-2">
            <CodeField value={code} onChange={setCode} />
            <button
              className={btnPrimary}
              disabled={act.busy || code.length !== 6}
              onClick={() =>
                void act.run(async () => {
                  await rpc.call("totp.confirm", { code });
                  setQr(null);
                  setCode("");
                })
              }
            >
              Подтвердить и запереть
            </button>
          </div>
        </div>
      )}
      <Msg error={act.error} />
    </div>
  );
}

function QrSvg({ matrix }: { matrix: boolean[][] }) {
  const quiet = 4;
  const n = matrix.length + quiet * 2;
  const cells: ReactNode[] = [];
  matrix.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) cells.push(<rect key={`${x}-${y}`} x={x + quiet} y={y + quiet} width={1} height={1} />);
    }),
  );
  return (
    <svg viewBox={`0 0 ${n} ${n}`} className="size-56 max-w-full rounded-md border border-border" role="img" aria-label="QR-код для приложения-аутентификатора" shapeRendering="crispEdges">
      <rect width={n} height={n} fill="#fff" />
      <g fill="#000">{cells}</g>
    </svg>
  );
}

/** What the deterministic checks found in one version (the decision table of spec §5.3 acts on it). */
function ChecksView({ result }: { result: CheckResult | undefined }) {
  if (!result) return <p className={`mt-2 text-xs ${muted}`}>Проверки ещё выполняются или не запускались для этой версии.</p>;
  const sev = (s: string) => (s === "block" ? "блок" : s === "review" ? "на ревью" : "инфо");
  return (
    <details className="mt-2" open={result.findings.some((f) => f.severity === "block")}>
      <summary className="cursor-pointer">
        Проверки: {result.findings.length === 0 ? "находок нет" : `${result.findings.length} находок`} · возможностей: {result.capabilities.length}
      </summary>
      {result.findings.length > 0 ? (
        <ul className="mt-1 list-disc pl-5">
          {result.findings.map((f, i) => (
            <li key={i} className="break-all">
              <b>{sev(f.severity)}</b> {f.rule} · <span className="font-mono">{f.file}{f.line ? `:${f.line}` : ""}</span> · <span className="font-mono">{f.excerpt}</span>
            </li>
          ))}
        </ul>
      ) : null}
      <p className="mt-1 font-semibold">Возможности</p>
      {result.capabilities.length === 0 ? (
        <p className={muted}>нет (безопасный класс)</p>
      ) : (
        <ul className="list-disc pl-5">
          {result.capabilities.map((c) => (
            <li key={c.kind} className="break-all">
              <span className="font-mono">{c.kind}</span>{c.detail.length ? `: ${c.detail.join(", ")}` : ""}
              <span className={muted}> ({c.sites.slice(0, 3).map((s) => `${s.file}${s.line ? `:${s.line}` : ""}`).join(", ")}{c.sites.length > 3 ? ", …" : ""})</span>
            </li>
          ))}
        </ul>
      )}
    </details>
  );
}

function QueueCard({ q, ov, rpc, refetch }: { q: QueueRow; ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const held = q.status === "held";
  const disabled = act.busy || code.length !== 6 || !registered;
  const done = () => setCode("");
  const found = ov.queueChecks[q.id];
  const blocked = (q.reason?.startsWith("заблокировано проверками") ?? false) || (found?.findings.some((f) => f.severity === "block") ?? false);
  const [ack, setAck] = useState(false);
  return (
    <div className={card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">
          #{q.id} · {q.pluginId} <span className={muted}>{q.version}</span>
        </h3>
        <span className={muted}>
          {held ? "держится" : q.status === "approved" ? "одобрено" : q.status === "stale" ? "устарело" : "отклонено"} · {when(q.firstSeen)}
        </span>
      </div>
      <p className={`mt-1 break-all ${muted}`}>
        {q.sourceKind}: {q.source}
        {q.threadId ? ` · из треда ${q.threadId}` : ""}
        {q.kind === "afterfact" ? " · выключен после загрузки (его код уже выполнялся)" : ""}
        {q.kind === "proposal" && !q.contentHash ? " · предложен агентом, окно было закрыто" : ""}
      </p>
      {q.contentHash ? <p className={`break-all font-mono text-xs ${muted}`}>{q.contentHash}</p> : null}
      {q.reason ? <p className={`mt-1 ${blocked ? "font-semibold text-red-600" : muted}`}>{q.reason}</p> : null}
      <ChecksView result={ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined)} />
      {held ? (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <CodeField value={code} onChange={setCode} />
          <button className={btnPrimary} disabled={disabled} onClick={() => void act.run(async () => { const r = await rpc.call("queue.approve", { id: q.id, code, acknowledgeBlock: ack }); done(); setAck(false); return r; })}>
            {blocked ? "Снять блок и одобрить" : "Одобрить версию"}
          </button>
          {blocked ? (
            <label className="flex items-center gap-1 text-xs">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> понимаю риск: проверки нашли жёсткий признак
            </label>
          ) : null}
          {q.threadId && !blocked ? (
            <button className={btn} disabled={disabled} onClick={() => void act.run(async () => { await rpc.call("window.open", { queueId: q.id, code }); done(); })}>
              Открыть окно
            </button>
          ) : null}
          <button className={btn} disabled={disabled} onClick={() => void act.run(async () => { await rpc.call("queue.dismiss", { id: q.id, code }); done(); })}>
            Отклонить
          </button>
        </div>
      ) : null}
      {held && !registered ? <p className={`mt-2 ${muted}`}>Сначала зарегистрируйте второй фактор.</p> : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function PluginRow({ p, rpc, refetch, registered, checks }: { p: PluginView; checks: Record<string, CheckResult>; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void; registered: boolean }) {
  const now = useNow();
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const remaining = p.window ? Math.max(0, Math.ceil((Math.min(p.window.expiresAt, p.window.hardExpiresAt) - now) / 1000)) : 0;
  return (
    <div className={card}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{p.id} <span className={muted}>{p.version} · {p.status}</span></h3>
        <span className={muted}>
          {p.pin ? `${p.frozenPin ? "закреплена при заморозке" : "пин"}: ${p.pin.version} (${p.pin.via === "window" ? "окном" : p.pin.via === "pin" ? "закреплено" : p.pin.via === "auto" ? "безопасный класс" : "касанием"}, ${when(p.pin.approvedAt)})` : p.unreviewedBaseline ? "стоял до secure-bb, не проверялся" : "не одобрен"}
        </span>
      </div>
      <p className={muted}>{p.window ? windowLine(p.window, remaining) : "окно закрыто"}</p>
      {p.pin ? <ChecksView result={checks[p.pin.contentHash]} /> : null}
      {p.history.length > 1 ? (
        <details className="mt-1">
          <summary className="cursor-pointer">История ({p.history.length})</summary>
          <ul className="mt-1 list-disc pl-5">
            {p.history.map((h) => (
              <li key={h.id}>{h.version} · {h.via === "window" ? "окно" : h.via === "pin" ? "закреплено" : h.via === "auto" ? "безопасный класс" : "касание"} · {when(h.approvedAt)}</li>
            ))}
          </ul>
        </details>
      ) : null}
      {registered && p.pin ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <CodeField value={code} onChange={setCode} />
          <button className={btn} disabled={act.busy || code.length !== 6} onClick={() => void act.run(async () => { await rpc.call("approval.revoke", { approvalId: p.pin!.id, code }); setCode(""); })}>
            Отозвать
          </button>
        </div>
      ) : null}
      <Msg error={act.error} />
    </div>
  );
}

function PolicyCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const p = ov.policy;
  const [windowMin, setWindowMin] = useState(String(p.windowMin));
  const [capMin, setCapMin] = useState(String(p.capMin));
  const [mode, setMode] = useState<"sliding" | "fixed">(p.mode);
  const [scope, setScope] = useState<"tree" | "thread">(p.scope);
  const [cfgWindowMin, setCfgWindowMin] = useState(String(p.cfgWindowMin));
  const [cfgCapMin, setCfgCapMin] = useState(String(p.cfgCapMin));
  const [cfgMode, setCfgMode] = useState<"sliding" | "fixed">(p.cfgMode);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  useEffect(() => {
    setWindowMin(String(p.windowMin));
    setCapMin(String(p.capMin));
    setMode(p.mode);
    setScope(p.scope);
    setCfgWindowMin(String(p.cfgWindowMin));
    setCfgCapMin(String(p.cfgCapMin));
    setCfgMode(p.cfgMode);
  }, [p.windowMin, p.capMin, p.mode, p.scope, p.cfgWindowMin, p.cfgCapMin, p.cfgMode]);
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
      <div className="mt-3 flex items-center gap-2">
        <CodeField value={code} onChange={setCode} />
        <button
          className={btnPrimary}
          disabled={act.busy}
          onClick={() =>
            void act.run(async () => {
              await rpc.call("policy.set", { windowMin: Number(windowMin), capMin: Number(capMin), mode, scope, cfgWindowMin: Number(cfgWindowMin), cfgCapMin: Number(cfgCapMin), cfgMode, ...(code.length === 6 ? { code } : {}) });
              setCode("");
            })
          }
        >
          Сохранить
        </button>
      </div>
      <Msg error={act.error} />
    </div>
  );
}

function LogCard({ ov }: { ov: Overview }) {
  return (
    <div className={card}>
      {ov.log.length === 0 ? <p className={muted}>Пока пусто.</p> : (
        <ul className="space-y-1 font-mono text-xs">
          {ov.log.map((l) => (
            <li key={l.id}>
              {when(l.ts)} · {l.kind}{l.pluginId ? ` · ${l.pluginId}` : ""}
              {l.kind === "window.freeze" ? ` · закреплена версия ${(l.detail as { pinnedVersion?: string | null } | null)?.pinnedVersion ?? "—"}` : ""}
              {l.kind === "totp.begin" ? ` · ${(l.detail as { attended?: boolean; caller?: string } | null)?.attended ? "со страницы" : "НЕ со страницы"} (${(l.detail as { caller?: string } | null)?.caller ?? "?"})` : ""}
              {l.kind === "hold" && (l.detail as { reason?: string } | null)?.reason ? ` · ${(l.detail as { reason: string }).reason}` : ""}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ------------------------------------------------------- config watchdog ---

const driftStatus: Record<Drift["status"], string> = {
  open: "открыто",
  "rollback-failed": "откат не удался",
  "rolled-back": "откатано",
  "accepted-window": "принято окном",
  "accepted-touch": "принято вами",
  reverted: "вернулось",
};

function DriftRow({ d, registered, rpc, refetch }: { d: Drift; registered: boolean; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
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
          <CodeField value={code} onChange={setCode} />
          <button className={btn} disabled={act.busy || code.length !== 6} onClick={() => void act.run(async () => { await rpc.call("watch.accept", { id: d.id, code }); setCode(""); })}>
            Принять
          </button>
          {d.rollbackable ? (
            <button className={btn} disabled={act.busy || code.length !== 6} onClick={() => void act.run(async () => { await rpc.call("watch.rollback", { id: d.id, code }); setCode(""); })}>
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

function WatchSection({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const w = ov.watch;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const [code, setCode] = useState("");
  const [scopes, setScopes] = useState<WindowScope[]>([]);
  const act = useCodeAction(refetch);
  const open = w.drifts.filter((d) => d.status === "open" || d.status === "rollback-failed");
  const settled = w.drifts.filter((d) => d.status !== "open" && d.status !== "rollback-failed");
  const toggle = (s: WindowScope) => setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  const need = code.length !== 6 || act.busy || !registered;
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
          <CodeField value={code} onChange={setCode} />
          <button className={btnPrimary} disabled={need} onClick={() => void act.run(async () => { const r = await rpc.call("watch.acceptAll", { code }); setCode(""); return { note: `Эталон принят, объектов: ${r.items}` }; })}>
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
          Переключается кодом (в обе стороны).
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <CodeField value={code} onChange={setCode} />
          <button className={btn} disabled={need} onClick={() => void act.run(async () => { await rpc.call("watch.rollbackMode", { enabled: !w.rollbackEnabled, code }); setCode(""); })}>
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
          <CodeField value={code} onChange={setCode} />
          <button className={btnPrimary} disabled={need || scopes.length === 0 || w.baselineAt === null} onClick={() => void act.run(async () => { await rpc.call("watch.window.open", { scopes, code }); setCode(""); setScopes([]); })}>
            Открыть окно
          </button>
        </div>
      </div>

      <h3 className="font-semibold">Расхождения ({open.length})</h3>
      {open.length === 0 ? <div className={`${card} ${muted}`}>Открытых расхождений нет.</div> : open.map((d) => <DriftRow key={d.id} d={d} registered={registered} rpc={rpc} refetch={refetch} />)}
      {settled.length > 0 ? (
        <details>
          <summary className={`cursor-pointer ${muted}`}>Лента ({settled.length})</summary>
          <div className="mt-2 space-y-2">{settled.map((d) => <DriftRow key={d.id} d={d} registered={registered} rpc={rpc} refetch={refetch} />)}</div>
        </details>
      ) : null}

      {w.failed.length > 0 ? (
        <div className={`${card} border-yellow-500/60`}>
          <h4 className="font-medium">Не удалось прочитать сейчас (здесь расхождения не оцениваются)</h4>
          <ul className="list-disc pl-5">{w.failed.map((f) => <li key={f.source} className="break-all"><span className="font-mono">{f.source}</span>: {f.reason}</li>)}</ul>
        </div>
      ) : null}
      <details className={card}>
        <summary className="cursor-pointer font-medium">Что не наблюдается вообще ({w.blind.length})</summary>
        <ul className="mt-2 list-disc pl-5">{w.blind.map((b) => <li key={b.source}>{b.reason}</li>)}</ul>
      </details>
    </div>
  );
}

// -------------------------------------------------------------------- page --

/** Tells the server this page is open, so a registration started now counts as attended. */
function usePagePing(rpc: ReturnType<typeof useRpc<SecureBbRpc>>) {
  useEffect(() => {
    const ping = () => void rpc.call("page.ping").catch(() => undefined);
    ping();
    const t = setInterval(ping, 15_000);
    return () => clearInterval(t);
  }, [rpc]);
}

function GatePage() {
  const { rpc, data: ov, error, refetch } = useOverview();
  usePagePing(rpc);
  if (error && !ov) return <div className="p-6 text-destructive">Не удалось загрузить: {error}</div>;
  if (!ov) return <div className={`p-6 ${muted}`}>Загрузка…</div>;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const held = ov.queue.filter((q) => q.status === "held");
  const settled = ov.queue.filter((q) => q.status !== "held").slice(0, 10);
  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-3xl space-y-6 p-4 sm:p-6">
        <h1 className="text-xl font-semibold">secure-bb</h1>
        {ov.totp.blockedUntil > 0 ? (
          <p className="rounded-md border border-destructive p-2 text-destructive">Слишком много неверных кодов: одобрения заблокированы до {when(ov.totp.blockedUntil)}.</p>
        ) : null}
        <WindowRows windows={ov.windows} cfgWindows={ov.watch.windows} rpc={rpc} refetch={refetch} />
        <Section title="Защита этого bb"><StageCard ov={ov} /></Section>
        <Section title="Второй фактор"><Registration ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title={`Гейт плагинов — очередь (${held.length})`}>
          {held.length === 0 ? <div className={`${card} ${muted}`}>Ничего не держится.</div> : held.map((q) => <QueueCard key={q.id} q={q} ov={ov} rpc={rpc} refetch={refetch} />)}
          {settled.length > 0 ? (
            <details>
              <summary className={`cursor-pointer ${muted}`}>Недавно рассмотренные ({settled.length})</summary>
              <div className="mt-2 space-y-2">{settled.map((q) => <QueueCard key={q.id} q={q} ov={ov} rpc={rpc} refetch={refetch} />)}</div>
            </details>
          ) : null}
        </Section>
        <Section title="Гейт плагинов — сторонние плагины">
          {ov.plugins.length === 0 ? <div className={`${card} ${muted}`}>Сторонних плагинов нет.</div> : ov.plugins.map((p) => <PluginRow key={p.id} p={p} rpc={rpc} refetch={refetch} registered={registered} checks={ov.checks} />)}
        </Section>
        <Section title="Гейт плагинов — окна доверия"><PolicyCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title={`Сторож конфигурации${ov.watch.drifts.some((d) => d.status === "open" || d.status === "rollback-failed") ? " (!)" : ""}`}><WatchSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title="Журнал"><LogCard ov={ov} /></Section>
      </div>
    </div>
  );
}

export default definePluginApp((app) => {
  app.slots.navPanel({
    id: "gate",
    title: "secure-bb",
    icon: "Shield",
    path: "gate",
    component: GatePage,
  });
  app.slots.experimental_appOverlay({ id: "windows", component: WindowOverlay });
});
