// secure-bb — frontend: the secure-bb page (the plugin gate is a section of it) and an always-visible banner
// for open trust windows. Plain React + host theme tokens; no vendored UI,
// no third-party code (this bundle runs in bb's origin, so it stays minimal).
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { definePluginApp, useRealtime, useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "./server";
import type { Overview, PluginView, WindowView } from "./src/overview";
import type { ScanView } from "./src/scan/view";
import type { QueueRow } from "./src/store";
import type { CheckResult } from "./src/checks/types";
import type { ConfigWindowView } from "./src/watch/watchdog";
import { CATEGORY_LABEL, WINDOW_SCOPES, SCOPE_LABEL } from "./src/watch/model";
import { NOT_OBSERVED, TAINT_LABEL } from "./src/taint/classify";
import type { TaintKind } from "./src/taint/classify";
import type { Drift, WindowScope } from "./src/watch/model";
import type { SkillQueueView } from "./src/skills/guard";
import { OUTCOME_LABEL, firedText, verdictText } from "./src/sentinel/view";
import type { QuestionView } from "./src/sentinel/view";
import type { FeedRow } from "./src/sentinel/types";
import { T } from "./src/text";

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

type Rpc = ReturnType<typeof useRpc<SecureBbRpc>>;

// ----------------------------------------------------- approval session ----
// The session token lives ONLY in this component's memory (state): not localStorage, not a cookie, not the URL. Reloading the page
// forgets it, and so does leaving it. The server keeps only a hash. Routine actions use it instead of a code; dangerous ones never do.
type Proof = { code: string } | { session: string };
interface SessionLocal {
  token: string;
  /** When this page stops using the token (a little before the server does: the server's clock decides, this only avoids a wasted call). */
  idleUntil: number;
  hardUntil: number;
}
interface Approval {
  session: SessionLocal | null;
  /** Can an action run with what is typed now? `dangerous`: it needs a fresh code whatever the session says. */
  ready: (code: string, dangerous?: boolean) => boolean;
  /** Runs a routine action: with the code when six digits are typed, else with the session; slides the local clock on success. */
  routine: <T>(code: string, fn: (proof: Proof) => Promise<T>, dangerous?: boolean) => Promise<T>;
}
const MARGIN_MS = 5_000;
const noApproval: Approval = {
  session: null,
  ready: (code) => code.length === 6,
  routine: (code, fn) => fn({ code }),
};
const ApprovalContext = createContext<Approval>(noApproval);
const useApproval = () => useContext(ApprovalContext);

/** A code field that gives way to the session note while a session covers the action. */
function RoutineCode({ value, onChange, dangerous }: { value: string; onChange: (v: string) => void; dangerous?: boolean }) {
  const ap = useApproval();
  if (ap.session && !dangerous) return <span className={`text-xs ${muted}`}>сессия открыта: код не нужен</span>;
  return <CodeField value={value} onChange={onChange} />;
}

function useApprovalSession(rpc: Rpc, refetch: () => void): { approval: Approval; open: (code: string) => Promise<void>; lock: () => Promise<void> } {
  const [session, setSession] = useState<SessionLocal | null>(null);
  const ref = useRef<SessionLocal | null>(null);
  ref.current = session;
  const now = useNow();
  // Time is up for this page: forget the token (the server stops accepting it at about the same moment).
  useEffect(() => {
    if (session && now >= Math.min(session.idleUntil, session.hardUntil)) setSession(null);
  }, [now, session]);
  // Leaving the page locks the session on the server too (best effort; the token is gone with the page anyway).
  useEffect(() => {
    const lockOnLeave = () => {
      if (ref.current) void rpc.call("session.close").catch(() => undefined);
    };
    window.addEventListener("pagehide", lockOnLeave);
    return () => {
      window.removeEventListener("pagehide", lockOnLeave);
      lockOnLeave();
    };
  }, [rpc]);
  const approval: Approval = {
    session,
    ready: (code, dangerous = false) => code.length === 6 || (session !== null && !dangerous),
    routine: async (code, fn, dangerous = false) => {
      const started = Date.now();
      const useSession = code.length !== 6 && !dangerous && ref.current !== null;
      const proof: Proof = useSession ? { session: ref.current!.token } : { code };
      try {
        const result = await fn(proof);
        if (useSession) setSession((cur) => (cur ? { ...cur, idleUntil: started + 15 * 60_000 - MARGIN_MS } : cur));
        return result;
      } catch (e) {
        // The server no longer knows this token: forget it here too, and say why.
        if (useSession && e instanceof Error && /expired session|blocked|too many/.test(e.message)) setSession(null);
        throw e;
      }
    },
  };
  const open = async (code: string) => {
    const started = Date.now();
    const r = await rpc.call("session.open", { code });
    setSession({ token: r.token, idleUntil: started + r.idleMs - MARGIN_MS, hardUntil: started + r.capMs - MARGIN_MS });
    refetch();
  };
  const lock = async () => {
    setSession(null);
    await rpc.call("session.close");
    refetch();
  };
  return { approval, open, lock };
}

/** The strip at the top: open a session with one code, or see how long it lasts and lock it. */
function SessionBar({ ov, session, open, lock }: { ov: Overview; session: SessionLocal | null; open: (code: string) => Promise<void>; lock: () => Promise<void> }) {
  const now = useNow();
  const [code, setCode] = useState("");
  const act = useCodeAction(() => undefined);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  if (!registered) return null;
  if (session) {
    const left = Math.max(0, Math.ceil((Math.min(session.idleUntil, session.hardUntil) - now) / 60_000));
    const ceiling = Math.max(0, Math.ceil((session.hardUntil - now) / 60_000));
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted px-3 py-2 text-sm" role="status">
        <span className="min-w-0 flex-1">Сессия открыта, осталось {left} мин (скользящие 15 мин от каждого действия; потолок — через {ceiling} мин). Опасное всё равно требует свежего кода.</span>
        <button className={btnPrimary} onClick={() => void act.run(() => lock())}>Заблокировать</button>
      </div>
    );
  }
  const blockers = ov.thirdPartyRunning;
  return (
    <div className={card}>
      <h3 className="font-semibold">Сессия подтверждения</h3>
      <p className={muted}>Один код открывает сессию на этой странице: 15 минут, скользящие, потолок 1 час. Рутину (одобрить версию, открыть окно, принять расхождение, одобрить скилл, принять эталон) она покрывает без кода; опасное — всегда со свежим кодом. Перезагрузка страницы закрывает сессию.</p>
      {blockers.length > 0 ? (
        <p className="mt-2 text-red-600">Сессию нельзя открыть, пока работают сторонние плагины: их код интерфейса в той же странице мог бы перехватить токен. Выключите: {blockers.join(", ")}.</p>
      ) : null}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <CodeField value={code} onChange={setCode} />
        <button className={btn} disabled={act.busy || code.length !== 6 || blockers.length > 0 || ov.totp.blockedUntil > 0} onClick={() => void act.run(async () => { await open(code); setCode(""); })}>
          Открыть сессию
        </button>
      </div>
      <Msg error={act.error} />
    </div>
  );
}

/** "Approve the selected": the list is fixed on the server and shown with its hash BEFORE the code; one code approves the whole list. */
type BatchKindUi = "queue" | "skill" | "drift";
function BatchCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const ap = useApproval();
  const [picked, setPicked] = useState<string[]>([]);
  const [prepared, setPrepared] = useState<Awaited<ReturnType<Rpc["call"]>> | null>(null);
  const [results, setResults] = useState<Array<{ kind: string; id: number; label: string; ok: boolean; note: string }> | null>(null);
  const [code, setCode] = useState("");
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
  const reset = () => { setPrepared(null); setCode(""); };
  return (
    <div className={card}>
      <h3 className="font-semibold">Пакетное одобрение</h3>
      {!prep ? (
        <>
          <p className={muted}>Отметьте, что одобрить разом: один код на весь список. Список фиксируется на сервере до ввода кода; элементы с блоком проверок в пакет не входят.</p>
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
          <p className={`mt-1 text-xs ${muted}`}>Список действует 10 минут и одобряется один раз. Если что-то изменится до ввода кода, это не будет одобрено.</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <RoutineCode value={code} onChange={setCode} />
            <button className={btnPrimary} disabled={act.busy || !ap.ready(code)} onClick={() => void act.run(async () => {
              const r = await ap.routine(code, (proof) => rpc.call("batch.approve", { batchId: prep.batchId, setHash: prep.setHash, ...proof }));
              setResults(r.results);
              setPicked([]);
              reset();
              return { note: `Одобрено: ${r.results.filter((x) => x.ok).length} из ${r.results.length}` };
            })}>
              Одобрить список ({prep.items.length})
            </button>
            <button className={btn} onClick={reset}>Отмена</button>
          </div>
        </>
      )}
      {results ? <ul className="mt-2 list-disc pl-5 text-xs">{results.map((r) => <li key={`${r.kind}${r.id}`} className={r.ok ? muted : "text-red-600"}>{r.label}: {r.ok ? "одобрено" : "не одобрено"} — {r.note}</li>)}</ul> : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

// ------------------------------------------------------------- AI scan ----

const MODEL_STATUS: Record<string, string> = { clean: "чисто", flag: "флаг", refusal: "отказ", invalid: "невалидный ответ", timeout: "таймаут", error: "ошибка", unavailable: "недоступна" };

/** Result of a scan next to the version it belongs to: not run / clean (date, models) / flags (what and where). */
function ScanResultView({ scan, other }: { scan: ScanView | undefined; other?: string }) {
  if (!scan) return <p className={`mt-1 ${muted}`}>ИИ-скан: не запускался</p>;
  const asked = scan.models.filter((m) => m.status !== "unavailable").map((m) => m.label).join(", ");
  const head =
    scan.status === "running" ? "идёт…" : scan.status === "clean" ? `чисто (${when(scan.finishedAt ?? scan.startedAt)}, ${asked})` : scan.status === "suspect" ? `ПОДОЗРЕНИЕ (${when(scan.finishedAt ?? scan.startedAt)})` : `недоступен${scan.note ? `: ${scan.note}` : ""}`;
  return (
    <div className="mt-1">
      <p className={scan.status === "suspect" ? "font-semibold text-red-600" : muted}>ИИ-скан #{scan.id}, версия {scan.version}: {head}{other ? ` · ${other}` : ""}</p>
      {scan.flags.length > 0 ? <ul className="list-disc pl-5 text-red-600">{scan.flags.map((f, i) => <li key={i}>{f}</li>)}</ul> : null}
      {scan.models.some((m) => m.status === "unavailable") ? <p className={muted}>Не отвечала: {scan.models.filter((m) => m.status === "unavailable").map((m) => `${m.label} (${m.detail})`).join("; ")}</p> : null}
      {scan.models.some((m) => m.report) ? (
        <details className="mt-1">
          <summary className="cursor-pointer">Что нашли модели</summary>
          {scan.models.map((m) => (
            <div key={m.model} className="mt-1">
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
          ))}
          <p className={muted}>Отправлено файлов: {scan.files}, {scan.chars} знаков (без комментариев). Модели одобрить версию не могут.</p>
        </details>
      ) : null}
    </div>
  );
}

const PUBLISH_STATE: Record<string, string> = {
  off: "публикация выключена",
  "no-address": "публикация включена, но адрес репозитория не задан",
  "not-configured": "публикация не настроена: на сервере не задана переменная BB_SECURE_BB_PUBLISH_TOKEN_FILE",
  ready: "публикация готова",
};
const PUBLISH_STATUS: Record<string, string> = { running: "идёт", published: "опубликовано", unchanged: "уже было опубликовано", failed: "ошибка", skipped: "пропущено" };

/** Where this version of this plugin went (or why it did not): the result of the last attempts, with the reason. */
function PublicationLine({ ov, pluginId, version, rpc, refetch }: { ov: Overview; pluginId: string; version: string | null; rpc: Rpc; refetch: () => void }) {
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

function PublishCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
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
      await rpc.call("publish.settings", { ...patch, ...(code.length === 6 ? { code } : {}) });
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
        <details className="mt-1">
          <summary className="cursor-pointer">Последние публикации ({ov.publish.recent.length})</summary>
          <ul className="mt-1 list-disc pl-5">
            {ov.publish.recent.slice(0, 15).map((r) => (
              <li key={r.id} className={r.status === "failed" ? "text-destructive" : undefined}>
                {r.pluginId}@{r.version} · {PUBLISH_STATUS[r.status] ?? r.status} · {when(r.startedAt)}{r.detail ? ` — ${r.detail}` : ""}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function ScanButton({ ov, target, rpc, refetch }: { ov: Overview; target: { pluginId: string } | { queueId: number }; rpc: Rpc; refetch: () => void }) {
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

function AiCard({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const ai = ov.ai;
  const [code, setCode] = useState("");
  const [model, setModel] = useState(ai.settings.secondModel);
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  useEffect(() => setModel(ai.settings.secondModel), [ai.settings.secondModel]);
  const set = (patch: Record<string, unknown>) =>
    void act.run(async () => {
      await rpc.call("ai.settings", { ...patch, ...(code.length === 6 ? { code } : {}) });
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
        <details className="mt-1">
          <summary className="cursor-pointer">Последние сканы ({ai.recent.length})</summary>
          {ai.recent.map((r) => <ScanResultView key={r.id} scan={r} other={r.trigger} />)}
        </details>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

// ------------------------------------------------------------ sentinel ----
function FeedItem({ row, riskThreshold }: { row: FeedRow; riskThreshold: number }) {
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

function QuestionEditor({ q, rpc, refetch }: { q: QuestionView; rpc: Rpc; refetch: () => void }) {
  const [text, setText] = useState(q.instructions);
  const [threshold, setThreshold] = useState(String(q.threshold ?? ""));
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  useEffect(() => setText(q.instructions), [q.instructions]);
  useEffect(() => setThreshold(String(q.threshold ?? "")), [q.threshold]);
  const save = (patch: Record<string, unknown>) => void act.run(async () => { await rpc.call("sentinel.settings", { ...patch, code }); setCode(""); return { note: "Сохранено." }; });
  return (
    <details className="rounded-md border border-border p-2">
      <summary className="cursor-pointer">{q.label}{q.threshold !== null ? ` · порог ${q.threshold}` : ""}{q.edited ? " · изменён" : ""}</summary>
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
    </details>
  );
}

function SentinelSection({ ov, rpc, refetch }: { ov: Overview; rpc: Rpc; refetch: () => void }) {
  const v = ov.sentinel;
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const set = (patch: Record<string, unknown>) => void act.run(async () => { await rpc.call("sentinel.settings", { ...patch, code }); setCode(""); });
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
      <details className={card}>
        <summary className="cursor-pointer font-semibold">Вопросы и пороги ({v.questions.length})</summary>
        <div className="mt-2 space-y-2">{v.questions.map((q) => <QuestionEditor key={q.id} q={q} rpc={rpc} refetch={refetch} />)}</div>
      </details>
    </div>
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
  const ap = useApproval();
  const act = useCodeAction(refetch);
  if (windows.length === 0 && cfgWindows.length === 0) return null;
  return (
    <div className="space-y-2">
      {cfgWindows.map((w) => {
        const remaining = Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000));
        return (
          <div key={`cfg-${w.id}`} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">{cfgWindowLine(w, remaining)}</span>
            <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("watch.window.close", { windowId: w.id }); })}>
              Закрыть
            </button>
          </div>
        );
      })}
      {windows.map((w) => {
        const remaining = Math.max(0, Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now) / 1000));
        return (
          <div key={w.id} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">{windowLine(w, remaining)}</span>
            <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("window.close", { windowId: w.id }); })}>
              Закрыть
            </button>
          </div>
        );
      })}
      <Msg error={act.error} />
    </div>
  );
}

/** A broken journal chain is an alarm: shown on the page and in the strip, never hidden. */
function JournalAlarm({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const act = useCodeAction(refetch);
  if (ov.journal.ok) return null;
  return (
    <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
      <p className="font-semibold">ТРЕВОГА: цепочка журнала решений нарушена</p>
      <ul className="mt-1 list-disc pl-5 text-xs">
        {ov.journal.problems.slice(0, 5).map((p, i) => <li key={i}>{p.detail}</li>)}
        {ov.journal.problems.length > 5 ? <li>и ещё {ov.journal.problems.length - 5}</li> : null}
      </ul>
      <p className="mt-1 text-xs">Журнал или база изменены не гейтом. Всё, что гейт «одобрил» до этого места, нельзя считать надёжным: проверьте плагины и одобрения вручную.</p>
      <button className={`${btn} mt-1`} disabled={act.busy} onClick={() => void act.run(async () => rpc.call("journal.verify"))}>Проверить заново</button>
      <Msg error={act.error} />
    </div>
  );
}

/** Threat model X3: the gate was off for a while, or bb's safe-mode is (or was) on. Shown on the page and in the strip, for a week. */
function AliveAlarm({ ov }: { ov: Overview }) {
  const a = ov.alive;
  if (a.gaps.length === 0 && a.safeMode !== true && !a.safeModeSeen) return null;
  const at = (t: number) => new Date(t).toLocaleString();
  return (
    <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
      <p className="font-semibold">ТРЕВОГА: гейт не всегда работал</p>
      <ul className="mt-1 list-disc pl-5 text-xs">
        {a.gaps.map((g, i) => <li key={i}>Гейт не работал с {at(g.from)} по {at(g.to)} ({Math.round(g.ms / 60_000)} мин){g.stopped ? ": его остановили (выключили)" : ": процесс остановился без предупреждения"}{g.safeMode ? "; safe-mode bb был включён" : ""}.</li>)}
        {a.safeMode === true ? <li>safe-mode bb включён сейчас: сторонние плагины не работают.</li> : null}
        {a.safeMode !== true && a.safeModeSeen ? <li>За последнюю неделю safe-mode bb включался (см. журнал).</li> : null}
      </ul>
      <p className="mt-1 text-xs">Пока гейта нет, ничего не удерживается и не проверяется; за это время могли поменять настройки и вернуть их. Проверьте конфигурацию и плагины вручную.</p>
    </div>
  );
}

/** Always-on-screen strip: open windows are never hidden. */
function WindowOverlay() {
  const { rpc, data, refetch } = useOverview();
  if (!data || (data.windows.length === 0 && data.watch.windows.length === 0 && data.journal.ok && data.alive.gaps.length === 0 && data.alive.safeMode !== true)) return null;
  return (
    <div className="pointer-events-auto fixed bottom-3 left-3 z-50 max-w-[min(32rem,calc(100vw-1.5rem))] space-y-2 rounded-lg border border-border bg-card p-2 shadow-lg" data-secure-bb-banner>
      <JournalAlarm ov={data} rpc={rpc} refetch={refetch} />
      <AliveAlarm ov={data} />
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
      <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">{T.totpFile.registerWarning}</p>
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
      <DependenciesView result={result} />
    </details>
  );
}

const DEP_STATUS: Record<string, string> = {
  ok: "проверена",
  young: "релиз моложе 3 дней",
  unchecked: "не проверена",
  "not-in-registry": "нет в реестре npm",
  "unknown-version": "версии нет в реестре",
  skipped: "не из реестра",
};

/** Dependencies and what the npm registry said about them (stage 2.3). */
function DependenciesView({ result }: { result: CheckResult }) {
  const st = result.dependencyStats;
  const deps = result.dependencies ?? [];
  if (!st || st.total === 0) return null;
  return (
    <>
      <p className="mt-1 font-semibold">Зависимости</p>
      <p className={muted}>
        всего {st.total} (объявлено {st.declared}) ·{" "}
        {st.registry ? `сверено с реестром npm: ${st.verified} · не проверено: ${st.unchecked} · моложе 3 дней: ${st.young}` : "реестр npm не опрашивался"}
        {st.lookalikes > 0 ? ` · похожи на популярные: ${st.lookalikes}` : ""}
      </p>
      {deps.length > 0 ? (
        <ul className="list-disc pl-5">
          {deps.map((d, i) => (
            <li key={i} className="break-all">
              <span className="font-mono">{d.name}@{d.version ?? d.installed ?? d.spec ?? "?"}</span>
              {d.declared ? "" : " (node_modules)"} · {d.status ? (DEP_STATUS[d.status] ?? d.status) : "не опрашивалась"}
              {d.publishedAt ? ` · выпущена ${d.publishedAt.slice(0, 10)}` : ""}
              {d.note ? <span className={muted}> — {d.note}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </>
  );
}

function QueueCard({ q, ov, rpc, refetch }: { q: QueueRow; ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const held = q.status === "held";
  const unsafeDirNow = q.reason?.startsWith("каталог доступен на запись другим") ?? false;
  const ap = useApproval();
  const found = ov.queueChecks[q.id];
  const blocked = (q.reason?.startsWith("заблокировано проверками") ?? false) || (found?.findings.some((f) => f.severity === "block") ?? false);
  const [ack, setAck] = useState(false);
  // Lifting a block is dangerous: it needs a fresh code even with a session open.
  const liftingBlock = blocked && ack;
  const disabled = act.busy || !ap.ready(code, liftingBlock) || !registered || unsafeDirNow;
  const done = () => setCode("");
  // The directory can be changed by someone other than the server's user: no code approves it; fix the directory, then it is looked at again.
  const unsafeDir = q.reason?.startsWith("каталог доступен на запись другим") ?? false;
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
      {q.reason ? <p className={`mt-1 ${blocked || unsafeDir ? "font-semibold text-red-600" : muted}`}>{q.reason}</p> : null}
      {unsafeDir && held ? <p className="mt-1 text-red-600">Одобрить нельзя: пока в каталоге или выше может писать кто-то кроме пользователя сервера, его содержимое может измениться после проверки. Исправьте права (владелец — пользователь сервера, без записи для группы и остальных) или предложите плагин через <span className="font-mono">bb secure-bb propose</span>: снимок гейт хранит у себя.</p> : null}
      <ChecksView result={ov.queueChecks[q.id] ?? (q.contentHash ? ov.checks[q.contentHash] : undefined)} />
      <ScanResultView scan={ov.ai.queueScans[q.id]} />
      {held ? (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} dangerous={liftingBlock} />
          <ScanButton ov={ov} target={{ queueId: q.id }} rpc={rpc} refetch={refetch} />
          <button className={btnPrimary} disabled={disabled} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("queue.approve", { id: q.id, ...proof, acknowledgeBlock: ack }), liftingBlock); done(); setAck(false); return r; })}>
            {blocked ? "Снять блок и одобрить" : "Одобрить версию"}
          </button>
          {blocked ? (
            <label className="flex items-center gap-1 text-xs">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> понимаю риск: проверки нашли жёсткий признак
            </label>
          ) : null}
          {q.threadId && !blocked ? (
            <button className={btn} disabled={disabled} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("window.open", { queueId: q.id, ...proof })); done(); })}>
              Открыть окно
            </button>
          ) : null}
          <button className={btn} disabled={disabled} onClick={() => void act.run(async () => { await ap.routine(code, (proof) => rpc.call("queue.dismiss", { id: q.id, ...proof })); done(); })}>
            Отклонить
          </button>
        </div>
      ) : null}
      {held && !registered ? <p className={`mt-2 ${muted}`}>Сначала зарегистрируйте второй фактор.</p> : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function PluginRow({ p, ov, rpc, refetch, registered, checks }: { p: PluginView; ov: Overview; checks: Record<string, CheckResult>; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void; registered: boolean }) {
  const now = useNow();
  const ap = useApproval();
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
      <PublicationLine ov={ov} pluginId={p.id} version={p.pin?.version ?? null} rpc={rpc} refetch={refetch} />
      <ScanResultView scan={ov.ai.pluginScans[p.id]} other={ov.ai.pluginScans[p.id] ? (ov.ai.pluginScans[p.id]!.current ? "это закреплённая версия" : "не закреплённая версия") : undefined} />
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
        <details className="mt-1">
          <summary className="cursor-pointer">История ({p.history.length})</summary>
          <ul className="mt-1 list-disc pl-5">
            {p.history.map((h) => (
              <li key={h.id}>{h.version} · {h.via === "window" ? "окно" : h.via === "pin" ? "закреплено" : h.via === "auto" ? "безопасный класс" : "касание"} · {when(h.approvedAt)}</li>
            ))}
          </ul>
        </details>
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

function PolicyCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const p = ov.policy;
  const [windowMin, setWindowMin] = useState(String(p.windowMin));
  const [capMin, setCapMin] = useState(String(p.capMin));
  const [mode, setMode] = useState<"sliding" | "fixed">(p.mode);
  const [scope, setScope] = useState<"tree" | "thread">(p.scope);
  const [cfgWindowMin, setCfgWindowMin] = useState(String(p.cfgWindowMin));
  const [cfgCapMin, setCfgCapMin] = useState(String(p.cfgCapMin));
  const [cfgMode, setCfgMode] = useState<"sliding" | "fixed">(p.cfgMode);
  const [autoSafe, setAutoSafe] = useState(p.autoSafe);
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  useEffect(() => {
    setAutoSafe(p.autoSafe);
    setWindowMin(String(p.windowMin));
    setCapMin(String(p.capMin));
    setMode(p.mode);
    setScope(p.scope);
    setCfgWindowMin(String(p.cfgWindowMin));
    setCfgCapMin(String(p.cfgCapMin));
    setCfgMode(p.cfgMode);
  }, [p.windowMin, p.capMin, p.mode, p.scope, p.cfgWindowMin, p.cfgCapMin, p.cfgMode, p.autoSafe]);
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
        <input type="checkbox" className="mt-1" checked={autoSafe} onChange={(e) => setAutoSafe(e.target.checked)} />
        <span>Автопропуск версий без возможностей (без касания)</span>
      </label>
      <p className="mt-1 rounded-md border border-destructive p-2 text-destructive">{T.autoSafeWarning}</p>
      <div className="mt-3 flex items-center gap-2">
        <CodeField value={code} onChange={setCode} />
        <button
          className={btnPrimary}
          disabled={act.busy}
          onClick={() =>
            void act.run(async () => {
              await rpc.call("policy.set", { autoSafe, windowMin: Number(windowMin), capMin: Number(capMin), mode, scope, cfgWindowMin: Number(cfgWindowMin), cfgCapMin: Number(cfgCapMin), cfgMode, ...(code.length === 6 ? { code } : {}) });
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

function TrustedRepos({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
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

function TaintCard({ ov }: { ov: Overview }) {
  return (
    <div className={card}>
      <p>
        Тред, который прочитал недоверенное (веб, чужой репозиторий, инструмент MCP, установка скилла, проект с <span className="font-mono">.bb-env-setup.sh</span>), закрывает окно доверия плагина, если он в его дереве, и окно конфигурации. Окно не открыть заново само: нужно новое касание.
      </p>
      {ov.tainted.length === 0 ? (
        <p className={`mt-2 ${muted}`}>Пока ни один просмотренный тред не отмечен.</p>
      ) : (
        <ul className="mt-2 space-y-1 text-xs">
          {ov.tainted.map((t) => (
            <li key={t.threadId} className="break-all">
              <span className="font-mono">{t.threadId}</span> · {t.kinds.map((k) => TAINT_LABEL[k as TaintKind] ?? k).join(", ")} · {when(t.first)}{t.last !== t.first ? ` … ${when(t.last)}` : ""}
            </li>
          ))}
        </ul>
      )}
      <details className="mt-2">
        <summary className={`cursor-pointer ${muted}`}>Что не наблюдается (честно)</summary>
        <ul className="mt-1 list-disc pl-5 text-xs">{NOT_OBSERVED.map((n) => <li key={n}>{n}</li>)}</ul>
        <p className={`mt-1 text-xs ${muted}`}>Источник — история событий треда в API bb. Берутся только события после открытия окна; «проект с .bb-env-setup.sh» считается всегда.</p>
      </details>
    </div>
  );
}

function logExtra(l: Overview["log"][number]): string {
  const d = (l.detail ?? {}) as Record<string, unknown>;
  if (l.kind === "window.taint" || l.kind === "watch.window.taint")
    return ` · окно закрыто: загрязнение (${((d.kinds as string[] | undefined) ?? []).map((k) => TAINT_LABEL[k as TaintKind] ?? k).join(", ")}); ${((d.lines as string[] | undefined) ?? []).join("; ")}`;
  if (l.kind === "trusted.add" || l.kind === "trusted.remove") return ` · ${(d.pattern as string | undefined) ?? ""}`;
  if (l.kind === "journal.alarm") return ` · цепочка нарушена: ${((d.problems as Array<{ kind: string; id: number | null }> | undefined) ?? []).map((p) => `${p.kind}${p.id ? ` #${p.id}` : ""}`).join(", ")}`;
  return "";
}

function LogCard({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const act = useCodeAction(refetch);
  const j = ov.journal;
  return (
    <div className={card}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className={j.ok ? "text-green-600" : "font-semibold text-destructive"}>
          {j.ok ? `Цепочка хешей цела: ${j.entries} записей, голова ${j.head ?? "—"}` : `Цепочка НАРУШЕНА (${j.problems.length}), записей ${j.entries}`}
        </p>
        <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => rpc.call("journal.verify"))}>Проверить целостность</button>
      </div>
      <p className={`text-xs ${muted}`}>
        Проверено {when(j.checkedAt)}. Каждая запись содержит хеш предыдущей; голова цепочки дополнительно лежит в файле рядом с базой, одобрение без записи в журнале — тоже тревога.
        {j.sealedLegacy > 0 ? ` ${j.sealedLegacy} записей были до цепочки: их целостность до этого момента не доказать.` : ""} Кто может писать и в базу, и в этот файл (тот же пользователь ОС, пока нет ступени 3), перепишет цепочку целиком незаметно.
      </p>
      <Msg error={act.error} />
      {ov.log.length === 0 ? <p className={muted}>Пока пусто.</p> : (
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {ov.log.map((l) => (
            <li key={l.id}>
              {when(l.ts)} · {l.kind}{l.pluginId ? ` · ${l.pluginId}` : ""}
              {l.kind === "window.freeze" ? ` · закреплена версия ${(l.detail as { pinnedVersion?: string | null } | null)?.pinnedVersion ?? "—"}` : ""}
              {l.kind === "totp.begin" ? ` · ${(l.detail as { attended?: boolean; caller?: string } | null)?.attended ? "со страницы" : "НЕ со страницы"} (${(l.detail as { caller?: string } | null)?.caller ?? "?"})` : ""}
              {l.kind === "hold" && (l.detail as { reason?: string } | null)?.reason ? ` · ${(l.detail as { reason: string }).reason}` : ""}
              {logExtra(l)}
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

function WatchSection({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
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
      {w.notApplicable.length > 0 ? (
        <div className={card}>
          <h4 className="font-medium">Не применимо (читать нечего)</h4>
          <ul className="list-disc pl-5">{w.notApplicable.map((f) => <li key={f.source} className="break-all"><span className="font-mono">{f.source}</span>: {f.reason}</li>)}</ul>
        </div>
      ) : null}
      <details className={card}>
        <summary className="cursor-pointer font-medium">Что не наблюдается вообще ({w.blind.length})</summary>
        <ul className="mt-2 list-disc pl-5">{w.blind.map((b) => <li key={b.source}>{b.reason}</li>)}</ul>
      </details>
    </div>
  );
}

// ----------------------------------------------------------------- skills ---

const skillState: Record<SkillQueueView["state"], string> = {
  held: "в очереди",
  alarm: "тревога",
  removed: "удалён",
  approved: "одобрен",
  gone: "исчез",
};

function SkillRow({ q, registered, rpc, refetch }: { q: SkillQueueView; registered: boolean; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const ap = useApproval();
  const [code, setCode] = useState("");
  const [ack, setAck] = useState(false);
  const [shown, setShown] = useState<Array<{ path: string; content: string | null }> | null>(null);
  const act = useCodeAction(refetch);
  const isOpen = q.state === "held" || q.state === "alarm";
  const canApprove = isOpen || q.state === "removed";
  const findings = (q.check?.findings ?? []).filter((f) => f.severity !== "info");
  return (
    <div className={`${card} ${isOpen ? (q.decision === "block" ? "border-destructive" : "border-yellow-500/60") : ""}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-semibold">{q.name} <span className={`text-xs font-normal ${muted}`}>({q.scope})</span></h3>
        <span className={muted}>{skillState[q.state]} · {when(q.firstSeen)}</span>
      </div>
      <p className="break-all">
        {q.decision === "block" ? "Жёсткий признак. " : ""}{q.reason}
        {q.preexisting ? " Был до модуля скиллов: сам не удаляется." : ""}
      </p>
      {q.note ? <p className={muted}>{q.note}</p> : null}
      {findings.length > 0 ? (
        <ul className="mt-1 list-disc pl-5 text-xs">
          {findings.slice(0, 12).map((f, i) => (
            <li key={i} className="break-all">
              <b>{f.severity}</b> <span className="font-mono">{f.rule}</span> {f.file}{f.line ? `:${f.line}` : ""} — {f.excerpt}
            </li>
          ))}
        </ul>
      ) : null}
      {q.check && q.check.capabilities.length > 0 ? (
        <p className={`mt-1 text-xs ${muted}`}>Возможности скриптов: {q.check.capabilities.map((c) => `${c.kind}${c.detail.length ? ` (${c.detail.slice(0, 3).join(", ")})` : ""}`).join("; ")}</p>
      ) : null}
      {q.source ? <p className={`text-xs ${muted}`}>Источник по метке рядом со скиллом: <span className="font-mono">{q.source}</span> (метка не доказательство)</p> : null}
      {q.removed ? (
        <div className="mt-1">
          <p className={`text-xs ${muted}`}>Что было: {q.removed.map((f) => `${f.path} (${f.size})`).join(", ")}</p>
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { setShown(await rpc.call("skills.removed", { id: q.id })); })}>Показать содержимое</button>
          {shown ? <div className="mt-2 space-y-2">{shown.map((f) => <pre key={f.path} className="max-h-60 overflow-auto rounded border border-border p-2 text-xs"><b>{f.path}</b>{"\n"}{(f.content ?? "(не прочитан)").slice(0, 6000)}</pre>)}</div> : null}
        </div>
      ) : null}
      {canApprove && registered ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <RoutineCode value={code} onChange={setCode} dangerous={q.decision === "block"} />
          {q.decision === "block" ? <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> принимаю, несмотря на жёсткий признак</label> : null}
          <button className={btn} disabled={act.busy || !ap.ready(code, q.decision === "block") || (q.decision === "block" && !ack)} onClick={() => void act.run(async () => { const r = await ap.routine(code, (proof) => rpc.call("skills.approve", { id: q.id, ...proof, acknowledgeBlock: ack }), q.decision === "block"); setCode(""); setAck(false); return r; })}>
            {q.state === "removed" ? "Одобрить хеш (поставить снова)" : "Одобрить"}
          </button>
          {isOpen && q.removable ? <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("skills.remove", { id: q.id }); })}>Удалить скилл</button> : null}
        </div>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}

function SkillTrusted({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const [pattern, setPattern] = useState("");
  const [code, setCode] = useState("");
  const act = useCodeAction(refetch);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const run = (change: { add: string } | { remove: string }) =>
    void act.run(async () => {
      const r = await rpc.call("skills.trusted", { ...change, code });
      setCode("");
      setPattern("");
      return r;
    });
  return (
    <div className={card}>
      <p>
        Доверенные источники: репозитории реестра скиллов (<span className="font-mono">owner/repo</span> или <span className="font-mono">owner/*</span>). Скилл, установленный оттуда, чистый по проверкам и не из очереди, принимается без кода. По умолчанию список пуст; менять — только с кодом. Источник определяется по метке рядом со скиллом, которую агент может подделать: проверки при этом всё равно проходят.
      </p>
      {ov.skills.trusted.length === 0 ? <p className={`mt-2 ${muted}`}>Список пуст: любой новый скилл вне окна «скиллы» ждёт вашего кода.</p> : (
        <ul className="mt-2 space-y-1 font-mono text-xs">
          {ov.skills.trusted.map((r) => (
            <li key={r} className="flex items-center gap-2">
              {r}
              <button className={btn} disabled={act.busy || code.length !== 6 || !registered} onClick={() => run({ remove: r })}>Убрать</button>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input className="rounded border border-border bg-transparent px-2 py-1 font-mono text-xs" placeholder="owner/repo или owner/*" value={pattern} onChange={(e) => setPattern(e.target.value)} />
        <CodeField value={code} onChange={setCode} />
        <button className={btnPrimary} disabled={act.busy || code.length !== 6 || pattern.trim() === "" || !registered} onClick={() => run({ add: pattern })}>Добавить</button>
      </div>
      <Msg error={act.error} />
    </div>
  );
}

function SkillsSection({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
  const k = ov.skills;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const act = useCodeAction(refetch);
  return (
    <div className="space-y-3">
      <div className={card}>
        <p>
          {k.baselineAt === null ? <b>Первая проверка ещё не завершена: всё, что есть, будет закреплено как существовавшее до модуля.</b> : <>Закреплено хешей: {k.pinned.total} (встроенные bb: {k.pinned.builtin}, были до модуля: {k.pinned.baseline}, одобрены: {k.pinned.approved}).</>}
          {k.lastScanAt ? ` Последняя проверка — ${when(k.lastScanAt)}.` : ""}
        </p>
        <p className={`mt-1 ${muted}`}>
          Режим «после факта»: у bb нет хука установки скиллов, поэтому скилл уже работал, пока его не проверили. Жёсткий признак — скилл сразу удаляется (если bb позволяет), иначе тревога; сомнительный ждёт здесь, но остаётся установленным. Встроенные скиллы bb только закрепляются.
        </p>
        <div className="mt-2">
          <button className={btn} disabled={act.busy} onClick={() => void act.run(async () => { await rpc.call("skills.scan"); })}>Проверить сейчас</button>
        </div>
        <Msg error={act.error} />
      </div>
      {k.unchecked.length > 0 ? (
        <div className={`${card} border-yellow-500/60`}>
          <h4 className="font-medium">Не удалось прочитать (проверка не проводилась, в окне не принимаются)</h4>
          <ul className="list-disc pl-5 font-mono text-xs">{k.unchecked.map((u) => <li key={u} className="break-all">{u}</li>)}</ul>
        </div>
      ) : null}
      <h3 className="font-semibold">Очередь скиллов ({k.open.length})</h3>
      {k.open.length === 0 ? <div className={`${card} ${muted}`}>Ничего не ждёт.</div> : k.open.map((q) => <SkillRow key={q.id} q={q} registered={registered} rpc={rpc} refetch={refetch} />)}
      {k.recent.length > 0 ? (
        <details>
          <summary className={`cursor-pointer ${muted}`}>Недавно рассмотренные ({k.recent.length})</summary>
          <div className="mt-2 space-y-2">{k.recent.map((q) => <SkillRow key={q.id} q={q} registered={registered} rpc={rpc} refetch={refetch} />)}</div>
        </details>
      ) : null}
      <SkillTrusted ov={ov} rpc={rpc} refetch={refetch} />
      <details className={card}>
        <summary className="cursor-pointer font-medium">Что не видно в скиллах ({k.blind.length})</summary>
        <ul className="mt-2 list-disc pl-5">{k.blind.map((b) => <li key={b}>{b}</li>)}</ul>
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
  const { approval, open, lock } = useApprovalSession(rpc, refetch);
  if (error && !ov) return <div className="p-6 text-destructive">Не удалось загрузить: {error}</div>;
  if (!ov) return <div className={`p-6 ${muted}`}>Загрузка…</div>;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  const held = ov.queue.filter((q) => q.status === "held");
  const settled = ov.queue.filter((q) => q.status !== "held").slice(0, 10);
  return (
    <ApprovalContext.Provider value={approval}>
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-3xl space-y-6 p-4 sm:p-6">
        <h1 className="text-xl font-semibold">secure-bb</h1>
        <SessionBar ov={ov} session={approval.session} open={open} lock={lock} />
        {ov.totp.blockedUntil > 0 ? (
          <p className="rounded-md border border-destructive p-2 text-destructive">Слишком много неверных кодов: одобрения заблокированы до {when(ov.totp.blockedUntil)}.</p>
        ) : null}
        <JournalAlarm ov={ov} rpc={rpc} refetch={refetch} />
        <AliveAlarm ov={ov} />
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
        <BatchCard ov={ov} rpc={rpc} refetch={refetch} />
        <Section title="Гейт плагинов — сторонние плагины">
          {ov.plugins.length === 0 ? <div className={`${card} ${muted}`}>Сторонних плагинов нет.</div> : ov.plugins.map((p) => <PluginRow key={p.id} p={p} ov={ov} rpc={rpc} refetch={refetch} registered={registered} checks={ov.checks} />)}
        </Section>
        <Section title="Гейт плагинов — окна доверия"><PolicyCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title="Гейт плагинов — ИИ-скан"><AiCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title="Гейт плагинов — публикация"><PublishCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title={`Сторож конфигурации${ov.watch.drifts.some((d) => d.status === "open" || d.status === "rollback-failed") ? " (!)" : ""}`}><WatchSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title={`Дозор${ov.sentinel.settings.enabled ? "" : " (выключен)"}`}><SentinelSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title={`Скиллы${ov.skills.open.length > 0 ? ` — очередь (${ov.skills.open.length})` : ""}`}><SkillsSection ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title={`Загрязнение тредов${ov.tainted.length > 0 ? ` (${ov.tainted.length})` : ""}`}><TaintCard ov={ov} /></Section>
        <Section title={`Доверенные репозитории (${ov.trustedRepos.length})`}><TrustedRepos ov={ov} rpc={rpc} refetch={refetch} /></Section>
        <Section title={`Журнал${ov.journal.ok ? "" : " (!)"}`}><LogCard ov={ov} rpc={rpc} refetch={refetch} /></Section>
      </div>
    </div>
    </ApprovalContext.Provider>
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
