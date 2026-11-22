import { useState } from "react";
import { useBbNavigate, useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview, WindowView } from "../src/overview";
import type { ConfigWindowView } from "../src/watch/watchdog";
import { gapsBySeverity, OVERLAY_COLLAPSE_KEY, overlayView } from "../src/pageview";
import { groupGaps } from "../src/ux";
import { useProof } from "./proof";
import { useApproval } from "./approval";
import { useCodeAction } from "./code";
import { card, btn, muted, minutes, when, useOverview, useNow, Msg, Fold } from "./ui";

export function windowLine(w: WindowView, remainingSec: number): string {
  const subs = w.scope === "tree" && w.subthreads > 0 ? ` и ${w.subthreads} вложенных чатов` : "";
  const only = w.scope === "thread" ? " (только этот чат)" : "";
  return `Временное доверие: плагин ${w.pluginId} из чата ${w.threadId}${subs}${only} — ещё ${minutes(remainingSec)}`;
}

export function cfgWindowLine(w: ConfigWindowView, remainingSec: number): string {
  return `Временное доверие: ${w.scopeLabels.join(", ")} — ещё ${minutes(remainingSec)}`;
}

export function WindowRows({ windows, cfgWindows, rpc, refetch }: { windows: WindowView[]; cfgWindows: ConfigWindowView[]; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
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
export function JournalAlarm({ ov, rpc, refetch }: { ov: Overview; rpc: ReturnType<typeof useRpc<SecureBbRpc>>; refetch: () => void }) {
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

/**
 * Threat model X3: the gate was off for a while (when it opened something), or bb's safe-mode is (or was) on. On the page of secure-bb only (the strip over bb has one line).
 * One line says it; «Подробнее» has the pauses and, once, what worked and what did not. «Я проверил» hides the named pauses after a code or a touch (it hides a real alarm);
 * a pause that comes later is red again, and the journal keeps them all.
 */
export function AliveAlarm({ ov }: { ov: Overview }) {
  const { rpc, refetch } = useOverview();
  const proof = useProof(ov, rpc, "alive-review");
  const act = useCodeAction(refetch);
  const a = ov.alive;
  const { critical } = gapsBySeverity(ov);
  if (critical.length === 0 && a.safeMode !== true && !a.safeModeSeen) return null;
  const at = (t: number) => new Date(t).toLocaleString();
  const groups = groupGaps(critical, at);
  const head = [...groups.map((g) => g.summary), ...(a.safeMode === true ? ["safe-mode bb включён сейчас"] : [])].join("; ");
  const review = () =>
    void act.run(async () => {
      await proof.run({ kind: "touch", purpose: "alive.review" } as never, (p) => rpc.call("alive.review", { ats: critical.map((g) => g.gap.at), ...p } as never), { dangerous: true, what: "Я проверил: убрать тревогу о простое плагина", detail: REVIEW_DETAIL });
      return { note: "Тревога о простое отмечена как проверенная; перерывы остались в журнале" };
    });
  return (
    <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
      <p className="font-semibold">{head ? `ТРЕВОГА: ${head}` : "Safe-mode bb включался на этой неделе"}</p>
      <Fold id="alive-details" summary="Подробнее" summaryClassName="cursor-pointer text-xs underline">
        <div className="mt-1 space-y-1 text-xs">
          {groups.map((g) => (
            <div key={g.mode}>
              <ul className="list-disc pl-5">{g.items.map((it, i) => <li key={i}>{it}</li>)}</ul>
              {g.works ? <p className="mt-1">{g.works}</p> : null}
              <p>{g.notWorking}</p>
            </div>
          ))}
          {a.safeMode === true ? <p>safe-mode bb включён сейчас: сторонние плагины не работают.</p> : null}
          {a.safeMode !== true && a.safeModeSeen ? <p>За последнюю неделю safe-mode bb включался (см. журнал).</p> : null}
          {critical.length > 0 ? <p>Проверьте {groups.every((g) => g.mode === "guard") ? "перечисленное" : "конфигурацию и плагины"} вручную; когда проверите, нажмите «Я проверил».</p> : null}
        </div>
      </Fold>
      {critical.length > 0 ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button type="button" className={btn} disabled={act.busy || !proof.registered} onClick={review}>Я проверил</button>
          <span className="text-xs">Нужен код или касание: это убирает настоящую тревогу.</span>
        </div>
      ) : null}
      <Msg error={act.error} ok={act.ok} />
    </div>
  );
}
const REVIEW_DETAIL = "Тревога о простое плагина уберётся с «Обзора» и из плашки. Сами перерывы останутся в журнале. Если плагин остановится ещё раз, тревога появится снова.";

/** Where the folded state is kept: the key of the alarm that was folded. A private mode or a full disk must not break the strip. */
function readCollapsed(): string | null {
  try {
    return window.localStorage.getItem(OVERLAY_COLLAPSE_KEY);
  } catch {
    return null;
  }
}
function writeCollapsed(key: string | null): void {
  try {
    if (key === null) window.localStorage.removeItem(OVERLAY_COLLAPSE_KEY);
    else window.localStorage.setItem(OVERLAY_COLLAPSE_KEY, key);
  } catch {
    /* not remembered: the strip is simply unfolded the next time */
  }
}

/**
 * The strip that floats over every screen of bb: it stays SMALL. The alarm about a pause is one line with a link to the plugin's page (the words and lists are there), «×» folds it
 * to a red dot in the same corner until a NEW alarm comes; folding hides nothing on the page and confirms nothing. An open trust window is never folded: its row is always here.
 */
export function WindowOverlay() {
  const { rpc, data, refetch } = useOverview();
  const nav = useBbNavigate();
  const [stored, setStored] = useState<string | null>(readCollapsed);
  if (!data) return null;
  const v = overlayView(data, stored);
  if (!v.show) return null;
  const fold = (key: string | null): void => {
    writeCollapsed(key);
    setStored(key);
  };
  const dotOnly = v.alarmLine !== null && v.collapsed && !v.windows && !v.journalAlarm;
  return (
    <div className={`pointer-events-auto fixed bottom-3 left-3 z-50 max-w-[min(24rem,calc(100vw-1.5rem))] space-y-2 rounded-lg border border-border bg-card shadow-lg ${dotOnly ? "p-1.5" : "p-2"}`} data-secure-bb-banner>
      <JournalAlarm ov={data} rpc={rpc} refetch={refetch} />
      {v.alarmLine !== null && v.collapsed ? (
        <button type="button" className="block h-3 w-3 rounded-full bg-destructive" aria-label={`${v.alarmLine}. Развернуть`} title={v.alarmLine} data-secure-bb-alarm-dot onClick={() => fold(null)} />
      ) : null}
      {v.alarmLine !== null && !v.collapsed ? (
        <div className="flex items-center gap-2 text-sm text-destructive" role="alert" data-secure-bb-alarm-line>
          <span className="min-w-0 flex-1 font-semibold">{v.alarmLine}</span>
          <button type="button" className="shrink-0 underline hover:no-underline" onClick={() => nav.toPluginPanel("gate")}>Открыть</button>
          <button type="button" className="shrink-0 px-1 leading-none" aria-label="Свернуть" title="Свернуть (тревога останется на странице secure-bb)" onClick={() => fold(v.alarmKey)}>×</button>
        </div>
      ) : null}
      <WindowRows windows={data.windows} cfgWindows={data.watch.windows} rpc={rpc} refetch={refetch} />
    </div>
  );
}
