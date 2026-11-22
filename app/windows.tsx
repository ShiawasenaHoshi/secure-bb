import { useRpc } from "@get-bb/plugin-sdk/app";
import type { SecureBbRpc } from "../server";
import type { Overview, WindowView } from "../src/overview";
import type { ConfigWindowView } from "../src/watch/watchdog";
import { gapsBySeverity } from "../src/pageview";
import { useApproval } from "./approval";
import { useCodeAction } from "./code";
import { card, btn, muted, minutes, when, useOverview, useNow, Msg } from "./ui";

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

/** Threat model X3: the gate was off for a while (when it opened something), or bb's safe-mode is (or was) on. Shown on the page and in the strip, for a week. */
export function AliveAlarm({ ov }: { ov: Overview }) {
  const a = ov.alive;
  const { critical } = gapsBySeverity(ov);
  if (critical.length === 0 && a.safeMode !== true && !a.safeModeSeen) return null;
  const at = (t: number) => new Date(t).toLocaleString();
  const guardOnly = critical.length > 0 && critical.every((g) => g.text.mode === "guard");
  return (
    <div className="rounded-md border-2 border-destructive bg-destructive/10 p-2 text-destructive" role="alert" data-secure-bb-alarm>
      <p className="font-semibold">{critical.length > 0 ? (guardOnly ? "ТРЕВОГА: плагин secure-bb не работал, часть защиты была закрыта" : "ТРЕВОГА: гейт не всегда работал") : "ТРЕВОГА: safe-mode bb"}</p>
      <ul className="mt-1 list-disc pl-5 text-xs">
        {critical.map(({ gap: g, text }, i) => (
          <li key={i}>
            {text.headline} ({at(g.from)} — {at(g.to)}){g.safeMode ? "; safe-mode bb был включён" : ""}.
            {text.works ? <> {text.works}</> : null} {text.notWorking}
          </li>
        ))}
        {a.safeMode === true ? <li>safe-mode bb включён сейчас: сторонние плагины не работают.</li> : null}
        {a.safeMode !== true && a.safeModeSeen ? <li>За последнюю неделю safe-mode bb включался (см. журнал).</li> : null}
      </ul>
      {critical.length > 0 ? <p className="mt-1 text-xs">Проверьте {guardOnly ? "перечисленное" : "конфигурацию и плагины"} вручную.</p> : null}
    </div>
  );
}

/** Always-on-screen strip: open windows are never hidden. */
export function WindowOverlay() {
  const { rpc, data, refetch } = useOverview();
  if (!data || (data.windows.length === 0 && data.watch.windows.length === 0 && data.journal.ok && gapsBySeverity(data).critical.length === 0 && data.alive.safeMode !== true)) return null;
  return (
    <div className="pointer-events-auto fixed bottom-3 left-3 z-50 max-w-[min(32rem,calc(100vw-1.5rem))] space-y-2 rounded-lg border border-border bg-card p-2 shadow-lg" data-secure-bb-banner>
      <JournalAlarm ov={data} rpc={rpc} refetch={refetch} />
      <AliveAlarm ov={data} />
      <WindowRows windows={data.windows} cfgWindows={data.watch.windows} rpc={rpc} refetch={refetch} />
    </div>
  );
}
