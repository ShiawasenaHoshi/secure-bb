import { btnPrimary, useNow } from "./ui";

export const statusStyle = {
  ok: "border-green-600 bg-green-50 text-green-950 dark:border-green-500 dark:bg-green-950/40 dark:text-green-100",
  attention: "border-yellow-500 bg-yellow-50 text-yellow-950 dark:border-yellow-500 dark:bg-yellow-950/40 dark:text-yellow-100",
  stopped: "border-red-600 bg-red-50 text-red-950 dark:border-red-500 dark:bg-red-950/40 dark:text-red-100",
  down: "border-red-600 bg-red-50 text-red-950 dark:border-red-500 dark:bg-red-950/40 dark:text-red-100",
} as const;

export const cardYellow = "rounded-lg border-2 border-yellow-500 bg-yellow-50 p-4 text-sm text-yellow-950 dark:border-yellow-500 dark:bg-yellow-950/30 dark:text-yellow-50";

/** Troubleshooting mode of the guard (switched on at its console): everything passes, every decision is written down; red, with the time left. */
export function TroubleshootBar({ until }: { until: number }) {
  const now = useNow();
  if (until <= 0 || until <= now) return null;
  const left = Math.max(0, Math.ceil((until - now) / 1000));
  const mmss = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  return (
    <div className="rounded-lg border-2 border-red-600 bg-red-600 p-4 text-white" role="alert" data-secure-bb-troubleshoot>
      <p className="text-lg font-semibold">Режим отладки: защита снята, осталось {mmss}</p>
      <p className="text-sm">Защита пропускает всё и пишет каждое решение в журнал. Она вернётся сама; раньше — командой «sbb-guard troubleshoot off» на этой машине. Не ставьте и не обновляйте ничего лишнего, пока плашка видна.</p>
    </div>
  );
}

export function StatusBar({ level, label, text, onShow }: { level: keyof typeof statusStyle; label: string; text: string | null; onShow: (() => void) | null }) {
  return (
    <div className={`flex flex-wrap items-center gap-3 rounded-lg border-2 p-4 ${statusStyle[level]}`} role="status" data-secure-bb-status={level}>
      <span aria-hidden className={`size-4 shrink-0 rounded-full ${level === "ok" ? "bg-green-600" : level === "attention" ? "bg-yellow-500" : "bg-red-600"}`} />
      <div className="min-w-0 flex-1">
        <p className="text-lg font-semibold">{label}</p>
        {text ? <p className="text-sm">{text}</p> : null}
      </div>
      {onShow ? <button className={btnPrimary} onClick={onShow}>Показать</button> : null}
    </div>
  );
}
