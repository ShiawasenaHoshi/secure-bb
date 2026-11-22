import { useState } from "react";
import type { ReactNode } from "react";
import type { HeaderLine } from "../src/pageview";
import { Alert } from "../components/ui/alert";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Icon } from "../components/ui/icon";
import { useNow } from "./ui";

/** Troubleshooting mode of the guard (switched on at its console): everything passes, every decision is written down; a real alarm, with the time left. */
export function TroubleshootBar({ until }: { until: number }) {
  const now = useNow();
  if (until <= 0 || until <= now) return null;
  const left = Math.max(0, Math.ceil((until - now) / 1000));
  const mmss = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  return (
    <Alert variant="destructive" data-secure-bb-troubleshoot>
      <Icon name="ShieldAlert" aria-hidden="true" className="size-4" />
      <div className="space-y-1">
        <p className="font-semibold">Режим отладки: защита снята, осталось {mmss}</p>
        <p className="text-sm">Защита пропускает всё и пишет каждое решение в журнал. Она вернётся сама; раньше — командой «sbb-guard troubleshoot off» на этой машине. Не ставьте и не обновляйте ничего лишнего, пока плашка видна.</p>
      </div>
    </Alert>
  );
}

const ICON: Record<HeaderLine["tone"], string> = { ok: "ShieldCheck", waiting: "Shield", alarm: "ShieldAlert" };

/**
 * The one line at the top: a shield, one sentence, one main button to the place where the action is. The session of confirmation is at its right, small.
 * A real alarm is this same line as a destructive Alert (one thing once): the point in one line, the button, «Подробнее» for the longer words.
 * Waiting cards are not an alarm: the line is calm and neutral then.
 */
export function StatusHeader({ line, onAction, session, more }: { line: HeaderLine; onAction: (() => void) | null; session: ReactNode; more: string | null }) {
  const [open, setOpen] = useState(false);
  const marker = line.tone === "alarm" ? "stopped" : line.tone === "waiting" ? "attention" : "ok";
  const body = (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <p className="min-w-0 flex-1 text-base font-semibold" data-secure-bb-status-text>{line.text}</p>
      {onAction && line.action ? <Button size="sm" variant={line.tone === "alarm" ? "destructive" : "default"} onClick={onAction}>{line.action}</Button> : null}
      {line.tone === "alarm" && more ? <Button size="sm" variant="ghost" aria-expanded={open} onClick={() => setOpen(!open)}>Подробнее</Button> : null}
      {open && more ? <p className="basis-full text-sm font-normal text-muted-foreground">{more}</p> : null}
      <div className="flex basis-full justify-end border-t border-border pt-2 sm:ml-auto sm:basis-auto sm:border-0 sm:pt-0">{session}</div>
    </div>
  );
  if (line.tone === "alarm") {
    return (
      <Alert variant="destructive" role="alert" data-secure-bb-status={marker} data-secure-bb-alarm-alert>
        <Icon name={ICON.alarm} aria-hidden="true" className="size-5" />
        {body}
      </Alert>
    );
  }
  return (
    <Card className="flex items-start gap-3 p-4" role="status" data-secure-bb-status={marker}>
      <Icon name={ICON[line.tone]} aria-hidden="true" className="mt-0.5 size-6 shrink-0" />
      <div className="min-w-0 flex-1">{body}</div>
    </Card>
  );
}
