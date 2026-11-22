import { useEffect, useRef } from "react";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";

/**
 * What stays where a card was after a decision: ONE short line, as tall as the «Пока вас не было» line: «Готово: chime 0.1.0 разрешён и включён · Вернуть · Скрыть».
 * It takes the focus when it appears (the button that was pressed is gone with its card), so the keyboard stays where the person was.
 */
export function DoneRow({ text, undoLabel, onUndo, onHide, busy }: { text: string; undoLabel: string | null; onUndo: (() => void) | null; onHide: () => void; busy?: boolean }) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    ref.current?.focus({ preventScroll: true });
  }, []);
  return (
    <Card ref={ref} tabIndex={-1} role="status" className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" data-secure-bb-stub>
      <span className="min-w-0 flex-1 font-medium">{text}</span>
      <span className="flex items-center gap-1">
        {onUndo && undoLabel ? <Button size="sm" variant="ghost" disabled={busy} onClick={onUndo}>{undoLabel}</Button> : null}
        <Button size="sm" variant="ghost" onClick={onHide}>Скрыть</Button>
      </span>
    </Card>
  );
}
