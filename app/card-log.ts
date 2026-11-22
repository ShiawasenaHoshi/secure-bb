// The journal for learning, page side: tells the guard that a card was shown (and what it showed), that «Подробнее» was opened, that «Решить позже» was pressed.
// Nothing here decides anything and nothing waits for it: a report that fails is dropped. The guard times the decision by its own clock.
import { useEffect, useRef } from "react";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";
import type { CheckResult } from "../src/checks/types";
import { CARD_TEXTS_VERSION } from "../src/ux";
import type { Rpc } from "./touch";

export type CardEvent = "shown" | "details" | "later";

/** What the card showed, in the shape of `card.view`: the level, the findings by rule/file/line (no code), the AI's verdict per model, the version of the texts. */
export function shownReport(level: string, found: CheckResult | undefined, scan: Overview["ai"]["queueScans"][number] | undefined, detailsOpen: boolean) {
  return {
    level,
    findings: (found?.findings ?? []).slice(0, 40).map((f) => ({ rule: f.rule, file: f.file, ...(f.line ? { line: f.line } : {}) })),
    ai: (scan?.models ?? []).slice(0, 8).map((m) => ({ model: m.label, status: m.status })),
    textsVersion: CARD_TEXTS_VERSION,
    detailsOpen,
  };
}

export function useCardLog(q: QueueRow, ov: Overview, rpc: Rpc, level: string, found: CheckResult | undefined, detailsOpen: boolean): (event: "details" | "later") => void {
  const live = ov.guard?.connected === true && q.status === "held" && q.id > 0;
  const send = (body: Record<string, unknown>) => void rpc.call("card.view", { id: q.id, ...body } as never).catch(() => undefined);
  const report = JSON.stringify(shownReport(level, found, ov.ai.queueScans[q.id], detailsOpen));
  const last = useRef<string | null>(null);
  // Once when the card appears, and again when what it shows changes (a verdict of the AI arrives): the guard keeps the newest.
  useEffect(() => {
    if (!live || last.current === report) return;
    last.current = report;
    send({ event: "shown", ...(JSON.parse(report) as object) });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `send` is rebuilt each draw; the report string is the key
  }, [live, q.id, report]);
  return (event) => {
    if (live) send({ event });
  };
}
