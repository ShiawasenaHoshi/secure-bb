// The feed as the page and `bb secure-bb watchman` show it. All wording is built here, in code: Jev writes no text.
import { CATEGORY_DEFS, LABEL, RISK_ID, shippedInstructions } from "./questions.js";
import type { FeedRow, Outcome, SentinelSettings } from "./types.js";

export const OUTCOME_LABEL: Record<Outcome, string> = {
  pending: "карточка ждёт решения",
  allow_once: "разрешено один раз",
  allow_for_session: "разрешено на сессию",
  deny: "запрещено",
  interrupted: "прервано",
  unknown: "исход неизвестен",
};

export interface QuestionView {
  id: string;
  label: string;
  /** Category questions have a threshold; the risk score does not. */
  threshold: number | null;
  instructions: string;
  edited: boolean;
}

export interface SentinelView {
  settings: SentinelSettings;
  /** A key file is set and readable. Only a yes/no: the path and the key stay on the server. */
  keyConfigured: boolean;
  solver: string;
  questions: QuestionView[];
  feed: FeedRow[];
}

export function questionViews(s: SentinelSettings): QuestionView[] {
  const list: QuestionView[] = CATEGORY_DEFS.map((d) => ({
    id: d.id,
    label: d.label,
    threshold: s.thresholds[d.id] ?? 0.5,
    instructions: s.instructions[d.id] ?? d.instructions,
    edited: s.instructions[d.id] !== undefined,
  }));
  list.push({ id: RISK_ID, label: LABEL[RISK_ID]!, threshold: null, instructions: s.instructions[RISK_ID] ?? shippedInstructions(RISK_ID)!, edited: s.instructions[RISK_ID] !== undefined });
  return list;
}

export const pct = (p: number): string => `${Math.round(p * 100)}%`;

/** Which categories fired, with probabilities: `секреты 92%, сеть 61%`; empty text when none. */
export function firedText(row: FeedRow): string {
  return row.categories
    .filter((c) => c.fired && c.p !== null)
    .sort((a, b) => b.p! - a.p!)
    .map((c) => `${LABEL[c.id] ?? c.id} ${pct(c.p!)}`)
    .join(", ");
}

export function verdictText(row: FeedRow, riskThreshold: number): string {
  if (row.status === "evaluating") return "оценивается…";
  if (row.status === "not_scored") return `не оценено: ${row.reason ?? "причина не записана"}`;
  const fired = firedText(row);
  const score = row.risk?.score;
  const risk = typeof score === "number" ? `риск ${score.toFixed(2)}${score >= riskThreshold ? " (высокий)" : ""}` : "риск не оценён";
  return `${fired ? `сработали: ${fired}` : "ничего не сработало"}; ${risk}`;
}

/** One feed entry for the terminal (several lines). */
export function feedText(row: FeedRow, riskThreshold: number): string {
  const lines = [
    `${new Date(row.ts).toISOString()} тред ${row.threadId} (${row.providerId})`,
    `  действие: ${row.tool}${row.args ? ` — ${row.args}` : ""}`,
    `  ${verdictText(row, riskThreshold)}`,
    `  человек: ${OUTCOME_LABEL[row.outcome]}`,
  ];
  return lines.join("\n");
}
