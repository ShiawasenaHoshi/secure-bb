// «Под защитой»: every installed plugin, its standing and rights in a line.
import { approvedByText } from "./decisions.js";
import { sourceLabel } from "./words.js";

export type Standing = "works" | "waits" | "quarantine";

export const STANDING_LABEL: Record<Standing, string> = { works: "работает", waits: "ждёт вашего решения", quarantine: "в карантине" };

export interface ProtectedInput {
  id: string;
  version: string;
  status: string;
  statusDetail?: string | null;
  source: string;
  /** The thread that proposed it, when known. */
  threadId: string | null;
  pin: { version: string; approvedAt: number; via: string; why?: string | null } | null;
  /** The headline of the rights of the approved version (`riskHeadline`), or null when nothing was read. */
  rights: string | null;
  /** A version of it waits for a decision on the page, and the person has not set it aside. */
  waits: boolean;
}

export interface ProtectedRow {
  id: string;
  standing: Standing;
  standingLabel: string;
  /** «из папки /x, тред thr_1» / «github.com/o/r». */
  from: string;
  rights: string;
  version: string;
  approved: string;
}

export const AI_SCAN_OFF_TEXT = "ИИ-скан выключен: включить его можно на вкладке «Журнал», в разделе «Гейт плагинов — ИИ-скан».";

export const AI_SCAN_NOT_YET_TEXT = "ИИ-скан: ещё не запускался (кнопка запуска — рядом).";

export const aiScanEmptyText = (enabled: boolean): string => (enabled ? AI_SCAN_NOT_YET_TEXT : AI_SCAN_OFF_TEXT);

export const NO_RIGHTS_TEXT = "права не определены (версию ещё не проверяли)";

const RUNNING_STATUS = new Set(["running", "starting", "degraded"]);

const HELD_STATUS_DETAIL = /waiting for activation guard|held by activation guard|held by secure-bb|удержан/i;

export function standingOf(i: Pick<ProtectedInput, "status" | "statusDetail" | "waits">): Standing {
  if (RUNNING_STATUS.has(i.status) && !HELD_STATUS_DETAIL.test(i.statusDetail ?? "")) return "works";
  return i.waits ? "waits" : "quarantine";
}

export function protectedRow(i: ProtectedInput, now: number): ProtectedRow {
  const standing = standingOf(i);
  const kind = /^path:/.test(i.source) ? "path" : /^git:|github\.com/.test(i.source) ? "git" : /^npm:/.test(i.source) ? "npm" : "";
  const from = `${sourceLabel(kind, i.source)}${i.threadId ? `, тред ${i.threadId}` : ""}`;
  return {
    id: i.id,
    standing,
    standingLabel: STANDING_LABEL[standing],
    from,
    rights: i.rights ?? NO_RIGHTS_TEXT,
    version: i.version,
    approved: i.pin ? `одобрена версия ${i.pin.version}: ${approvedByText(i.pin, now)}` : "версия не одобрена",
  };
}

export interface ProtectedHeadline {
  title: string;
  builtinLine: string | null;
}

/** The title of the fold (the count of every installed plugin that is not bb's own) and the one line about bb's own. */
export function protectedHeadline(rows: Array<Pick<ProtectedRow, "standing">>, builtin: number): ProtectedHeadline {
  return { title: `Под защитой (${rows.length})`, builtinLine: builtin > 0 ? `встроенные bb: ${builtin}` : null };
}

/** Sorted: waiting first, then quarantine, then the working ones; by name inside. */
export function sortProtected<T extends Pick<ProtectedRow, "standing" | "id">>(rows: T[]): T[] {
  const rank: Record<Standing, number> = { waits: 0, quarantine: 1, works: 2 };
  return [...rows].sort((a, b) => rank[a.standing] - rank[b.standing] || a.id.localeCompare(b.id));
}
