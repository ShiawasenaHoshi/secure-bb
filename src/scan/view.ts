// What the page and the CLI show of a scan: "not run / clean (date, models) / flags (what and where)".
import { flagLines } from "./prompt.js";
import type { ModelOutcome, ScanResult, ScanRow, ScanStatus, ScanTrigger } from "./types.js";

export interface ScanView {
  id: number;
  pluginId: string;
  version: string;
  status: ScanStatus;
  trigger: ScanTrigger;
  startedAt: number;
  finishedAt: number | null;
  localHash: string;
  contentHash: string | null;
  models: ModelOutcome[];
  /** One line per concern: `model: what — file:line`; failures and incomplete coverage are lines too. */
  flags: string[];
  incomplete: string[];
  skipped: string[];
  files: number;
  chars: number;
  note: string | null;
}

const FAILURE_WORD: Record<string, string> = { refusal: "отказ", invalid: "невалидный ответ", timeout: "таймаут", error: "ошибка" };

export function flagsOf(r: ScanResult): string[] {
  const out: string[] = [];
  for (const m of r.models) {
    if (m.status === "flag" && m.report) for (const l of flagLines(m.report)) out.push(`${m.label}: ${l}`);
    else if (m.status === "flag") out.push(`${m.label}: ${m.detail}`);
    else if (FAILURE_WORD[m.status]) out.push(`${m.label}: ${FAILURE_WORD[m.status]} — ${m.detail}`);
  }
  for (const i of r.incomplete) out.push(`неполный скан: ${i}`);
  return out;
}

export function scanView(row: ScanRow): ScanView {
  const r = row.result;
  return {
    id: row.id,
    pluginId: row.pluginId,
    version: row.version,
    status: row.status,
    trigger: row.trigger,
    startedAt: row.startedAt,
    finishedAt: row.finishedAt,
    localHash: row.localHash,
    contentHash: row.contentHash,
    models: r?.models ?? [],
    flags: r ? flagsOf(r) : [],
    incomplete: r?.incomplete ?? [],
    skipped: r?.skipped ?? [],
    files: r?.files ?? 0,
    chars: r?.chars ?? 0,
    note: r?.note ?? null,
  };
}

/** Plain-text line for the CLI and the log. */
export function scanLine(v: ScanView): string {
  const when = new Date(v.finishedAt ?? v.startedAt).toISOString();
  const models = v.models.filter((m) => m.status !== "unavailable").map((m) => m.label).join(", ");
  const unavailable = v.models.filter((m) => m.status === "unavailable").map((m) => `${m.label}: ${m.detail}`);
  const head =
    v.status === "running"
      ? "идёт"
      : v.status === "clean"
        ? `чисто (${when}, ${models})`
        : v.status === "suspect"
          ? `ПОДОЗРЕНИЕ (${when})`
          : `недоступен (${v.note ?? unavailable.join("; ")})`;
  return [`${v.pluginId}@${v.version} — скан #${v.id}: ${head}`, ...v.flags.map((f) => `  ! ${f}`), ...(v.status === "clean" ? unavailable.map((u) => `  (не отвечала: ${u})`) : [])].join("\n");
}
