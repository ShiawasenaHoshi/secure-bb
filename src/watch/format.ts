// Text for `bb secure-bb config`: the feed of differences, readable in a terminal.
// Hashes and states only, like everything the watchdog keeps.
import { CATEGORY_LABEL, SCOPE_LABEL } from "./model.js";
import type { Drift, DriftStatus } from "./model.js";
import type { WatchView } from "./watchdog.js";

const STATUS: Record<DriftStatus, string> = {
  open: "ОТКРЫТО",
  "rollback-failed": "ОТКАТ НЕ УДАЛСЯ",
  "rolled-back": "откатано",
  "accepted-window": "принято окном",
  "accepted-touch": "принято человеком",
  reverted: "вернулось",
};

const stamp = (ms: number): string => new Date(ms).toISOString().replace("T", " ").slice(0, 19);
const KIND = { added: "+", removed: "−", changed: "~" } as const;

export function formatDrift(d: Drift): string {
  const change = d.kind === "added" ? `новое: ${d.after}` : d.kind === "removed" ? `пропало (было: ${d.before})` : `${d.before} → ${d.after}`;
  const tail = [d.rollbackable && (d.status === "open" || d.status === "rollback-failed") ? "откат возможен" : null, d.note].filter(Boolean).join("; ");
  return `${stamp(d.firstSeen)} #${d.id} [${STATUS[d.status]}] ${KIND[d.kind]} ${d.label}: ${change}${tail ? ` (${tail})` : ""}`;
}

export function formatWatch(v: WatchView, now: number, limit = 20): string {
  const lines: string[] = [];
  lines.push(
    v.baselineAt === null
      ? "эталон: не принят — человек принимает текущую конфигурацию на странице secure-bb (с кодом); до этого расхождения не оцениваются"
      : `эталон: принят ${stamp(v.baselineAt)}`,
  );
  lines.push(`откат: ${v.rollbackEnabled ? "включён" : "выключен (расхождения только показываются)"}`);
  if (v.windows.length === 0) lines.push("окно доверия «конфигурация»: закрыто");
  for (const w of v.windows) lines.push(`окно доверия «конфигурация»: ${w.scopes.map((s) => SCOPE_LABEL[s]).join(", ")} — ещё ${Math.ceil(w.remainingSec / 60)} мин`);
  lines.push(
    v.lastScanAt === null
      ? "последняя проверка: ещё не было"
      : `последняя проверка: ${stamp(v.lastScanAt)} (${Math.max(0, Math.round((now - v.lastScanAt) / 1000))} с назад), наблюдается объектов: ${v.observedCount}`,
  );
  const cats = Object.entries(v.byCategory).map(([c, n]) => `${CATEGORY_LABEL[c as keyof typeof CATEGORY_LABEL]}: ${n}`);
  if (cats.length > 0) lines.push(`наблюдается: ${cats.join("; ")}`);

  const open = v.drifts.filter((d) => d.status === "open" || d.status === "rollback-failed");
  lines.push("", `расхождения: ${open.length === 0 ? "нет открытых" : `${open.length} открыто`}`);
  for (const d of v.drifts.slice(0, limit)) lines.push(`  ${formatDrift(d)}`);
  if (v.failed.length > 0) {
    lines.push("", "не удалось прочитать сейчас (расхождения здесь не оцениваются):");
    for (const f of v.failed) lines.push(`  ${f.source}: ${f.reason}`);
  }
  if (v.notApplicable.length > 0) {
    lines.push("", "не применимо (читать нечего):");
    for (const f of v.notApplicable) lines.push(`  ${f.source}: ${f.reason}`);
  }
  if (v.blind.length > 0) {
    lines.push("", "не наблюдается вообще (в API bb этого нет):");
    for (const b of v.blind) lines.push(`  ${b.reason}`);
  }
  return lines.join("\n");
}
