import type { CheckResult } from "../src/checks/types";
import { checksSummary, significantFindings } from "../src/ux";
import { attachFlow, capabilityPhrase } from "../src/ux";
import { muted, Fold } from "./ui";

/** What the deterministic checks found in one version (the decision table of spec §5.3 acts on it). */
export function ChecksView({ id, result }: { id: string; result: CheckResult | undefined }) {
  if (!result) return <p className={`mt-2 text-xs ${muted}`}>Проверки ещё выполняются или не запускались для этой версии.</p>;
  const sev = (s: string) => (s === "block" ? "блок" : s === "review" ? "на ревью" : "инфо");
  const lines = significantFindings(result.findings);
  return (
    <Fold id={`checks-${id}`} className="mt-2" defaultOpen={lines.some((l) => l.severity === "block")} summary={checksSummary(lines, result.capabilities.length)}>
      {lines.length > 0 ? (
        <ul className="mt-1 list-disc pl-5">
          {lines.map((l, i) => (
            <li key={i}>
              <b>{l.severity === "block" ? "Останавливает" : "Нужен взгляд"}:</b> {l.text}
              {l.count > 1 ? ` (${l.count} мест)` : ""}
              {l.where.length > 0 ? <span className={muted}> · {l.where.join(", ")}{l.count > l.where.length ? ", …" : ""}</span> : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className={`mt-1 ${muted}`}>Ничего, что требовало бы взгляда.</p>
      )}
      <p className="mt-1 font-semibold">Возможности</p>
      {result.capabilities.length === 0 ? (
        <p className={muted}>нет (безопасный класс)</p>
      ) : (
        <ul className="list-disc pl-5">
          {result.capabilities.map((c) => (
            <li key={c.kind}>{capabilityPhrase(attachFlow(result, { kind: c.kind, detail: c.detail }))}</li>
          ))}
        </ul>
      )}
      <DependenciesView result={result} />
      <Fold id={`checks-raw-${id}`} className="mt-2" summaryClassName={`cursor-pointer text-xs ${muted}`} summary="Для разработчика: сырые данные проверок">
        <ul className="mt-1 list-disc pl-5 text-xs">
          {result.findings.map((f, i) => (
            <li key={i} className="break-all">
              <b>{sev(f.severity)}</b> {f.rule} · <span className="font-mono">{f.file}{f.line ? `:${f.line}` : ""}</span> · <span className="font-mono">{f.excerpt}</span>
            </li>
          ))}
          {result.capabilities.map((c) => (
            <li key={`cap-${c.kind}`} className="break-all"><span className="font-mono">{c.kind}</span>{c.detail.length ? `: ${c.detail.join(", ")}` : ""}</li>
          ))}
          {(result.flows ?? []).map((f) => (
            <li key={`flow-${f.source}`} className="break-all"><span className="font-mono">flow {f.source}</span>{f.detail.length ? ` (${f.detail.join(", ")})` : ""}: {f.verdict}{f.sinks.length ? ` → ${f.sinks.map((k) => `${k.kind}${k.target ? `:${k.target}` : ""} ${k.file}:${k.line}`).join(", ")}` : ""}{f.why ? ` — ${f.why}` : ""}</li>
          ))}
          {(result.purposes ?? []).map((p, i) => (
            <li key={`purpose-${i}`} className="break-all"><span className="font-mono">purpose</span> {p.on.join("/")}: {p.text} ({p.pair})</li>
          ))}
        </ul>
      </Fold>
    </Fold>
  );
}

export const DEP_STATUS: Record<string, string> = {
  ok: "проверена",
  young: "релиз моложе 3 дней",
  unchecked: "не проверена",
  "not-in-registry": "нет в реестре npm",
  "unknown-version": "версии нет в реестре",
  skipped: "не из реестра",
};

/** Dependencies and what the npm registry said about them (stage 2.3). */
export function DependenciesView({ result }: { result: CheckResult }) {
  const st = result.dependencyStats;
  const deps = result.dependencies ?? [];
  if (!st || st.total === 0) return null;
  return (
    <>
      <p className="mt-1 font-semibold">Зависимости</p>
      <p className={muted}>
        всего {st.total} (объявлено {st.declared}) ·{" "}
        {st.registry ? `сверено с реестром npm: ${st.verified} · не проверено: ${st.unchecked} · моложе 3 дней: ${st.young}` : "реестр npm не опрашивался"}
        {st.lookalikes > 0 ? ` · похожи на популярные: ${st.lookalikes}` : ""}
      </p>
      {deps.length > 0 ? (
        <ul className="list-disc pl-5">
          {deps.map((d, i) => (
            <li key={i} className="break-all">
              <span className="font-mono">{d.name}@{d.version ?? d.installed ?? d.spec ?? "?"}</span>
              {d.declared ? "" : " (node_modules)"} · {d.status ? (DEP_STATUS[d.status] ?? d.status) : "не опрашивалась"}
              {d.publishedAt ? ` · выпущена ${d.publishedAt.slice(0, 10)}` : ""}
              {d.note ? <span className={muted}> — {d.note}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </>
  );
}
