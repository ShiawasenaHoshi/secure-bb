import type { Overview } from "../src/overview";
import { pluginRightsText, protectedHeadline, protectedRow, sortProtected } from "../src/ux";
import { card, muted, Fold, useNow } from "./ui";

/** «Под защитой»: every installed plugin, not only the ones that wait. Folded; the count is in the title; bb's own plugins are one line. */
export function ProtectedSection({ ov, waiting }: { ov: Overview; waiting: ReadonlySet<string> }) {
  const now = useNow();
  const rows = sortProtected(
    ov.plugins.map((p) => ({
      ...protectedRow({ id: p.id, version: p.version, status: p.status, statusDetail: p.statusDetail, source: p.source, threadId: p.threadId, pin: p.pin, rights: pluginRightsText(p.id, p.pin, ov, ov.policy.flowDowngrade), waits: waiting.has(p.id) }, now),
    })),
  );
  const head = protectedHeadline(rows, ov.builtinPlugins);
  return (
    <Fold id="protected" summaryClassName="cursor-pointer font-semibold" summary={head.title}>
      <ul className="mt-2 space-y-2" data-secure-bb-protected>
        {rows.map((r) => (
          <li key={r.id} className={card} data-protected-plugin={r.id}>
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="font-semibold">{r.id} <span className={muted}>{r.version}</span></span>
              <span className={r.standing === "works" ? "text-green-700 dark:text-green-400" : r.standing === "waits" ? "font-semibold text-yellow-700 dark:text-yellow-400" : muted}>{r.standingLabel}</span>
            </div>
            <p className={`text-xs ${muted}`}>Откуда: {r.from}</p>
            <p className="text-sm">{r.rights}</p>
            <p className={`text-xs ${muted}`}>{r.approved}</p>
          </li>
        ))}
      </ul>
      {head.builtinLine ? <p className={`mt-2 text-xs ${muted}`} data-secure-bb-builtin>{head.builtinLine}</p> : null}
    </Fold>
  );
}
