import type { Overview } from "../src/overview";
import { truthfulApproval } from "../src/factor";
import { pluginRightsText, protectedHeadline, protectedRow, sortProtected } from "../src/ux";
import { Badge } from "../components/ui/badge";
import { Card } from "../components/ui/card";
import { EmptyState } from "../components/ui/empty-state";
import { muted, useNow } from "./ui";

const STANDING_BADGE = { works: "secondary", waits: "outline", quarantine: "outline" } as const;

/**
 * «Под защитой»: every installed plugin, not only the ones that wait. One row each: the name, the status, where it came from, its rights in a line, the version
 * and when it was approved. bb's own plugins are one line at the bottom. No plugins: an empty state.
 */
export function ProtectedSection({ ov, waiting, onShowCard }: { ov: Overview; waiting: ReadonlySet<string>; onShowCard: (pluginId: string) => void }) {
  const now = useNow();
  const rows = sortProtected(
    ov.plugins.map((p) => ({
      ...protectedRow({ id: p.id, version: p.version, status: p.status, statusDetail: p.statusDetail, source: p.source, threadId: p.threadId, pin: p.pin ? truthfulApproval(p.pin, { guardMode: ov.guard?.connected === true, recent: ov.guard?.recent ?? [] }) : null, rights: pluginRightsText(p.id, p.pin, ov, ov.policy.flowDowngrade), waits: waiting.has(p.id) }, now),
    })),
  );
  const head = protectedHeadline(rows, ov.builtinPlugins);
  return (
    <section className="space-y-2" id="sbb-protected">
      <h2 className="text-base font-semibold">{head.title}</h2>
      {rows.length === 0 ? (
        <EmptyState message="Пока нет установленных плагинов" />
      ) : (
        <Card className="divide-y divide-border p-0" data-secure-bb-protected>
          {rows.map((r) => (
            <div key={r.id} className="space-y-1 p-3 text-sm" data-protected-plugin={r.id}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="min-w-0 break-all font-medium">{r.id} <span className={`text-xs font-normal ${muted}`}>{r.version}</span></span>
                <Badge variant={STANDING_BADGE[r.standing]} data-secure-bb-standing={r.id}>{r.standingLabel}</Badge>
              </div>
              {r.standing === "waits" ? (
                // The card above says everything (the source, the rights); here it is one line with the way to it.
                <p className={`text-xs ${muted}`}>ждёт решения · <button type="button" className="underline hover:no-underline" onClick={() => onShowCard(r.id)}>к карточке</button></p>
              ) : (
                <>
                  <p className={`break-all text-xs ${muted}`}>{r.from}</p>
                  <p>{r.rights}</p>
                  <p className={`text-xs ${muted}`}>{r.approved}</p>
                </>
              )}
            </div>
          ))}
        </Card>
      )}
      {head.builtinLine ? <p className={`text-xs ${muted}`} data-secure-bb-builtin>{head.builtinLine}</p> : null}
    </section>
  );
}
