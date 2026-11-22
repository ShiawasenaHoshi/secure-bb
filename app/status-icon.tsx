// The shield of SecureBB in bb's chrome: the icon of the sidebar footer and of the entry in the navigation (one registered glyph, `secure-bb-shield`), the badge on the
// entry, and the small status the footer opens. All three read the view of status-store.ts; the words are the header's sentence, said once.
import type { ExperimentalBadge, ExperimentalSidebarFooterDisclosureProps } from "@get-bb/plugin-sdk/app";
import { useBbNavigate } from "@get-bb/plugin-sdk/app";
import { ShieldIcon } from "../components/ui/shield-icon";
import { Button } from "../components/ui/button";
import { cn } from "../lib/utils";
import { PAGE_TITLE } from "./page-title";
import { MARK } from "./header";
import { useProtectionView } from "./status-store";

export const SHIELD_ICON = "secure-bb-shield";

/** Theme tokens only: the shield keeps the text color when all is well; a waiting request is the theme's warning, an alarm is destructive. */
const SHIELD_TINT = { ok: "", waiting: "text-[var(--warning-text)]", alarm: "text-destructive" } as const;
const BADGE_TINT = { warning: "border-[var(--warning)] text-[var(--warning-text)]", critical: "border-destructive text-destructive" } as const;

/** The glyph bb draws wherever the name `secure-bb-shield` is used: it sizes by `className`, inherits the color, and shows the state (check, alert, the number waiting). */
export function ShieldStatusIcon({ className }: { className?: string }) {
  const v = useProtectionView();
  const tone = v?.tone ?? "ok";
  const badge = v?.badge ?? null;
  return (
    <span className={cn("relative inline-flex", className)} data-secure-bb-sidebar-icon={v ? tone : "unknown"}>
      <ShieldIcon mark={v ? MARK[tone] : "none"} className={cn("size-full", SHIELD_TINT[tone])} />
      {badge ? (
        <span className={cn("absolute -right-1.5 -top-1.5 flex min-w-3 items-center justify-center rounded-full border bg-background px-0.5 text-[9px] font-semibold leading-3", BADGE_TINT[badge.tone])} data-secure-bb-sidebar-badge={badge.tone}>
          {badge.count !== undefined ? (badge.count > 9 ? "9+" : badge.count) : null}
        </span>
      ) : null}
    </span>
  );
}

/** The badge of the navigation entry (its tooltip is the label): none when all is well. */
export function useNavBadge(): ExperimentalBadge | null {
  const v = useProtectionView();
  return v?.badge ?? null;
}

/** What the footer's shield opens: the status sentence, once, and the way to the page. */
export function ProtectionStatus({ dismiss }: ExperimentalSidebarFooterDisclosureProps) {
  const v = useProtectionView();
  const nav = useBbNavigate();
  return (
    <div className="flex items-center gap-2 p-3" role="status" data-secure-bb-sidebar-status={v?.tone ?? "unknown"}>
      <ShieldIcon mark={v ? MARK[v.tone] : "none"} className={cn("size-5", SHIELD_TINT[v?.tone ?? "ok"])} />
      <p className="min-w-0 flex-1 text-sm font-medium">{v ? v.text : "Состояние защиты ещё не получено"}</p>
      <Button size="sm" variant={v?.tone === "alarm" ? "destructive" : "outline"} onClick={() => { nav.toPluginPanel("gate"); dismiss(); }}>Открыть {PAGE_TITLE}</Button>
    </div>
  );
}
