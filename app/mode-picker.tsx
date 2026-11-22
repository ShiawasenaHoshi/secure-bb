import type { TrustMode } from "../src/guardlink";
import { MODE_DESCRIPTIONS, MODE_NAMES } from "../src/ux";
import { RadioGroup, RadioGroupItem } from "../components/ui/radio-group";
import { Badge } from "../components/ui/badge";
import { muted } from "./ui";

export const MODE_RANK_UI = { simple: 0, detailed: 1, strict: 2 } as const;

/** The first line of a mode's description: the card's one-line explanation. The longer rules are under «Как это работает». */
export const modeLine = (m: TrustMode): string => MODE_DESCRIPTIONS[m].split(/(?<=\.)\s/)[0] ?? MODE_DESCRIPTIONS[m];

/** Three cards, one of them chosen: the same on the trust tab and in the first-run wizard. */
export function ModePicker({ value, onChange, disabled, recommended = "simple" }: { value: TrustMode; onChange: (m: TrustMode) => void; disabled?: boolean; recommended?: TrustMode | null }) {
  return (
    <RadioGroup value={value} onValueChange={(v) => onChange(v as TrustMode)} disabled={disabled} aria-label="Режим проверки плагинов" data-secure-bb-modes>
      {(["simple", "detailed", "strict"] as const).map((m) => (
        <RadioGroupItem key={m} value={m} data-mode={m}>
          <span className="flex flex-wrap items-center gap-2 font-medium">
            {MODE_NAMES[m]}
            {m === recommended ? <Badge variant="secondary">рекомендуется</Badge> : null}
          </span>
          <span className={`block text-xs ${muted}`}>{modeLine(m)}</span>
        </RadioGroupItem>
      ))}
    </RadioGroup>
  );
}
