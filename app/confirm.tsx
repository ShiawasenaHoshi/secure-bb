import type { Overview } from "../src/overview";
import { T } from "../src/text";
import type { PasskeyAssertion } from "../src/guardlink";
import { glossSegments, emphasize, proofHint } from "../src/ux";
import { useApproval } from "./approval";
import type { ProofHook } from "./proof";
import { usePasskey } from "./touch";
import { card, muted, when } from "./ui";

export const lsGet = (k: string): string | null => {
  try {
    return window.localStorage.getItem(k);
  } catch {
    return null;
  }
};

/** localStorage holds only conveniences (when "while you were away" starts, which cards were put aside): not security data. */
export const lsSet = (k: string, v: string): void => {
  try {
    window.localStorage.setItem(k, v);
  } catch {
    /* a private window: the page just forgets */
  }
};

/** What stands where the code field used to: a session note, or why nothing can be approved yet. The code is asked for by the dialog. */
export function ProofField({ proof, routine, dangerous }: { proof: ProofHook; routine?: boolean; dangerous?: boolean }) {
  const ap = useApproval();
  if (!proof.registered) return <span className={muted}>сначала зарегистрируйте второй фактор</span>;
  if (ap.session && routine && !dangerous) return <span className={`text-xs ${muted}`}>сессия открыта: подтверждение не нужно</span>;
  return null;
}

/** Plain words next to a bare code field (outside ProofField). */
export function CodeHint({ ov }: { ov: Overview }) {
  const pk = usePasskey(ov);
  return <span className={`basis-full text-xs ${muted}`}>{proofHint({ hasKey: pk.has, keyOnly: pk.keyOnly })}</span>;
}

/** What a card says a plugin can do; the word «все» (of all variables) is red. */
export function Emph({ text }: { text: string }) {
  return <>{glossSegments(emphasize(text)).map((x, i) => (x.red ? <b key={i} className="text-destructive">{x.text}</b> : x.hint ? <abbr key={i} title={x.hint} className="cursor-help underline decoration-dotted underline-offset-2">{x.text}</abbr> : <span key={i}>{x.text}</span>))}</>;
}

/** `a command in backticks` is shown as code; the words around it go through the glossary. */
export function Rich({ text }: { text: string }) {
  return <>{text.split("`").map((part, i) => (i % 2 === 1 ? <code key={i} className="break-all rounded bg-muted px-1 font-mono text-xs">{part}</code> : <Emph key={i} text={part} />))}</>;
}

/** Kept for the cards that still call it: a touch is shown in the dialog now. */
export function ProofNotes(_: { proof: ProofHook }) {
  return null;
}
