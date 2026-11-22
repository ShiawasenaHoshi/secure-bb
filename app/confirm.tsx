import { useId } from "react";
import type { Overview } from "../src/overview";
import { T } from "../src/text";
import type { PasskeyAssertion } from "../src/guardlink";
import { glossSegments, emphasize, proofHint } from "../src/ux";
import { useApproval } from "./approval";
import { drafts, CodeField, type Rpc, type PasskeyState, usePasskey, type TouchQuery } from "./code";
import { useAskConfirm } from "./confirm-dialog";
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

export type AnyProof = { code?: string; session?: string; passkey?: PasskeyAssertion };

export interface ProofOpts {
  routine?: boolean;
  dangerous?: boolean;
  /** What the dialog says is being approved («Разрешить chime 0.1.0»). Default: the words of the button that was pressed. */
  what?: string;
  /** One more line under it: what gets more dangerous. */
  detail?: string;
  /** The guard may say the action needs no touch (it only tightens): then it runs at once, with no dialog. */
  optional?: boolean;
}

export interface ProofHook {
  /** The draft of the code the dialog works with (a card has no field of its own any more). */
  clearDraft: () => void;
  pk: PasskeyState;
  registered: boolean;
  /** Can the action start? A second factor is set up; the code or the touch is asked for by the dialog. */
  ready: (o?: ProofOpts) => boolean;
  /**
   * Runs an action: with the open session when it is a routine one (no question), otherwise through the confirmation dialog
   * (a touch or a code; its error stays in the dialog). Closing the dialog rejects with ConfirmCancelled, which the action runner ignores.
   */
  run: <T>(query: TouchQuery, call: (proof: AnyProof) => Promise<T>, o?: ProofOpts) => Promise<T>;
}

/** What the server says when an action needs a code or a touch (the same sentence humanError turns into «Нужен код…»). */
const NEEDS_PROOF = /a code or a touch is needed|a code is needed|code, or an open session|invalid_code/i;

const pressedLabel = (): string => {
  const el = typeof document !== "undefined" ? (document.activeElement as HTMLElement | null) : null;
  const text = el && el.tagName === "BUTTON" ? (el.textContent ?? "").replace(/\s+/g, " ").trim() : "";
  return text || "Подтвердите действие";
};

export function useProof(ov: Overview, rpc: Rpc, draftKey?: string): ProofHook {
  const ap = useApproval();
  const ask = useAskConfirm();
  const pk = usePasskey(ov);
  const ownKey = useId();
  const key = draftKey ?? ownKey;
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  // An open session covers a routine action: no touch and no code (with a key too). The dangerous kind of an action never uses it.
  const viaSession = (o: ProofOpts): boolean => o.routine === true && o.dangerous !== true && ap.session !== null;
  const ready: ProofHook["ready"] = () => registered;
  const run: ProofHook["run"] = async (query, call, o = {}) => {
    if (viaSession(o)) return await ap.routine("", (p) => call(p as AnyProof), o.dangerous);
    if (o.optional) {
      // An action that may only tighten needs no touch, and then runs at once, with no dialog. The guard says so when asked; without a guard the action itself is tried
      // with no proof, and only an answer «a code or a touch is needed» (it widens) sends the person to the dialog.
      let widens = false;
      if (ov.guard) {
        const c = await rpc.call("passkey.challenge", query as never).catch(() => null);
        if (c && !c.needed) return await call({});
        widens = c !== null && c.needed;
      }
      if (!widens) {
        try {
          return await call({});
        } catch (e) {
          if (!NEEDS_PROOF.test(e instanceof Error ? e.message : String(e))) throw e;
        }
      }
    }
    return (await ask({ what: o.what ?? pressedLabel(), ...(o.detail ? { detail: o.detail } : {}), query, draftKey: key, call: (p) => call(p as AnyProof) })) as Awaited<ReturnType<typeof call>>;
  };
  return { clearDraft: () => drafts.clear(key), pk, registered, ready, run };
}

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
