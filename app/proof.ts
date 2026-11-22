// A decision with a proof: runs the action with the open session when it is a routine one, otherwise asks the confirmation dialog (a touch or a code).
// No drawing here: the dialog and the session are what it stands on.
import { useId } from "react";
import type { Overview } from "../src/overview";
import type { PasskeyAssertion } from "../src/guardlink";
import { useApproval } from "./approval";
import { useAskConfirm } from "./confirm-dialog";
import { drafts, usePasskey, type PasskeyState, type Rpc, type TouchQuery } from "./touch";

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
