import { useId, useState } from "react";
import type { Overview } from "../src/overview";
import { T } from "../src/text";
import type { PasskeyAssertion } from "../src/guardlink";
import { glossSegments, emphasize, proofHint } from "../src/ux";
import { useApproval, RoutineCode } from "./approval";
import { useDraftCode, CodeField, type Rpc, type PasskeyState, usePasskey, type TouchQuery, TouchNote, touchFor } from "./code";
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

export interface ProofHook {
  code: string;
  setCode: (v: string) => void;
  pk: PasskeyState;
  touching: string | null;
  registered: boolean;
  /** Can the action start with what is typed now? */
  ready: (o?: { routine?: boolean; dangerous?: boolean }) => boolean;
  /** Runs an action with a touch (a key, if there is one and no code typed) or a code (or a session, for a routine action). */
  run: <T>(query: TouchQuery, call: (proof: AnyProof) => Promise<T>, o?: { routine?: boolean; dangerous?: boolean }) => Promise<T>;
}

export function useProof(ov: Overview, rpc: Rpc, draftKey?: string): ProofHook {
  const ap = useApproval();
  const pk = usePasskey(ov);
  const ownKey = useId();
  const [code, setCode] = useDraftCode(draftKey ?? ownKey);
  const [touching, setTouching] = useState<string | null>(null);
  const registered = ov.totp.state === "locked" || ov.totp.state === "external";
  // An open session covers a routine action: no touch and no code (with a key too). The dangerous kind of an action never uses it.
  const viaSession = (o: { routine?: boolean; dangerous?: boolean }): boolean => o.routine === true && o.dangerous !== true && ap.session !== null && code.length !== 6;
  const ready: ProofHook["ready"] = (o = {}) => registered && (viaSession(o) ? true : pk.has ? pk.problem === null || code.length === 6 : o.routine ? ap.ready(code, o.dangerous) : code.length === 6);
  const run: ProofHook["run"] = async (query, call, o = {}) => {
    try {
      if (viaSession(o)) return await ap.routine(code, (p) => call(p as AnyProof), o.dangerous);
      if (pk.has && code.length !== 6) {
        setTouching(null);
        const t = await touchFor(rpc, query, setTouching);
        return await call(t ? { passkey: t.passkey } : {});
      }
      if (o.routine) return await ap.routine(code, (p) => call(p as AnyProof), o.dangerous);
      return await call({ code });
    } finally {
      setCode("");
      setTouching(null);
    }
  };
  return { code, setCode, pk, touching, registered, ready, run };
}

/** The code field (when codes work), the note about what is being touched, and why a touch is impossible. */
export function ProofField({ proof, routine, dangerous }: { proof: ProofHook; routine?: boolean; dangerous?: boolean }) {
  const ap = useApproval();
  return (
    <>
      {ap.session && routine && !dangerous ? <span className={`text-xs ${muted}`}>сессия открыта: {proof.pk.has ? "касание и код" : "код"} не нужен</span> : null}
      {ap.session && routine && !dangerous ? null : proof.pk.has ? <span className={muted}>касание или код:</span> : null}
      {ap.session && routine && !dangerous ? null : proof.pk.keyOnly ? null : routine && !proof.pk.has ? <RoutineCode value={proof.code} onChange={proof.setCode} dangerous={dangerous} /> : <CodeField value={proof.code} onChange={proof.setCode} />}
      {!proof.registered ? <span className={muted}>сначала зарегистрируйте второй фактор</span> : null}
      {proof.registered && !(ap.session && routine && !dangerous) ? <span className={`basis-full text-xs ${muted}`}>{proofHint({ hasKey: proof.pk.has, keyOnly: proof.pk.keyOnly })}</span> : null}
    </>
  );
}

/** Plain words next to a bare code field (outside ProofField). */
export function CodeHint({ ov }: { ov: Overview }) {
  const pk = usePasskey(ov);
  return <span className={`basis-full text-xs ${muted}`}>{proofHint({ hasKey: pk.has, keyOnly: pk.keyOnly })}</span>;
}

/** What a card says a plugin can do; the word «все» (of all variables) is red. */
export function Emph({ text }: { text: string }) {
  return <>{glossSegments(emphasize(text)).map((x, i) => (x.red ? <b key={i} className="text-red-700 dark:text-red-400">{x.text}</b> : x.hint ? <abbr key={i} title={x.hint} className="cursor-help underline decoration-dotted underline-offset-2">{x.text}</abbr> : <span key={i}>{x.text}</span>))}</>;
}

/** `a command in backticks` is shown as code; the words around it go through the glossary. */
export function Rich({ text }: { text: string }) {
  return <>{text.split("`").map((part, i) => (i % 2 === 1 ? <code key={i} className="break-all rounded bg-muted px-1 font-mono text-xs">{part}</code> : <Emph key={i} text={part} />))}</>;
}

export function ProofNotes({ proof }: { proof: ProofHook }) {
  return (
    <>
      {proof.pk.has && proof.pk.problem ? <p className="mt-1 text-destructive">{proof.pk.problem}</p> : null}
      <TouchNote text={proof.touching} />
    </>
  );
}
