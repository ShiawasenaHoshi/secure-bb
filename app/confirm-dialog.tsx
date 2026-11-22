import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { Overview } from "../src/overview";
import type { PasskeyAssertion } from "../src/guardlink";
import { humanError, proofHint } from "../src/ux";
import { Button } from "../components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../components/ui/dialog";
import { Icon } from "../components/ui/icon";
import { InputOTP } from "../components/ui/input-otp";
import { drafts, usePasskey, touchFor, type Rpc, type TouchQuery } from "./code";

/** What the dialog sends: a code or a signed touch. The action itself (`call`) is run by the dialog, so that its error is shown under the field. */
export type ConfirmProof = { code?: string; passkey?: PasskeyAssertion };

export interface ConfirmRequest {
  /** What is being approved, in the page's words: «Разрешить chime 0.1.0». */
  what: string;
  /** What gets more dangerous, or what the action does, when the title does not say it all. */
  detail?: string;
  /** The same query the guard binds the touch to. */
  query: TouchQuery;
  /** The key the code draft lives under (a draft survives a redraw, as before). */
  draftKey: string;
  call: (proof: ConfirmProof) => Promise<unknown>;
}

/** The person closed the dialog: not an error, nothing is shown. */
export class ConfirmCancelled extends Error {
  constructor() {
    super("confirmation cancelled");
  }
}

export type AskConfirm = (req: ConfirmRequest) => Promise<unknown>;

export const ConfirmContext = createContext<AskConfirm>(() => Promise.reject(new Error("no confirmation dialog on this page")));
export const useAskConfirm = (): AskConfirm => useContext(ConfirmContext);

interface Pending {
  req: ConfirmRequest;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
}

/** Holds the one dialog of the page: every action that needs a touch or a code asks it. */
export function ConfirmHost({ ov, rpc, children }: { ov: Overview; rpc: Rpc; children: ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const ref = useRef<Pending | null>(null);
  ref.current = pending;
  const ask = useCallback<AskConfirm>(
    (req) =>
      new Promise((resolve, reject) => {
        ref.current?.reject(new ConfirmCancelled());
        setPending({ req, resolve, reject });
      }),
    [],
  );
  const finish = (how: "done" | "cancel", value?: unknown) => {
    const p = ref.current;
    if (!p) return;
    setPending(null);
    if (how === "done") p.resolve(value);
    else p.reject(new ConfirmCancelled());
  };
  return (
    <ConfirmContext.Provider value={ask}>
      {children}
      {pending ? <ConfirmDialog key={`${pending.req.draftKey}:${pending.req.what}`} ov={ov} rpc={rpc} req={pending.req} onDone={(v) => finish("done", v)} onCancel={() => finish("cancel")} /> : null}
    </ConfirmContext.Provider>
  );
}

export function ConfirmDialog({ ov, rpc, req, onDone, onCancel }: { ov: Overview; rpc: Rpc; req: ConfirmRequest; onDone: (v: unknown) => void; onCancel: () => void }) {
  const pk = usePasskey(ov);
  const [code, setCodeState] = useState<string>(() => drafts.get(req.draftKey));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [touching, setTouching] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => () => void (alive.current = false), []);
  const setCode = (v: string) => {
    drafts.set(req.draftKey, v);
    setCodeState(v);
    if (error) setError(null);
  };
  /** Runs the action with the proof; a failure stays under the field and the dialog stays open. A code is spent either way: the field is cleared. */
  const submit = async (get: () => Promise<ConfirmProof>, fromCode: boolean) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const proof = await get();
      const result = await req.call(proof);
      drafts.clear(req.draftKey);
      onDone(result);
    } catch (e) {
      const raw = e instanceof Error ? e.message : String(e);
      console.error("[secure-bb]", raw);
      if (alive.current) {
        setError(humanError(raw));
        if (fromCode) setCode("");
      }
    } finally {
      if (alive.current) {
        setBusy(false);
        setTouching(null);
      }
    }
  };
  const touch = () =>
    void submit(async () => {
      const t = await touchFor(rpc, req.query, setTouching);
      return t ? { passkey: t.passkey } : {};
    }, false);
  const sendCode = (v: string) => void submit(async () => ({ code: v }), true);
  return (
    <Dialog open onOpenChange={(o) => (!o && !busy ? onCancel() : undefined)}>
      <DialogContent data-secure-bb-confirm>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icon name="Shield" aria-hidden="true" className="size-5 shrink-0" />
            <span data-secure-bb-confirm-what>{req.what}</span>
          </DialogTitle>
          <DialogDescription>{req.detail ?? "Это действие требует подтверждения."}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          {pk.has ? (
            <div className="space-y-2">
              <Button className="w-full" disabled={busy} onClick={touch}>
                Приложить палец / ключ
              </Button>
              {pk.problem ? <p className="text-sm text-destructive">{pk.problem}</p> : null}
              {touching ? <p className="text-sm text-muted-foreground" role="status">{touching}</p> : null}
            </div>
          ) : null}
          {pk.keyOnly ? null : (
            <div className="space-y-2">
              {pk.has ? <p className="text-sm text-muted-foreground">или код из приложения</p> : <p className="text-sm text-muted-foreground">Код из приложения на телефоне</p>}
              <InputOTP value={code} onChange={setCode} onComplete={sendCode} disabled={busy} invalid={error !== null} autoFocus={!pk.has} />
            </div>
          )}
          <p className="text-xs text-muted-foreground">{proofHint({ hasKey: pk.has, keyOnly: pk.keyOnly })}</p>
          <p className="min-h-5 text-sm text-destructive" role="alert" data-secure-bb-confirm-error>{error}</p>
        </div>
        <DialogFooter>
          <Button variant="ghost" disabled={busy} onClick={onCancel}>
            Отмена
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
