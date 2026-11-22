import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { ComponentType, ReactNode } from "react";
import type { Overview } from "../src/overview";
import type { PasskeyAssertion } from "../src/guardlink";
import { humanError, proofHint, OPEN_IN_BROWSER } from "../src/ux";
import type { ProofPlan } from "../src/proofplan";
import { Button } from "../components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../components/ui/dialog";
import { ShieldIcon } from "../components/ui/shield-icon";
import { InputOTP } from "../components/ui/input-otp";
import { ConfirmCancelled } from "./confirm-error";
import { drafts, usePasskey, touchFor, type Rpc, type TouchQuery } from "./touch";

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

export type AskConfirm = (req: ConfirmRequest) => Promise<unknown>;

export const ConfirmContext = createContext<AskConfirm>(() => Promise.reject(new Error("no confirmation dialog on this page")));
export const useAskConfirm = (): AskConfirm => useContext(ConfirmContext);

interface Pending {
  req: ConfirmRequest;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
}

/** Holds the one dialog of the page: every action that needs a touch or a code asks it. */
/** `Shell` is what the panel is drawn in: the dialog (a test may draw it bare). */
export function ConfirmHost({ ov, rpc, children, Shell = ConfirmDialog }: { ov: Overview; rpc: Rpc; children: ReactNode; Shell?: ComponentType<PanelProps> }) {
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
      {pending ? <Shell key={`${pending.req.draftKey}:${pending.req.what}`} ov={ov} rpc={rpc} req={pending.req} onDone={(v) => finish("done", v)} onCancel={() => finish("cancel")} /> : null}
    </ConfirmContext.Provider>
  );
}

export interface PanelProps {
  ov: Overview;
  rpc: Rpc;
  req: ConfirmRequest;
  onDone: (v: unknown) => void;
  onCancel: () => void;
}

/** The dialog's own parts, so that the panel can be drawn (and tested) without the dialog around it. */
export interface PanelParts {
  Title: ComponentType<{ className?: string; children: ReactNode }>;
  Description: ComponentType<{ children: ReactNode }>;
}

/** Why there is no key button here, and the way to the page where it works. The link opens the browser's page at the guard's own origin. */
export function KeyNote({ plan }: { plan: ProofPlan }) {
  return (
    <div className="space-y-2" data-secure-bb-key-note>
      <p className="text-sm text-muted-foreground">{plan.note}</p>
      {plan.openUrl ? (
        <a className="text-sm underline" href={plan.openUrl} target="_blank" rel="noopener noreferrer">
          {OPEN_IN_BROWSER}
        </a>
      ) : null}
    </div>
  );
}

/** What the dialog says and does: the action, the touch button, the code cells, the error under them. */
export function ConfirmPanel({ ov, rpc, req, onDone, onCancel, parts }: PanelProps & { parts: PanelParts }) {
  const { Title, Description } = parts;
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
  const keyPart = (
    <div className="space-y-2">
      <Button className="w-full" variant={pk.plan.key === "second" ? "outline" : "default"} disabled={busy} onClick={touch}>
        Приложить палец / ключ
      </Button>
      {touching ? <p className="text-sm text-muted-foreground" role="status">{touching}</p> : null}
    </div>
  );
  return (
    <>
      <DialogHeader>
        <Title className="flex items-center gap-2">
          <ShieldIcon />
          <span data-secure-bb-confirm-what>{req.what}</span>
        </Title>
        <Description>{req.detail ?? "Это действие требует подтверждения."}</Description>
      </DialogHeader>
      <div className="space-y-4">
        {pk.plan.note ? <KeyNote plan={pk.plan} /> : null}
        {pk.plan.key === "first" ? keyPart : null}
        {pk.plan.code ? (
          <div className="space-y-2">
            {pk.plan.key === "first" ? <p className="text-sm text-muted-foreground">или код из приложения</p> : <p className="text-sm text-muted-foreground">Код из приложения на телефоне</p>}
            <InputOTP value={code} onChange={setCode} onComplete={sendCode} disabled={busy} invalid={error !== null} autoFocus={pk.plan.key !== "first"} />
          </div>
        ) : null}
        {pk.plan.key === "second" ? keyPart : null}
        <p className="text-xs text-muted-foreground">{proofHint({ hasKey: pk.plan.key !== "none", keyOnly: pk.keyOnly && pk.plan.key !== "none" })}</p>
        <p className="min-h-5 text-sm text-destructive" role="alert" data-secure-bb-confirm-error>{error}</p>
      </div>
      <DialogFooter>
        <Button variant="ghost" disabled={busy} onClick={onCancel}>
          Отмена
        </Button>
      </DialogFooter>
    </>
  );
}

const DIALOG_PARTS: PanelParts = { Title: DialogTitle, Description: DialogDescription };

export function ConfirmDialog(props: PanelProps) {
  return (
    <Dialog open onOpenChange={(o) => (!o ? props.onCancel() : undefined)}>
      <DialogContent data-secure-bb-confirm>
        <ConfirmPanel {...props} parts={DIALOG_PARTS} />
      </DialogContent>
    </Dialog>
  );
}
