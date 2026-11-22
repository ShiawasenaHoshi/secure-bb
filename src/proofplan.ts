// How a person can prove a change from THIS page: a key (only where it can work), a code (anywhere), and a link to the page at the address the key needs.
// It decides the order and the offer, nothing else: the guard still checks the origin of every touch itself (that check is the phishing defence and stays).
import { originProblem } from "./webauthn.js";

export interface ProofPlanInput {
  currentOrigin: string;
  currentPath: string;
  guardOrigin: string;
  hasKey: boolean;
  /** Codes are switched off at the guard. */
  keyOnly: boolean;
  /** `navigator.credentials.get` exists here. */
  webauthn: boolean;
  /** The page is shown by the bb desktop app (Electron): it loads no extensions, so a password manager's key is not reachable. */
  desktopApp: boolean;
}

export interface ProofPlan {
  /** Where the key button stands: before the code, after it, or not at all (it cannot work here). */
  key: "first" | "second" | "none";
  /** The code field is offered. */
  code: boolean;
  /** Why the key is not offered (or not first) here, in words; null when nothing needs saying. */
  note: string | null;
  /** The same page at the address where the key works; null when the key has nothing to ask for or this is already the place. */
  openUrl: string | null;
}

export const isDesktopApp = (userAgent: string): boolean => /\bElectron\//.test(userAgent);

export function proofPlan(i: ProofPlanInput): ProofPlan {
  if (!i.hasKey) return { key: "none", code: true, note: null, openUrl: null };
  const rightPlace = originProblem(i.currentOrigin, i.guardOrigin) === null;
  const canTry = rightPlace && i.webauthn;
  const key = !canTry ? "none" : i.desktopApp ? "second" : "first";
  // A link is only built from the guard's own origin and the path of this page: no query and no fragment (an enrolment token lives there).
  const openUrl = !rightPlace || i.desktopApp ? new URL(i.currentPath.startsWith("/") ? i.currentPath : "/", i.guardOrigin).toString() : null;
  return { key, code: !i.keyOnly, note: key === "first" ? null : planNote(i, rightPlace), openUrl };
}

function planNote(i: ProofPlanInput, rightPlace: boolean): string {
  const base = rightPlace && !i.webauthn ? "В этом браузере нет WebAuthn" : `Ключ работает в браузере на ${i.guardOrigin}`;
  const app = i.desktopApp ? " (в приложении bb ключи менеджеров паролей недоступны)" : "";
  return i.keyOnly ? `${base}${app}. Коды отключены, поэтому здесь подтвердить нельзя.` : `${base}${app}; здесь — код из приложения.`;
}
