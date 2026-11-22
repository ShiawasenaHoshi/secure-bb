// The touch and the session in words: where a key is stored, hints for a stuck touch, what to enter, the session paragraph.
import type { TrustMode } from "../guardlink.js";
import { SESSION_CAP_MS, SESSION_IDLE_MS, minutesWords, minutesWordsUpTo, sessionCoverage } from "../../guard/src/session-rules.ts";

const AAGUIDS: Record<string, string> = {
  "fbfc3007154e4ecc8c0b6e020557d7bd": "iCloud-связка",
  adce000235bcc60a648b0b25f1f05503: "Chrome (Touch ID)",
  "50726f746f6e5061737350726f746f6e": "Proton Pass",
  bada5566a7aa401fbd9645619a55120d: "1Password",
  "531126d6e717415c93203d9aa6981239": "Dashlane",
  d548826e79b4db40a3d811116f7e8349: "Bitwarden",
  "6028b017b1d44c02b4b3afcdafc96bb2": "Windows Hello",
  "08987058cadc4b81b6e130de50dcbe96": "Windows Hello",
  "9ddd1817af5a4672a2b93e3dd95000a9": "Windows Hello",
};

/** Where the key is kept, by the AAGUID the guard recorded (hex, with or without dashes). Unknown or empty: «другое». */
export function aaguidName(aaguid: string | null | undefined): string {
  const h = (aaguid ?? "").toLowerCase().replace(/[^0-9a-f]/g, "");
  return AAGUIDS[h] || "другое";
}

/** For a name that is not one of the safe stores a warning goes with it: a password manager's extension may answer the request instead of the system. */
export const isPasswordManager = (name: string): boolean => name === "Proton Pass" || name === "1Password" || name === "Dashlane" || name === "Bitwarden";

export const TOUCH_SLOW_MS = 12_000;

export const TOUCH_SLOW_HINT = "Касание не завершилось. Если ключ в менеджере паролей — посмотрите его окно; или выберите другое устройство.";

export const SAVED_NARROWING = "Сохранено: это сужение, касание не требуется.";

export const touchWithHint = (description: string, slow: boolean): string => `Подтвердите касанием. Защита: «${description}»${slow ? `. ${TOUCH_SLOW_HINT}` : ""}`;

export interface TouchTimers {
  set: (fn: () => void, ms: number) => unknown;
  clear: (handle: unknown) => void;
}

/**
 * The sentence under a button that touches: at once without the hint, and after TOUCH_SLOW_MS with it. The request is never cancelled (the touch may
 * still come); the returned function only stops the timer. `timers` is for tests.
 */
export function startTouchNote(description: string, shown: (text: string) => void, timers: TouchTimers = { set: (fn, ms) => setTimeout(fn, ms), clear: (h) => clearTimeout(h as never) }): () => void {
  shown(touchWithHint(description, false));
  const handle = timers.set(() => shown(touchWithHint(description, true)), TOUCH_SLOW_MS);
  return () => timers.clear(handle);
}

export const OPEN_IN_BROWSER = "Открыть в браузере";

export const CODE_HINT = "6 цифр из приложения на телефоне (Google Authenticator и т. п.)";

export const KEY_HINT = "приложите палец";

/** The line next to the code field: a key if there is one (the code is the fallback), else the code's own words. */
export function proofHint(i: { hasKey: boolean; keyOnly: boolean }): string {
  if (i.hasKey) return i.keyOnly ? `${KEY_HINT[0]!.toUpperCase()}${KEY_HINT.slice(1)}.` : `${KEY_HINT[0]!.toUpperCase()}${KEY_HINT.slice(1)} или введите ${CODE_HINT}.`;
  return `${CODE_HINT[0]!.toUpperCase()}${CODE_HINT.slice(1)}.`;
}

/**
 * The action Enter presses in a code field: the first enabled button that follows the field in the document order inside the nearest group
 * (the field's parent, then up to two levels higher) — the buttons of a card stand next to its code field.
 */
export function firstButtonAfter(field: Element): HTMLButtonElement | null {
  let scope: Element | null = field.parentElement;
  for (let up = 0; scope && up < 3; up++, scope = scope.parentElement) {
    const buttons = Array.from(scope.querySelectorAll("button"));
    const after = buttons.find((b) => !b.disabled && (field.compareDocumentPosition(b) & 4) !== 0);
    if (after) return after;
  }
  return null;
}

/** Why the approval session is closed, in words, for the strip that tells the person (a session that goes quietly looked like «my click did nothing»). */
export type SessionCloseReason = "idle" | "ceiling" | "locked" | "server";

export function sessionClosedText(reason: SessionCloseReason): string {
  const why: Record<SessionCloseReason, string> = {
    idle: "прошло 15 минут без действий",
    ceiling: "прошёл час, дольше сессия не живёт",
    locked: "вы нажали «Заблокировать»",
    server: "сервер её больше не признаёт (закончилось время или её закрыли на другой странице)",
  };
  return `Сессия закрыта: ${why[reason]}. Чтобы не вводить код каждый раз, откройте её снова.`;
}

/** The page's own count of the end: which of the two limits ran out. */
export const sessionEndReason = (s: { idleUntil: number; hardUntil: number }, now: number): SessionCloseReason => (now >= s.hardUntil ? "ceiling" : "idle");

/** After a use the idle end moves ahead by 15 minutes, but never back: a session opened for an hour keeps its hour. */
export const slideIdle = (cur: { idleUntil: number }, startedAt: number, idleMs: number, marginMs: number): number => Math.max(cur.idleUntil, startedAt + idleMs - marginMs);

export const SESSION_LINE = `Открыть на ${minutesWords(SESSION_IDLE_MS)} или на ${minutesWords(SESSION_CAP_MS)}, чтобы не вводить код каждый раз`;

export interface SessionText {
  /** The one line (always). */
  line: string;
  /** The rest, folded in «Простой» and open in the others; null: none. */
  details: string;
  foldDetails: boolean;
}

/** The session paragraph without «токен» and «хеш»: one line in «Простой», the details folded. */
export function sessionText(mode: TrustMode | null, guard: boolean): SessionText {
  const touch = guard ? "касанием" : "кодом";
  // What it covers is told from the guard's table (session-rules.ts), the same one the guard's own description and its decision use.
  const cov = sessionCoverage();
  const details = `Действует на этой странице: ${minutesWords(SESSION_IDLE_MS)} после последнего действия, не дольше ${minutesWordsUpTo(SESSION_CAP_MS)}. Рутину (${cov.routine.join(", ")}) она покрывает без ${guard ? "касания" : "кода"}. Опасное (${cov.fresh.join(", ")}) — всегда ${touch} заново. ${guard ? "Ключ сессии хранится только в памяти этой страницы. " : ""}Перезагрузка страницы закрывает сессию.`;
  return { line: SESSION_LINE, details, foldDetails: mode === null || mode === "simple" };
}
