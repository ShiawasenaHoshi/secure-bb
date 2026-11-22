// What a card offers besides «Разрешить»: the trust window, «доверять источнику», and the note when a plugin did not start.
import type { Level } from "./cards.js";

export interface WindowAvailInput {
  /** The thread the version came from (a window covers a thread and its tree). */
  threadId: string | null;
  /** Negative: a proposal not yet installed. */
  queueId: number;
  sourceKind: string;
  level: Level;
}

export interface WindowAvail {
  available: boolean;
  /** Why not, and what to do instead (shown on the card). */
  note: string | null;
}

/** A trust window belongs to a plugin that an agent installs from a thread. A plugin from a folder has no such thread: say so, and say what to use instead. */
export function windowAvailability(i: WindowAvailInput): WindowAvail {
  if (i.threadId && i.queueId > 0) return { available: true, note: null };
  if (i.sourceKind === "path") {
    return {
      available: false,
      note: `Окно доверия тут не подходит: оно работает для плагинов, которые агент ставит из чата, а этот взят из папки на компьютере. ${i.level === "own" ? "Ваш источник уже в «моих источниках»: версии без новых прав проходят сами." : "Вместо него доверьте источник кнопкой «Разрешить и доверять источнику»: тогда версии без новых прав будут проходить сами."}`,
    };
  }
  return { available: false, note: "Окно доверия тут не подходит: оно работает для плагинов, которые агент ставит из чата, а этот пришёл иначе. Разрешите версию или доверьте источник." };
}

/**
 * «Открыть окно на N мин» on a plugin's own row. A window is bound to the thread an agent put the plugin in from, so it is possible only for a plugin with such a
 * thread (and only with a guard); otherwise the row says why not and what to use instead — never a bare «окно закрыто».
 */
export function pluginWindowAvail(i: { guard: boolean; threadId: string | null; level: Level }): WindowAvail {
  if (!i.guard) return { available: false, note: "Временное доверие открывается с карточки версии, которая ждёт решения; кнопка на строке плагина есть при включённой защите." };
  if (i.threadId) return { available: true, note: null };
  const instead = i.level === "own" ? "Версии из ваших источников и без окна проходят сами, пока не просят новых прав." : "Версию можно одобрить касанием или доверить её источник.";
  return { available: false, note: `Временное доверие здесь невозможно: оно привязано к чату, из которого агент поставил плагин, а у этого плагина такого чата нет. ${instead}` };
}

export interface TrustButtonInput {
  entry: string | null;
  level: Level;
  queueId: number;
}

export interface TrustButton {
  enabled: boolean;
  /** Under the button: why it does nothing, or what it does. */
  note: string | null;
}

/** «Разрешить и доверять источнику» is active only when it changes something: the source is not yet trusted and can be named. */
export function trustButton(i: TrustButtonInput): TrustButton {
  if (i.entry === null) return { enabled: false, note: "Этот источник нельзя занести в «мои источники» (не github и не папка на диске)." };
  if (i.queueId < 0) return { enabled: false, note: "Плагин ещё не установлен: сначала разрешите версию." };
  if (i.level === "own") return { enabled: false, note: "Ваш источник уже в «моих источниках»: версии без новых прав проходят сами." };
  return { enabled: true, note: null };
}

/** The core's `error` after an approval: the plugin is allowed but did not start. Null: nothing to add. */
export function launchProblem(p: { status: string; statusDetail?: string | null }): string | null {
  if (p.status !== "error") return null;
  const why = (p.statusDetail ?? "").replace(/\s+/g, " ").trim();
  return `Разрешён, но упал при запуске: ${why !== "" ? (why.length > 300 ? `${why.slice(0, 299)}…` : why) : "ядро не назвало причину"}`;
}
