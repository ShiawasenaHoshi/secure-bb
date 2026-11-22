// What a mode (Simple / Detailed / Strict) changes on the page, and the first-run wizard's words. Display only: the guard keeps the mode.
import type { TrustMode } from "../guardlink.js";
import { sourceKindOf } from "../../guard/src/github-address.ts";

export interface DetailLevel {
  /** Technical fields are open when the card is drawn. */
  expanded: boolean;
  /** Hashes and exact versions are shown (Strict). */
  hashes: boolean;
  /** "Всё равно разрешить…" exists on a red card. */
  bypass: boolean;
}

/** What a mode changes on the page: Simple folds the technical fields, Detailed opens them, Strict opens them with hashes and has no bypass. */
export function detailLevel(mode: TrustMode | null): DetailLevel {
  switch (mode) {
    case "detailed":
      return { expanded: true, hashes: false, bypass: true };
    case "strict":
      return { expanded: true, hashes: true, bypass: false };
    default:
      return { expanded: false, hashes: false, bypass: true };
  }
}

export const MODE_NAMES: Record<TrustMode, string> = { simple: "Простой", detailed: "Подробный", strict: "Строгий" };

export const MODE_DESCRIPTIONS: Record<TrustMode, string> = {
  simple: "Свои и известные источники проходят сами, пока не просят нового. Технические подробности свёрнуты. Для большинства.",
  detailed: "Так же, но подробности на карточках сразу открыты: что именно просит плагин и где это в коде.",
  strict: "Каждая версия ждёт вас. Подробности открыты, обойти красную карточку нельзя.",
};

/** Whether to show the wizard: the guard knows the modes, nothing is set up yet, and the person has not closed it. */
export function wizardNeeded(i: { hasTrust: boolean; mySources: number; done: boolean }): boolean {
  return i.hasTrust && i.mySources === 0 && !i.done;
}

/** Suggestions for «мои источники»: git repositories and folders of the installed plugins, from the core's `source`, once each. */
export function suggestSources(plugins: Array<{ sourceKind?: string; source: string; rootDir?: string | null }>, identity: (kind: string, source: string, rootDir?: string | null) => string | null): string[] {
  const out = new Set<string>();
  for (const p of plugins) {
    const kind = p.sourceKind ?? sourceKindOf(p.source);
    const id = identity(kind, p.source, p.rootDir);
    if (id) out.add(id);
  }
  return [...out].slice(0, 20);
}

/** Wizard, step 2: a source in words a person knows. */
export function friendlySource(entry: string): string {
  const gh = /^github:([^/\s]+\/[^\s]+)$/i.exec(entry);
  if (gh) return `${gh[1]} (на GitHub)`;
  if (/^path:/.test(entry)) return `папка ${entry.slice(5)}`;
  return entry;
}

export const WIZARD_SOURCES_TEXT = "Ставили плагины из каталога bb? Тогда здесь ничего отмечать не нужно: защита спросит вас про каждую новую версию. Отмечайте только то, что вы сами пишете или ведёте: новые версии оттуда будут проходить без вопросов, пока плагин не попросит новых прав.";

/** Wizard, step 3: the second factor in words, without a count of keys. */
export function secondFactorText(i: { codes: boolean; keys: number }): string {
  if (i.codes && i.keys > 0) return "Второй фактор настроен: коды из приложения на телефоне и ключ.";
  if (i.codes) return "Второй фактор настроен: коды из приложения на телефоне.";
  if (i.keys > 0) return "Второй фактор настроен: ключ (отпечаток или ключ безопасности).";
  return "Второй фактор ещё не настроен.";
}
