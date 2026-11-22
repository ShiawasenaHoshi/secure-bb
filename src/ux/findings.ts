// The checks' findings in a person's words.
import { RED, RED_FALLBACK } from "./cards.js";
import { plural } from "./words.js";

/** What a check that asks for a look says, in a sentence (the rules that stop a version have their own, in `RED`). */
const REVIEW_TEXT: Record<string, string> = {
  "dynamic-access": "код обращается к функциям по имени, собранному на лету: что именно он вызывает, из кода не видно",
  "require-alias": "код подключает модули непрямым способом, который трудно проследить",
  "module-load": "код подгружает модули внутренним способом bb",
  "dynamic-constructor": "код создаёт функции из текста",
  "global-proxy": "код подменяет глобальные объекты",
  webassembly: "в плагине есть скомпилированный код (WebAssembly)",
  "native-load": "плагин загружает готовую программу",
  "unknown-builtin": "плагин использует системный модуль, которого проверки не знают",
  "secret-path": "в коде упомянуты файлы с паролями или ключами",
  "secret-literal": "в коде есть строка, похожая на пароль или ключ",
  "secret-reference": "в коде упомянуты пароли или ключи",
  "env-secret-network": "плагин читает переменные с паролями и умеет выходить в сеть",
  "env-passed": "плагин передаёт все переменные окружения другой функции",
  "parse-failed": "часть кода не удалось разобрать: проверить её нечем",
  "limit-exceeded": "проверка не смогла просмотреть всё: файлов или кода слишком много",
  "file-too-large": "один из файлов слишком большой, чтобы его проверить",
  "executable-file": "в плагине лежит исполняемый файл",
  "sdk-unclassified": "плагин обращается к частям bb, которых проверки не знают",
  "bad-package-json": "описание плагина (package.json) составлено неправильно",
  "workspace-dependency": "плагин зависит от соседней папки, а не от опубликованного пакета",
  "dep-lookalike": "название одного из пакетов похоже на название известного: так подделывают пакеты",
  "dep-modified": "один из пакетов отличается от того, что лежит в реестре npm",
  "dep-name-mismatch": "название пакета не совпадает с тем, под которым он лежит",
  "dep-young": "один из пакетов выпущен меньше трёх дней назад",
  "external-script-link": "страница плагина подключает скрипт из интернета",
  "injection-phrase": "в тексте есть фраза, которой пытаются управлять агентом",
  "network-command": "в тексте есть команда, которая ходит в сеть",
  "too-large": "файл слишком большой для проверки",
};

const NOT_SHOWN_RULES = new Set(["ignored-findings", "unreachable-files", "dep-content-unverified", "parse-note", "config-path", "shell-pipe-string", "agent-config"]);

export interface FindingLine {
  /** One sentence in Russian. */
  text: string;
  severity: "block" | "review";
  /** Where, at most three places. */
  where: string[];
  /** How many places in all. */
  count: number;
}

/**
 * The findings a person is told of: only those that matter (a version is stopped, or a look is asked for), grouped by what they say, in Russian. What is only
 * noted («info»), the book-keeping of the checks («not scanned»), and the raw rule names stay in the developer's fold.
 */
export function significantFindings(findings: Array<{ rule: string; severity: string; file: string; line: number }>): FindingLine[] {
  const by = new Map<string, FindingLine>();
  for (const f of findings) {
    if ((f.severity !== "block" && f.severity !== "review") || NOT_SHOWN_RULES.has(f.rule)) continue;
    const text = f.severity === "block" ? (RED[f.rule]?.title ?? RED_FALLBACK.title) : (REVIEW_TEXT[f.rule] ?? "проверка нашла особенность в коде");
    const key = `${f.severity}|${text}`;
    const e = by.get(key) ?? { text: text.charAt(0).toUpperCase() + text.slice(1), severity: f.severity, where: [], count: 0 };
    e.count++;
    const place = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "";
    if (place !== "" && e.where.length < 3 && !e.where.includes(place)) e.where.push(place);
    by.set(key, e);
  }
  return [...by.values()].sort((a, b) => (a.severity === b.severity ? b.count - a.count : a.severity === "block" ? -1 : 1));
}

/** The fold's summary on a card: what the findings come to, in the same terms as the card's colour. */
export function checksSummary(lines: FindingLine[], capabilities: number): string {
  const n = lines.reduce((x, l) => x + l.count, 0);
  const things = lines.length === 0 ? "значимых находок нет" : `${n} ${plural(n, "находка", "находки", "находок")} (${lines.length} ${plural(lines.length, "вид", "вида", "видов")})`;
  return `Проверки: ${things} · возможностей: ${capabilities}`;
}
