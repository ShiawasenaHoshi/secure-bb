// What may be put into the publish settings. Everything here ends up in a git command line or a ref name,
// so it is checked as data: no dash first, no whitespace, no credentials in the address.
import type { PublishSettings } from "./types.js";

export interface UrlRules {
  /** Local `file://` addresses: for tests only. The server never sets this. */
  allowFile?: boolean;
}

/** Returns the normalized address, or an error text. */
export function checkRepoUrl(raw: string, rules: UrlRules = {}): { ok: true; url: string } | { ok: false; error: string } {
  const url = raw.trim();
  if (url.length === 0 || url.length > 300 || /[\s\x00-\x1f\x7f]/.test(url)) return { ok: false, error: "адрес репозитория пустой, длинный или с пробелами" };
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { ok: false, error: "адрес репозитория не разобрать (нужен https://хост/владелец/репозиторий.git)" };
  }
  if (u.protocol === "file:" && rules.allowFile === true) {
    if (u.host !== "" || !u.pathname.startsWith("/")) return { ok: false, error: "file-адрес без хоста и с абсолютным путём" };
    return { ok: true, url };
  }
  if (u.protocol !== "https:") return { ok: false, error: "публикация только по https" };
  if (u.username !== "" || u.password !== "") return { ok: false, error: "в адресе не должно быть логина и пароля: токен задаётся файлом на сервере" };
  if (u.search !== "" || u.hash !== "") return { ok: false, error: "в адресе не должно быть параметров и фрагмента" };
  if (u.hostname === "" || u.pathname.length < 2) return { ok: false, error: "адрес должен указывать на репозиторий: https://хост/владелец/репозиторий.git" };
  return { ok: true, url };
}

/** A branch name that is safe as an argument and as a ref: plain characters, no `..`, no leading dash. */
export function checkBranch(raw: string): string | null {
  const b = raw.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/.test(b) || b.includes("..") || b.includes("//") || b.endsWith("/") || b.endsWith(".") || b.endsWith(".lock") || b.includes("/.")) {
    return "имя ветки: латиница, цифры и . _ / -, не с дефиса, без «..»";
  }
  return null;
}

/** The directory name and tag part: what `package.json` gives us, but never trusted to be a safe ref. */
export const SAFE_PLUGIN_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const SAFE_VERSION = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/;

export function sameSettings(a: PublishSettings, b: PublishSettings): boolean {
  return a.enabled === b.enabled && a.repoUrl === b.repoUrl && a.branch === b.branch && a.onApprove === b.onApprove;
}
