// Secrets are masked by code before anything goes to the cloud (spec §9). Whatever the patterns miss is still
// bounded by the length cap the caller applies; the rules lean towards hiding too much.

// '/' is left out on purpose so long file paths stay readable; base64 with slashes is cut into runs, and the long ones are still hidden.
const MIN_BLOB = 40;

/** Order matters: more specific shapes first. */
const RULES: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[скрыт приватный ключ]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, "[скрыт JWT]"],
  [/\b(?:sk|pk|rk)-(?:or-|ant-|proj-|live-|test-)?[A-Za-z0-9_-]{16,}/g, "[скрыт ключ]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}/g, "[скрыт токен GitHub]"],
  [/\bglpat-[A-Za-z0-9_-]{16,}|\bnpm_[A-Za-z0-9]{30,}/g, "[скрыт токен]"],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}/g, "[скрыт токен Slack]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[скрыт ключ AWS]"],
  [/\bAIza[0-9A-Za-z_-]{30,}/g, "[скрыт ключ Google]"],
  // Credentials inside a URL: scheme://user:password@host
  [/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi, "$1[скрыто]@"],
  // Authorization headers and bearer tokens.
  [/\b(authorization\s*[:=]\s*)(?:bearer|basic|token)?\s*[^\s"'`]+/gi, "$1[скрыто]"],
  [/\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, "$1[скрыто]"],
  // name=value / name: value where the name says "secret" (also inside flags: --token abc, TOKEN=abc).
  [/(\b[\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key|credential|auth)[\w.-]*\s*(?:=|:|\s)\s*)(?:"[^"]*"|'[^']*'|[^\s"'`;&|]+)/gi, "$1[скрыто]"],
  // Long uninterrupted base64/hex runs are keys more often than words.
  [new RegExp(`[A-Za-z0-9+_=-]{${MIN_BLOB},}`, "g"), "[скрыта длинная строка]"],
];

export function maskSecrets(text: string): string {
  let out = text;
  for (const [re, to] of RULES) out = out.replace(re, to);
  return out;
}

/** Masked, then cut to `max` characters (cutting after masking, so a secret is never left half-visible). */
export function maskAndCut(text: string, max: number): string {
  const masked = maskSecrets(text).replace(/\s+/g, " ").trim();
  return masked.length > max ? `${masked.slice(0, max - 1)}…` : masked;
}
