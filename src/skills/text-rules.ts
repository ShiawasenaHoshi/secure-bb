// Deterministic checks of the text of a skill (stage 6): what an agent that reads this skill would be told to do,
// and what a script in it would do. No network, no model. A skill is read by agents as instructions, so unlike plugin
// code the dangerous thing is often a sentence, not a call.
import { extname } from "node:path";
import type { Finding } from "../checks/types.js";
import { escapeInvisible, excerptOf } from "../checks/files.js";
import type { SkillCapability } from "./types.js";

export interface TextFile {
  path: string;
  content: string;
}

export const DOC_EXT = new Set([".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc"]);
const SHELL_EXT = new Set([".sh", ".bash", ".zsh", ".fish", ".ksh"]);
const WINDOWS_EXT = new Set([".ps1", ".psm1", ".psd1", ".bat", ".cmd"]);
const OTHER_SCRIPT_EXT = new Set([".py", ".rb", ".pl", ".php", ".lua", ".r", ".tcl"]);

export type FileClass = "doc" | "shell" | "windows" | "script" | "js" | "text";
const JS_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"]);

export function classify(path: string, content: string): FileClass {
  const ext = extname(path).toLowerCase();
  if (DOC_EXT.has(ext)) return "doc";
  if (JS_EXT.has(ext)) return "js";
  if (SHELL_EXT.has(ext)) return "shell";
  if (WINDOWS_EXT.has(ext)) return "windows";
  if (OTHER_SCRIPT_EXT.has(ext)) return "script";
  const shebang = /^#!\s*(\S+)(?:\s+(?:-\S+\s+)*(\S+))?/.exec(content);
  if (shebang) {
    const base = shebang[1]!.split("/").pop()!.toLowerCase();
    const interp = (base === "env" ? (shebang[2] ?? "") : base).split("/").pop()!.toLowerCase();
    if (/^(?:ba|z|da|k|c|fi)?sh$/.test(interp)) return "shell";
    if (/^(?:node|deno|bun|tsx)$/.test(interp)) return "js";
    return "script";
  }
  return "text";
}

// ---- helpers ---------------------------------------------------------------------------------------------------------
const W = (src: string): string => `(?<![\\p{L}\\p{N}_])(?:${src})`;

const lineOf = (text: string, index: number): number => {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
};

/** A line continued with a trailing backslash is one command. Positions stay on the first physical line. */
function logicalLines(text: string): Array<{ line: number; text: string }> {
  const out: Array<{ line: number; text: string }> = [];
  const raw = text.split("\n");
  for (let i = 0; i < raw.length; i++) {
    let cur = raw[i]!.replace(/\r$/, "");
    const start = i + 1;
    while (/\\\s*$/.test(cur) && i + 1 < raw.length) cur = cur.replace(/\\\s*$/, " ") + raw[++i]!.replace(/\r$/, "");
    out.push({ line: start, text: cur });
  }
  return out;
}

// ---- invisible characters in documents ------------------------------------------------------------------------------
const INVISIBLE = /[\p{Cc}\p{Cf}\u2028\u2029\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/u;
const PICTO = /[\p{Extended_Pictographic}\p{Emoji_Modifier}\u20E3]/u;

/**
 * Invisible and control characters (spec §5.1), except what makes emoji work: U+FE0F and U+200D inside an emoji sequence
 * (⚠\uFE0F, 👩\u200D💻). The other code points stay a block everywhere: tag characters, bidi controls, zero-width space, soft hyphen.
 */
export function invisibleInDoc(path: string, text: string): Finding[] {
  const out: Finding[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length && out.length < 5; i++) {
    let line = lines[i]!.replace(/\r$/, "");
    if (i === 0 && line.startsWith("\uFEFF")) line = line.slice(1);
    const chars = [...line];
    let bad = false;
    for (let j = 0; j < chars.length && !bad; j++) {
      const c = chars[j]!;
      if (c === "\t" || !INVISIBLE.test(c)) continue;
      const prev = chars[j - 1] ?? "";
      const next = chars[j + 1] ?? "";
      if (c === "\uFE0F" && (PICTO.test(prev) || /[©®‼-㊙#*0-9]/u.test(prev))) continue;
      if (c === "\u200D" && (PICTO.test(prev) || prev === "\uFE0F") && PICTO.test(next)) continue;
      bad = true;
    }
    if (bad) out.push({ rule: "invisible-chars", severity: "block", file: path, line: i + 1, excerpt: excerptOf(escapeInvisible(line)) });
  }
  return out;
}

// ---- download and execute ---------------------------------------------------------------------------------------------
const SHELLS = "(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+\\S+=\\S+\\s+)?(?:ba|z|da|k|fi|c)?sh|python[0-9.]*|node|deno|bun|perl|ruby|php|pwsh|powershell";
const DOWNLOADERS = "curl|wget|fetch|aria2c|http|https|xh|lwp-download";
const PS_DOWNLOAD = "iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Net\\.WebClient|DownloadString|DownloadFile|Start-BitsTransfer";
const PS_EXEC = "iex|Invoke-Expression";
const DOWNLOAD_EXEC: RegExp[] = [
  new RegExp(`${W(DOWNLOADERS)}\\b[^\\n]*\\|\\s*(?:${SHELLS})(?![\\p{L}\\p{N}_])`, "iu"),
  new RegExp(`${W(PS_DOWNLOAD)}[^\\n]*\\|\\s*(?:${PS_EXEC})(?![\\p{L}\\p{N}_])`, "iu"),
  new RegExp(`${W(PS_EXEC)}(?![\\p{L}\\p{N}_])[^\\n]*(?:${PS_DOWNLOAD})`, "iu"),
  new RegExp(`${W(`(?:${SHELLS}|source|eval|\\.)`)}(?![\\p{L}\\p{N}_])[^\\n|;&]*?(?:<\\(|\\$\\(|\`)\\s*(?:${DOWNLOADERS})\\b`, "iu"),
  new RegExp(`${W("(?:exec|eval)")}\\s*\\([^\\n]*(?:urlopen|requests\\.|urllib|http\\.client|fetch\\()`, "iu"),
];

/** Fetch to a file, then run that same file on the same line: `curl -o x.sh URL && chmod +x x.sh && ./x.sh`. */
function downloadThenRun(text: string): boolean {
  const m = new RegExp(`${W("(?:curl|wget)")}\\b[^\\n]*?(?:\\s-o\\s*|\\s-O\\s*|\\s>\\s*)(["']?)([^\\s"'&;|]+)\\1`, "iu").exec(text);
  if (!m) return false;
  const file = m[2]!;
  const rest = text.slice((m.index ?? 0) + m[0].length);
  const esc = file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const runs = new RegExp(`(?:&&|;|\\|\\|)\\s*(?:(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby|source|\\.)\\s+)?(?:\\./)?${esc}(?![\\w.-])`, "u");
  return runs.test(rest);
}

const BASE64_EXEC: RegExp[] = [
  new RegExp(`base64\\s+(?:-d|-D|--decode)\\b[^\\n]*\\|\\s*(?:${SHELLS})(?![\\p{L}\\p{N}_])`, "iu"),
  new RegExp(`FromBase64String[^\\n]*(?:${PS_EXEC})|(?:${PS_EXEC})[^\\n]*FromBase64String`, "iu"),
  new RegExp(`${W("(?:eval|exec|Function)")}\\s*\\(\\s*(?:atob|Buffer\\.from|base64\\.b64decode|Base64\\.decode)`, "iu"),
  new RegExp(`(?:atob|b64decode|base64_decode)\\s*\\([^\\n]*\\)[^\\n]*${W("(?:eval|exec|system|assert)")}(?![\\p{L}\\p{N}_])`, "iu"),
  /powershell[^\n]*\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}/i,
];

// ---- secrets ---------------------------------------------------------------------------------------------------------
const SECRET_PATHS: RegExp[] = [
  /(?:^|[\s"'`/=(:])\.ssh(?![\w.-])/,
  /\bid_(?:rsa|ed25519|ecdsa|dsa)\b/,
  /\.aws\/(?:credentials|config)|\bAWS_SECRET_ACCESS_KEY\b/,
  /(?:^|[\s"'`/=(:~])\.(?:npmrc|netrc|pypirc|git-credentials|gnupg|vault-token)(?![\w-])/,
  /\.kube\/config|\.docker\/config\.json|\.config\/gh\/hosts\.yml/,
  /(?:^|[\s"'`/=(:])\.env(?:\.[\w-]+)?(?![\w.-])/,
  /\b(?:credentials|secrets)\.json\b|\/etc\/shadow|\/proc\/self\/environ|\bfind-generic-password\b|\bsecurity\s+dump-keychain\b|Library\/Keychains/i,
  /secure-bb[^\n]{0,80}\.(?:sqlite3?|db)\b|journal\.head/i,
];
const SECRET_NAMES = /\b(?:[A-Z][A-Z0-9]*_)?(?:GITHUB|GH|NPM|ANTHROPIC|OPENAI|AWS|GITLAB|SLACK|STRIPE|HF|HUGGINGFACE|OPENROUTER|CLAUDE|BB|CURSOR)_(?:[A-Z0-9_]*_)?(?:TOKEN|API_?KEY|SECRET|PASSWORD)\b|\b(?:api[_-]?key|auth[_-]?token|access[_-]?token|bearer\s+token|private[_-]?key)\b/i;
const SECRET_LITERALS = /\bgh[pousr]_[A-Za-z0-9]{30,}|\bsk-[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bnpm_[A-Za-z0-9]{30,}|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/;
const NETWORK_TOOL = new RegExp(`${W("(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|ftp|telnet|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)")}(?![\\p{L}\\p{N}_])|\\bnslookup\\b|\\bdig\\s`, "iu");
const SEND_VERB = new RegExp(`${W("(?:send|upload|post|exfiltrat\\p{L}*|transmit|email|e-mail|forward|paste|отправ\\p{L}*|передай\\p{L}*|пересл\\p{L}*|выгруз\\p{L}*|загруз\\p{L}*|скопируй\\p{L}*\\s+на)")}(?![\\p{L}\\p{N}_])`, "iu");
const REMOTE = /https?:\/\/(?!(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$))\S+|\bwebhook\b|\bendpoint\b|\bсервер\p{L}*|\bremote\s+(?:server|host)\b/iu;

function secretHits(text: string): Array<{ index: number; text: string }> {
  const out: Array<{ index: number; text: string }> = [];
  for (const re of [...SECRET_PATHS, SECRET_NAMES]) {
    const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
    for (const m of text.matchAll(g)) out.push({ index: m.index ?? 0, text: m[0].trim() });
  }
  return out.sort((a, b) => a.index - b.index);
}

function exfilIn(text: string): boolean {
  return NETWORK_TOOL.test(text) || (SEND_VERB.test(text) && REMOTE.test(text));
}

// ---- protection switched off -----------------------------------------------------------------------------------------
const PROTECTION_TARGET = W("(?:secure-?bb|sandbox(?:ing)?|песочниц\\p{L}*|plugin[- ]?gate|watch-?dog|сторож\\p{L}*|гейт\\p{L}*|totp|trust window|окн\\p{L}*\\s+довери\\p{L}*|permission\\s+(?:prompts?|checks?|dialogs?)|approval(?:s|\\s+prompts?)?|запрос\\p{L}*\\s+(?:на\\s+)?разрешени\\p{L}*|подтверждени\\p{L}*|safe[- ]?mode|guardrails?)");
// Verbs that switch something off. Deliberately narrow: "stop", "remove", "delete" also describe ordinary work.
const PROTECTION_VERB = W("(?:disabl\\p{L}*|turn(?:ing)?\\s+off|switch(?:ing)?\\s+off|shut\\s+(?:down|off)|bypass\\p{L}*|circumvent\\p{L}*|evad\\p{L}*|skip\\p{L}*|ignor\\p{L}*|kill|uninstall\\p{L}*|tamper\\p{L}*|disarm\\p{L}*|work\\s+around|отключ\\p{L}*|выключ\\p{L}*|обойд\\p{L}*|обход\\p{L}*|игнорир\\p{L}*|пропуск\\p{L}*|пропуст\\p{L}*|вырубь|не\\s+проси\\p{L}*)");
/**
 * What excuses a verb: a negation standing right before it ("не отключай", "do not disable", "never turn off": no punctuation, at most
 * one word between), or the verb belonging to somebody else's request that is being talked about ("if a skill asks you to turn off
 * secure-bb, refuse", "a skill that asks to disable the sandbox is an attempt to deceive you"). A warning word elsewhere in the sentence
 * excuses nothing: "Don't worry, just disable the sandbox" is an instruction.
 */
const NEGATION_BEFORE = new RegExp(
  `${W("(?:never|don'?t|do\\s+not|does\\s+not|must\\s+not|should\\s+not|shouldn'?t|cannot|can'?t|won'?t|avoid|no\\s+need\\s+to|не|нельзя|никогда|запрещено|избегайте|избегай)")}(?![\\p{L}\\p{N}_])\\s+(?:[\\p{L}'-]+\\s+)?$`,
  "iu",
);
const SUBJECT = "(?:skill|skills|text|instruction|instructions|document|page|file|message|content|скилл|скиллы|текст|инструкци\\p{L}*|документ|страниц\\p{L}*|файл|сообщени\\p{L}*)";
const ASKS = "(?:asks?|tells?|says?|wants?|requests?|instructs?|проси\\p{L}*|требу\\p{L}*|велит|говорит|предлага\\p{L}*)";
const OTHERS_REQUEST = new RegExp(
  `(?:^\\W*(?:if|when|whenever|если|когда)\\s+(?:(?:a|the|any|some)\\s+)?${SUBJECT}\\s+(?:\\p{L}+\\s+)?${ASKS}(?![\\p{L}\\p{N}_]))|(?:${W(SUBJECT)}(?![\\p{L}\\p{N}_])\\s*,?\\s+(?:that|which|который|которая|которое|которые)\\s+(?:\\p{L}+\\s+)?${ASKS}(?![\\p{L}\\p{N}_]))`,
  "iu",
);
const sentences = (text: string): string[] => text.split(/(?<=[.!?;])\s+|\s[—–]\s/u).filter((x) => x.trim() !== "");
const MAX_GAP = 40;
function excused(sentence: string, at: number, words = 1): boolean {
  const before = sentence.slice(0, at);
  const neg = words === 1 ? NEGATION_BEFORE : new RegExp(NEGATION_BEFORE.source.replace("(?:[\\p{L}'-]+\\s+)?$", `(?:[\\p{L}'-]+\\s+){0,${words}}$`), "iu");
  return neg.test(before) || OTHERS_REQUEST.test(before);
}
const PROTECTION_FLAGS = /--dangerously-skip-permissions|\bbypassPermissions\b|\bdangerouslyDisableSandbox\b|\bdangerously[-_]?disable\w*|sandbox(?:Enabled)?["']?\s*[:=]\s*(?:false|0|off|no)\b|\bBB_PLUGIN_ACTIVATION_GUARDS\b|permission[-_ ]?mode["']?\s*[:=]\s*["']?(?:full|bypass\w*)|--permission-mode[ =](?:full|bypass\w*)|\bunset\s+BB_\w+/iu;

function protectionFindings(path: string, lines: Array<{ line: number; text: string }>): Finding[] {
  const out: Finding[] = [];
  for (const { line, text } of lines) {
    if (out.length >= 5) break;
    for (const sentence of sentences(text)) {
      let hit = false;
      const flag = PROTECTION_FLAGS.exec(sentence);
      if (flag && !excused(sentence, flag.index, 3)) hit = true;
      if (!hit) {
        for (const t of sentence.matchAll(new RegExp(PROTECTION_TARGET, "giu"))) {
          const from = Math.max(0, (t.index ?? 0) - MAX_GAP);
          // every verb close before the target counts; "не проси" is itself the instruction ("don't ask for confirmation")
          for (const v of sentence.slice(from, t.index ?? 0).matchAll(new RegExp(PROTECTION_VERB, "giu"))) {
            if (!excused(sentence, from + (v.index ?? 0))) {
              hit = true;
              break;
            }
          }
          if (hit) break;
        }
      }
      if (hit) {
        out.push({ rule: "disable-protection", severity: "block", file: path, line, excerpt: excerptOf(text) });
        break;
      }
    }
  }
  return out;
}

// ---- external scripts ---------------------------------------------------------------------------------------------------
const SCRIPT_LINK = /https?:\/\/[^\s)>"'`\]]+\.(?:sh|bash|zsh|ps1|psm1|bat|cmd|py|rb|pl|js|mjs)(?![\w-])(?:\?[^\s)>"'`\]]*)?/gi;
const PASTE_HOSTS = /https?:\/\/(?:raw\.githubusercontent\.com|gist\.github(?:usercontent)?\.com|pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|0x0\.st|bit\.ly|tinyurl\.com|t\.co|is\.gd|[\w.-]+\.ngrok(?:-free)?\.(?:io|app|dev))[^\s)>"'`\]]*/gi;

// ---- base64 -------------------------------------------------------------------------------------------------------------
const B64_MIN = 40;
const B64_REVIEW = 120;
const B64_RUN = /[A-Za-z0-9+/]{40,}={0,2}/g;
const B64_LINE = /^[A-Za-z0-9+/]{30,}={0,2}$/;

function decodeText(b64: string): string | null {
  try {
    const buf = Buffer.from(b64, "base64");
    if (buf.length < 16) return null;
    const s = buf.toString("utf8");
    let printable = 0;
    for (const ch of s) if (ch === "\n" || ch === "\t" || (ch >= " " && ch !== "�")) printable++;
    return printable / [...s].length >= 0.9 ? s : null;
  } catch {
    return null;
  }
}

/** Does text (a decoded payload) say something the other rules would block? */
function payloadRule(text: string): string | null {
  const lines = logicalLines(text);
  if (lines.some((l) => DOWNLOAD_EXEC.some((re) => re.test(l.text)) || downloadThenRun(l.text))) return "download and execute";
  if (lines.some((l) => BASE64_EXEC.some((re) => re.test(l.text)))) return "decode and execute";
  if (protectionFindings("", lines).length > 0) return "disables protection";
  if (secretHits(text).length > 0 && exfilIn(text)) return "secrets sent out";
  if (/\b(?:eval|exec|system|child_process|subprocess|os\.system)\b/.test(text) && /\b(?:#!\s*\/|import\s|require\(|function\s|\bdef\s)/.test(text)) return "executable code";
  return null;
}

function base64Findings(path: string, text: string): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const report = (b64: string, line: number): void => {
    if (seen.has(b64) || /^[0-9a-f]+$/i.test(b64) || /^[0-9]+$/.test(b64)) return;
    seen.add(b64);
    const decoded = decodeText(b64);
    const why = decoded === null ? null : payloadRule(decoded);
    if (why) out.push({ rule: "base64-payload", severity: "block", file: path, line, excerpt: `base64 block that decodes to text that ${why}` });
    else if (b64.length >= B64_REVIEW) out.push({ rule: "base64-block", severity: "review", file: path, line, excerpt: excerptOf(`${b64.slice(0, 48)}… (${b64.length} chars of base64)`) });
  };
  const lines = text.split("\n").map((l) => l.replace(/\r$/, ""));
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (/data:(?:image|font|application\/(?:font|octet-stream))/i.test(l)) continue;
    for (const m of l.matchAll(B64_RUN)) report(m[0], i + 1);
    // the same block wrapped over several lines
    if (B64_LINE.test(l.trim())) {
      let j = i;
      let joined = "";
      while (j < lines.length && B64_LINE.test(lines[j]!.trim())) joined += lines[j++]!.trim();
      if (j - i >= 2 && joined.length >= B64_MIN) {
        report(joined, i + 1);
        i = j - 1;
      }
    }
    if (out.length >= 6) break;
  }
  return out;
}

// ---- the entry point -------------------------------------------------------------------------------------------------------
/** Findings for one file's text. `cls` decides how strictly secrets are read: in a script, a secret and a network call anywhere is enough. */
export function textFindings(file: TextFile, cls: FileClass): Finding[] {
  const { path, content } = file;
  const out: Finding[] = [];
  const lines = logicalLines(content);

  for (const { line, text } of lines) {
    if (DOWNLOAD_EXEC.some((re) => re.test(text)) || downloadThenRun(text)) out.push({ rule: "download-exec", severity: "block", file: path, line, excerpt: excerptOf(text) });
    else if (BASE64_EXEC.some((re) => re.test(text))) out.push({ rule: "decode-exec", severity: "block", file: path, line, excerpt: excerptOf(text) });
    if (out.length >= 12) break;
  }
  out.push(...protectionFindings(path, lines));
  out.push(...base64Findings(path, content));

  // Secrets: alone they are a review (a README may well say "put the token in .env"); with a way out, a block.
  const hits = secretHits(content);
  if (hits.length > 0) {
    const wholeFile = cls !== "doc" && cls !== "text";
    let blocked = false;
    if (wholeFile) {
      if (exfilIn(content)) {
        out.push({ rule: "secret-exfil", severity: "block", file: path, line: lineOf(content, hits[0]!.index), excerpt: excerptOf(`${hits[0]!.text} (and the script uses the network)`) });
        blocked = true;
      }
    } else {
      // paragraph by paragraph
      let offset = 0;
      for (const para of content.split(/\n\s*\n/)) {
        const inPara = hits.filter((h) => h.index >= offset && h.index < offset + para.length);
        if (inPara.length > 0 && exfilIn(para)) {
          out.push({ rule: "secret-exfil", severity: "block", file: path, line: lineOf(content, inPara[0]!.index), excerpt: excerptOf(`${inPara[0]!.text} next to an instruction to send data out`) });
          blocked = true;
        }
        offset += para.length + 2;
      }
    }
    if (!blocked) out.push({ rule: "secret-reference", severity: "review", file: path, line: lineOf(content, hits[0]!.index), excerpt: excerptOf(`refers to ${[...new Set(hits.map((h) => h.text))].slice(0, 4).join(", ")}`) });
  }
  const literal = SECRET_LITERALS.exec(content);
  if (literal) out.push({ rule: "secret-literal", severity: "review", file: path, line: lineOf(content, literal.index), excerpt: excerptOf(`${literal[0].slice(0, 6)}… looks like a credential`) });

  // Links to scripts somewhere else.
  const links = new Set<string>();
  for (const re of [SCRIPT_LINK, PASTE_HOSTS]) for (const m of content.matchAll(re)) links.add(`${lineOf(content, m.index ?? 0)}\0${m[0]}`);
  for (const l of [...links].slice(0, 5)) {
    const [line, url] = l.split("\0");
    out.push({ rule: "external-script-link", severity: "review", file: path, line: Number(line), excerpt: excerptOf(url!) });
  }
  return out;
}

// ---- capabilities of scripts that are not JS (JS goes through the AST checks of plugins) -----------------------------
const NET_CODE = /\b(?:requests|urllib|http\.client|aiohttp|httpx|socket|ftplib|smtplib|paramiko|Net::HTTP|open-uri|LWP|curl_exec|fsockopen)\b|file_get_contents\(\s*["']https?|\b(?:curl|wget|nc|ncat|ssh|scp|rsync|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/;
const PROC_CODE = /\b(?:subprocess|os\.system|os\.popen|popen|Popen|pexpect|Start-Process|spawn|system\s*\(|exec[lv]p?\s*\()|`[^`\n]+`/;
const DYN_CODE = /\b(?:eval|exec|compile|__import__|importlib|Invoke-Expression|iex|instance_eval|class_eval)\b\s*\(?/;
const ENV_CODE = /\b(?:os\.environ|os\.getenv|getenv|ENV\[|printenv|\$env:|%[A-Z_]+%)|^\s*env\s*$|\benv\s*\|/m;

export function scriptCapabilities(path: string, content: string, cls: FileClass): SkillCapability[] {
  const caps: SkillCapability[] = [{ kind: "script", detail: [`${path} (${cls})`] }];
  if (cls === "shell" || cls === "windows") caps.push({ kind: "child_process", detail: [`${path}: ${cls === "shell" ? "shell" : "Windows"} script`] });
  else if (PROC_CODE.test(content)) caps.push({ kind: "child_process", detail: [path] });
  if (NET_CODE.test(content)) caps.push({ kind: "network", detail: [path] });
  if (DYN_CODE.test(content)) caps.push({ kind: "dynamic_code", detail: [path] });
  if (ENV_CODE.test(content)) caps.push({ kind: "env", detail: [path] });
  return caps;
}
