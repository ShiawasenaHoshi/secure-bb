// Checks of one skill (stage 6). Everything that is code goes through the same checks as plugin code
// (`src/checks`: files, AST capabilities); text goes through the skill rules (text-rules.ts).
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join } from "node:path";
import { runChecks } from "../checks/index.js";
import { excerptOf } from "../checks/files.js";
import type { Finding } from "../checks/types.js";
import { MAX_SKILL_BYTES, MAX_SKILL_FILES } from "./reader.js";
import { classify, invisibleInDoc, scriptCapabilities, textFindings } from "./text-rules.js";
import type { SkillCapability, SkillCheck, SkillDecision, SkillSnapshot } from "./types.js";

/** Native code and archives: never part of a skill. */
const NATIVE_EXT = new Set([".node", ".so", ".dylib", ".dll", ".exe", ".msi", ".wasm", ".class", ".jar", ".pyc", ".pyo", ".o", ".a", ".bin", ".com", ".app", ".dmg", ".pkg", ".deb", ".rpm", ".apk"]);
const ARCHIVE_EXT = new Set([".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"]);
const MEDIA_EXT = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".wav", ".svg"]);

const SEVERITY_ORDER = { block: 0, review: 1, info: 2 } as const;

function badPath(p: string): string | null {
  if (p.length === 0 || p.length > 1024) return "empty or too long";
  if (isAbsolute(p) || p.startsWith("/")) return "absolute path";
  if (p.includes("\0") || p.includes("\\")) return "control character or backslash";
  if (p.split("/").some((s) => s === "" || s === "." || s === "..")) return "path escapes the skill directory";
  return null;
}

/** Many replacement characters: bytes that are not text, decoded as text. */
function looksLikeBinary(text: string): boolean {
  if (text.includes("\0")) return true;
  let bad = 0;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 0xfffd) bad++;
  return bad >= 4 && bad / text.length >= 0.01;
}

export async function inspectSkill(snap: SkillSnapshot): Promise<SkillCheck> {
  const t0 = Date.now();
  const findings: Finding[] = [];
  const caps = new Map<string, Set<string>>();
  const addCap = (c: SkillCapability): void => {
    let s = caps.get(c.kind);
    if (!s) caps.set(c.kind, (s = new Set()));
    for (const d of c.detail) s.add(d);
  };
  let scripts = 0;
  let bytes = 0;

  if (snap.truncated) findings.push({ rule: "listing-truncated", severity: "review", file: "", line: 0, excerpt: `bb shows at most ${MAX_SKILL_FILES} files of a skill: the rest is not seen` });
  if (snap.bytes > MAX_SKILL_BYTES) findings.push({ rule: "limit-exceeded", severity: "review", file: "", line: 0, excerpt: `${snap.bytes} bytes of text: larger than the checks read` });
  if (snap.files.length === 0) findings.push({ rule: "empty-skill", severity: "review", file: "", line: 0, excerpt: "no files could be listed" });

  const dir = await mkdtemp(join(tmpdir(), "secure-bb-skill-"));
  let written = 0;
  try {
    for (const f of snap.files) {
      const why = badPath(f.path);
      if (why) {
        findings.push({ rule: "bad-path", severity: "block", file: excerptOf(f.path, 80), line: 0, excerpt: why });
        continue;
      }
      if (f.content === null) {
        findings.push({ rule: "unreadable-file", severity: "review", file: f.path, line: 0, excerpt: `could not be read: ${excerptOf(f.error ?? "unknown", 100)}` });
        continue;
      }
      bytes += f.content.length;
      const ext = extname(f.path).toLowerCase();
      if (NATIVE_EXT.has(ext)) {
        findings.push({ rule: "binary", severity: "block", file: f.path, line: 0, excerpt: `native/binary file (${ext})` });
        continue;
      }
      if (ARCHIVE_EXT.has(ext)) {
        findings.push({ rule: "archive", severity: "block", file: f.path, line: 0, excerpt: `archive (${ext}): its content cannot be checked` });
        continue;
      }
      if (MEDIA_EXT.has(ext)) continue;
      if (looksLikeBinary(f.content)) {
        findings.push({ rule: "binary", severity: "block", file: f.path, line: 0, excerpt: "binary data" });
        continue;
      }
      const cls = classify(f.path, f.content);
      findings.push(...textFindings({ path: f.path, content: f.content }, cls));
      if (cls === "doc") {
        findings.push(...invisibleInDoc(f.path, f.content));
        continue;
      }
      // Everything that is not a document goes to the plugin checks (invisible characters, minified code, AST capabilities…).
      const target = join(dir, ...f.path.split("/"));
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, f.content, { mode: 0o600 });
      written++;
      if (cls !== "text" && cls !== "js") {
        scripts++;
        for (const c of scriptCapabilities(f.path, f.content, cls)) addCap(c);
      } else if (cls === "js") scripts++;
    }

    if (written > 0) {
      const res = await runChecks(dir);
      for (const x of res.findings) {
        // The temp directory is ours and has no history: its own facts are not skill facts.
        if (x.rule === "writable-by-others") continue;
        findings.push(x);
      }
      for (const c of res.capabilities) addCap({ kind: c.kind, detail: c.detail });
      if (res.capabilities.length > 0 || res.findings.some((x) => x.rule === "parse-failed")) scripts = Math.max(scripts, 1);
    }
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }

  // A skill whose scripts can do something beyond reading and writing its own text is outside the safe class (spec §5.2).
  for (const [kind, detail] of caps) {
    if (kind === "script") continue;
    findings.push({ rule: "script-capability", severity: "review", file: "", line: 0, excerpt: `${kind}${detail.size ? `: ${[...detail].sort().slice(0, 6).join(", ")}` : ""}` });
  }

  const uniq = new Map<string, Finding>();
  for (const f of findings) uniq.set(`${f.rule}\0${f.file}\0${f.line}\0${f.excerpt}`, f);
  const sorted = [...uniq.values()].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line);
  const capabilities = [...caps].map(([kind, d]) => ({ kind, detail: [...d].sort() })).sort((a, b) => (a.kind < b.kind ? -1 : 1));
  return { findings: sorted, capabilities, stats: { files: snap.files.length, bytes, scripts, ms: Date.now() - t0 } };
}

export function decide(check: SkillCheck): SkillDecision {
  if (check.findings.some((f) => f.severity === "block")) return "block";
  if (check.findings.some((f) => f.severity === "review")) return "review";
  return "clean";
}

/**
 * Version of the skill rules (text-rules.ts and the checks they use). Raise it whenever a rule changes what it finds:
 * every open queue entry decided by an older version is checked again at the next scan.
 * 2: secret mentions in prohibitions and warnings are no finding.
 */
export const SKILL_RULES_VERSION = 2;

/** One line for the page and the journal. */
export function summarize(check: SkillCheck): string {
  const top = check.findings.filter((f) => f.severity !== "info").slice(0, 3);
  if (top.length === 0) return "проверки чисты";
  return top.map((f) => `${f.rule}${f.file ? ` (${f.file}${f.line ? `:${f.line}` : ""})` : ""}`).join("; ");
}
