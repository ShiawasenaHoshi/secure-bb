// What of a snapshot goes into the monorepo, and the last look for secrets before anything leaves the machine.
import { cp, lstat, readFile, readdir } from "node:fs/promises";
import { join, relative, sep } from "node:path";

/** `.git` and `node_modules` at any depth, `dist` at the top (it is rebuilt on install): never published. */
export function publishExcluded(rel: string): boolean {
  const parts = rel.split(sep);
  return parts.includes(".git") || parts.includes("node_modules") || parts[0] === "dist";
}

/** Copies the publishable part of `src` to `dest` (which must not exist); symlinks stay links. */
export async function copyForPublish(src: string, dest: string): Promise<void> {
  await cp(src, dest, {
    recursive: true,
    verbatimSymlinks: true,
    force: false,
    errorOnExist: true,
    filter: (from) => {
      const rel = relative(src, from);
      return rel === "" || !publishExcluded(rel);
    },
  });
}

export interface SecretFinding {
  rule: string;
  file: string;
}

const RULES: Array<{ rule: string; re: RegExp }> = [
  { rule: "private-key", re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/ },
  { rule: "github-token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/ },
  { rule: "aws-access-key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { rule: "slack-token", re: /\bxox[abprs]-[A-Za-z0-9-]{20,}\b/ },
  { rule: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { rule: "bearer-literal", re: /\bAuthorization["']?\s*[:=]\s*["']?(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{24,}/ },
  { rule: "url-credentials", re: /\bhttps?:\/\/[^\s/:@"']+:[^\s/@"']{3,}@[A-Za-z0-9.-]+/ },
];
const MAX_FILE = 4 * 1024 * 1024;

/**
 * Looks at every file that would be published. Reports rule and file, never the text found.
 * `literals` are values that must not appear at all (the push token itself).
 */
export async function findSecrets(root: string, literals: string[] = []): Promise<SecretFinding[]> {
  const out: SecretFinding[] = [];
  const walk = async (rel: string): Promise<void> => {
    for (const entry of await readdir(join(root, rel), { withFileTypes: true })) {
      const childRel = rel === "" ? entry.name : join(rel, entry.name);
      if (publishExcluded(childRel)) continue;
      if (entry.isDirectory()) {
        await walk(childRel);
        continue;
      }
      const full = join(root, childRel);
      const st = await lstat(full);
      if (!st.isFile()) continue;
      if (st.size > MAX_FILE) continue; // assets, not source: the plugin checks list binaries separately
      const buf = await readFile(full);
      const text = buf.toString("latin1");
      for (const { rule, re } of RULES) if (re.test(text)) out.push({ rule, file: childRel });
      for (const lit of literals) if (lit.length >= 8 && text.includes(lit)) out.push({ rule: "push-token", file: childRel });
    }
  };
  await walk("");
  return out;
}
