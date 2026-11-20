// What goes to the models (spec §8): the plugin's own code with every comment removed, and nothing else.
// Comments are removed with the real parser (never regex over source), keeping the newlines so that
// the line numbers a model reports are the file's own. A file the parser cannot read is not sent
// and makes the scan incomplete (and so suspect): comments are exactly where injected instructions hide.
import { lstat, readdir, readFile } from "node:fs/promises";
import { join, sep } from "node:path";
import { parseSource } from "../checks/ast.js";
import { escapeInvisible, scanTree } from "../checks/files.js";

/** Code sent to the models, in characters (about 75k tokens). More than this does not fit: the scan is incomplete. */
export const MAX_DATA_CHARS = 300_000;
const MAX_PACKAGE_JSON = 40_000;
const MAX_DESCRIPTION = 2_000;
const MAX_SKIPPED_LISTED = 80;

export interface ScanFile {
  rel: string;
  /** Code without comments, invisible characters escaped. */
  text: string;
}
export interface Collected {
  name: string;
  version: string;
  /** Declared by the plugin itself (untrusted). */
  description: string;
  packageJson: string;
  files: ScanFile[];
  chars: number;
  incomplete: string[];
  skipped: string[];
  /** Packages in `node_modules`: not sent (the deterministic checks and the registry stage cover them). */
  packagesNotSent: number;
}

/** `text` with the given comment ranges replaced by as many line breaks as they contained. */
export function removeComments(text: string, ranges: Array<{ start: number; end: number }>): string {
  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  let out = "";
  let at = 0;
  for (const r of sorted) {
    if (r.start < at) continue;
    out += text.slice(at, r.start);
    const removed = text.slice(r.start, r.end);
    out += removed.includes("\n") ? "\n".repeat(removed.split("\n").length - 1) : " ";
    at = r.end;
  }
  return out + text.slice(at);
}

/** Other files in the tree, by name and size only. */
async function listOthers(root: string, sent: Set<string>): Promise<string[]> {
  const out: string[] = [];
  let more = 0;
  const walk = async (rel: string): Promise<void> => {
    const entries = await readdir(join(root, rel), { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      const childRel = rel === "" ? e.name : join(rel, e.name);
      const segs = childRel.split(sep);
      if (segs[0] === ".git" || segs[0] === "dist" || segs.includes("node_modules")) continue;
      if (e.isDirectory()) await walk(childRel);
      else if (!sent.has(childRel) && childRel !== "package.json") {
        if (out.length < MAX_SKIPPED_LISTED) out.push(`${childRel} (${(await lstat(join(root, childRel))).size} B)`);
        else more++;
      }
    }
  };
  await walk("");
  if (more > 0) out.push(`… и ещё ${more}`);
  return out;
}

export async function collectForScan(dir: string, limit = MAX_DATA_CHARS): Promise<Collected> {
  const tree = await scanTree(dir);
  const pkg = tree.rootPackage ?? {};
  const bbBlock = pkg.bb && typeof pkg.bb === "object" ? (pkg.bb as Record<string, unknown>) : {};
  const declared = [bbBlock.description, pkg.description].find((d) => typeof d === "string" && d.trim() !== "");
  const incomplete: string[] = [];

  let packageJson = "";
  try {
    packageJson = await readFile(join(dir, "package.json"), "utf8");
  } catch {
    incomplete.push("package.json: нет или не читается");
  }
  if (packageJson.length > MAX_PACKAGE_JSON) {
    incomplete.push(`package.json: больше ${MAX_PACKAGE_JSON} знаков, обрезан`);
    packageJson = packageJson.slice(0, MAX_PACKAGE_JSON);
  }

  const files: ScanFile[] = [];
  let chars = packageJson.length;
  let overflow = 0;
  for (const src of tree.sources) {
    if (src.dep || src.dist) continue;
    const comments: Array<{ start: number; end: number }> = [];
    const parsed = parseSource(src.rel, src.text, comments);
    if (!parsed.ok) {
      incomplete.push(`${src.rel}: не разобран парсером (${parsed.reason}), поэтому не отправлен: комментарии из него не убрать`);
      continue;
    }
    const text = escapeInvisible(removeComments(src.text, comments));
    if (chars + text.length > limit) {
      overflow++;
      incomplete.push(`${src.rel}: не поместился (лимит ${limit} знаков)`);
      continue;
    }
    chars += text.length;
    files.push({ rel: src.rel, text });
  }

  return {
    name: typeof pkg.name === "string" ? pkg.name : "",
    version: typeof pkg.version === "string" ? pkg.version : "",
    description: typeof declared === "string" ? declared.slice(0, MAX_DESCRIPTION) : "",
    packageJson: escapeInvisible(packageJson),
    files,
    chars,
    incomplete,
    skipped: await listOthers(dir, new Set(tree.sources.map((s) => s.rel))),
    packagesNotSent: tree.installed.length,
  };
}
