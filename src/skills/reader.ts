// Reads a whole skill through bb's API (listFiles + getContent per file) and hashes it.
// Memoised per scan: the watchdog (value of the skill in its snapshot) and the guard (checks) ask for the same skill.
import { hashSkillFiles } from "./hash.js";
import type { SkillFileData, SkillFileSource, SkillRef, SkillSnapshot } from "./types.js";

export const MAX_SKILL_FILES = 200;
export const MAX_SKILL_BYTES = 8 * 1024 * 1024;
const PARALLEL = 4;

export class SkillReader {
  private generation = 0;
  private memo = new Map<string, Promise<SkillSnapshot>>();

  constructor(private readonly source: SkillFileSource) {}

  /** A new scan: answers of the previous one are not reused. */
  beginScan(): void {
    this.generation++;
    this.memo = new Map();
  }

  snapshot(ref: SkillRef): Promise<SkillSnapshot> {
    const key = `${this.generation}:${ref.id}`;
    let p = this.memo.get(key);
    if (!p) {
      p = this.read(ref);
      this.memo.set(key, p);
      // A failed read is not kept: the next asker (same scan) tries again.
      p.catch(() => this.memo.delete(key));
    }
    return p;
  }

  private async read(ref: SkillRef): Promise<SkillSnapshot> {
    const listing = await this.source.listFiles(ref);
    const paths = [...new Set(listing.files)].sort();
    const files: SkillFileData[] = new Array(Math.min(paths.length, MAX_SKILL_FILES));
    let bytes = 0;
    let next = 0;
    const worker = async (): Promise<void> => {
      for (;;) {
        const i = next++;
        if (i >= files.length) return;
        const path = paths[i]!;
        try {
          const r = await this.source.readFile(ref, path);
          files[i] = { path, revision: r.revision, content: r.content };
          bytes += r.content.length;
        } catch (err) {
          // Not reading a file is not an all-clear: the revision says so, and the hash differs from any readable state.
          files[i] = { path, revision: "unreadable", content: null, error: err instanceof Error ? err.message : String(err) };
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(PARALLEL, files.length) }, worker));
    const overflow = paths.length > MAX_SKILL_FILES;
    const truncated = listing.truncated || overflow;
    return { hash: hashSkillFiles(files, truncated), files, truncated, bytes };
  }
}
