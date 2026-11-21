// One careful pass over a plugin directory: the guard hashes what it reads the way the core does (`hashInstallDir`, install-sources.ts of the core)
// AND keeps the very bytes it hashed, so that the checks run on exactly the hashed content. Reading the directory twice (once for the hash, once for
// the checks) would let it change in between; this reads it once and the checks read a private copy of what was read.
//
// The hash, byte for byte as the core does it: sha256 over, recursively, the entries of a directory sorted by `localeCompare` of the name;
// a directory `d\0<name>\0` and then its entries, a link `l\0<name>\0<readlink>\0`, a file `f\0<name>\0<mode & 0o777>\0` and its bytes;
// the name is the path from the root joined with `/`; the result is `sha256:<hex>`. Anything else (a socket, a fifo) the core skips; here it is a
// refusal (nothing the core skips is something the guard can vouch for). Links are never followed (lstat; a file is opened with O_NOFOLLOW and its
// device and inode must be those lstat saw, as in the agent watch).
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open, readdir, readlink, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface TreeLimits {
  /** Entries (files, links, directories). */
  maxEntries: number;
  maxFileBytes: number;
  maxTotalBytes: number;
}
export const DEFAULT_TREE_LIMITS: TreeLimits = { maxEntries: 20_000, maxFileBytes: 16 * 1024 * 1024, maxTotalBytes: 64 * 1024 * 1024 };

export class TreeRefused extends Error {}

export interface TreeCopy {
  /** The core's hash of what was read. */
  hash: string;
  /** A private copy of exactly what was read (same names, modes and links). */
  dir: string;
  cleanup(): Promise<void>;
}

/** Reads `root` once; throws `TreeRefused` over a limit or for something that is not a file, a directory or a link. */
export async function readTree(root: string, limits: TreeLimits = DEFAULT_TREE_LIMITS): Promise<TreeCopy> {
  const hash = createHash("sha256");
  const copy = await mkdtemp(join(tmpdir(), "sbb-guard-read-"));
  const dirs: string[] = [];
  const dirModes: Array<[string, number]> = [];
  let entries = 0;
  let total = 0;
  const cleanup = async (): Promise<void> => {
    // A copied directory may have lost its write bit: give it back before removing.
    await Promise.all(dirs.map((d) => chmod(d, 0o700).catch(() => undefined)));
    await rm(copy, { recursive: true, force: true });
  };
  try {
    const visit = async (directory: string, prefix: string, target: string): Promise<void> => {
      const list = await readdir(directory, { withFileTypes: true });
      list.sort((left, right) => left.name.localeCompare(right.name));
      for (const entry of list) {
        if (++entries > limits.maxEntries) throw new TreeRefused(`больше ${limits.maxEntries} записей в каталоге`);
        const path = join(directory, entry.name);
        const name = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
        const out = join(target, entry.name);
        const st = await lstat(path);
        if (st.isDirectory()) {
          hash.update(`d\0${name}\0`);
          await mkdir(out, { mode: 0o700 });
          dirs.push(out);
          dirModes.push([out, st.mode & 0o7777]);
          await visit(path, name, out);
        } else if (st.isSymbolicLink()) {
          const to = await readlink(path);
          hash.update(`l\0${name}\0${to}\0`);
          await symlink(to, out);
        } else if (st.isFile()) {
          if (st.size > limits.maxFileBytes) throw new TreeRefused(`файл ${name} больше ${limits.maxFileBytes} байт`);
          const fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
          let bytes: Buffer;
          try {
            const fst = await fh.stat();
            if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) throw new TreeRefused(`файл ${name} подменён во время чтения`);
            if (fst.size > limits.maxFileBytes) throw new TreeRefused(`файл ${name} больше ${limits.maxFileBytes} байт`);
            bytes = await fh.readFile();
          } finally {
            await fh.close();
          }
          if (bytes.length > limits.maxFileBytes) throw new TreeRefused(`файл ${name} больше ${limits.maxFileBytes} байт`);
          total += bytes.length;
          if (total > limits.maxTotalBytes) throw new TreeRefused(`каталог больше ${limits.maxTotalBytes} байт`);
          hash.update(`f\0${name}\0${st.mode & 0o777}\0`);
          hash.update(bytes);
          await writeFile(out, bytes, { mode: 0o600 });
          await chmod(out, st.mode & 0o7777);
        } else {
          throw new TreeRefused(`${name}: не файл, не каталог и не ссылка`);
        }
      }
    };
    await visit(root, "", copy);
    // Directory modes last: a directory without a write bit could not be filled.
    for (const [d, mode] of dirModes.reverse()) await chmod(d, mode);
    return { hash: `sha256:${hash.digest("hex")}`, dir: copy, cleanup };
  } catch (err) {
    await cleanup();
    throw err;
  }
}
