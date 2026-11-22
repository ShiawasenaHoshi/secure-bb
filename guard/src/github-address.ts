// Reading a github.com address as `owner/name`: ONE function for the guard's sources (`trust.ts`) and the plugin's pollution tracker (`src/taint/repos.ts`).
// A LEAF: it imports nothing, not even `node:*`, because the page (built for the browser) reaches the tracker. Do not add an import here.
export const OWNER = /^[a-z0-9](?:[a-z0-9-]{0,38})$/;
export const REPO = /^[a-z0-9._-]{1,100}$/;

/**
 * The ONE reading of a github.com address as `owner/name` (lower case); the plugin's pollution tracker (`src/taint/repos.ts`) calls it too.
 * `https://github.com/o/r.git`, `git@github.com:o/r`, `ssh://git@github.com/o/r`: the host must be exactly github.com.
 * `@ref` is the syntax of bb's PLUGIN SOURCES (`git@github.com:o/r@v1`): only with `allowRef` is it cut off. Anywhere else (an address in a shell command) a name with
 * `@` is not a repository of GitHub, so it is not one here: the choice that never trusts more (a repo is not «the same» because a suffix was ignored).
 */
export function githubRepo(address: string, opts: { allowRef?: boolean } = {}): string | null {
  let host: string;
  let path: string;
  const scp = /^[\w.-]+@([\w.-]+):(.+)$/.exec(address);
  if (scp) {
    host = scp[1]!;
    path = scp[2]!;
  } else {
    try {
      const u = new URL(address);
      if (!["https:", "http:", "ssh:", "git:"].includes(u.protocol)) return null;
      host = u.hostname;
      path = u.pathname;
    } catch {
      return null;
    }
  }
  if (host.toLowerCase() !== "github.com") return null;
  const parts = path.split(/[?#]/)[0]!.replace(/^\/+/, "").split("/");
  if (parts.length < 2) return null;
  const owner = parts[0]!.toLowerCase();
  const rawName = parts[1]!;
  if (!opts.allowRef && rawName.includes("@")) return null;
  const name = rawName.split("@")[0]!.replace(/\.git$/i, "").toLowerCase();
  return OWNER.test(owner) && REPO.test(name) && name !== "." && name !== ".." ? `${owner}/${name}` : null;
}
