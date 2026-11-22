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

// ---- the `source` bb gives a guard for a plugin installed from git -----------------------------------------------------------------
// What the core sends (apps/server, services/plugins/install-sources.ts `parsePluginSource` / `parseGitSource`) is the string the person installed with, as typed:
//   https://github.com/o/r                 a bare https:// (or http://) address is a git source
//   git:https://github.com/o/r             `git:` + an address
//   git:github.com/o/r                     `git:` + a bare host and path (the core puts `https://` in front)
//   …/o/r.git, …/o/r/                      `.git` and a trailing slash are dropped by the core
//   …@v1.2.0, …@ref:main, …@semver:^1.0.0, …@semver:v:^1.0.0   a ref after the LAST `@` (the core cuts there)
//   git:<url>@semver:<range>               what an update of a range install carries (`gitRangeSourceSpec`)
// Not in `source`: the subdirectory (`--subdirectory`, `--plugin`) of a monorepo; it is only in the directory the core loads from (`gitSubdirectoryOf`).
// The core does not take `git@github.com:o/r` or `ssh://` as a git source (it makes `https://` of them and fails): they are not one here either.
// Everything else (another host, a port, user info, a query, a fragment, extra path segments, `http://`) is null: a source is called GitHub's only when it surely is.

/** How the core files a source by its first characters (the plugin sees only `source`, not the kind): `git`, `path` (the `path:` form) or "". */
export function sourceKindOf(source: string): "git" | "path" | "" {
  if (source.startsWith("path:")) return "path";
  if (source.startsWith("git:") || /^https?:\/\//i.test(source)) return "git";
  return "";
}

/** `owner/name` (lower case) of the GitHub repository a git `source` names, or null. Mirrors the core's reading of the string (same split at the last `@`). */
export function githubRepoOfGitSource(source: string): string | null {
  if (sourceKindOf(source) !== "git") return null;
  const spec = source.startsWith("git:") ? source.slice(4) : source;
  const at = spec.lastIndexOf("@");
  if (at === spec.length - 1) return null; // an empty ref: the core refuses it
  const urlish = at <= 0 ? spec : spec.slice(0, at);
  // eslint-disable-next-line no-control-regex
  if (urlish === "" || /[\s\\\u0000-\u001f\u007f]/.test(urlish)) return null;
  let url: URL;
  try {
    if (/^https?:\/\//.test(urlish)) url = new URL(urlish);
    else if (/^[a-z0-9]/i.test(urlish) && !/^[a-z]:[\\/]/i.test(urlish)) url = new URL(`https://${urlish}`);
    else return null;
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.hostname !== "github.com" || url.port !== "" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") return null;
  const parts = url.pathname.replace(/^\/+|\/+$/g, "").split("/");
  if (parts.length !== 2) return null;
  const owner = parts[0]!.toLowerCase();
  const name = parts[1]!.replace(/\.git$/i, "").toLowerCase();
  return OWNER.test(owner) && REPO.test(name) && name !== "." && name !== ".." ? `${owner}/${name}` : null;
}

/**
 * The subdirectory of a git plugin's repository, from the directory the core loads it from: `<data>/plugins/cache/git/github.com/<owner>/<name>/<commit>[/<subdirectory>]`.
 * `{ subdirectory: null }`: the plugin is the repository's root. Null: the directory is not where the core puts a checkout of THIS repository (another place, another
 * repository), so the source and the directory do not agree and nothing is said about the source.
 */
export function gitSubdirectoryOf(repo: string, rootDir: string | null | undefined): { subdirectory: string | null } | null {
  if (typeof rootDir !== "string") return null;
  const m = /^.*?\/plugins\/cache\/git\/github\.com\/([^/]+)\/([^/]+)\/[0-9a-f]{7,40}(?:\/(.+))?$/i.exec(rootDir.replace(/\/+$/, ""));
  if (!m || `${m[1]!.toLowerCase()}/${m[2]!.toLowerCase()}` !== repo) return null;
  if (m[3] === undefined) return { subdirectory: null };
  const segs = m[3].split("/");
  if (segs.some((x) => x === "" || x === "." || x === ".." || /[\u0000-\u001f\u007f#\\]/.test(x))) return null;
  return { subdirectory: segs.join("/") };
}
