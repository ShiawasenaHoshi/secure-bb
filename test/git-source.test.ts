// The `source` bb gives a guard for a plugin installed from GitHub, as the core really sends it (apps/server install-sources.ts `parsePluginSource`): a bare https:// address,
// `git:` + an address, `git:` + host and path, `.git`, a trailing slash, `@ref` after the last `@`. Each form names `github:owner/name`; every forgery of the host is null.
import { describe, expect, it } from "vitest";
import { entryCovers, identityOf, levelOf, normalizeEntry } from "../guard/src/trust.ts";
import { githubRepoOfGitSource, gitSubdirectoryOf, sourceKindOf } from "../guard/src/github-address.ts";
import { suggestSources } from "../src/ux/modes.ts";

const SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
const dir = (repo: string, sub = "") => `/var/bb/plugins/cache/git/github.com/${repo}/${SHA}${sub}`;

describe("the forms of a git source the core sends", () => {
  const cases: Array<[string, string]> = [
    ["https://github.com/gtramontina/bb-plugin-chime", "gtramontina/bb-plugin-chime"],
    ["git:https://github.com/o/r", "o/r"],
    ["git:github.com/o/r", "o/r"],
    ["https://github.com/o/r.git", "o/r"],
    ["https://github.com/o/r/", "o/r"],
    ["https://github.com/o/r@v1.2.0", "o/r"],
    ["git:https://github.com/o/r@ref:main", "o/r"],
    ["git:https://github.com/o/r@semver:^1.0.0", "o/r"],
    ["git:https://github.com/o/r@semver:v:^1.0.0", "o/r"],
    ["git:github.com/Owner/Repo.git@v2", "owner/repo"],
    ["https://GITHUB.COM/o/r", "o/r"],
  ];
  for (const [source, repo] of cases) {
    it(`${source} → github:${repo}`, () => {
      expect(sourceKindOf(source)).toBe("git");
      expect(githubRepoOfGitSource(source)).toBe(repo);
      expect(identityOf("git", source, dir(repo))).toEqual({ kind: "git", id: `github:${repo}` });
    });
  }
  it("what the core does not take as a git source is not one here: scp and ssh addresses, a local path, npm", () => {
    for (const s of ["git@github.com:o/r", "git:git@github.com:o/r", "ssh://git@github.com/o/r", "git:/abs/repo", "path:/x", "npm:foo", "foo/bar"]) expect(githubRepoOfGitSource(s), s).toBeNull();
  });
});

describe("forgeries of the address are not GitHub", () => {
  const forged = [
    "https://github.com.evil.com/o/r",
    "https://evil.com/github.com/o/r",
    "https://github.com@evil.com/o/r",
    "git:github.com@evil.com/o/r",
    "git:github.com.evil.com/o/r",
    "git:evilgithub.com/o/r",
    "https://github.com:8443/o/r",
    "https://user@github.com/o/r",
    "https://github.com/o/r?x=1",
    "https://github.com/o/r#x",
    "https://github.com/o/r/tree/main",
    "https://github.com/o",
    "https://github.com./o/r",
    "http://github.com/o/r",
    "https://github.com/o/r@",
    "https://github.com/o/%72",
    "https://github.com/o/..",
    "https://github.com/ /r",
    "HTTPS://github.com/o/r@v1",
    "git:https://gitlab.com/o/r",
  ];
  for (const s of forged) it(`${s} → null`, () => expect(githubRepoOfGitSource(s)).toBeNull());
  it("a source whose directory is another repository's is not named (the source and the directory must agree)", () => {
    expect(identityOf("git", "https://github.com/o/r", dir("p/q"))).toBeNull();
    expect(identityOf("git", "https://github.com/o/r", "/tmp/anything")).toBeNull();
    expect(identityOf("git", "https://github.com/o/r", undefined)).toBeNull();
    expect(identityOf("git", "https://github.com/o/r", null)).toBeNull();
  });
  it("a path inside a plugin's own tree cannot pose as a checkout of another repository", () => {
    const inner = `${dir("attacker/evil")}/plugins/cache/git/github.com/victim/own/${SHA}`;
    expect(identityOf("git", "https://github.com/victim/own", inner)).toBeNull();
    expect(identityOf("git", "https://github.com/attacker/evil", inner)?.id).toBe(`github:attacker/evil#plugins/cache/git/github.com/victim/own/${SHA}`);
  });
});

describe("a plugin of a monorepo is its own source", () => {
  it("the subdirectory is part of the identity; the root of the repository is not", () => {
    expect(gitSubdirectoryOf("o/r", dir("o/r"))).toEqual({ subdirectory: null });
    expect(gitSubdirectoryOf("o/r", dir("o/r", "/plugins/x"))).toEqual({ subdirectory: "plugins/x" });
    expect(gitSubdirectoryOf("o/r", dir("o/r", "/../y"))).toBeNull();
    expect(identityOf("git", "https://github.com/o/r", dir("o/r"))?.id).toBe("github:o/r");
    expect(identityOf("git", "https://github.com/o/r", dir("o/r", "/plugins/x"))?.id).toBe("github:o/r#plugins/x");
  });
  it("«мой источник» github:o/r does not cover another plugin of the repository; the exact entry and the owner's wildcard do", () => {
    const root = identityOf("git", "https://github.com/o/r", dir("o/r"))!;
    const sub = identityOf("git", "https://github.com/o/r", dir("o/r", "/plugins/x"))!;
    expect(entryCovers("github:o/r", root)).toBe(true);
    expect(entryCovers("github:o/r", sub)).toBe(false);
    expect(entryCovers("github:o/r#plugins/x", sub)).toBe(true);
    expect(entryCovers("github:o/r#plugins/y", sub)).toBe(false);
    expect(entryCovers("github:o/*", sub)).toBe(true);
    expect(levelOf(sub, ["github:o/r"], []).level).toBe("unknown");
    expect(levelOf(sub, ["github:o/r#plugins/x"], []).level).toBe("own");
    expect(levelOf(root, ["github:o/r"], []).level).toBe("own");
  });
  it("the entry with a subdirectory is read once, keeping the directory's case, and bad ones are refused", () => {
    expect(normalizeEntry("github:O/R#Plugins/X")).toBe("github:o/r#Plugins/X");
    expect(normalizeEntry("github:o/r#./plugins/x/")).toBe("github:o/r#plugins/x");
    for (const bad of ["github:o/r#", "github:o/r#..", "github:o/r#a/../b", "github:o/*#x", "github:o/r#a//b", "github:o/r#a b"]) expect(normalizeEntry(bad), bad).toBeNull();
  });
});

describe("the page's suggestions for «мои источники» read a git plugin by its real source", () => {
  it("a plugin installed from https:// is suggested as github:owner/name (and with its subdirectory in a monorepo)", () => {
    const ident = (k: string, s: string, d?: string | null) => identityOf(k, s, d)?.id ?? null;
    expect(suggestSources([{ source: "https://github.com/o/r", rootDir: dir("o/r") }, { source: "git:github.com/o/m", rootDir: dir("o/m", "/p/x") }], ident)).toEqual(["github:o/r", "github:o/m#p/x"]);
  });
});
