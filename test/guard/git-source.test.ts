// A plugin installed from GitHub, against a real guard and the `source` the core really sends (`sourceKind: "git"`, `source: "https://github.com/…"`).
// Before: `identityOf` named nothing for it, so the guard never read a git version itself, «мои источники» never covered one, and (after #40) a harmless plugin
// looked like one that may carry a hard flag.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { coreHash, startGuard, type TestGuard } from "./support.ts";

const cleanup: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});
const tmp = (p: string): string => {
  const d = realpathSync(mkdtempSync(join(tmpdir(), p)));
  cleanup.push(() => rmSync(d, { recursive: true, force: true }));
  return d;
};
// A chime-like plugin: plays a sound, nothing else.
const CHIME = (n: number) => `export default function plugin(bb) {\n  bb.log.info("chime ${n}");\n}\n`;
const LOUD = `export default function plugin(bb) {\n  eval(atob("YWxlcnQoMSk="));\n}\n`;
const sha = (n: number): string => n.toString(16).padStart(40, "a").slice(-40);

/** The directory the core loads a git plugin from: <data>/plugins/cache/git/github.com/<owner>/<name>/<commit>[/<subdirectory>]. */
function checkout(data: string, repo: string, n: number, server: string, sub = ""): string {
  const root = join(data, "plugins", "cache", "git", "github.com", ...repo.split("/"), sha(n));
  const d = sub === "" ? root : join(root, ...sub.split("/"));
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "chime", version: `1.0.${n}`, bb: { name: "chime", server: "./server.ts" } }));
  writeFileSync(join(d, "server.ts"), server);
  return realpathSync(d);
}
const decide = (rootDir: string, source: string, version: string) => ({ op: "decide", pluginId: "chime", version, contentHash: coreHash(rootDir), rootDir, source, sourceKind: "git", provenance: "direct", trigger: "install" });
const entryOf = async (g: TestGuard, id: number): Promise<any> => ((await g.send({ op: "state" })).queue as any[]).find((q) => q.id === id);

async function setup() {
  const data = tmp("sbb-git-");
  const g: TestGuard = await startGuard({ trust: { pluginsRoots: [join(data, "plugins", "cache", "git")] } });
  cleanup.push(() => g.close());
  return { data, g };
}
const CHIME_URL = "https://github.com/gtramontina/bb-plugin-chime";

describe("a git plugin as the core sends it", () => {
  it("the guard reads it itself: blocks is a list, the reason is not «block», and the card has a reason to show", async () => {
    const { data, g } = await setup();
    const dir = checkout(data, "gtramontina/bb-plugin-chime", 1, CHIME(1));
    const r = await g.send(decide(dir, CHIME_URL, "1.0.1"));
    expect(r.action).toBe("wait");
    const q = await entryOf(g, r.requestId);
    expect(q.blocks).toEqual([]);
    expect(q.reasonKind).toBe("unknown-source");
    expect(q.note).toBe("неизвестный источник");
    // and approving it is routine again: no acknowledgement, a session covers it
    const sess = await g.send({ op: "session-open", code: g.nextCode() });
    expect((await g.send({ op: "approve", requestId: r.requestId, session: sess.token })).ok).toBe(true);
  });

  it("with the source among «мои источники»: the next version with the same rights passes by itself", async () => {
    const { data, g } = await setup();
    expect((await g.send({ op: "sources-add", entries: ["github:gtramontina/bb-plugin-chime"], code: g.nextCode() })).ok).toBe(true);
    const d1 = checkout(data, "gtramontina/bb-plugin-chime", 1, CHIME(1));
    const first = await g.send(decide(d1, CHIME_URL, "1.0.1"));
    expect(first.action).toBe("wait"); // nothing approved from this source yet
    expect((await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() })).ok).toBe(true);
    const d2 = checkout(data, "gtramontina/bb-plugin-chime", 2, CHIME(2));
    expect(await g.send(decide(d2, `git:${CHIME_URL}@v1.0.2`, "1.0.2"))).toMatchObject({ action: "proceed", via: "source" });
    // the same repository by another spelling is the same source
    const d3 = checkout(data, "gtramontina/bb-plugin-chime", 3, CHIME(3));
    expect(await g.send(decide(d3, "git:github.com/gtramontina/bb-plugin-chime.git", "1.0.3"))).toMatchObject({ action: "proceed", via: "source" });
  });

  it("a version with a hard flag is held with its blocks, even from an own source", async () => {
    const { data, g } = await setup();
    await g.send({ op: "sources-add", entries: ["github:gtramontina/bb-plugin-chime"], code: g.nextCode() });
    const d1 = checkout(data, "gtramontina/bb-plugin-chime", 1, CHIME(1));
    const first = await g.send(decide(d1, CHIME_URL, "1.0.1"));
    await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() });
    const d2 = checkout(data, "gtramontina/bb-plugin-chime", 2, LOUD);
    const r = await g.send(decide(d2, CHIME_URL, "1.0.2"));
    expect(r.action).toBe("wait");
    const q = await entryOf(g, r.requestId);
    expect(q.reasonKind).toBe("block");
    expect(q.blocks.length).toBeGreaterThan(0);
    expect(q.stop ?? true).toBeTruthy();
  });

  it("a forged address is not read by the guard and not trusted: held as «unread», and a list entry for the real repository does not cover it", async () => {
    const { data, g } = await setup();
    await g.send({ op: "sources-add", entries: ["github:gtramontina/bb-plugin-chime"], code: g.nextCode() });
    const d1 = checkout(data, "gtramontina/bb-plugin-chime", 1, CHIME(1));
    const first = await g.send(decide(d1, CHIME_URL, "1.0.1"));
    await g.send({ op: "approve", requestId: first.requestId, code: g.nextCode() });
    const d2 = checkout(data, "gtramontina/bb-plugin-chime", 2, CHIME(2));
    for (const source of ["https://github.com.evil.com/gtramontina/bb-plugin-chime", "https://evil.com/github.com/gtramontina/bb-plugin-chime", "git:github.com@evil.com/gtramontina/bb-plugin-chime"]) {
      const r = await g.send(decide(d2, source, "1.0.2"));
      expect(r.action, source).toBe("wait");
      const q = await entryOf(g, r.requestId);
      expect(q.blocks, source).toBeNull();
      expect(q.note, source).toMatch(/нельзя назвать своим/);
    }
  });

  it("a plugin of a monorepo is its own source: «мои источники» for the repository does not let another plugin of it pass", async () => {
    const { data, g } = await setup();
    await g.send({ op: "sources-add", entries: ["github:o/mono"], code: g.nextCode() });
    const root = checkout(data, "o/mono", 1, CHIME(1));
    const a = await g.send(decide(root, "https://github.com/o/mono", "1.0.1"));
    await g.send({ op: "approve", requestId: a.requestId, code: g.nextCode() });
    // another plugin of the same repository (a subdirectory): the repository entry does not cover it
    const sub = checkout(data, "o/mono", 2, CHIME(2), "plugins/other");
    const b = await g.send(decide(sub, "https://github.com/o/mono", "1.0.2"));
    expect(b.action).toBe("wait");
    expect((await entryOf(g, b.requestId)).note).toBe("неизвестный источник");
    // …until that very plugin is named
    expect((await g.send({ op: "sources-add", entries: ["github:o/mono#plugins/other"], code: g.nextCode() })).ok).toBe(true);
    const sub2 = checkout(data, "o/mono", 3, CHIME(3), "plugins/other");
    expect((await g.send(decide(sub2, "https://github.com/o/mono", "1.0.3"))).action).toBe("wait"); // first version from this source: nobody approved it yet
  });
});
