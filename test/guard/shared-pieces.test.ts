// The pieces the guard and the plugin share instead of keeping copies: canonical JSON, the journal chain's pure part, the line socket.
import { mkdtempSync, realpathSync } from "node:fs";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { canonicalJson } from "../../guard/src/canonical-json.ts";
import { entryHash as guardEntryHash, GENESIS as guardGenesis } from "../../guard/src/journal.ts";
import { entryHash, GENESIS, scanChain, type ChainRow } from "../../guard/src/journal-chain.ts";
import { listenLines, probeListener } from "../../guard/src/line-socket.ts";
import { entryHash as pluginEntryHash, GENESIS as pluginGenesis } from "../../src/journal.ts";

describe("canonical JSON", () => {
  it("sorted keys, no spaces, the same text for the same data (the bytes sbb-restore and the part ids rely on)", () => {
    expect(canonicalJson({ b: 1, a: [2, { d: null, c: "x" }], z: undefined })).toBe('{"a":[2,{"c":"x","d":null}],"b":1,"z":null}');
    expect(canonicalJson([3, "a", true, null])).toBe('[3,"a",true,null]');
    expect(canonicalJson({ a: 1, b: 2 })).toBe(canonicalJson({ b: 2, a: 1 }));
  });
});

describe("the journal chain's pure part is one for both journals", () => {
  it("the guard's and the plugin's journals use the same hash and the same first link", () => {
    expect(guardEntryHash).toBe(entryHash);
    expect(pluginEntryHash).toBe(entryHash);
    expect(guardGenesis).toBe(GENESIS);
    expect(pluginGenesis).toBe(GENESIS);
  });
  const row = (id: number, prev: string, over: Partial<ChainRow> = {}): ChainRow => {
    const base = { id, ts: 1000 + id, kind: "approved.touch", plugin_id: "p", content_hash: "h", detail: null };
    const hash = entryHash(prev, base.ts, base.kind, base.plugin_id, base.content_hash, base.detail);
    return { ...base, prev_hash: prev, hash, ...over };
  };
  const chain = (): ChainRow[] => {
    const a = row(1, GENESIS);
    const b = row(2, a.hash!);
    const c = row(3, b.hash!);
    return [a, b, c];
  };
  it("an intact chain has no breaks and a head", () => {
    const rows = chain();
    expect(scanChain(rows)).toEqual({ entries: 3, maxId: 3, head: { id: 3, hash: rows[2]!.hash }, breaks: [] });
  });
  it("a changed record, a removed one and a record without a hash are each told once, at their place", () => {
    const changed = chain();
    changed[1] = { ...changed[1]!, kind: "forged" };
    expect(scanChain(changed).breaks).toEqual([{ kind: "hash-mismatch", id: 2, recordKind: "forged" }]);
    const removed = chain().filter((r) => r.id !== 2);
    expect(scanChain(removed).breaks).toEqual([{ kind: "prev-mismatch", id: 3, recordKind: "approved.touch" }]);
    const unhashed = chain();
    unhashed[1] = { ...unhashed[1]!, hash: null, prev_hash: null };
    expect(scanChain(unhashed).breaks.map((b) => [b.kind, b.id])).toEqual([["missing-hash", 2], ["prev-mismatch", 3]]);
  });
});

const dirs: string[] = [];
afterEach(() => void dirs.splice(0));
const sock = (): string => {
  const d = realpathSync(mkdtempSync(join(tmpdir(), "sbb-line-")));
  dirs.push(d);
  return join(d, "s.sock");
};
const ask = (path: string, lines: string[]): Promise<string[]> =>
  new Promise((resolve, reject) => {
    const c = net.connect(path);
    let got = "";
    c.setEncoding("utf8");
    c.on("data", (d: string) => {
      got += d;
      if (got.split("\n").length - 1 >= lines.length) (c.destroy(), resolve(got.trim().split("\n")));
    });
    c.on("error", reject);
    c.on("connect", () => c.write(lines.map((l) => `${l}\n`).join("")));
  });

describe("the line socket", () => {
  it("answers each line in order (a slow one first), probes a listener, and closes a connection with an endless line", async () => {
    const path = sock();
    expect(await probeListener(path)).toBe(false);
    const server = await listenLines(path, { maxLine: 32, maxConn: 4, timeoutMs: 2000, onLine: async (l) => (l === "slow" ? (await new Promise((r) => setTimeout(r, 60)), "slow-done") : `echo:${l}`) });
    try {
      expect(await probeListener(path)).toBe(true);
      expect(await ask(path, ["slow", "fast"])).toEqual(["slow-done", "echo:fast"]);
      const closed = await new Promise<boolean>((resolve) => {
        const c = net.connect(path);
        c.on("connect", () => c.write("x".repeat(100)));
        c.on("close", () => resolve(true));
        c.on("error", () => resolve(true));
      });
      expect(closed).toBe(true);
    } finally {
      server.close();
    }
  });
  it("closes the connections over the limit", async () => {
    const path = sock();
    const server = await listenLines(path, { maxLine: 1024, maxConn: 1, timeoutMs: 2000, onLine: (l) => l });
    try {
      const first = net.connect(path);
      await new Promise((r) => first.once("connect", r));
      const second = await new Promise<string>((resolve) => {
        const c = net.connect(path);
        c.on("close", () => resolve("closed"));
        c.on("error", () => resolve("closed"));
        setTimeout(() => resolve("open"), 400);
      });
      expect(second).toBe("closed");
      first.destroy();
    } finally {
      server.close();
    }
  });
});
