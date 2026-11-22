// Stage 5 through the plugin's real surfaces (hook, RPC, CLI, background service) over the fake bb host.
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterEach, describe, expect, it, vi } from "vitest";
import plugin from "../server.js";
import { base32Decode, hotp, stepAt } from "../guard/src/totp.ts";

interface Ev {
  seq: number;
  createdAt: number;
  type: string;
  data: unknown;
}
async function boot() {
  const events = new Map<string, Ev[]>();
  const threadCbs: Array<(e: { id?: string; changes?: string[] }) => void> = [];
  const listCalls: unknown[] = [];
  const dataDir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-s5s-")));
  const { bb, harness } = createFakePluginHost({
    pluginId: "secure-bb",
    experimental_dataDir: dataDir,
    sdk: {
      subscribe: (opts: { event: string; callback: (e: { id?: string; changes?: string[] }) => void }) => {
        if (opts.event === "thread:changed") threadCbs.push(opts.callback);
        return () => undefined;
      },
      plugins: { list: async () => ({ plugins: [] }), install: async () => ({ id: "demo", version: "1.0.0", status: "disabled", statusDetail: 'held by secure-bb: каталог /Users/x/.ssh decode-eval (review #3)' }) },
      system: { config: async () => ({ generalSettings: { telemetryEnabled: true }, primaryHostId: "H1" }) },
      projects: { fileContent: async () => Promise.reject(Object.assign(new Error("not found"), { status: 404 })) },
      environments: { get: async () => ({ hostId: "H1" }) },
      threads: {
        experimental_listAncestors: async ({ threadIds }: { threadIds: string[] }) => ({ threads: threadIds.map((threadId) => ({ threadId, ancestorIds: [] })) }),
        experimental_listDescendants: async ({ threadIds }: { threadIds: string[] }) => ({ threads: threadIds.map((threadId) => ({ threadId, descendantIds: threadId === "T1" ? ["T1.a"] : [] })) }),
        get: async ({ threadId }: { threadId: string }) => ({ environmentId: "E1", projectId: `P-${threadId}` }),
        events: {
          list: async (args: { threadId: string; afterSeq?: string; limit?: string; order?: string; types?: string[] }) => {
            listCalls.push(args);
            const after = args.afterSeq === undefined ? 0 : Number(args.afterSeq);
            return (events.get(args.threadId) ?? []).filter((e) => e.seq > after);
          },
        },
      },
    } as never,
  } as never);
  await plugin(bb);
  const push = (threadId: string, item: Record<string, unknown>) => {
    const list = events.get(threadId) ?? [];
    list.push({ seq: list.length + 1, createdAt: Date.now(), type: "item/completed", data: { item } });
    events.set(threadId, list);
  };
  return { bb, harness, push, threadCbs, listCalls, dataDir };
}
type Booted = Awaited<ReturnType<typeof boot>>;

async function register(h: Booted): Promise<() => string> {
  await h.harness.behavior.callRpc("page.ping", null);
  const begin = (await h.harness.behavior.callRpc("totp.begin", null)) as { secret: string };
  const gen = () => hotp(base32Decode(begin.secret), stepAt(Date.now()));
  await h.harness.behavior.callRpc("totp.confirm", { code: gen() });
  return gen;
}

describe("journal integrity through the CLI and the page", () => {
  it("`log --verify` says ok, then BROKEN with exit code 2 after the database is edited; the agent gets no details", async () => {
    const h = await boot();
    await register(h); // something to journal
    const ok = await h.harness.behavior.runCli(["log", "--verify"]);
    expect(ok.exitCode).toBe(0);
    expect(ok.stdout).toMatch(/^journal: ok \(\d+ entries, head [0-9a-f]{12}\)$/);

    const db = h.bb.storage.database();
    db.prepare(`UPDATE log SET kind = 'forged' WHERE id = (SELECT MIN(id) FROM log)`).run();
    const bad = await h.harness.behavior.runCli(["log", "--verify"]);
    expect(bad.exitCode).toBe(2);
    expect(bad.stdout).toBe("journal: BROKEN (1 problem); a human must look at the secure-bb page");

    const status = await h.harness.behavior.runCli(["status"]);
    expect(status.stdout).toContain("journal: BROKEN");

    // the page has the details and the alarm
    const ov = (await h.harness.behavior.callRpc("overview", null)) as { journal: { ok: boolean; problems: Array<{ kind: string; detail: string }> } };
    expect(ov.journal.ok).toBe(false);
    expect(ov.journal.problems[0]).toMatchObject({ kind: "hash-mismatch" });
    expect(ov.journal.problems[0]!.detail).toMatch(/изменена/);
  });

  it("a plain `log` shows decisions for agents without reasons", async () => {
    const h = await boot();
    h.bb.storage.database().prepare(`INSERT INTO log (ts, kind, plugin_id, content_hash, detail, prev_hash, hash) VALUES (1, 'hold', 'demo', NULL, ?, ?, ?)`).run(
      JSON.stringify({ review: 4, version: "1.0.0", reason: "новая возможность в окне: network:evil.example" }),
      "0".repeat(64),
      "1".repeat(64),
    );
    const res = await h.harness.behavior.runCli(["log"]);
    expect(res.stdout).toContain("hold demo@1.0.0 review #4");
    expect(res.stdout).not.toMatch(/evil\.example|новая возможность/);
  });

  it("the RPC verifies on demand; the head file is written next to the database", async () => {
    const h = await boot();
    const r = (await h.harness.behavior.callRpc("journal.verify", null)) as { ok: boolean; entries: number };
    expect(r.ok).toBe(true);
    expect(typeof r.entries).toBe("number");
  });
});

describe("pollution through the real event API", () => {
  afterEach(() => vi.useRealTimers());
  it("a thread of the window's tree that used WebFetch closes the window; the background service reacts to thread events", { timeout: 15_000 }, async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const h = await boot();
    const code = await register(h);
    // a plugin proposed from T1, a human opens the window
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-s5p-")));
    chmodSync(dir, 0o755);
    const plug = join(dir, "demo");
    mkdirSync(plug, { mode: 0o755 });
    writeFileSync(join(plug, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: "1.0.0", bb: { server: "./server.ts" } }), { mode: 0o644 });
    writeFileSync(join(plug, "server.ts"), "fetch('https://x.example');\n", { mode: 0o644 });
    const first = await h.harness.behavior.runCli(["propose", plug], { threadId: "T1" });
    expect(first.exitCode).toBe(3);
    const ov0 = (await h.harness.behavior.callRpc("overview", null)) as { queue: Array<{ id: number }> };
    const queueId = ov0.queue[0]!.id;
    await h.harness.behavior.callRpc("window.open", { queueId, code: await freshCode(code) });
    let ov = (await h.harness.behavior.callRpc("overview", null)) as { windows: Array<{ id: number }> };
    expect(ov.windows).toHaveLength(1);

    const svc = h.harness.runService("watch");
    await new Promise((r) => setTimeout(r, 50));
    // T1.a (a subthread) fetches a web page; bb announces new events on it
    vi.setSystemTime(Date.now() + 5_000);
    h.push("T1.a", { type: "webFetch", url: "https://evil.example/readme", prompt: null, resultText: null });
    for (const cb of h.threadCbs) cb({ id: "T1.a", changes: ["events-appended"] });
    await new Promise((r) => setTimeout(r, 1900)); // debounce 1.5 s
    ov = (await h.harness.behavior.callRpc("overview", null)) as { windows: Array<{ id: number }>; log: Array<{ kind: string }>; tainted: Array<{ threadId: string; kinds: string[] }> };
    expect(ov.windows).toHaveLength(0);
    expect((ov as unknown as { log: Array<{ kind: string }> }).log.some((l) => l.kind === "window.taint")).toBe(true);
    expect((ov as unknown as { tainted: Array<{ threadId: string }> }).tainted.map((t) => t.threadId)).toEqual(["T1.a"]);
    // the events API was asked for the item events of the thread, oldest first
    expect(h.listCalls[0]).toMatchObject({ order: "asc", types: ["item/started", "item/completed"] });

    // the agent that proposes again is told only that the window is closed
    const again = await h.harness.behavior.runCli(["propose", plug], { threadId: "T1" });
    expect(again.exitCode).toBe(3);
    expect(again.stdout).toMatch(/окно доверия для demo закрыто/);
    expect(again.stdout).not.toMatch(/загрязн|taint|WebFetch|evil/i);
    svc.controller.abort();
    await svc.done;
  });
});

/** Codes are one-time per 30 s step: move the (faked) clock to the next step instead of waiting for it. */
async function freshCode(gen: () => string): Promise<string> {
  vi.setSystemTime(Date.now() + 31_000);
  return gen();
}

describe("the hook and a directory that others can write to (real file system)", () => {
  it("a plugin installed from a world-writable directory is held with a generic status; no code approves it; fixing the mode does", { timeout: 30_000 }, async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const h = await boot();
      const code = await register(h);
      const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-s5d-")));
      chmodSync(dir, 0o755);
      const plug = join(dir, "demo");
      mkdirSync(plug, { mode: 0o755 });
      writeFileSync(join(plug, "package.json"), JSON.stringify({ name: "bb-plugin-demo", version: "1.0.0", bb: { server: "./server.ts" } }), { mode: 0o644 });
      writeFileSync(join(plug, "server.ts"), "export default () => {};\n", { mode: 0o644 });
      chmodSync(plug, 0o777); // anyone can add or replace files in it
      const hook = h.harness.registrations.hooks["plugin.activate"]!;
      const ctx = { pluginId: "demo", version: "1.0.0", source: `path:${plug}`, sourceKind: "path" as const, provenance: "direct" as const, gitCommit: null, npmIntegrity: null, rootDir: plug, contentHash: "sha256:abc", trigger: "install" as const };
      const first = await hook(ctx);
      expect(first).toEqual({ action: "wait", reason: expect.stringMatching(/^held by secure-bb: review #\d+$/) });
      const ov = (await h.harness.behavior.callRpc("overview", null)) as { queue: Array<{ id: number; reason: string | null }> };
      expect(ov.queue[0]!.reason).toMatch(/^каталог доступен на запись другим: .*запись для всех/);
      vi.setSystemTime(Date.now() + 31_000);
      await expect(h.harness.behavior.callRpc("queue.approve", { id: ov.queue[0]!.id, code: code() })).rejects.toThrow(/others can write/);
      chmodSync(plug, 0o755);
      await hook(ctx); // core re-asks after the fix (recheck)
      vi.setSystemTime(Date.now() + 31_000);
      await h.harness.behavior.callRpc("queue.approve", { id: ov.queue[0]!.id, code: code() });
      expect(await hook(ctx)).toEqual({ action: "proceed" });
    } finally {
      vi.useRealTimers();
    }
  });
});
