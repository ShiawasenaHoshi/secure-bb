// A guard in the test process on a temporary socket (nothing global: its own directory, its own clock).
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type net from "node:net";
import { resolvePaths, type GuardPaths } from "../../guard/src/config.ts";
import { openDb, privateDir } from "../../guard/src/db.ts";
import { Guard } from "../../guard/src/guard.ts";
import { request } from "../../guard/src/cli.ts";
import { listen } from "../../guard/src/server.ts";
import { base32Decode, generateSecret, hotp, stepAt } from "../../guard/src/totp.ts";

export class Clock {
  t = 1_800_000_000_000;
  now = (): number => this.t;
  advance(ms: number): void {
    this.t += ms;
  }
}

export interface TestGuard {
  clock: Clock;
  paths: GuardPaths;
  guard: Guard;
  server: net.Server | null;
  secret: string;
  /** A valid code for the current step. */
  code(): string;
  /** Jumps 31 s ahead (so the next `code()` is a fresh step) and returns it. */
  nextCode(): string;
  send(req: Record<string, unknown>): Promise<Record<string, any>>;
  close(): Promise<void>;
}

export async function startGuard(opts: { register?: boolean; serve?: boolean } = {}): Promise<TestGuard> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-guard-")));
  const paths = resolvePaths({ data: dir, socket: join(dir, "run", "guard.sock") });
  privateDir(paths.stateDir);
  const clock = new Clock();
  const db = openDb(paths.db);
  const guard = new Guard({ db, now: clock.now, secretPath: paths.secret, headPath: paths.head });
  const secret = generateSecret();
  const code = (): string => hotp(base32Decode(secret), stepAt(clock.t));
  if (opts.register !== false) {
    guard.registerSecret(secret, code());
    clock.advance(31_000);
  }
  let closed = false;
  const server = opts.serve === false ? null : await listen({ guard, socket: paths.socket, socketGid: null, version: "test" });
  const tg: TestGuard = {
    clock,
    paths,
    guard,
    server,
    secret,
    code,
    nextCode() {
      clock.advance(31_000);
      return code();
    },
    send: (req) => request(paths.socket, req) as Promise<Record<string, any>>,
    async close() {
      if (closed) return;
      closed = true;
      await new Promise<void>((r) => {
        const s = tg.server;
        if (s?.listening) s.close(() => r());
        else r();
      });
      db.close();
    },
  };
  return tg;
}

export const decideReq = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  op: "decide",
  pluginId: "demo",
  version: "1.0.0",
  contentHash: "a".repeat(64),
  rootDir: "/tmp/demo",
  source: "path:/tmp/demo",
  sourceKind: "path",
  trigger: "install",
  ...over,
});

// ---- the plugin in guard mode, over the fake bb host ------------------------------------------------------------------
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import plugin from "../../server.js";
import { Guard as GuardClass } from "../../guard/src/guard.ts";

/** A guard whose clock is the (faked) Date, so the plugin and the guard agree on time. */
export async function startGuardOnDate(): Promise<TestGuard> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-guard-")));
  const paths = resolvePaths({ data: dir, socket: join(dir, "run", "guard.sock") });
  privateDir(paths.stateDir);
  const db = openDb(paths.db);
  const guard = new GuardClass({ db, now: () => Date.now(), secretPath: paths.secret, headPath: paths.head });
  const secret = generateSecret();
  const code = (): string => hotp(base32Decode(secret), stepAt(Date.now()));
  guard.registerSecret(secret, code());
  const server = await listen({ guard, socket: paths.socket, socketGid: null, version: "test" });
  const clock = new Clock();
  let closed = false;
  const tg: TestGuard = {
    clock,
    paths,
    guard,
    server,
    secret,
    code,
    nextCode: () => code(),
    send: (req) => request(paths.socket, req) as Promise<Record<string, any>>,
    async close() {
      if (closed) return;
      closed = true;
      await new Promise<void>((r) => (tg.server?.listening ? tg.server.close(() => r()) : r()));
      db.close();
    },
  };
  return tg;
}

export interface Installed {
  id: string;
  provenance: string;
  enabled: boolean;
  status: string;
  version: string;
  source: string;
  rootDir: string;
}

/** Boots the plugin with BB_SECURE_BB_GUARD_SOCKET set (or without it: `socket: null`). */
export async function bootPlugin(socket: string | null, opts: { onInstall?: (source: string) => Promise<void> } = {}) {
  let plugins: Installed[] = [];
  const installs: string[] = [];
  const dataDir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-gm-")));
  const prev = process.env.BB_SECURE_BB_GUARD_SOCKET;
  if (socket === null) delete process.env.BB_SECURE_BB_GUARD_SOCKET;
  else process.env.BB_SECURE_BB_GUARD_SOCKET = socket;
  const { bb, harness } = createFakePluginHost({
    pluginId: "secure-bb",
    experimental_dataDir: dataDir,
    sdk: {
      plugins: {
        list: async () => ({ plugins }),
        enable: async () => ({}),
        disable: async () => ({}),
        install: async (a: { source: string }) => {
          installs.push(a.source);
          await opts.onInstall?.(a.source); // the core asks the guard and the hooks while installing
          return { id: "demo", version: "1.0.0", status: "disabled", statusDetail: null };
        },
      },
      system: { config: async () => ({ generalSettings: { telemetryEnabled: true }, primaryHostId: "h1" }) },
      environments: { get: async () => ({ hostId: "h1" }) },
      projects: { fileContent: async () => Promise.reject(Object.assign(new Error("not found"), { status: 404 })) },
      threads: {
        experimental_listAncestors: async ({ threadIds }: { threadIds: string[] }) => ({ threads: threadIds.map((threadId) => ({ threadId, ancestorIds: [] })) }),
        experimental_listDescendants: async ({ threadIds }: { threadIds: string[] }) => ({ threads: threadIds.map((threadId) => ({ threadId, descendantIds: [] })) }),
        get: async ({ threadId }: { threadId: string }) => ({ environmentId: "e1", projectId: `P-${threadId}` }),
        events: { list: async () => [] },
      },
    } as never,
  } as never);
  try {
    await plugin(bb);
  } finally {
    if (prev === undefined) delete process.env.BB_SECURE_BB_GUARD_SOCKET;
    else process.env.BB_SECURE_BB_GUARD_SOCKET = prev;
  }
  const rpc = <T = unknown>(name: string, input: unknown = null) => harness.behavior.callRpc(name as never, input as never) as Promise<T>;
  const hook = harness.registrations.hooks["plugin.activate"]!;
  return { bb, harness, rpc, hook, installs, dataDir, setPlugins: (p: Installed[]) => (plugins = p) };
}
export type Booted = Awaited<ReturnType<typeof bootPlugin>>;

export function plugDir(name: string, body = "fetch('https://x.example');\n"): string {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-gm-p-")));
  chmodSync(dir, 0o755);
  const plug = join(dir, name);
  mkdirSync(plug, { mode: 0o755 });
  writeFileSync(join(plug, "package.json"), JSON.stringify({ name: `bb-plugin-${name}`, version: "1.0.0", bb: { server: "./server.ts" } }), { mode: 0o644 });
  writeFileSync(join(plug, "server.ts"), body, { mode: 0o644 });
  return plug;
}
export const hookCtx = (name: string, dir: string, hash = `sha256:${name}`) => ({ pluginId: name, version: "1.0.0", source: `path:${dir}`, sourceKind: "path" as const, provenance: "direct" as const, gitCommit: null, npmIntegrity: null, rootDir: dir, contentHash: hash, trigger: "install" as const });

/**
 * What the core does (patch 0003): asks the guard, runs the hooks; any "no" or "held" wins. The order is the core's choice and the
 * plugin must be right in both: guard first means the guard may record an approval by a window before this plugin's hook holds the version.
 */
export async function core(g: TestGuard, h: Booted, ctx: ReturnType<typeof hookCtx>, order: "guard-first" | "hooks-first" = "guard-first"): Promise<"load" | "held" | "rejected"> {
  const ask = () => g.send({ op: "decide", pluginId: ctx.pluginId, version: ctx.version, contentHash: ctx.contentHash, rootDir: ctx.rootDir, source: ctx.source, sourceKind: ctx.sourceKind, trigger: ctx.trigger });
  let asked: Record<string, any> | null = null;
  if (order === "guard-first") asked = await ask();
  const hooked = (await h.hook(ctx)) as { action: string };
  if (hooked.action === "reject") return "rejected";
  if (order === "hooks-first") {
    if (hooked.action !== "proceed") return "held"; // the guard is not even asked
    asked = await ask();
  }
  return asked!.ok === true && asked!.action === "proceed" && hooked.action === "proceed" ? "load" : "held";
}
