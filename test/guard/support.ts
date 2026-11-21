// A guard in the test process on a temporary socket (nothing global: its own directory, its own clock).
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type net from "node:net";
import { resolvePaths, type GuardPaths } from "../../guard/src/config.ts";
import { openDb, privateDir } from "../../guard/src/db.ts";
import { Guard, type AgentsConfig, type TrustConfig } from "../../guard/src/guard.ts";
import { request } from "../../guard/src/cli.ts";
import { listen } from "../../guard/src/server.ts";
import { base32Decode, generateSecret, hotp, stepAt } from "../../guard/src/totp.ts";
import type { RelyingParty } from "../../guard/src/config.ts";
import { SoftAuthenticator, type Assertion, type Overrides } from "./authenticator.ts";

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

export async function startGuard(opts: { register?: boolean; serve?: boolean; rp?: RelyingParty; agents?: AgentsConfig; trust?: TrustConfig } = {}): Promise<TestGuard> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-guard-")));
  const paths = resolvePaths({ data: dir, socket: join(dir, "run", "guard.sock") });
  privateDir(paths.stateDir);
  const clock = new Clock();
  const db = openDb(paths.db);
  const guard = new Guard({ db, now: clock.now, secretPath: paths.secret, headPath: paths.head, ...(opts.rp ? { rp: opts.rp } : {}), ...(opts.agents ? { agents: opts.agents } : {}), ...(opts.trust ? { trust: opts.trust } : {}) });
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
export async function startGuardOnDate(opts: { agents?: AgentsConfig; trust?: TrustConfig } = {}): Promise<TestGuard> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sbb-guard-")));
  const paths = resolvePaths({ data: dir, socket: join(dir, "run", "guard.sock") });
  privateDir(paths.stateDir);
  const db = openDb(paths.db);
  const guard = new GuardClass({ db, now: () => Date.now(), secretPath: paths.secret, headPath: paths.head, ...(opts.agents ? { agents: opts.agents } : {}), ...(opts.trust ? { trust: opts.trust } : {}) });
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
export async function bootPlugin(socket: string | null, opts: { onInstall?: (source: string) => Promise<void>; environments?: Array<{ id: string; path: string | null }>; threadsOfEnvironment?: Record<string, string[]> } = {}) {
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
      environments: { get: async () => ({ hostId: "h1" }), list: async () => opts.environments ?? [] },
      projects: { fileContent: async () => Promise.reject(Object.assign(new Error("not found"), { status: 404 })) },
      threads: {
        experimental_listAncestors: async ({ threadIds }: { threadIds: string[] }) => ({ threads: threadIds.map((threadId) => ({ threadId, ancestorIds: [] })) }),
        experimental_listDescendants: async ({ threadIds }: { threadIds: string[] }) => ({ threads: threadIds.map((threadId) => ({ threadId, descendantIds: [] })) }),
        get: async ({ threadId }: { threadId: string }) => ({ environmentId: "e1", projectId: `P-${threadId}` }),
        events: { list: async () => [] },
        list: async ({ environmentId }: { environmentId?: string }) => ((environmentId && opts.threadsOfEnvironment?.[environmentId]) || []).map((id) => ({ id })),
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

// ---- passkeys ----------------------------------------------------------------------------------------------------------
/**
 * The registration the way it happens: the console opens the window (`enrollStart`), the page registers over the socket with the token,
 * the console confirms. `confirm: false` leaves the key waiting. Returns what the console printed.
 */
export async function enrollKey(g: TestGuard, auth: SoftAuthenticator, opts: { label?: string; confirm?: boolean; create?: Overrides } = {}) {
  const e = g.guard.enrollStart(opts.label ?? "laptop");
  const options = (await g.send({ op: "passkey-register", token: e.token })).options;
  const reg = await g.send({ op: "passkey-register", token: e.token, ...auth.create(options, opts.create) });
  if (reg.ok && opts.confirm !== false) g.guard.confirmEnrollment(e.id);
  return { enrollment: e, options, reg };
}

/** Asks for a challenge for `action` and signs it. The result goes into the command as `passkey`. */
export async function touchFor(g: TestGuard, auth: SoftAuthenticator, action: Record<string, unknown>, o: Overrides = {}): Promise<{ passkey: Assertion; challenge: Record<string, any> }> {
  const c = await g.send({ op: "challenge", action });
  if (!c.ok) throw new Error(`challenge refused: ${JSON.stringify(c.error)}`);
  return { passkey: auth.get(c.challenge, o), challenge: c };
}
export { SoftAuthenticator };

// ---- the core's hash of a plugin directory -------------------------------------------------------------------------------
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
/**
 * `hashInstallDir` of the core (apps/server/src/services/plugins/install-sources.ts), repeated here as the reference the guard's own
 * hash is compared with: sha256, entries sorted by `localeCompare`, `d\0name\0` and descent, `l\0name\0target\0`, `f\0name\0mode&0o777\0` + bytes.
 * Synchronous (the core's is async; the bytes fed to the hash are the same).
 */
export function coreHash(rootDir: string): string {
  const hash = createHash("sha256");
  const visit = (directory: string, prefix: string): void => {
    const entries = readdirSync(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const name = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
      const stats = lstatSync(path);
      if (stats.isDirectory()) {
        hash.update(`d\0${name}\0`);
        visit(path, name);
      } else if (stats.isSymbolicLink()) {
        hash.update(`l\0${name}\0${readlinkSync(path)}\0`);
      } else if (stats.isFile()) {
        hash.update(`f\0${name}\0${stats.mode & 0o777}\0`);
        hash.update(readFileSync(path));
      }
    }
  };
  visit(rootDir, "");
  return `sha256:${hash.digest("hex")}`;
}
