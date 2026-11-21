// Collects the facts `assess()` needs. Every probe is best-effort and
// independent: a failure becomes "unknown", never an exception, and nothing
// is assumed about this machine (no hardcoded users, paths or ports).
import { execFile } from "node:child_process";
import { accessSync, constants, existsSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Probe } from "./detect.js";

const run = promisify(execFile);

export interface InstalledPluginLite {
  id: string;
  provenance: string;
  enabled: boolean;
  status: string;
  /** What the core says about the status (for `error`: why the plugin did not start). */
  statusDetail?: string | null;
  version: string;
  source: string;
  rootDir: string;
}

export interface ProbeSource {
  hookRegistered: boolean;
  loopbackBaseUrl: () => string;
  dataDir: () => string;
  listPlugins: () => Promise<InstalledPluginLite[]>;
  telemetryEnabled: () => Promise<boolean | null>;
}

const builtinKey = (id: string): string => id.replace(/^bb--/, "");
const RUNNING = new Set(["running", "starting", "degraded"]);

export function isThirdParty(p: InstalledPluginLite): boolean {
  return p.provenance !== "builtin" && p.id !== "secure-bb";
}
/** The core says a plugin waits for a guard (ours): its code is not loaded, whatever else the status says. */
const HELD_DETAIL = /waiting for activation guard|held by secure-bb|удержан/i;
/** Is the plugin's code running now? By the core's STATUS (`enabled` is only the wish: a held plugin is enabled and does not run). */
export const isRunning = (p: Pick<InstalledPluginLite, "status" | "statusDetail">): boolean => RUNNING.has(p.status) && !HELD_DETAIL.test(p.statusDetail ?? "");
export const runningThirdParty = (plugins: InstalledPluginLite[]): string[] => plugins.filter((p) => isThirdParty(p) && isRunning(p)).map((p) => p.id);

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

async function agentUid(): Promise<number | null> {
  const { stdout } = await run("ps", ["-axo", "uid=,command="], { timeout: 4000, maxBuffer: 8 * 1024 * 1024 });
  const uids = new Set<number>();
  for (const line of stdout.split("\n")) {
    if (!/host-daemon|bb-host/i.test(line) || /\bps\b|grep/.test(line)) continue;
    const m = /^\s*(\d+)\s/.exec(line);
    if (m) uids.add(Number(m[1]));
  }
  return uids.size === 1 ? [...uids][0]! : null;
}

async function bindInfo(port: number): Promise<Probe["bind"]> {
  const { stdout } = await run("lsof", ["-nP", "-a", "-p", String(process.pid), "-iTCP", "-sTCP:LISTEN", "-Fn"], { timeout: 4000 });
  const addrs = stdout
    .split("\n")
    .filter((l) => l.startsWith("n"))
    .map((l) => l.slice(1))
    .filter((a) => a.endsWith(`:${port}`));
  if (addrs.length === 0) return { address: null, loopbackOnly: null };
  const loopback = (a: string) => a.startsWith("127.") || a.startsWith("[::1]") || a.startsWith("localhost");
  return { address: addrs.join(", "), loopbackOnly: addrs.every(loopback) };
}

/** The bb account state through the bb-account plugin's RPC (a call to our own server). "unknown" when that plugin is off or silent. */
export async function fetchAccountState(base: string): Promise<Probe["accountState"]> {
  const res = await fetch(`${base}/api/v1/plugins/bb-account/rpc/bb-account.v1.status`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "null",
    signal: AbortSignal.timeout(4000),
  });
  const body = (await res.json()) as { ok?: boolean; result?: { state?: string } };
  if (!body.ok) return "unknown";
  return body.result?.state === "signed-out" ? "signed-out" : body.result?.state === undefined ? "unknown" : "signed-in";
}

export async function collectProbe(src: ProbeSource): Promise<Probe> {
  const base = safeSync(() => src.loopbackBaseUrl(), "");
  const port = base ? Number(new URL(base).port) : NaN;
  const plugins = await safe(src.listPlugins, [] as InstalledPluginLite[]);
  const builtins: Probe["builtins"] = {};
  for (const p of plugins) if (p.provenance === "builtin") builtins[builtinKey(p.id)] = p.enabled;

  const [agent, account, bind, apiAuth, telemetry] = await Promise.all([
    safe(agentUid, null),
    safe<Probe["accountState"]>(() => fetchAccountState(base), "unknown"),
    safe<Probe["bind"]>(() => bindInfo(port), { address: null, loopbackOnly: null }),
    safe<Probe["apiAuth"]>(async () => {
      const res = await fetch(`${base}/api/v1/hosts`, { signal: AbortSignal.timeout(4000) });
      return res.status === 401 || res.status === 403 ? "enforced" : res.ok ? "none" : "unknown";
    }, "unknown"),
    safe(src.telemetryEnabled, null),
  ]);

  const holdPath = join(safeSync(() => src.dataDir(), ""), "server-connect-hold.json");
  const exists = holdPath !== "server-connect-hold.json" && existsSync(holdPath);
  let serverCanDelete: boolean | null = null;
  try {
    // Deleting a file needs write access to its directory. (An immutable flag
    // is not visible from here; the page says so.)
    accessSync(join(holdPath, ".."), constants.W_OK);
    serverCanDelete = true;
  } catch {
    serverCanDelete = exists ? false : null;
  }

  return {
    hookRegistered: src.hookRegistered,
    // Only the variables the assessment reads: the page never needs the rest of the environment.
    env: {
      BB_PLUGIN_ACTIVATION_GUARDS: process.env.BB_PLUGIN_ACTIVATION_GUARDS,
      BB_TELEMETRY: process.env.BB_TELEMETRY,
      BB_MARKETPLACE_URL: process.env.BB_MARKETPLACE_URL,
      BB_SECURE_BB_TOTP_FILE: process.env.BB_SECURE_BB_TOTP_FILE,
    },
    serverUid: typeof process.getuid === "function" ? process.getuid() : null,
    agentUid: agent,
    accountState: account,
    builtins,
    connectHold: { exists, serverCanDelete },
    bind,
    apiAuth,
    thirdParty: runningThirdParty(plugins),
    telemetryConfigured: telemetry,
  };
}

function safeSync<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}
