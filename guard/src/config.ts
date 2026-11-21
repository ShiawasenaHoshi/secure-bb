// Where the guard keeps things. Never hardcoded in the logic: arguments, then environment, then the documented default.
import { isAbsolute, join } from "node:path";

export interface GuardPaths {
  /** Root of the guard's data (default /var/sbb-guard). */
  dataDir: string;
  /** Private files: database, TOTP secret, journal head, mark of life. Mode 0700. */
  stateDir: string;
  db: string;
  secret: string;
  head: string;
  alive: string;
  /** Unix socket the core and the plugin talk to. */
  socket: string;
  /** Group id to give the socket (the group that contains only the bb user); null = leave as is. */
  socketGid: number | null;
  /** The WebAuthn relying party passkeys are bound to. */
  rp: RelyingParty;
  /** Agent watch: the agents' home, and the extra roots the console names (absolute paths; extending the list is a console matter only). */
  agentsHome: string;
  agentsRoots: string[];
}

export const DEFAULT_DATA_DIR = "/var/sbb-guard";
/** The agents' home: where the daemon of the agents keeps its settings, and (data/plugins/*\/host-data/workspaces/*) the working directories of threads. */
export const DEFAULT_AGENTS_HOME = "/var/bbagent";
/** Outside the data directory: that one is 0700, and the bb user must reach the socket through a directory of its own (0750, owner the guard, group the bb user's). */
export const DEFAULT_SOCKET = "/var/run/sbb-guard/guard.sock";

export function resolvePaths(opts: { data?: string; socket?: string; socketGid?: string; rpId?: string; origin?: string; agentsHome?: string; agentsRoots?: string }, env: Record<string, string | undefined> = process.env): GuardPaths {
  const dataDir = opts.data ?? env.SBB_GUARD_DATA ?? DEFAULT_DATA_DIR;
  const stateDir = join(dataDir, "state");
  const gidText = opts.socketGid ?? env.SBB_GUARD_SOCKET_GID;
  const socketGid = gidText === undefined || gidText === "" ? null : Number(gidText);
  if (socketGid !== null && (!Number.isInteger(socketGid) || socketGid < 0)) throw new Error("socket group id must be a non-negative integer");
  return {
    dataDir,
    stateDir,
    db: join(stateDir, "guard.db"),
    secret: join(stateDir, "totp.secret"),
    head: join(stateDir, "journal.head"),
    alive: join(stateDir, "alive"),
    socket: opts.socket ?? env.SBB_GUARD_SOCKET ?? DEFAULT_SOCKET,
    socketGid,
    rp: resolveRp({ rpId: opts.rpId, origin: opts.origin }, env),
    agentsHome: absolute(opts.agentsHome ?? env.SBB_GUARD_AGENTS_HOME ?? DEFAULT_AGENTS_HOME, "--agents-home"),
    agentsRoots: (opts.agentsRoots ?? env.SBB_GUARD_AGENTS_ROOTS ?? "")
      .split(",")
      .map((x) => x.trim())
      .filter((x) => x !== "")
      .map((x) => absolute(x, "--agents-root")),
  };
}

function absolute(p: string, flag: string): string {
  if (!isAbsolute(p)) throw new Error(`${flag} must be an absolute path`);
  return p.length > 1 ? p.replace(/\/+$/, "") : p;
}

export const DEFAULT_RP_ID = "localhost";
export const DEFAULT_ORIGIN = "http://localhost:38886";

/** The WebAuthn relying party: the page must be opened at exactly this origin (an IP address cannot be an RP ID, so not 127.0.0.1). */
export interface RelyingParty {
  rpId: string;
  origin: string;
}

export function resolveRp(opts: { rpId?: string; origin?: string }, env: Record<string, string | undefined> = process.env): RelyingParty {
  const rpId = opts.rpId ?? env.SBB_GUARD_RP_ID ?? DEFAULT_RP_ID;
  const origin = opts.origin ?? env.SBB_GUARD_ORIGIN ?? DEFAULT_ORIGIN;
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(rpId) || /^[0-9.]+$/.test(rpId)) throw new Error("--rp-id must be a domain name (an IP address cannot be a WebAuthn RP ID; use localhost, not 127.0.0.1)");
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    throw new Error("--origin must be a URL like http://localhost:38886");
  }
  if (u.origin !== origin || (u.protocol !== "https:" && u.protocol !== "http:")) throw new Error("--origin must be a bare origin (scheme, host, port; no path)");
  if (u.protocol === "http:" && u.hostname !== "localhost") throw new Error("--origin over http is only valid for localhost (WebAuthn needs a secure context)");
  if (u.hostname !== rpId && !u.hostname.endsWith(`.${rpId}`)) throw new Error("--origin must be on the RP ID's domain");
  return { rpId, origin };
}
