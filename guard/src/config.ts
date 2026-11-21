// Where the guard keeps things. Never hardcoded in the logic: arguments, then environment, then the documented default.
import { join } from "node:path";

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
}

export const DEFAULT_DATA_DIR = "/var/sbb-guard";
/** Outside the data directory: that one is 0700, and the bb user must reach the socket through a directory of its own (0750, owner the guard, group the bb user's). */
export const DEFAULT_SOCKET = "/var/run/sbb-guard/guard.sock";

export function resolvePaths(opts: { data?: string; socket?: string; socketGid?: string }, env: Record<string, string | undefined> = process.env): GuardPaths {
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
  };
}
