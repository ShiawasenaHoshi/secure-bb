// Giving a socket (or its directory) to the group that may connect: `chown(path, -1, gid)`.
//
// On Linux the group of a file may be changed only by root, or by the file's owner who is himself a member of that group. The restore helper runs as the
// agents' user and owns its socket, so that user MUST be a member of the socket's group; without it chown fails with EPERM. A bare stack trace says nothing
// to the administrator: this turns the failure into one sentence that says what to do. Zero dependencies (`node:*` only).
import { chownSync } from "node:fs";

export type ChownFn = (path: string, uid: number, gid: number) => void;

/** The program that failed, and who it runs as: for the sentence below. */
export interface ChownWho {
  program: "sbb-restore" | "sbb-guard";
  /** The user the program runs as (uid), when known. */
  uid?: number | null;
}

/** The error is the administrator's to fix; `main` prints `message` and nothing else (no stack). */
export class SocketGroupError extends Error {
  readonly code = "socket_group";
  constructor(message: string) {
    super(message);
    this.name = "SocketGroupError";
  }
}

/** The sentence for an administrator. Pure: tests check the words. */
export function chownMessage(who: ChownWho, path: string, gid: number, code: string): string {
  const user = who.uid === null || who.uid === undefined ? "the user this program runs as" : `the user with uid ${who.uid} (the one this program runs as)`;
  const reason = code === "EPERM" || code === "EACCES" ? `the system refused (${code})` : `failed (${code})`;
  if (code !== "EPERM" && code !== "EACCES") return `${who.program}: cannot give ${path} to group ${gid}: ${reason}.`;
  return [
    `${who.program}: cannot give ${path} to group ${gid}: ${reason}.`,
    `On Linux only root, or the owner of the file who is a member of that group, may change the group of a file. Fix (as administrator):`,
    `add ${user} to the group with id ${gid} (for example: usermod -aG <group name> <user name>; \`getent group ${gid}\` gives the name), then restart the service so that it starts with the new group.`,
    `This gives the user no new rights: the helper writes as that same user and only to that user's own files.`,
    `If the group is not needed (a test setup), start without --socket-gid.`,
  ].join("\n");
}

/** `chown(path, -1, gid)`; a refusal becomes a `SocketGroupError` with the sentence above. `chown` is injectable for tests. */
export function chownGroup(who: ChownWho, path: string, gid: number, chown: ChownFn = chownSync): void {
  try {
    chown(path, -1, gid);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (typeof code === "string") throw new SocketGroupError(chownMessage({ uid: typeof process.getuid === "function" ? process.getuid() : null, ...who }, path, gid, code));
    throw err;
  }
}
