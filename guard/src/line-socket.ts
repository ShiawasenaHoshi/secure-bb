// The loop both local services share (the guard's `server.ts` and `sbb-restore`'s `restore.ts`): a Unix socket that takes one JSON request per line and answers one line.
// What is NOT here: the directory and mode of the socket, the group, the limits' values and what a request means: each service sets those itself.
import * as net from "node:net";

/** Asks by connecting (and at once closing): is something already listening there? A stale socket file (a crash) is not. It does touch the socket: not a pure check. */
export function probeListener(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const c = net.connect(path);
    c.once("connect", () => (c.destroy(), resolve(true)));
    c.once("error", () => resolve(false));
  });
}

export interface LineServerOptions {
  /** A connection that sends a line longer than this (no newline yet) is closed: an endless line is not a request. */
  maxLine: number;
  /** More connections at once than this are closed at once. */
  maxConn: number;
  /** A connection that is idle this long is closed. */
  timeoutMs: number;
  /** One request line → the answer line (without the newline). Requests of one connection are answered in order, even when one of them takes time. */
  onLine: (line: string) => string | Promise<string>;
}

/** The server, not yet listening. */
export function createLineServer(o: LineServerOptions): net.Server {
  let open = 0;
  return net.createServer((conn) => {
    if (open >= o.maxConn) return void conn.destroy();
    open++;
    conn.once("close", () => open--);
    conn.setTimeout(o.timeoutMs, () => conn.destroy());
    let buf = "";
    let chain: Promise<void> = Promise.resolve();
    conn.setEncoding("utf8");
    conn.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() !== "")
          chain = chain.then(async () => {
            const out = await o.onLine(line);
            if (!conn.destroyed) conn.write(`${out}\n`);
          });
      }
      if (buf.length > o.maxLine) conn.destroy();
    });
    conn.on("error", () => conn.destroy());
  });
}

/** Starts listening on `socket`; the socket is born with the umask's mode, and the caller sets its group and mode right after. */
export async function listenLines(socket: string, o: LineServerOptions): Promise<net.Server> {
  const server = createLineServer(o);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socket, resolve);
  });
  return server;
}
