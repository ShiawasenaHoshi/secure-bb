// The guard's side of the restore helper's socket (the helper is restore.ts, a service of the agents' user). The guard is the only one allowed to talk to it
// (the socket's group has one member: the guard's user). What is sent is built here from the guard's own baseline, never from a request of the plugin.
import net from "node:net";

export interface RestoreSend {
  path: string;
  sha256: string;
  content?: string;
  delete?: true;
}
export type RestoreAnswer = { ok: true; result: "written" | "deleted" | "absent" } | { ok: false; code: string; message: string };

const TIMEOUT_MS = 5000;

/** Is something listening on the helper's socket? (Looked at before a touch is spent: a touch is not wasted on a helper that is not there.) */
export function helperUp(socket: string, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const c = net.connect(socket);
    const timer = setTimeout(() => (c.destroy(), resolve(false)), timeoutMs);
    c.once("connect", () => (clearTimeout(timer), c.destroy(), resolve(true)));
    c.once("error", () => (clearTimeout(timer), resolve(false)));
  });
}

/** One restore. A helper that cannot be reached or does not answer is an `unavailable` answer, not an exception. */
export function sendRestore(socket: string, req: RestoreSend, timeoutMs = TIMEOUT_MS): Promise<RestoreAnswer> {
  return new Promise((resolve) => {
    const c = net.connect(socket);
    let buf = "";
    let done = false;
    const finish = (a: RestoreAnswer): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      c.destroy();
      resolve(a);
    };
    const timer = setTimeout(() => finish({ ok: false, code: "unavailable", message: "the restore helper did not answer" }), timeoutMs);
    c.setEncoding("utf8");
    c.once("connect", () => c.write(`${JSON.stringify({ op: "restore", ...req })}\n`));
    c.on("data", (d: string) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const r = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; result?: string; error?: { code?: string; message?: string } };
        if (r.ok === true && (r.result === "written" || r.result === "deleted" || r.result === "absent")) finish({ ok: true, result: r.result });
        else finish({ ok: false, code: String(r.error?.code ?? "refused"), message: String(r.error?.message ?? "the helper refused") });
      } catch {
        finish({ ok: false, code: "unavailable", message: "the restore helper answered with something that is not JSON" });
      }
    });
    c.once("error", () => finish({ ok: false, code: "unavailable", message: "the restore helper cannot be reached" }));
    c.once("close", () => finish({ ok: false, code: "unavailable", message: "the restore helper closed the connection" }));
  });
}
