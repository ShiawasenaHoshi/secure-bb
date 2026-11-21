// The socket: line-delimited JSON, request → response, 5 s per request.
//
//   → {"op":"decide","pluginId":"x","version":"1.0.0","contentHash":"…","rootDir":"…","source":"…","sourceKind":"path","trigger":"install"}
//   ← {"ok":true,"action":"wait","reason":"held by secure-bb guard: review #3","requestId":3}
//   ← {"ok":false,"error":{"code":"invalid_code","message":"…"}}
//
// Access control is the socket's file mode (0660, the group that holds only the bb user), the way the design doc
// says. Node cannot read the peer's uid, so the guard does not try to tell callers apart: every op it serves is
// safe for any process of that user to send (a harmful plugin included), and the ones that need a human need a code.
import { chmodSync, chownSync, existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import net from "node:net";
import { Guard, GuardError } from "./guard.ts";

export const REQUEST_TIMEOUT_MS = 5000;
export const MAX_LINE_BYTES = 512 * 1024;
export const MAX_CONNECTIONS = 64;
export const PROTOCOL = 1;

/** Dispatches one parsed request. Never returns a secret: nothing the guard holds is shaped like one. */
export function dispatch(guard: Guard, req: unknown, version: string): Record<string, unknown> {
  if (typeof req !== "object" || req === null || Array.isArray(req)) throw new GuardError("invalid", "a request is a JSON object");
  const r = req as Record<string, unknown>;
  switch (r.op) {
    case "ping":
      return { protocol: PROTOCOL, version, ts: Date.now() };
    case "decide": {
      const d = guard.decide(r);
      return d.action === "proceed" ? { action: "proceed", via: d.via } : { action: "wait", reason: d.reason, requestId: d.requestId };
    }
    case "hold":
      return guard.hold(r);
    case "state":
      return guard.state();
    case "lookup":
      return guard.lookup(r);
    case "annotate":
      return guard.annotate(r);
    case "close-window":
      return guard.closeWindow(r);
    case "revoke":
      return guard.revoke(r);
    case "approve": {
      const { approval } = guard.approve(r);
      return { approval };
    }
    case "dismiss":
      return guard.dismiss(r);
    case "open-window":
      return { window: guard.openWindow(r) };
    case "policy": {
      if (r.patch === undefined) return { policy: guard.policy() };
      if (typeof r.patch !== "object" || r.patch === null) throw new GuardError("invalid", "patch is an object");
      return { policy: guard.setPolicy(r.patch as Record<string, never>, r.code) };
    }
    case "touch":
      return guard.touch(r);
    case "journal-verify": {
      const v = guard.verifyJournal();
      return { valid: v.ok, entries: v.entries, head: v.head, problems: v.problems };
    }
    default:
      throw new GuardError("unknown_op", "unknown op");
  }
}

export function answer(guard: Guard, line: string, version: string): string {
  let id: unknown;
  try {
    const req = JSON.parse(line) as unknown;
    if (typeof req === "object" && req !== null && "id" in req) id = (req as { id: unknown }).id;
    const body = dispatch(guard, req, version);
    return JSON.stringify({ ...(id !== undefined ? { id } : {}), ...body, ok: true });
  } catch (err) {
    if (err instanceof GuardError) return JSON.stringify({ ...(id !== undefined ? { id } : {}), ok: false, error: { code: err.code, message: err.message } });
    if (err instanceof SyntaxError) return JSON.stringify({ ok: false, error: { code: "invalid", message: "not JSON" } });
    // An internal failure says nothing about what failed: the guard fails closed, the caller holds.
    process.stderr.write(`sbb-guard: internal error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
    return JSON.stringify({ ...(id !== undefined ? { id } : {}), ok: false, error: { code: "internal", message: "internal error" } });
  }
}

export interface ServerOptions {
  guard: Guard;
  socket: string;
  socketGid: number | null;
  version: string;
  /** Per-request timeout; tests shorten it. */
  timeoutMs?: number;
}

/** Is something already listening there? A stale socket file (a crash) is not. */
function isLive(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const c = net.connect(path);
    c.once("connect", () => (c.destroy(), resolve(true)));
    c.once("error", () => resolve(false));
  });
}

export async function listen(o: ServerOptions): Promise<net.Server> {
  const dir = dirname(o.socket);
  const fresh = !existsSync(dir);
  mkdirSync(dir, { recursive: true, mode: 0o750 });
  // The socket's directory must be enterable by the socket's group (the umask of `serve` would make it 0700); one that already existed is the installer's.
  if (fresh) chmodSync(dir, 0o750);
  if (await isLive(o.socket)) throw new Error(`another guard is already listening on ${o.socket}`);
  try {
    unlinkSync(o.socket);
  } catch {
    /* there was none */
  }
  let open = 0;
  const server = net.createServer((conn) => {
    if (open >= MAX_CONNECTIONS) return void conn.destroy();
    open++;
    conn.once("close", () => open--);
    conn.setTimeout(o.timeoutMs ?? REQUEST_TIMEOUT_MS, () => conn.destroy());
    let buf = "";
    conn.setEncoding("utf8");
    conn.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() !== "") conn.write(`${answer(o.guard, line, o.version)}\n`);
      }
      if (buf.length > MAX_LINE_BYTES) conn.destroy(); // an endless line is not a request
    });
    conn.on("error", () => conn.destroy());
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(o.socket, resolve);
  });
  // Between listen and these two calls the socket has the default mode: nobody but the owner and the same user's group can write to it anyway.
  if (o.socketGid !== null) chownSync(o.socket, -1, o.socketGid);
  chmodSync(o.socket, 0o660);
  return server;
}
