// The socket: line-delimited JSON, request → response, 5 s per request.
//
//   → {"op":"decide","pluginId":"x","version":"1.0.0","contentHash":"…","rootDir":"…","source":"…","sourceKind":"path","trigger":"install"}
//   ← {"ok":true,"action":"wait","reason":"held by secure-bb guard: review #3","requestId":3}
//   ← {"ok":false,"error":{"code":"invalid_code","message":"…"}}
//   → {"op":"challenge","action":{"op":"approve","requestId":3}}
//   ← {"ok":true,"challenge":"…","allowCredentials":[{"type":"public-key","id":"…"}],"description":"…","rpId":"localhost","origin":"http://localhost:38886","expiresAt":…}
//   → {"op":"approve","requestId":3,"passkey":{"credentialId":"…","clientDataJSON":"…","authenticatorData":"…","signature":"…"}}   (instead of "code")
//
// Access control is the socket's file mode (0660, the group that holds only the bb user), the way the design doc
// says. Node cannot read the peer's uid, so the guard does not try to tell callers apart: every op it serves is
// safe for any process of that user to send (a harmful plugin included), and the ones that need a human need a code.
import { chmodSync, existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import net from "node:net";
import { chownGroup, type ChownFn } from "./chown.ts";
import { Guard, GuardError } from "./guard.ts";

export const REQUEST_TIMEOUT_MS = 5000;
export const MAX_LINE_BYTES = 512 * 1024;
export const MAX_CONNECTIONS = 64;
export const PROTOCOL = 1;

/** Dispatches one parsed request. Never returns a secret: nothing the guard holds is shaped like one. */
export function dispatch(guard: Guard, req: unknown, version: string): Record<string, unknown> | Promise<Record<string, unknown>> {
  if (typeof req !== "object" || req === null || Array.isArray(req)) throw new GuardError("invalid", "a request is a JSON object");
  const r = req as Record<string, unknown>;
  switch (r.op) {
    case "ping":
      return { protocol: PROTOCOL, version, ts: Date.now() };
    // The only op that takes time: the guard reads the version's directory itself before it answers.
    case "decide":
      return guard.decideChecked(r).then((d) => (d.action === "proceed" ? { action: "proceed", via: d.via } : d.action === "reject" ? { action: "reject", message: d.message } : { action: "wait", reason: d.reason, requestId: d.requestId }));
    case "trust":
      return guard.trustState();
    case "trust-mode":
      return { mode: guard.setTrustMode(r.mode, { code: r.code, passkey: r.passkey, session: r.session }) };
    case "sources-add":
      return guard.addSources(r);
    case "sources-remove":
      return guard.removeSource(r);
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
    // «Вернуть и доверять источнику»: one touch, one operation, one journal record.
    case "approve-trust":
      return guard.approveAndTrust(r);
    // Approval sessions: opening takes a fresh touch; the token is in this one answer and nowhere else. Locking tightens: no touch.
    case "session-open":
      return guard.sessionOpen(r);
    case "session-close":
      return guard.sessionClose();
    // A list for one touch: fixed here first, then one touch names only its id and hash.
    case "batch-prepare":
      return guard.batchPrepare(r);
    case "batch-approve":
      return guard.batchApprove(r);
    case "open-window":
      return { window: guard.openWindow(r) };
    case "policy": {
      if (r.patch === undefined) return { policy: guard.policy() };
      if (typeof r.patch !== "object" || r.patch === null) throw new GuardError("invalid", "patch is an object");
      return { policy: guard.setPolicy(r.patch as Record<string, never>, { code: r.code, passkey: r.passkey, session: r.session }) };
    }
    // Passkeys: the page asks for a challenge bound to an action, and registers a key with the console's one-time token. Listing, confirming and
    // removing keys, and switching codes off, are console commands and have no op here.
    case "challenge":
      return guard.challenge(r);
    case "passkey-register":
      return guard.passkeyRegister(r);
    case "touch":
      return guard.touch(r);
    // Agent watch. `agents-state` and `agents-scan` carry no secret (a scan is rate-limited at the guard); `agents-accept` is a touch.
    case "agents-state":
      return guard.agentsState();
    case "agents-scan": {
      if (!guard.agentsEnabled()) return { enabled: false };
      const res = guard.agentsScan();
      return { ...res, ...guard.agentsState() };
    }
    case "agents-accept":
      return guard.agentsAccept(r);
    // «Вернуть как было»: a touch; the content is the guard's own baseline, the id is all the request carries.
    case "agents-restore":
      return guard.agentsRestore(r);
    // «Это не я — отклонить»: tightening, no code.
    case "agents-reject":
      return guard.agentsReject(r);
    case "journal-verify": {
      const v = guard.verifyJournal();
      return { valid: v.ok, entries: v.entries, head: v.head, problems: v.problems };
    }
    default:
      throw new GuardError("unknown_op", "unknown op");
  }
}

export async function answer(guard: Guard, line: string, version: string): Promise<string> {
  let id: unknown;
  try {
    const req = JSON.parse(line) as unknown;
    if (typeof req === "object" && req !== null && "id" in req) id = (req as { id: unknown }).id;
    const body = await dispatch(guard, req, version);
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
  /** Tests: stands in for chown. */
  chown?: ChownFn;
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
    // Requests of one connection are answered in order, even when one of them takes time.
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
            const out = await answer(o.guard, line, o.version);
            if (!conn.destroyed) conn.write(`${out}\n`);
          });
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
  try {
    if (o.socketGid !== null) chownGroup({ program: "sbb-guard" }, o.socket, o.socketGid, o.chown);
    chmodSync(o.socket, 0o660);
  } catch (err) {
    server.close();
    throw err;
  }
  return server;
}
