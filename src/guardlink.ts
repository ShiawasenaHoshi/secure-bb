// Guard mode: the link to the decision guard (`sbb-guard`, its own process and OS user; guard/ in this repository).
// Active only when the server's environment names its socket (`BB_SECURE_BB_GUARD_SOCKET`). Then approvals,
// trust windows and the TOTP secret live in the guard, not here: this plugin asks, shows, and may only ADD
// restrictions (hold / reject) to what the guard allows.
//
// Everything here is a line of JSON on a Unix socket; no answer carries a secret. A socket that cannot be
// reached is an error the callers treat as "hold" (fail closed), the same way the core treats it.
import net from "node:net";

export class GuardLinkError extends Error {
  /** The guard's error code, or `unavailable` when the guard could not be reached or answered nonsense. */
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export interface GuardApproval {
  id: number;
  contentHash: string;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  via: string;
  windowId: number | null;
  approvedAt: number;
  revokedAt: number | null;
}
export interface GuardQueueEntry {
  id: number;
  contentHash: string;
  pluginId: string;
  version: string;
  source: string;
  sourceKind: string;
  rootDir: string;
  trigger: string;
  status: "held" | "approved" | "dismissed";
  firstSeen: number;
  lastSeen: number;
  seenCount: number;
  /** Supplied by this plugin (the guard cannot check it): for display only. */
  annotation: { ts: number; findings: unknown; verified: false } | null;
}
export interface GuardWindow {
  id: number;
  pluginId: string;
  sizeSec: number;
  capSec: number;
  mode: "sliding" | "fixed";
  openedAt: number;
  expiresAt: number;
  hardExpiresAt: number;
  closedAt: number | null;
  closedReason: string | null;
  uses: number;
}
export interface GuardPolicy {
  windowMin: number;
  capMin: number;
  mode: "sliding" | "fixed";
}
export interface GuardState {
  now: number;
  totp: { registered: boolean; blockedUntil: number };
  policy: GuardPolicy;
  queue: GuardQueueEntry[];
  approvals: GuardApproval[];
  revoked: GuardApproval[];
  windows: Array<GuardWindow & { remainingSec: number }>;
  closedWindows: GuardWindow[];
  journal: { head: { id: number; hash: string } | null; recent: Array<{ id: number; ts: number; kind: string; pluginId: string | null; contentHash: string | null; detail: unknown }> };
}
export interface GuardLookup {
  approved: boolean;
  approval: { id: number; via: string; windowId: number | null } | null;
  window: { id: number; expiresAt: number; hardExpiresAt: number; mode: string; sizeSec: number } | null;
  requestId: number | null;
}
export interface GuardJournalReport {
  valid: boolean;
  entries: number;
  head: { id: number; hash: string } | null;
  problems: Array<{ kind: string; id: number | null; detail: string }>;
}

export interface GuardHoldRequest {
  pluginId: string;
  version: string;
  contentHash: string;
  rootDir: string;
  source: string;
  sourceKind: string;
  trigger: string;
}

/** What the gate and the server use. A test double implements it too. */
export interface GuardPort {
  state(): Promise<GuardState>;
  lookup(pluginId: string, contentHash: string): Promise<GuardLookup>;
  /** Asks the guard to keep a version for a human; `stop`: even if a window is open (a window does not lift it). Tightening: no code. */
  hold(ctx: GuardHoldRequest, stop: boolean): Promise<void>;
  annotate(target: { requestId?: number; contentHash?: string }, findings: unknown): Promise<void>;
  approve(requestId: number, code: string): Promise<{ approval: GuardApproval }>;
  /** Tightening: no code. */
  dismiss(requestId: number): Promise<void>;
  openWindow(pluginId: string, minutes: number | undefined, code: string): Promise<GuardWindow>;
  closeWindow(target: { windowId?: number; pluginId?: string }): Promise<void>;
  revoke(target: { approvalId?: number; pluginId?: string }): Promise<number>;
  policy(patch?: Partial<GuardPolicy>, code?: string): Promise<GuardPolicy>;
  touch(purpose: string, code: string): Promise<void>;
  verifyJournal(): Promise<GuardJournalReport>;
}

const TIMEOUT_MS = 5000;

export class GuardLink implements GuardPort {
  private readonly socket: string;
  private readonly timeoutMs: number;
  constructor(socket: string, timeoutMs = TIMEOUT_MS) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
  }

  call(req: Record<string, unknown>): Promise<Record<string, any>> {
    return new Promise((resolve, reject) => {
      const c = net.connect(this.socket);
      let buf = "";
      let settled = false;
      const done = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        c.destroy();
        fn();
      };
      const timer = setTimeout(() => done(() => reject(new GuardLinkError("unavailable", "the guard did not answer in time"))), this.timeoutMs);
      c.setEncoding("utf8");
      c.once("connect", () => c.write(`${JSON.stringify(req)}\n`));
      c.on("data", (d: string) => {
        buf += d;
        const nl = buf.indexOf("\n");
        if (nl < 0) return;
        done(() => {
          let res: Record<string, any>;
          try {
            res = JSON.parse(buf.slice(0, nl)) as Record<string, any>;
          } catch {
            return reject(new GuardLinkError("unavailable", "the guard answered something that is not JSON"));
          }
          if (res.ok === true) return resolve(res);
          const e = (res.error ?? {}) as { code?: string; message?: string };
          reject(new GuardLinkError(typeof e.code === "string" ? e.code : "unavailable", typeof e.message === "string" ? e.message : "the guard refused"));
        });
      });
      c.once("error", (err) => done(() => reject(new GuardLinkError("unavailable", `the guard cannot be reached: ${err.message}`))));
      c.once("close", () => done(() => reject(new GuardLinkError("unavailable", "the guard closed the connection"))));
    });
  }

  async state(): Promise<GuardState> {
    return (await this.call({ op: "state" })) as unknown as GuardState;
  }
  async lookup(pluginId: string, contentHash: string): Promise<GuardLookup> {
    const r = await this.call({ op: "lookup", pluginId, contentHash });
    return { approved: r.approved === true, approval: r.approval ?? null, window: r.window ?? null, requestId: r.requestId ?? null };
  }
  async hold(ctx: GuardHoldRequest, stop: boolean): Promise<void> {
    await this.call({ op: "hold", ...ctx, stop });
  }
  async annotate(target: { requestId?: number; contentHash?: string }, findings: unknown): Promise<void> {
    await this.call({ op: "annotate", ...target, findings });
  }
  async approve(requestId: number, code: string): Promise<{ approval: GuardApproval }> {
    return (await this.call({ op: "approve", requestId, code })) as unknown as { approval: GuardApproval };
  }
  async dismiss(requestId: number): Promise<void> {
    await this.call({ op: "dismiss", requestId });
  }
  async openWindow(pluginId: string, minutes: number | undefined, code: string): Promise<GuardWindow> {
    const r = await this.call({ op: "open-window", pluginId, ...(minutes === undefined ? {} : { minutes }), code });
    return r.window as GuardWindow;
  }
  async closeWindow(target: { windowId?: number; pluginId?: string }): Promise<void> {
    await this.call({ op: "close-window", ...target });
  }
  async revoke(target: { approvalId?: number; pluginId?: string }): Promise<number> {
    return Number((await this.call({ op: "revoke", ...target })).revoked);
  }
  async policy(patch?: Partial<GuardPolicy>, code?: string): Promise<GuardPolicy> {
    const r = await this.call({ op: "policy", ...(patch === undefined ? {} : { patch }), ...(code === undefined ? {} : { code }) });
    return r.policy as GuardPolicy;
  }
  async touch(purpose: string, code: string): Promise<void> {
    await this.call({ op: "touch", purpose, code });
  }
  async verifyJournal(): Promise<GuardJournalReport> {
    return (await this.call({ op: "journal-verify" })) as unknown as GuardJournalReport;
  }
}

/** The socket named by the environment, or null: then this plugin keeps its own approvals, windows and secret as before. */
export const guardSocketFromEnv = (env: Record<string, string | undefined>): string | null => env.BB_SECURE_BB_GUARD_SOCKET?.trim() || null;
