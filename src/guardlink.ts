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
  /** What the guard itself read in this version (capability tokens): the page decides what the approval says about it. Absent in an older guard. */
  rights?: { tokens: string[]; review: string[] } | null;
  /** Why it was let in (the guard's own words). Absent in an older guard or an older approval. */
  why?: string | null;
}
/** Trust by source and rights (the guard's own): the mode, "my sources", the sources the owner named as the official catalog. */
export type TrustMode = "simple" | "detailed" | "strict";
export interface GuardTrust {
  mode: TrustMode;
  mySources: string[];
  known: string[];
  /** How many plugin directories the guard may read for sources from git (0: nothing from git passes by itself). */
  pluginsRoots: number;
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
  /** Why the version did not pass by itself, in the guard's words (it read the directory itself). Absent in a guard that predates the rule. */
  note?: string | null;
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
/** What a passkey touch sends back to the guard (all base64url, as the browser gives it). */
export interface PasskeyAssertion {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}
/** A touch: a TOTP code (a plain string), a passkey assertion, or — for a routine action only — the token of an approval session (the guard checks which). */
export type GuardProof = string | { passkey: PasskeyAssertion } | { session: string };
const proofFields = (p: GuardProof): Record<string, unknown> => (typeof p === "string" ? { code: p } : "passkey" in p ? { passkey: p.passkey } : { session: p.session });

/** An action the guard issues a challenge for (see the guard's design: the signature is good for this action only). */
export type GuardAction =
  | { op: "approve"; requestId: number; acknowledgeBlock?: boolean }
  | { op: "approve-trust"; requestId: number }
  | { op: "session-open"; hour?: true }
  | { op: "batch-approve"; batchId: string; setHash: string }
  | { op: "open-window"; pluginId: string; minutes?: number; scope?: "tree" | "thread" }
  | { op: "policy"; patch: Partial<GuardPolicy> }
  | { op: "touch"; purpose: string }
  | { op: "trust-mode"; mode: TrustMode }
  | { op: "sources-add"; entries: string[] }
  | { op: "agents-accept"; ids: number[] };
export interface GuardChallenge {
  challenge: string;
  allowCredentials: Array<{ type: "public-key"; id: string }>;
  /** The guard's own words about what is about to be approved (the page shows them next to the touch). */
  description: string;
  rpId: string;
  origin: string;
  expiresAt: number;
}

/** Agent watch (the guard's `agents-state`): differences between the files of the agents and the baseline a human accepted. The diff is masked at the guard. */
export interface AgentDrift {
  id: number;
  path: string;
  root: string;
  rootKind: "global" | "workspace" | "extra";
  /** The name of the working directory (for a thread's own directory, the thread's id). */
  rootName: string;
  rel: string;
  kind: string;
  change: "added" | "changed" | "removed";
  class: "critical" | "instructions" | "other";
  reasons: string[];
  findings: Array<{ rule: string; severity: "block" | "review" | "info"; file: string; line: number; excerpt: string }>;
  oldSha: string | null;
  newSha: string | null;
  size: number | null;
  mtime: number | null;
  diff: string;
  /** Found by the first scan: part of the first baseline, no consequences. */
  initial: boolean;
  status: "open" | "accepted" | "reverted" | "superseded";
  firstSeen: number;
  lastSeen: number;
  resolvedAt: number | null;
  /** «Это не я»: the person rejected it. It stays open (alarm and pollution stay) until the file is fixed. */
  rejected?: boolean;
  rejectedAt?: number | null;
}
export interface AgentsState {
  enabled: boolean;
  home?: string;
  extraRoots?: string[];
  lastScanAt?: number | null;
  scannedFiles?: number;
  roots?: number;
  baselineFiles?: number;
  initial?: { pending: number; baselineAt: number | null };
  openTotal?: number;
  drifts?: AgentDrift[];
  recent?: AgentDrift[];
  alarms?: Array<{ path: string; kind: "unreadable" | "outside" | "swapped"; error: string }>;
  notes?: Array<{ kind: string; text: string }>;
  /** Set on the answer to `agents-scan`: the scan was served at most once in 10 s. */
  scanned?: boolean;
  throttled?: boolean;
}

export interface GuardState {
  now: number;
  totp: { registered: boolean; disabled?: boolean; blockedUntil: number };
  /** Open approval sessions (no secret of theirs: only that they exist and until when). Absent in a guard that predates them. */
  sessions?: Array<{ id: number; openedAt: number; expiresAt: number; hardExpiresAt: number; uses: number }>;
  /** Troubleshooting mode: the guard passes everything until this time and writes every decision down. Null or absent: off. */
  troubleshoot?: { until: number } | null;
  /** Absent in a guard that predates passkeys. */
  passkeys?: { rpId: string; origin: string; keys: Array<{ id: number; label: string; createdAt: number; lastUsedAt: number | null; aaguid?: string }>; enrollmentOpen: boolean };
  policy: GuardPolicy;
  /** Absent in a guard that predates trust by source. */
  trust?: GuardTrust;
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
  /** Troubleshooting mode is on until this time (0: off). */
  troubleshootUntil: number;
  /** The person rejected this version and has not brought it back («Вернуть» in Quarantine). */
  rejected: boolean;
}
/** One item of a list the guard fixes for one touch. */
export interface GuardBatchItem {
  kind: "queue" | "skill" | "drift";
  id: number;
  label: string;
  fingerprint: string;
}
export interface GuardBatchPrepared {
  batchId: string;
  setHash: string;
  expiresAt: number;
  items: GuardBatchItem[];
  skipped: Array<{ kind: string; id: number; reason: string }>;
}
export interface GuardBatchResult {
  kind: "queue" | "skill" | "drift";
  id: number;
  label: string;
  ok: boolean;
  /** Not the guard's own: the touch was accepted and the plugin approves it. */
  local: boolean;
  note: string;
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
  /**
   * Asks what the core asks (the same op): the guard reads the version's directory itself and lets a version of an own source in when its
   * rights did not grow. The hook asks first because the core runs hooks BEFORE it asks the guard, and a hook that holds would keep that version out.
   */
  decide(ctx: GuardHoldRequest): Promise<{ action: "proceed" | "wait" | "reject" }>;
  /** Asks the guard to keep a version for a human; `stop`: even if a window is open (a window does not lift it). Tightening: no code. */
  hold(ctx: GuardHoldRequest, stop: boolean): Promise<void>;
  annotate(target: { requestId?: number; contentHash?: string }, findings: unknown): Promise<void>;
  approve(requestId: number, proof: GuardProof, opts?: { acknowledgeBlock?: boolean }): Promise<{ approval: GuardApproval }>;
  /** «Вернуть и доверять источнику»: approves the version and adds its source, one touch, one operation at the guard. */
  approveTrust(requestId: number, proof: GuardProof): Promise<{ approval: GuardApproval; entry: string; mySources: string[] }>;
  /** Approval sessions: opening takes a fresh touch (never a session); the token comes back once. Locking tightens: no touch. */
  sessionOpen(proof: GuardProof, hour?: boolean): Promise<{ token: string; idleMs: number; capMs: number }>;
  sessionClose(): Promise<void>;
  /** A list for one touch: fixed at the guard first, then one touch names only its id and hash. */
  batchPrepare(items: Array<{ kind: "queue" | "skill" | "drift"; id: number; fingerprint?: string; label?: string }>): Promise<GuardBatchPrepared>;
  batchApprove(batchId: string, setHash: string, proof: GuardProof): Promise<GuardBatchResult[]>;
  /** Tightening: no code. */
  dismiss(requestId: number): Promise<void>;
  openWindow(pluginId: string, minutes: number | undefined, proof: GuardProof, scope?: "tree" | "thread"): Promise<GuardWindow>;
  closeWindow(target: { windowId?: number; pluginId?: string }): Promise<void>;
  revoke(target: { approvalId?: number; pluginId?: string }): Promise<number>;
  policy(patch?: Partial<GuardPolicy>, proof?: GuardProof): Promise<GuardPolicy>;
  touch(purpose: string, proof: GuardProof): Promise<void>;
  /** The mode of trust by source: weakening it takes a touch (the guard checks), the same or a stricter one does not. */
  setTrustMode(mode: TrustMode, proof?: GuardProof): Promise<TrustMode>;
  /** "My sources": adding takes a touch (`migrated`: from the old list of trusted repositories); removing does not. */
  addSources(entries: string[], proof: GuardProof | undefined, migrated?: boolean): Promise<string[]>;
  removeSource(entry: string): Promise<string[]>;
  /** A challenge for one action; the touch that answers it goes with the command itself. */
  challenge(action: GuardAction): Promise<GuardChallenge>;
  /** Registering a key: `{token}` → creation options; `{token, clientDataJSON, attestationObject}` → the key waits for the console. */
  passkeyRegister(body: { token: string; clientDataJSON?: string; attestationObject?: string }): Promise<Record<string, any>>;
  verifyJournal(): Promise<GuardJournalReport>;
  /** Agent watch: no secret; `scan` asks for a fresh scan (the guard serves one at most every 10 s). */
  agentsState(): Promise<AgentsState>;
  agentsScan(): Promise<AgentsState>;
  /** A touch for exactly these differences. */
  agentsAccept(ids: number[], proof: GuardProof): Promise<{ accepted: number }>;
  /** «Это не я — отклонить»: no touch (tightening). */
  agentsReject(ids: number[]): Promise<{ rejected: number }>;
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
    return { approved: r.approved === true, approval: r.approval ?? null, window: r.window ?? null, requestId: r.requestId ?? null, troubleshootUntil: typeof r.troubleshootUntil === "number" ? r.troubleshootUntil : 0, rejected: r.rejected === true };
  }
  async decide(ctx: GuardHoldRequest): Promise<{ action: "proceed" | "wait" | "reject" }> {
    const r = await this.call({ op: "decide", ...ctx });
    return { action: r.action === "proceed" ? "proceed" : r.action === "reject" ? "reject" : "wait" };
  }
  async hold(ctx: GuardHoldRequest, stop: boolean): Promise<void> {
    await this.call({ op: "hold", ...ctx, stop });
  }
  async annotate(target: { requestId?: number; contentHash?: string }, findings: unknown): Promise<void> {
    await this.call({ op: "annotate", ...target, findings });
  }
  async approve(requestId: number, proof: GuardProof, opts: { acknowledgeBlock?: boolean } = {}): Promise<{ approval: GuardApproval }> {
    return (await this.call({ op: "approve", requestId, ...(opts.acknowledgeBlock === true ? { acknowledgeBlock: true } : {}), ...proofFields(proof) })) as unknown as { approval: GuardApproval };
  }
  async approveTrust(requestId: number, proof: GuardProof): Promise<{ approval: GuardApproval; entry: string; mySources: string[] }> {
    return (await this.call({ op: "approve-trust", requestId, ...proofFields(proof) })) as unknown as { approval: GuardApproval; entry: string; mySources: string[] };
  }
  async sessionOpen(proof: GuardProof, hour = false): Promise<{ token: string; idleMs: number; capMs: number }> {
    const r = await this.call({ op: "session-open", ...(hour ? { hour: true } : {}), ...proofFields(proof) });
    return { token: String(r.token), idleMs: Number(r.idleMs), capMs: Number(r.capMs) };
  }
  async sessionClose(): Promise<void> {
    await this.call({ op: "session-close" });
  }
  async batchPrepare(items: Array<{ kind: "queue" | "skill" | "drift"; id: number; fingerprint?: string; label?: string }>): Promise<GuardBatchPrepared> {
    const { ok: _ok, id: _id, ...rest } = await this.call({ op: "batch-prepare", items });
    return rest as unknown as GuardBatchPrepared;
  }
  async batchApprove(batchId: string, setHash: string, proof: GuardProof): Promise<GuardBatchResult[]> {
    return (await this.call({ op: "batch-approve", batchId, setHash, ...proofFields(proof) })).results as GuardBatchResult[];
  }
  async dismiss(requestId: number): Promise<void> {
    await this.call({ op: "dismiss", requestId });
  }
  async openWindow(pluginId: string, minutes: number | undefined, proof: GuardProof, scope?: "tree" | "thread"): Promise<GuardWindow> {
    const r = await this.call({ op: "open-window", pluginId, ...(minutes === undefined ? {} : { minutes }), ...(scope === undefined ? {} : { scope }), ...proofFields(proof) });
    return r.window as GuardWindow;
  }
  async closeWindow(target: { windowId?: number; pluginId?: string }): Promise<void> {
    await this.call({ op: "close-window", ...target });
  }
  async revoke(target: { approvalId?: number; pluginId?: string }): Promise<number> {
    return Number((await this.call({ op: "revoke", ...target })).revoked);
  }
  async policy(patch?: Partial<GuardPolicy>, proof?: GuardProof): Promise<GuardPolicy> {
    const r = await this.call({ op: "policy", ...(patch === undefined ? {} : { patch }), ...(proof === undefined ? {} : proofFields(proof)) });
    return r.policy as GuardPolicy;
  }
  async touch(purpose: string, proof: GuardProof): Promise<void> {
    await this.call({ op: "touch", purpose, ...proofFields(proof) });
  }
  async setTrustMode(mode: TrustMode, proof?: GuardProof): Promise<TrustMode> {
    return (await this.call({ op: "trust-mode", mode, ...(proof === undefined ? {} : proofFields(proof)) })).mode as TrustMode;
  }
  async addSources(entries: string[], proof: GuardProof | undefined, migrated = false): Promise<string[]> {
    return (await this.call({ op: "sources-add", entries, ...(migrated ? { migrated: true } : {}), ...(proof === undefined ? {} : proofFields(proof)) })).mySources as string[];
  }
  async removeSource(entry: string): Promise<string[]> {
    return (await this.call({ op: "sources-remove", entry })).mySources as string[];
  }
  async challenge(action: GuardAction): Promise<GuardChallenge> {
    const r = await this.call({ op: "challenge", action });
    return { challenge: r.challenge, allowCredentials: r.allowCredentials, description: r.description, rpId: r.rpId, origin: r.origin, expiresAt: r.expiresAt };
  }
  async passkeyRegister(body: { token: string; clientDataJSON?: string; attestationObject?: string }): Promise<Record<string, any>> {
    const { ok: _ok, id: _id, ...rest } = await this.call({ op: "passkey-register", ...body });
    return { ok: true, ...rest };
  }
  async agentsState(): Promise<AgentsState> {
    const { ok: _ok, id: _id, ...rest } = await this.call({ op: "agents-state" });
    return rest as unknown as AgentsState;
  }
  async agentsScan(): Promise<AgentsState> {
    const { ok: _ok, id: _id, ...rest } = await this.call({ op: "agents-scan" });
    return rest as unknown as AgentsState;
  }
  async agentsReject(ids: number[]): Promise<{ rejected: number }> {
    return { rejected: Number((await this.call({ op: "agents-reject", ids })).rejected) };
  }
  async agentsAccept(ids: number[], proof: GuardProof): Promise<{ accepted: number }> {
    return { accepted: Number((await this.call({ op: "agents-accept", ids, ...proofFields(proof) })).accepted) };
  }
  async verifyJournal(): Promise<GuardJournalReport> {
    return (await this.call({ op: "journal-verify" })) as unknown as GuardJournalReport;
  }
}

/** The socket named by the environment, or null: then this plugin keeps its own approvals, windows and secret as before. */
export const guardSocketFromEnv = (env: Record<string, string | undefined>): string | null => env.BB_SECURE_BB_GUARD_SOCKET?.trim() || null;
