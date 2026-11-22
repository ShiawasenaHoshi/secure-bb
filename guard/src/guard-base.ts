// The guard's plumbing: the database handle, the clock, the journal (`log`, `tx`), the policy and trust-mode reads, and the state every other layer shares.
// The Guard class is built as a chain of layers (base → agents-plan → actions → factor → windows → queue → decide → agents-watch → agents-apply → guard.ts), one file each;
// a layer calls only the layers below it, so the imports run one way. The public API is the one `Guard` always had.
import { dirname } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { DEFAULT_ORIGIN, DEFAULT_RP_ID, type RelyingParty } from "./config.ts";
import { append, HeadFile, readHead, verify, type JournalHead, type JournalReport } from "./journal.ts";
import { memoryManifestCache, runChecks as runChecksPlain, runChecksVerified, type CheckResult, type RegistryFetch } from "./checks/index.ts";
import { type TreeLimits } from "./tree-read.ts";
import { DEFAULT_TRUST_MODE, MAX_SOURCES, normalizeEntry, TRUST_MODES, type TrustMode } from "./trust.ts";
import { GuardError, type Policy, DEFAULT_POLICY, type QueueRow, type Raw, queueOf, type GuardOptions, type TrustConfig, DEFAULT_BUDGET_MS, type AgentsConfig } from "./guard-types.ts";

/** What the guard's own checks may spend on comparing node_modules with the registry; the budget of one evaluation is {@link DEFAULT_BUDGET_MS}. */
export const INTEGRITY_DEADLINE_MS = 2500;

export const manifestCache = memoryManifestCache();

export const runChecksOffline = (dir: string, o: { pluginId?: string } = {}): Promise<CheckResult> => runChecksPlain(dir, o.pluginId ? { pluginId: o.pluginId } : {});

export const runChecks = (dir: string, o: { pluginId?: string } = {}): Promise<CheckResult> => runChecksVerified(dir, { fetch: globalThis.fetch as unknown as RegistryFetch, cache: manifestCache, deadlineMs: INTEGRITY_DEADLINE_MS }, o.pluginId);

export class GuardBase {
  protected readonly trustCfg: Required<Pick<TrustConfig, "pluginsRoots" | "budgetMs">> & { treeLimits?: TreeLimits } & { known: string[]; checks: (dir: string, opts?: { pluginId?: string }) => Promise<CheckResult> };
  protected evalsRunning = 0;
  protected evalTimes: number[] = [];
  protected readonly db: DatabaseSync;
  protected readonly now: () => number;
  protected readonly secretPath: string;
  protected readonly head: HeadFile;
  protected readonly rp: RelyingParty;
  protected readonly agents: AgentsConfig | null;
  protected lastAgentsScan = 0;
  protected troubleshootPasses: number[] = [];
  protected passkeyFails = 0;
  protected passkeyFailLoggedAt = -Infinity;
  protected readonly secretDir: string;
  protected readonly headDir: string;
  constructor(o: GuardOptions) {
    this.agents = o.agents ?? null;
    const known: string[] = [];
    for (const k of o.trust?.knownSources ?? []) {
      const n = normalizeEntry(k);
      if (n === null) throw new Error(`known source ${JSON.stringify(k)} is not github:owner/name, github:owner/* or path:/dir`);
      known.push(n);
    }
    this.trustCfg = { pluginsRoots: o.trust?.pluginsRoots ?? [], budgetMs: o.trust?.budgetMs ?? DEFAULT_BUDGET_MS, ...(o.trust?.treeLimits ? { treeLimits: o.trust.treeLimits } : {}), known, checks: o.trust?.checks ?? (o.trust?.offline ? runChecksOffline : runChecks) };
    this.secretDir = dirname(o.secretPath);
    this.headDir = dirname(o.headPath);
    this.rp = o.rp ?? { rpId: DEFAULT_RP_ID, origin: DEFAULT_ORIGIN };
    this.db = o.db;
    this.now = o.now;
    this.secretPath = o.secretPath;
    this.head = new HeadFile(o.headPath);
  }
  // ---- plumbing -----------------------------------------------------------
  /** One transaction; the journal head file follows the commit. A throw rolls everything back. */
  protected tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    let out: T;
    try {
      out = fn();
      this.db.exec("COMMIT");
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* nothing open */
      }
      throw err;
    }
    this.flushHead();
    return out;
  }
  protected flushHead(): void {
    const h = readHead(this.db);
    const on = this.head.read();
    if (h && (!on || on.id !== h.id || on.hash !== h.hash)) this.head.write(h);
  }
  protected log(kind: string, pluginId: string | null, contentHash: string | null, detail: Record<string, unknown> | null): JournalHead {
    return append(this.db, this.now(), kind, pluginId, contentHash, detail);
  }
  protected meta(key: string): string | null {
    const r = this.db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as { value: string } | undefined;
    return r ? r.value : null;
  }
  protected setMeta(key: string, value: string): void {
    this.db.prepare(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(key, value);
  }
  /** Writes a record outside any request (start, stop, console commands). */
  record(kind: string, pluginId: string | null, contentHash: string | null, detail: Record<string, unknown> | null): void {
    this.tx(() => this.log(kind, pluginId, contentHash, detail));
  }
  // ---- policy -------------------------------------------------------------
  policy(): Policy {
    const raw = this.meta("policy");
    if (raw === null) return { ...DEFAULT_POLICY };
    try {
      const p = JSON.parse(raw) as Partial<Policy>;
      return { windowMin: p.windowMin ?? DEFAULT_POLICY.windowMin, capMin: p.capMin ?? DEFAULT_POLICY.capMin, mode: p.mode === "fixed" ? "fixed" : "sliding" };
    } catch {
      return { ...DEFAULT_POLICY };
    }
  }
  // ---- trust by source and rights -------------------------------------------------------------------------------
  trustMode(): TrustMode {
    const m = this.meta("trust_mode");
    return TRUST_MODES.includes(m as TrustMode) ? (m as TrustMode) : DEFAULT_TRUST_MODE;
  }
  mySources(): string[] {
    try {
      const j = JSON.parse(this.meta("my_sources") ?? "[]") as unknown;
      return Array.isArray(j) ? j.filter((x): x is string => typeof x === "string" && normalizeEntry(x) === x) : [];
    } catch {
      return [];
    }
  }
  trustState(): { mode: TrustMode; mySources: string[]; known: string[]; pluginsRoots: number } {
    return { mode: this.trustMode(), mySources: this.mySources(), known: [...this.trustCfg.known], pluginsRoots: this.trustCfg.pluginsRoots.length };
  }
  /** Does this version pass by itself? If not, the note says why in plain words. The rule is all of: source own or known · mode lets it · an approved version from the same source · rights did not grow · no hard flag. */
  /** A critical difference that is not part of the first baseline is open (the same fact the page's red bar and the hold of the agents use). */
  protected criticalAgentsOpen(): boolean {
    if (this.agents === null) return false;
    return this.db.prepare(`SELECT 1 FROM agent_drifts WHERE status = 'open' AND class = 'critical' AND initial = 0 LIMIT 1`).get() !== undefined;
  }
  // ---- views ----------------------------------------------------------------------------------------------
  verifyJournal(): JournalReport {
    return verify(this.db, this.head);
  }

  /** Everything the page shows. No secret, no code, no hash of one. */
  // ---- agent watch: configurations and memory of the agents (design: secure-bb-agent-watch-design.md) ----------------------------
  // The guard reads the agents' files (read-only ACL for its user, granted by the installer) and compares them with the baseline a human
  // accepted. v1 consequences are signals, not blocks: the feed, the windows closed, and (by the plugin) the thread marked polluted.
  // Without a touch nothing here changes the baseline: `agents-accept` is a touch, `agents-scan` and `agents-state` carry no secret.
  /** A held entry, or (when `orRejected`) one the person rejected: «Вернуть» approves it with a touch. */
  protected heldRequest(id: number, orRejected = false): QueueRow {
    const row = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(id) as Raw | undefined;
    if (!row) throw new GuardError("not_found", `no request #${id}`);
    const q = queueOf(row);
    if (q.status !== "held" && !(orRejected && q.status === "dismissed")) throw new GuardError("conflict", `request #${id} is already ${q.status}`);
    return q;
  }
  protected entriesOf(v: unknown): string[] {
    if (!Array.isArray(v) || v.length === 0 || v.length > MAX_SOURCES) throw new GuardError("invalid", `entries is a list of 1..${MAX_SOURCES} sources`);
    const out = new Set<string>();
    for (const x of v) {
      const n = normalizeEntry(x);
      if (n === null) throw new GuardError("invalid", `${JSON.stringify(typeof x === "string" ? x.slice(0, 80) : x)} is not github:owner/name, github:owner/* or path:/dir`);
      out.add(n);
    }
    return [...out].sort();
  }
}
