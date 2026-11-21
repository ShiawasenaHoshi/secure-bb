// Sentinel ("дозор", spec §9, stage 7) — OBSERVATION ONLY.
//
// For every approval card in a watched thread it asks the solver the ten category questions plus the risk score
// and writes the answer to the feed. It never answers a card: until API tokens (stage 5) an agent can answer cards
// itself, so a decision here would be decoration. Any failure — timeout, error, limit, no key — is a feed record
// "не оценено", never an exception to the caller.
import { effectiveQuestions, CATEGORY_IDS, RISK_ID, shippedInstructions } from "./questions.js";
import { actionText, buildState, describeAction } from "./state.js";
import { maskAndCut } from "./mask.js";
import { normalizeSettings, type SentinelStore } from "./store.js";
import type { JevProvider, CategoryScore, FeedRow, NotScoredReason, Outcome, SentinelSettings, SolveResult, Solver } from "./types.js";

export class SentinelError extends Error {
  constructor(
    readonly code: "invalid" | "invalid_code" | "conflict",
    message: string,
  ) {
    super(message);
  }
}

/** bb's side, injected so tests need no host. */
export interface SentinelSource {
  /** The first message a human sent in this thread or above it, or null. */
  task(threadId: string): Promise<string | null>;
  /** The command or tool call the thread is running right now (masked, cut), or null. */
  pending(threadId: string): Promise<string | null>;
  /** Current state of a card: what the human did with it. null = the card is gone. */
  card(threadId: string, interactionId: string): Promise<{ status: string; decision: string | null } | null>;
}

export interface SentinelDeps {
  store: SentinelStore;
  now: () => number;
  solver: Solver;
  source: SentinelSource;
  /** The plugin whose open trust window covers this thread (the thread or its tree), or null. */
  windowCovering: (threadId: string) => Promise<string | null>;
  /** Checks a TOTP code for a change of settings (throws when wrong). */
  touch: (purpose: string, code: string) => void;
  log: (m: string) => void;
  /** Whether a key for the solver is configured (a boolean for the page; the key itself never comes here). */
  keyConfigured?: () => boolean;
  onChange?: () => void;
}

const MINUTE = 60_000;
const TASK_CACHE_MAX = 200;

export interface SettingsPatch {
  provider?: JevProvider;
  enabled?: boolean;
  allThreads?: boolean;
  timeoutMs?: number;
  maxPerMinute?: number;
  riskThreshold?: number;
  threshold?: { id: string; value: number };
  instruction?: { id: string; text: string | null };
}

export class Sentinel {
  private readonly calls: number[] = [];
  private readonly inflight = new Set<Promise<void>>();
  private readonly tasks = new Map<string, string | null>();

  constructor(private readonly d: SentinelDeps) {}

  settings(): SentinelSettings {
    return this.d.store.settings();
  }

  /** The `interaction.pending` event. Never throws; the evaluation runs in the background (see `settled`). */
  async handle(payload: { thread?: { id?: string } | null; interaction?: unknown }): Promise<void> {
    try {
      const s = this.settings();
      if (!s.enabled) return;
      const action = describeAction(payload.interaction);
      if (!action) return; // not an approval card (a question to the human, a plugin dialog)
      const i = payload.interaction as { id: string; threadId?: string; status?: string };
      const threadId = i.threadId ?? payload.thread?.id;
      if (typeof i.id !== "string" || typeof threadId !== "string") return;
      if (i.status !== undefined && i.status !== "pending") return;
      let windowPlugin: string | null = null;
      if (!s.allThreads) {
        windowPlugin = await this.d.windowCovering(threadId);
        if (windowPlugin === null) return;
      }
      if (action.kind === "permission_grant") {
        try {
          action.pending = await this.d.source.pending(threadId);
        } catch (err) {
          this.d.log(`sentinel: pending action of thread ${threadId} not read: ${String(err)}`);
        }
      }
      const row = this.d.store.insert({ threadId, interactionId: i.id, providerId: action.provider, windowPlugin, tool: action.tool, args: actionText(action), task: null, solver: this.d.solver.name });
      if (!row) return;
      this.d.onChange?.();
      const job = this.evaluate(row, action, s).catch((err) => this.d.log(`sentinel: evaluation of ${row.id} failed: ${String(err)}`));
      const tracked = job.finally(() => this.inflight.delete(tracked));
      this.inflight.add(tracked);
    } catch (err) {
      this.d.log(`sentinel: card not recorded: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /** Resolves when every evaluation started so far is finished (tests, shutdown). */
  async settled(): Promise<void> {
    while (this.inflight.size > 0) await Promise.all([...this.inflight]);
  }

  private async task(threadId: string): Promise<string | null> {
    if (this.tasks.has(threadId)) return this.tasks.get(threadId) ?? null;
    let task: string | null = null;
    try {
      task = await this.d.source.task(threadId);
    } catch (err) {
      this.d.log(`sentinel: task of thread ${threadId} not read: ${String(err)}`);
    }
    if (task !== null) {
      if (this.tasks.size >= TASK_CACHE_MAX) this.tasks.delete(this.tasks.keys().next().value as string);
      this.tasks.set(threadId, task); // only found tasks are remembered; a missing one is looked up again
    }
    return task;
  }

  private limited(s: SentinelSettings): boolean {
    const t = this.d.now();
    while (this.calls.length > 0 && t - this.calls[0]! >= MINUTE) this.calls.shift();
    if (this.calls.length >= s.maxPerMinute) return true;
    this.calls.push(t);
    return false;
  }

  private notScored(row: FeedRow, kind: NotScoredReason, reason: string): void {
    this.d.store.setNotScored(row.id, kind, reason);
    this.d.onChange?.();
  }

  private async evaluate(row: FeedRow, action: NonNullable<ReturnType<typeof describeAction>>, s: SentinelSettings): Promise<void> {
    const task = await this.task(row.threadId);
    const state = buildState(task, action);
    this.d.store.setTask(row.id, task === null ? null : maskAndCut(task, 300));
    if (this.limited(s)) return this.notScored(row, "limit", `лимит: не больше ${s.maxPerMinute} запросов в минуту`);

    const questions = effectiveQuestions(s);
    const ctl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<SolveResult>((resolve) => {
      timer = setTimeout(() => {
        ctl.abort();
        resolve({ ok: false, reason: "timeout", message: `решатель не ответил за ${Math.round(s.timeoutMs / 1000)} с` });
      }, s.timeoutMs);
    });
    let result: SolveResult;
    try {
      result = await Promise.race([this.d.solver.solve({ state, questions, signal: ctl.signal }), deadline]);
    } catch (err) {
      result = { ok: false, reason: ctl.signal.aborted ? "timeout" : "error", message: `решатель упал: ${err instanceof Error ? err.message.slice(0, 200) : "ошибка"}` };
    } finally {
      clearTimeout(timer);
    }
    if (!result.ok) return this.notScored(row, result.reason, result.message);

    const categories: CategoryScore[] = CATEGORY_IDS.map((id) => {
      const a = result.answers[id];
      const p = a && !a.refused && typeof a.p === "number" ? a.p : null;
      return { id, p, fired: p !== null && p >= (s.thresholds[id] ?? 0.5) };
    });
    const r = result.answers[RISK_ID];
    const risk = r && !r.refused && typeof r.score === "number" ? { score: r.score, probabilities: r.probabilities ?? null } : { score: null, probabilities: null };
    this.d.store.setScored(row.id, categories, risk);
    this.d.onChange?.();
  }

  // ---- what the human did with the card -------------------------------------------------------------
  /** Reads the state of cards that had no outcome yet (all of them, or one thread's). */
  async refreshOutcomes(threadId?: string): Promise<number> {
    let changed = 0;
    for (const row of this.d.store.openOutcomes(threadId)) {
      let outcome: Outcome = "pending";
      try {
        const card = await this.d.source.card(row.threadId, row.interactionId);
        if (card === null) outcome = "unknown";
        else if (card.status === "interrupted") outcome = "interrupted";
        else if (card.status === "resolved") outcome = card.decision === "allow_once" || card.decision === "allow_for_session" || card.decision === "deny" ? card.decision : "unknown";
      } catch {
        continue; // try again at the next tick
      }
      if (outcome !== "pending") {
        this.d.store.setOutcome(row.id, outcome);
        changed++;
      }
    }
    if (changed > 0) this.d.onChange?.();
    return changed;
  }

  // ---- settings: every change needs a code (spec §9: policy is changed only by touch) --------------
  setSettings(patch: SettingsPatch, code: string | undefined): SentinelSettings {
    if (code === undefined) throw new SentinelError("invalid_code", "изменение настроек дозора требует кода");
    const cur = this.settings();
    const next: SentinelSettings = { ...cur, thresholds: { ...cur.thresholds }, instructions: { ...cur.instructions } };
    if (patch.provider !== undefined) next.provider = patch.provider;
    if (patch.enabled !== undefined) next.enabled = patch.enabled;
    if (patch.allThreads !== undefined) next.allThreads = patch.allThreads;
    if (patch.timeoutMs !== undefined) next.timeoutMs = patch.timeoutMs;
    if (patch.maxPerMinute !== undefined) next.maxPerMinute = patch.maxPerMinute;
    if (patch.riskThreshold !== undefined) next.riskThreshold = patch.riskThreshold;
    if (patch.threshold) {
      if (!CATEGORY_IDS.includes(patch.threshold.id)) throw new SentinelError("invalid", `нет категории ${patch.threshold.id}`);
      next.thresholds[patch.threshold.id] = patch.threshold.value;
    }
    if (patch.instruction) {
      const { id, text } = patch.instruction;
      if (shippedInstructions(id) === null) throw new SentinelError("invalid", `нет вопроса ${id}`);
      if (text === null || text.trim() === "") delete next.instructions[id];
      else next.instructions[id] = text.trim().slice(0, 2000);
    }
    const normalized = normalizeSettings(next);
    this.d.touch("sentinel.settings", code);
    this.d.store.setSettings(normalized);
    this.d.onChange?.();
    return normalized;
  }

  recent(limit: number): FeedRow[] {
    return this.d.store.list(limit);
  }

  keyConfigured(): boolean {
    return this.d.keyConfigured?.() ?? false;
  }
}
