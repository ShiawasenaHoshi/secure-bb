// Sentinel ("дозор", spec §9), observation mode only. Shared types.

/** A question for the solver (the shape follows the Jev API, see jev.ts; "noul" = probability of yes). */
export interface QuestionSpec {
  id: string;
  type: "noul" | "score";
  instructions: string;
  /** noul: what true / false mean. score: a list from lowest to highest. */
  criteria: { true: string; false: string } | string[];
}

export interface Answer {
  id: string;
  type: "noul" | "score";
  /** noul: probability of "yes" (0..1). */
  p?: number;
  /** score: 0..2. */
  score?: number;
  confidence?: number;
  probabilities?: Record<string, number>;
  /** The model declined to answer this question: it counts as "not scored". */
  refused?: boolean;
}

export type NotScoredReason = "timeout" | "error" | "limit" | "no_key" | "refused";

export type SolveResult =
  | { ok: true; answers: Record<string, Answer>; meta?: { model?: string; id?: string; cost?: number } }
  | { ok: false; reason: NotScoredReason; message: string };

export interface SolveRequest {
  state: unknown;
  questions: QuestionSpec[];
  signal: AbortSignal;
}

/** Questions -> probabilities. Jev is the first implementation; a local classifier can replace it later. */
export interface Solver {
  readonly name: string;
  solve(req: SolveRequest): Promise<SolveResult>;
}

/** Where the Jev call goes: TypeSafe's own API (default) or OpenRouter. The key must belong to that provider. */
export type JevProvider = "typesafe" | "openrouter";
export const JEV_PROVIDERS: readonly JevProvider[] = ["typesafe", "openrouter"];

export interface SentinelSettings {
  /** Provider of the Jev solver; changed only with a code. */
  provider: JevProvider;
  /** Off by default. */
  enabled: boolean;
  /** Also watch threads that have no open trust window. */
  allThreads: boolean;
  /** Per call to the solver. */
  timeoutMs: number;
  /** At most this many solver calls in a minute; the rest are recorded as "not scored: limit". */
  maxPerMinute: number;
  /** Per category id: a category "fires" at this probability or above. */
  thresholds: Record<string, number>;
  /** Score 0..2 at or above this is shown as high risk. */
  riskThreshold: number;
  /** Edited instructions by question id (the shipped text is used where absent). */
  instructions: Record<string, string>;
}

export interface FiredCategory {
  id: string;
  p: number;
}
export interface CategoryScore {
  id: string;
  p: number | null;
  fired: boolean;
}

export type Outcome = "pending" | "allow_once" | "allow_for_session" | "deny" | "interrupted" | "unknown";

export interface FeedRow {
  id: number;
  ts: number;
  threadId: string;
  interactionId: string;
  providerId: string;
  /** Plugin whose trust window covered the thread (null: watched because "all threads" is on). */
  windowPlugin: string | null;
  tool: string;
  /** Shortened, masked arguments. */
  args: string;
  /** Masked excerpt of the task (first human message), or null when none was found. */
  task: string | null;
  status: "evaluating" | "scored" | "not_scored";
  /** For not_scored: why, in words. */
  reason: string | null;
  reasonKind: NotScoredReason | null;
  categories: CategoryScore[];
  risk: { score: number | null; probabilities: Record<string, number> | null } | null;
  solver: string;
  outcome: Outcome;
  outcomeAt: number | null;
}
