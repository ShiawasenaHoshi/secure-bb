// Jev (TypeSafe AI): the first Solver, through TypeSafe's own API (default, answer shape checked with a live request
// on 2026-11-21) or through OpenRouter (documented, ALPHA: "the shape may change", not called live). See
// secure-bb-stage7-jev-api.md. Every shape-dependent line lives in `buildBody` and `parseAnswers` below.
//
// The key is read from the file named by BB_SECURE_BB_JEV_KEY_FILE at the moment of a call, goes into the
// Authorization header and nowhere else: it is not stored, not logged and not part of any error text.
import { readFileSync } from "node:fs";
import type { JevProvider, Answer, NotScoredReason, QuestionSpec, SolveRequest, SolveResult, Solver } from "./types.js";

export const JEV_KEY_FILE_ENV = "BB_SECURE_BB_JEV_KEY_FILE";
/** The two providers; the request body has the same shape, the address, the model name and the key differ. */
export const JEV_TARGETS: Record<JevProvider, { endpoint: string; model: string }> = {
  // Direct API, checked with a live request (2026-11-21): the default.
  typesafe: { endpoint: "https://api.typesafe.ai/v1/systemone", model: "jev-latest" },
  // OpenRouter "Decisions" (alpha); not called live.
  openrouter: { endpoint: "https://openrouter.ai/api/alpha/decisions", model: "typesafe/jev-1.13" },
};
export const JEV_ENDPOINT = JEV_TARGETS.openrouter.endpoint;
export const JEV_MODEL = JEV_TARGETS.openrouter.model;

export type JevFetch = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal },
) => Promise<{ status: number; ok: boolean; text(): Promise<string> }>;

export interface JevDeps {
  /** Path from the environment of the server, or null. */
  keyFile: string | null;
  fetch: JevFetch;
  readFile?: (path: string) => string;
  /** Read at every call (the setting can change). Default: typesafe. */
  provider?: () => JevProvider;
}

/** The request body. Questions are a map keyed by id (not a list). */
export function buildBody(model: string, state: unknown, questions: QuestionSpec[]): Record<string, unknown> {
  const map: Record<string, unknown> = {};
  for (const q of questions) map[q.id] = { type: q.type, instructions: q.instructions, criteria: q.criteria };
  return { model, state, questions: map };
}

const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const rec = (v: unknown): Record<string, unknown> | null => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

/** `answers.<id>.noul | score` (+ `probabilities`, `confidence`); `{type: "refusal"}` means the model declined. */
export function parseAnswers(json: unknown, questions: QuestionSpec[]): Record<string, Answer> | null {
  const answers = rec(rec(json)?.answers);
  if (!answers) return null;
  const out: Record<string, Answer> = {};
  for (const q of questions) {
    const a = rec(answers[q.id]);
    if (!a) {
      out[q.id] = { id: q.id, type: q.type, refused: true }; // not answered = not scored
      continue;
    }
    if (a.type === "refusal") {
      out[q.id] = { id: q.id, type: q.type, refused: true };
      continue;
    }
    const probs = rec(a.probabilities);
    const probabilities = probs ? Object.fromEntries(Object.entries(probs).flatMap(([k, v]) => (num(v) === undefined ? [] : [[k, num(v)!]]))) : undefined;
    const base = { id: q.id, type: q.type, confidence: num(a.confidence), probabilities };
    if (q.type === "noul") {
      const p = num(a.noul);
      out[q.id] = p === undefined ? { ...base, refused: true } : { ...base, p: Math.min(1, Math.max(0, p)) };
    } else {
      const score = num(a.score);
      out[q.id] = score === undefined ? { ...base, refused: true } : { ...base, score };
    }
  }
  return out;
}

function failure(reason: NotScoredReason, message: string): SolveResult {
  return { ok: false, reason, message };
}

export class JevSolver implements Solver {
  readonly name = "jev";
  constructor(private readonly d: JevDeps) {}

  private readKey(): string | null {
    if (!this.d.keyFile) return null;
    try {
      const key = (this.d.readFile ?? ((p: string) => readFileSync(p, "utf8")))(this.d.keyFile).trim();
      return key === "" ? null : key;
    } catch {
      return null;
    }
  }

  /** Is a key file set and readable (a yes/no for the page; the key does not leave this class). */
  keyConfigured(): boolean {
    return this.readKey() !== null;
  }

  async solve(req: SolveRequest): Promise<SolveResult> {
    const key = this.readKey();
    if (key === null) return failure("no_key", `ключ Jev не задан: нужен файл, путь к нему — в переменной ${JEV_KEY_FILE_ENV} сервера`);
    // Any text that comes back or is thrown goes through this: the key must not reach the log or the page.
    const clean = (s: string) => s.split(key).join("[ключ]").slice(0, 200);
    let res: Awaited<ReturnType<JevFetch>>;
    try {
      const target = JEV_TARGETS[this.d.provider?.() ?? "typesafe"];
      res = await this.d.fetch(target.endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body: JSON.stringify(buildBody(target.model, req.state, req.questions)),
        signal: req.signal,
      });
    } catch (err) {
      if (req.signal.aborted) return failure("timeout", "решатель не ответил вовремя");
      return failure("error", `запрос не удался: ${clean(err instanceof Error ? err.message : String(err))}`);
    }
    let text = "";
    try {
      text = await res.text();
    } catch (err) {
      if (req.signal.aborted) return failure("timeout", "решатель не ответил вовремя");
      return failure("error", `ответ не прочитан: ${clean(String(err))}`);
    }
    let json: unknown = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* handled below */
    }
    const error = rec(rec(json)?.error);
    if (!res.ok || error) {
      const code = num(error?.code) ?? res.status;
      const msg = clean(typeof error?.message === "string" ? error.message : `HTTP ${res.status}`);
      // 402 (no credits) and 429 (rate limit) are limits; everything else is an error. No retries here: the caller does not loop.
      if (code === 402 || code === 429) return failure("limit", `лимит решателя (${code}): ${msg}`);
      return failure("error", `ошибка решателя (${code}): ${msg}`);
    }
    const answers = parseAnswers(json, req.questions);
    if (!answers) return failure("error", "ответ решателя не похож на ожидаемый (alpha-формат мог измениться)");
    if (Object.values(answers).every((a) => a.refused)) return failure("refused", "решатель отказался отвечать");
    const j = rec(json);
    const usage = rec(j?.usage);
    return { ok: true, answers, meta: { model: typeof j?.model === "string" ? j.model : undefined, id: typeof j?.id === "string" ? j.id : undefined, cost: num(usage?.cost) } };
  }
}
