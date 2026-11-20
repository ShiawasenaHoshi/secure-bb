// The AI scan (spec §8): collects a plugin's code, asks the enabled models in parallel, and keeps what came back.
// Models only ever ADD suspicion: nothing here approves, installs or opens a window.
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hashTree } from "../tree.js";
import type { Store } from "../store.js";
import { claudeCommand, CLAUDE_BIN_ENV, CURSOR_BIN_ENV, cursorCommand, findExecutable, interpret, readToken, TOKEN_FILE_ENV, type ProcessRunner } from "./commands.js";
import { collectForScan, MAX_DATA_CHARS, type Collected } from "./collect.js";
import { buildPrompt } from "./prompt.js";
import type { AiSettings, ModelOutcome, ScanResult, ScanRow, ScanTrigger } from "./types.js";

export class ScanError extends Error {
  constructor(
    readonly code: "off" | "busy" | "limit" | "invalid",
    message: string,
  ) {
    super(message);
  }
}

export interface ScanTarget {
  pluginId: string;
  version: string;
  dir: string;
  contentHash: string | null;
  trigger: ScanTrigger;
}

export interface ScannerDeps {
  store: Store;
  now: () => number;
  run: ProcessRunner;
  /** The server's environment (token file path, binary overrides). Read, never copied wholesale into a child. */
  env: NodeJS.ProcessEnv;
  /** Where the empty working directories are made. */
  tmpRoot?: string;
  /** Code sent at most (characters). */
  maxChars?: number;
  timeoutMs?: number;
  log?: (message: string) => void;
  /** A scan finished (the page refreshes, held versions are rechecked). */
  onDone?: (row: ScanRow) => void;
}

/** At most this many scans at once: each one sends a plugin's code to a cloud model. */
const MAX_RUNNING = 3;
/** A scan spends the subscription: one scan of one version per 10 minutes, and 20 scans a day, whoever asks. */
export const SAME_VERSION_MS = 10 * 60_000;
export const DAY_MS = 24 * 3_600_000;
export const MAX_SCANS_PER_DAY = 20;

export interface Availability {
  /** Where Claude's login comes from. */
  claude: { mode: "token-file" | "user-login" | "unavailable"; detail: string };
  cursor: { found: boolean; detail: string } | null;
}

export class Scanner {
  private readonly running = new Map<string, { row: ScanRow; done: Promise<ScanRow> }>();

  constructor(private readonly d: ScannerDeps) {}

  /** Honest answer to "can a scan run at all": from the environment only, no model is asked. */
  availability(settings: AiSettings): Availability {
    const t = readToken(this.d.env);
    const bin = this.d.env[CLAUDE_BIN_ENV]?.trim() || "claude";
    const found = findExecutable(bin, this.d.env);
    let claude: Availability["claude"];
    if (!found) claude = { mode: "unavailable", detail: `программа ${bin} не найдена` };
    else if (!t.ok) claude = { mode: "unavailable", detail: t.reason };
    else if (t.token !== null) claude = { mode: "token-file", detail: `токен из файла (${TOKEN_FILE_ENV})` };
    else claude = { mode: "user-login", detail: "вход пользователя, от которого работает сервер (не проверялся: станет ясно при первом скане)" };
    const cbin = this.d.env[CURSOR_BIN_ENV]?.trim() || "cursor-agent";
    const cursor = settings.second ? (findExecutable(cbin, this.d.env) ? { found: true, detail: `${cbin}, модель ${settings.secondModel || "не задана"}` } : { found: false, detail: `программа ${cbin} не найдена` }) : null;
    return { claude, cursor };
  }

  /**
   * Starts a scan and returns at once with its row; `done` resolves with the finished row.
   * Callers asking for the same tree share one run. Automatic triggers reuse an earlier result for the same tree.
   */
  async start(t: ScanTarget): Promise<{ row: ScanRow; done: Promise<ScanRow> }> {
    const settings = this.d.store.aiSettings();
    if (!settings.enabled) throw new ScanError("off", "ИИ-скан выключен");
    const localHash = await hashTree(t.dir);
    const key = `${localHash}:${settings.second ? settings.secondModel : ""}`;
    const live = this.running.get(key);
    if (live) return { row: live.row, done: live.done };
    if (t.trigger === "freeze" || t.trigger === "external") {
      // An automatic scan of a tree that was already scanned says nothing new; just link the core's hash.
      const prior = this.d.store.latestScanFor({ localHash });
      if (prior && prior.status !== "running" && prior.status !== "unavailable") {
        if (t.contentHash) this.d.store.linkScan(prior.id, t.contentHash);
        const row = this.d.store.getScan(prior.id)!;
        return { row, done: Promise.resolve(row) };
      }
    }
    const now = this.d.now();
    const recent = this.d.store.recentScanOfTree(localHash, now - SAME_VERSION_MS);
    if (recent) {
      const wait = Math.ceil((recent.startedAt + SAME_VERSION_MS - now) / 60_000);
      throw new ScanError("limit", `эта версия уже сканировалась недавно (скан #${recent.id}); повторить можно через ${wait} мин`);
    }
    if (this.d.store.countScansSince(now - DAY_MS) >= MAX_SCANS_PER_DAY)
      throw new ScanError("limit", `достигнут суточный предел сканов (${MAX_SCANS_PER_DAY}); он бережёт подписку, попробуйте позже`);
    if (this.running.size >= MAX_RUNNING) throw new ScanError("busy", "уже идут другие сканы; повторите позже");
    const row = this.d.store.insertScan({ pluginId: t.pluginId, version: t.version, localHash, contentHash: t.contentHash, trigger: t.trigger });
    const done = this.execute(row, t.dir, settings).finally(() => this.running.delete(key));
    this.running.set(key, { row, done });
    return { row, done };
  }

  scan(t: ScanTarget): Promise<ScanRow> {
    return this.start(t).then((r) => r.done);
  }

  /** Resolves when no scan is running (tests, shutdown). */
  async idle(): Promise<void> {
    while (this.running.size > 0) await Promise.allSettled([...this.running.values()].map((r) => r.done));
  }

  private async execute(row: ScanRow, dir: string, settings: AiSettings): Promise<ScanRow> {
    let result: ScanResult;
    try {
      result = await this.runModels(dir, settings);
    } catch (err) {
      result = { status: "suspect", models: [], files: 0, chars: 0, incomplete: [], skipped: [], note: `скан не завершён: ${err instanceof Error ? err.message : String(err)}` };
    }
    this.d.store.finishScan(row.id, result);
    this.d.store.log("scan", row.pluginId, row.contentHash, {
      scan: row.id,
      version: row.version,
      trigger: row.trigger,
      status: result.status,
      models: result.models.map((m) => `${m.label}: ${m.status}`),
      incomplete: result.incomplete.length,
    });
    const done = this.d.store.getScan(row.id)!;
    try {
      this.d.onDone?.(done);
    } catch (err) {
      this.d.log?.(`scan callback failed: ${String(err)}`);
    }
    return done;
  }

  private async runModels(dir: string, settings: AiSettings): Promise<ScanResult> {
    const collected: Collected = await collectForScan(dir, this.d.maxChars ?? MAX_DATA_CHARS);
    const prompt = buildPrompt(collected);
    const plan: Array<{ model: "claude" | "cursor"; label: string }> = [{ model: "claude", label: "claude" }];
    if (settings.second) plan.push({ model: "cursor", label: `cursor-agent (${settings.secondModel || "?"})` });
    const outcomes = await Promise.all(plan.map((p) => this.askOne(p.model, p.label, prompt, settings)));

    const failures = outcomes.filter((o) => o.status === "flag" || o.status === "refusal" || o.status === "invalid" || o.status === "timeout" || o.status === "error");
    const answered = outcomes.filter((o) => o.status !== "unavailable");
    const status: ScanResult["status"] = failures.length > 0 || collected.incomplete.length > 0 ? "suspect" : answered.length === 0 ? "unavailable" : "clean";
    return {
      status,
      models: outcomes,
      files: collected.files.length,
      chars: collected.chars,
      incomplete: collected.incomplete,
      skipped: collected.skipped,
      note: status === "unavailable" ? "ни одна модель не отвечала: скан не выполнен" : null,
    };
  }

  private async askOne(model: "claude" | "cursor", label: string, prompt: string, settings: AiSettings): Promise<ModelOutcome> {
    const started = this.d.now();
    const root = await mkdtemp(join(this.d.tmpRoot ?? tmpdir(), "sbb-scan-"));
    try {
      // An empty working directory; the home directory (for Claude with a token) is a sibling, not inside it.
      const cwd = join(root, "work");
      const home = join(root, "home");
      await mkdir(cwd, { mode: 0o700 });
      await mkdir(home, { mode: 0o700 });
      const built =
        model === "claude"
          ? claudeCommand({ prompt, cwd, home, server: this.d.env, timeoutMs: this.d.timeoutMs })
          : cursorCommand({ prompt, cwd, model: settings.secondModel, server: this.d.env, timeoutMs: this.d.timeoutMs });
      if (!built.ok) return { model, label, status: "unavailable", detail: built.unavailable, report: null, ms: 0 };
      const raw = await this.d.run(built.spec);
      return interpret(model, label, raw, built.secret, this.d.now() - started);
    } catch (err) {
      return { model, label, status: "error", detail: `сбой запуска: ${err instanceof Error ? err.message : String(err)}`.slice(0, 240), report: null, ms: this.d.now() - started };
    } finally {
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

/** Reason to hold a version because of a scan, or null (no scan, clean, or the models were unavailable). */
export function flagReason(row: ScanRow | null): string | null {
  if (!row || row.status !== "suspect" || !row.result) return null;
  const first = row.result.models.find((m) => m.status !== "clean" && m.status !== "unavailable");
  const why = first ? `${first.label}: ${first.detail}` : (row.result.incomplete[0] ?? row.result.note ?? "подозрение");
  return `подозрение ИИ-скана #${row.id}: ${why}`.slice(0, 400);
}
