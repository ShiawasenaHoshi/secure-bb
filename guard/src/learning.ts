// The journal for learning: what the person saw when a decision was made, how they decided, the mark they gave afterwards, and the file the owner exports.
// Pure functions over plain values, so that the export can be tested for what it must never contain. Everything that leaves the guard goes through
// the cleaners below: a field is copied only if it has a known shape (a whitelist), so a record that carries more, or something tampered with, leaks nothing.
// This module decides nothing about trust: no record here changes what is approved.
import { GuardError } from "./guard-types.ts";
import { identityOf } from "./trust.ts";

/** Marks the owner may give a decision afterwards (one click). The latest mark of a record counts. */
export const MARKS = ["false_alarm", "was_dangerous", "unknown"] as const;
export type Mark = (typeof MARKS)[number];

/** Journal kinds that are a decision about a version (or a window): the only ones an export has. */
export const DECISION_KINDS = ["approved.touch", "approved.trust", "approved.window", "approved.source", "approved.import", "dismissed", "revoked", "window.open"] as const;
export const isDecisionKind = (k: string): boolean => (DECISION_KINDS as readonly string[]).includes(k);

export const MAX_VIEW_FINDINGS = 40;
export const MAX_VIEW_MODELS = 8;
export const MAX_RIGHT_KEYS = 40;
export const MAX_REASON_CHARS = 200;
export const EXPORT_SCHEMA = 1;

export interface FindingRef {
  rule: string;
  file: string;
  line: number | null;
}
export interface ModelVerdict {
  model: string;
  status: string;
}
/** What the page reports it showed on the card (the guard cannot see the page; the guard's own facts are added beside this). */
export interface ViewReport {
  level: string | null;
  findings: FindingRef[];
  ai: ModelVerdict[];
  textsVersion: number | null;
}
/** What the person saw: the page's report plus the facts the guard read itself. */
export interface Seen extends ViewReport {
  /** Rights by key (`network`, `fs.write`…), not the full tokens. */
  rights: string[];
  /** Rules that needed a look (the guard's own reading). */
  reviewRules: string[];
  reasonKind: string | null;
  /** The guard's reading found a hard flag: true / false; null: the version was not read. */
  blocked: boolean | null;
}
/** How the person decided. Times are the guard's own clock. */
export interface How {
  /** From the first time the card was shown to the decision; null when the page never said it showed the card. */
  decideMs: number | null;
  detailsOpened: boolean;
  snoozedBefore: boolean;
}

const RULE = /^[A-Za-z0-9._:-]{1,64}$/;
// The kind of a right (`network`, `fs`, `child_process`, `flow`…): lowercase words only, so a value that merely looks like a token or a key does not pass.
const KEY = /^[a-z][a-z_]{1,24}$/;
const LEVEL = /^[a-z_-]{1,24}$/;
const MODEL = /^[\p{L}\p{N} ._()/:+-]{1,64}$/u;
const STATUSES = ["clean", "flag", "refusal", "invalid", "timeout", "error", "unavailable"];
// A path inside the plugin (never a line of code): printable, short.
// eslint-disable-next-line no-control-regex
const NO_CONTROL = /^[^\u0000-\u001f\u007f]{1,200}$/;

const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const asObj = (v: unknown): Record<string, unknown> => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {});

export function cleanFindings(v: unknown): FindingRef[] {
  const out: FindingRef[] = [];
  for (const raw of asList(v)) {
    const f = asObj(raw);
    if (typeof f.rule !== "string" || !RULE.test(f.rule)) continue;
    const file = typeof f.file === "string" && NO_CONTROL.test(f.file) ? f.file : "";
    const line = typeof f.line === "number" && Number.isInteger(f.line) && f.line > 0 && f.line < 10_000_000 ? f.line : null;
    out.push({ rule: f.rule, file, line });
    if (out.length >= MAX_VIEW_FINDINGS) break;
  }
  return out;
}

export function cleanModels(v: unknown): ModelVerdict[] {
  const out: ModelVerdict[] = [];
  for (const raw of asList(v)) {
    const m = asObj(raw);
    if (typeof m.model !== "string" || !MODEL.test(m.model) || typeof m.status !== "string" || !STATUSES.includes(m.status)) continue;
    out.push({ model: m.model, status: m.status });
    if (out.length >= MAX_VIEW_MODELS) break;
  }
  return out;
}

export function cleanViewReport(raw: unknown): ViewReport {
  const r = asObj(raw);
  const texts = r.textsVersion;
  return {
    level: typeof r.level === "string" && LEVEL.test(r.level) ? r.level : null,
    findings: cleanFindings(r.findings),
    ai: cleanModels(r.ai),
    textsVersion: typeof texts === "number" && Number.isInteger(texts) && texts >= 0 && texts < 1_000_000 ? texts : null,
  };
}

/** `network:evil.com` → `network`: the key says which right it is, not what it points at. */
export function rightKeys(tokens: string[]): string[] {
  const keys = new Set<string>();
  for (const t of tokens) {
    const k = t.split(":")[0]!;
    if (KEY.test(k)) keys.add(k);
  }
  return [...keys].sort().slice(0, MAX_RIGHT_KEYS);
}

export function cleanSeen(raw: unknown): Seen | null {
  const s = asObj(raw);
  if (Object.keys(s).length === 0) return null;
  const strs = (v: unknown, re: RegExp): string[] => asList(v).filter((x): x is string => typeof x === "string" && re.test(x)).slice(0, MAX_RIGHT_KEYS);
  return {
    ...cleanViewReport(s),
    rights: rightKeys(asList(s.rights).filter((x): x is string => typeof x === "string")),
    reviewRules: strs(s.reviewRules, RULE),
    reasonKind: typeof s.reasonKind === "string" && LEVEL.test(s.reasonKind) ? s.reasonKind : null,
    blocked: typeof s.blocked === "boolean" ? s.blocked : null,
  };
}

export function cleanHow(raw: unknown): How | null {
  const h = asObj(raw);
  if (Object.keys(h).length === 0) return null;
  const ms = h.decideMs;
  return { decideMs: typeof ms === "number" && Number.isFinite(ms) && ms >= 0 && ms < 1e11 ? Math.round(ms) : null, detailsOpened: h.detailsOpened === true, snoozedBefore: h.snoozedBefore === true };
}

/** One line, no control characters, at most MAX_REASON_CHARS; empty is null. */
export function cleanReason(v: unknown): string | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== "string") throw new GuardError("invalid", "reason is a string");
  // eslint-disable-next-line no-control-regex
  const one = v.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  if (one.length > MAX_REASON_CHARS) throw new GuardError("invalid", `reason is one line of at most ${MAX_REASON_CHARS} characters`);
  return one === "" ? null : one;
}

/** `30d`, `12h`, `90m` back from now, or a date `2026-11-01`: the time in ms the export starts at. */
export function parseSince(text: string, now: number): number {
  const rel = /^(\d{1,4})([dhm])$/.exec(text);
  if (rel) return now - Number(rel[1]) * { d: 86_400_000, h: 3_600_000, m: 60_000 }[rel[2] as "d" | "h" | "m"];
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) {
    const t = Date.parse(`${text}T00:00:00Z`);
    if (Number.isFinite(t)) return t;
  }
  throw new GuardError("invalid", "--since is a period like 30d, 12h, 90m, or a date like 2026-11-01");
}

export interface JournalRow {
  id: number;
  ts: number;
  kind: string;
  pluginId: string | null;
  detail: Record<string, unknown> | null;
}
export interface MarkRow {
  record: number;
  mark: Mark;
  reason: string | null;
  ts: number;
}

/** One line of the export. Nothing here is free text from a plugin or a person except the owner's own one-line reasons. */
export interface ExportRecord {
  schema: typeof EXPORT_SCHEMA;
  id: number;
  ts: number;
  decision: string;
  plugin: string | null;
  version: string | null;
  /** How it got through or was stopped: the journal kind's tail plus the factor (`code`, `passkey`, `session`), when there was one. */
  by: string | null;
  sourceKind: string | null;
  /** `github:owner/name` only; a path on the owner's disk is not exported. */
  source: string | null;
  seen: Seen | null;
  how: How | null;
  mark: { mark: Mark; reason: string | null; ts: number } | null;
  /** The owner's one-line reason given at revoking. */
  reason: string | null;
}

const SAFE_TEXT = /^[\p{L}\p{N} ._+@/-]{1,64}$/u;
const safe = (v: unknown): string | null => (typeof v === "string" && SAFE_TEXT.test(v) ? v : null);
const SOURCE_ID = /^github:[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;

export function exportRecord(row: JournalRow, mark: MarkRow | null): ExportRecord | null {
  if (!isDecisionKind(row.kind)) return null;
  const d = row.detail ?? {};
  const sourceKind = safe(d.sourceKind);
  const id = typeof d.source === "string" && sourceKind ? identityOf(sourceKind, d.source, typeof d.rootDir === "string" ? d.rootDir : "")?.id ?? null : null;
  let reason: string | null = null;
  try {
    reason = cleanReason(d.reason);
  } catch {
    reason = null;
  }
  return {
    schema: EXPORT_SCHEMA,
    id: row.id,
    ts: row.ts,
    decision: row.kind,
    plugin: safe(row.pluginId),
    version: safe(d.version),
    by: safe(d.via),
    sourceKind,
    source: id !== null && SOURCE_ID.test(id) ? id : null,
    seen: cleanSeen(d.seen),
    how: cleanHow(d.how),
    mark: mark ? { mark: mark.mark, reason: mark.reason, ts: mark.ts } : null,
    reason,
  };
}
