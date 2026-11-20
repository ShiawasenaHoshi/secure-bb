// Pure helpers for the §5.3 decision table: what the checks say, and what is new.
import type { CheckResult, Finding } from "./checks/types.js";

/** Check-result key of a snapshot checked at propose time, before the core has hashed it. */
export const localCheckKey = (localHash: string): string => `local:${localHash}`;

/** Prefix of a queue entry's reason when the checks blocked the version. */
export const BLOCKED_REASON = "заблокировано проверками";

/**
 * Capability tokens of a check result: `kind` and `kind:detail` for every detail
 * (hosts, env names, modules, routes). A version is "new" if it has a token the window lacks.
 */
export function capabilityTokens(r: CheckResult): string[] {
  const out = new Set<string>();
  for (const c of r.capabilities) {
    out.add(c.kind);
    for (const d of c.detail) out.add(`${c.kind}:${d}`);
  }
  return [...out].sort();
}

export const newTokens = (r: CheckResult, known: readonly string[]): string[] => {
  const have = new Set(known);
  return capabilityTokens(r).filter((t) => !have.has(t));
};

export const bySeverity = (r: CheckResult, severity: Finding["severity"]): Finding[] => r.findings.filter((f) => f.severity === severity);

/** `rule file:line` of the first few findings, for messages. */
export function summarize(findings: Finding[], max = 4): string {
  const shown = findings.slice(0, max).map((f) => `${f.rule} ${f.file}${f.line ? `:${f.line}` : ""}`);
  return shown.join(", ") + (findings.length > max ? ` и ещё ${findings.length - max}` : "");
}
