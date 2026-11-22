// The words the flow analysis speaks in (where a thing read goes, and what we make of it): types only, no analyzer. A leaf module, so that `types.ts` (the result of the
// checks) and `flow.ts` (the analysis) need not import each other.

export type SourceKind = "threads" | "questions" | "env" | "credentials" | "files";
export type SinkKind = "network" | "process" | "file" | "send" | "settings" | "notify" | "sound" | "ui" | "route" | "log" | "store" | "unknown";
/**
 * nowhere — no path from the source to any sink was found, and the analysis saw the whole code.
 * shown   — it reaches only what is shown to the person (a notification, a sound, the plugin's own page, a log).
 * kept    — it reaches only the plugin's own storage.
 * leaves  — it reaches a dangerous sink: the network, another program, a file outside, a message in the person's name.
 * unknown — the analysis could not tell (a library, a computed call, dynamic code, a limit).
 */
export type Verdict = "nowhere" | "shown" | "kept" | "leaves" | "unknown";

export interface FlowSink {
  kind: SinkKind;
  /** Only the choice reaches it: what is sent, to where, or whether at all depends on what was read (a branch, a comparison, a length, a delay), though the content itself is not in it. */
  choice?: boolean;
  /** The host, the program, the path, the call: what the code names. */
  target?: string;
  file: string;
  line: number;
}
export interface FlowSummary {
  source: SourceKind;
  /** Environment variable names, whose credentials: what the source is, concretely. */
  detail: string[];
  verdict: Verdict;
  /** The sinks it reaches (a few, dangerous first). Empty for «nowhere». */
  sinks: FlowSink[];
  /** For «unknown»: why. */
  why?: string;
}
/** «Зачем» by the pair access → sink (second step): one short sentence, deterministic. */
export interface Purpose {
  /** The capability kinds whose line it belongs to. */
  on: string[];
  text: string;
  /** The pair it comes from (`thread.idle → sound`). */
  pair: string;
}
