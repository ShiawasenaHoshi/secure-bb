// What an approval SESSION covers, in one table. A session (opened with a fresh code or touch, 15 minutes sliding, one hour at most) stands in for the code on
// ROUTINE actions only; everything else asks for a fresh factor every time. The guard decides with `isRoutineAction`, its description of «Открыть сессию»
// and the page's paragraph about the session are built from `SESSION_RULES`, and the plugin's table of RPCs (`RPC_AUTH`) is checked against it
// (test/session-rules.test.ts). A new routine action is one row here; the text and the check follow.

/** An idle session ends this long after its last use; any session ends at the ceiling. The guard keeps them, the plugin only shows them. */
export const SESSION_IDLE_MS = 15 * 60_000;
export const SESSION_CAP_MS = 60 * 60_000;

/** `touch` purposes of the plugin's own routine actions (the guard only checks the factor; the plugin does the thing). */
const ROUTINE_PURPOSES = ["watch.accept", "watch.acceptAll", "watch.rollback", "watch.window.open", "skills.approve"] as const;
export const ROUTINE_TOUCH_PURPOSES: ReadonlySet<string> = new Set(ROUTINE_PURPOSES);

export interface SessionRule {
  id: string;
  /** Covered by a session (true) or always a fresh factor (false). */
  routine: boolean;
  /** The words the paragraphs use; rules with the same label are told once. Null: not told (a catch-all). */
  label: string | null;
  /** The plugin's RPCs this routine rule stands for (`RPC_AUTH` group "routine" is exactly the union of these). */
  rpcs: string[];
  /** The guard action, as the guard normalizes it. */
  match: (a: Record<string, unknown>) => boolean;
  /** For the test: an action this rule matches. */
  example: Record<string, unknown>;
}
/** In order: the first rule that matches decides. */
export const SESSION_RULES: readonly SessionRule[] = [
  { id: "approve-block", routine: false, label: "снятие блока проверок", rpcs: [], match: (a) => a.op === "approve" && a.acknowledgeBlock === true, example: { op: "approve", requestId: 1, acknowledgeBlock: true } },
  { id: "approve", routine: true, label: "одобрить версию", rpcs: ["queue.approve"], match: (a) => a.op === "approve", example: { op: "approve", requestId: 1 } },
  // A window while the agents' settings are under a critical alarm is never routine: a fresh touch, with the warning in the description.
  { id: "window-alarm", routine: false, label: "окно доверия при критичной тревоге по настройкам агентов", rpcs: [], match: (a) => a.op === "open-window" && a.alarm === true, example: { op: "open-window", pluginId: "p", alarm: true } },
  { id: "window", routine: true, label: "открыть окно", rpcs: ["window.open"], match: (a) => a.op === "open-window", example: { op: "open-window", pluginId: "p" } },
  { id: "batch", routine: true, label: "пакет", rpcs: ["batch.approve"], match: (a) => a.op === "batch-approve", example: { op: "batch-approve", batchId: "b", setHash: "h" } },
  { id: "routine-touch", routine: true, label: "принять расхождение, одобрить скилл", rpcs: [...ROUTINE_PURPOSES], match: (a) => a.op === "touch" && typeof a.purpose === "string" && ROUTINE_TOUCH_PURPOSES.has(a.purpose), example: { op: "touch", purpose: "watch.accept" } },
  // Keeping a part of a settings file that does not make the agent more dangerous (the guard has checked the flag itself): routine. A dangerous one: never.
  { id: "keep-part", routine: true, label: "оставить безопасную часть настроек агента", rpcs: ["agents.keepPart"], match: (a) => a.op === "agents-keep-part" && a.danger === false, example: { op: "agents-keep-part", danger: false } },
  { id: "keep-part-danger", routine: false, label: "критичные настройки агентов", rpcs: [], match: (a) => a.op === "agents-keep-part", example: { op: "agents-keep-part", danger: true } },
  { id: "approve-trust", routine: false, label: "добавление источника", rpcs: [], match: (a) => a.op === "approve-trust" || a.op === "sources-add", example: { op: "approve-trust", requestId: 1 } },
  { id: "trust-mode", routine: false, label: "ослабление режима", rpcs: [], match: (a) => a.op === "trust-mode", example: { op: "trust-mode", mode: "simple" } },
  { id: "policy", routine: false, label: "расширение политики", rpcs: [], match: (a) => a.op === "policy", example: { op: "policy", patch: { capMin: 480 } } },
  { id: "session", routine: false, label: "сама сессия", rpcs: [], match: (a) => a.op === "session-open", example: { op: "session-open" } },
  // Everything else — another touch purpose, accepting agent files, restoring, a passkey, a source — a fresh factor, whatever it is.
  { id: "other", routine: false, label: null, rpcs: [], match: () => true, example: { op: "agents-accept", ids: [1] } },
];

/** Does a session cover this action? Routine ones only: lifting a block, widening, trusting a source, the session itself — never. */
export function isRoutineAction(a: Record<string, unknown>): boolean {
  return SESSION_RULES.find((r) => r.match(a))?.routine ?? false;
}

/** The words of the two lists, each label once, in table order. */
export function sessionCoverage(): { routine: string[]; fresh: string[] } {
  const pick = (routine: boolean): string[] => [...new Set(SESSION_RULES.filter((r) => r.routine === routine && r.label !== null).map((r) => r.label as string))];
  return { routine: pick(true), fresh: pick(false) };
}
/** «15 минут» / «час»: the length of a session in words, from the constants (accusative: «на час»). */
export const minutesWords = (ms: number): string => (ms === 3_600_000 ? "час" : `${ms / 60_000} минут`);
/** The same after «не дольше» (genitive: «часа»). */
export const minutesWordsUpTo = (ms: number): string => (ms === 3_600_000 ? "часа" : `${ms / 60_000} минут`);
