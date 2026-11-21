// RPC contract shared by server.ts and app.tsx (the app imports only its type).
import { defineRpcContract } from "@get-bb/plugin-sdk";
import type { AgentsView } from "./agents.js";
import type { BatchPrepared, BatchResult } from "./batch.js";
import type { GuardJournalReport, GuardChallenge } from "./guardlink.js";
import type { JournalReport } from "./journal.js";
import type { Overview } from "./overview.js";
import * as s from "./schema.js";

const code = s.string({ min: 1, max: 16 });
/** A passkey touch, as the browser returns it (base64url). The guard checks it; only the sizes are bounded here. */
const passkey = s.optional(s.object({ credentialId: s.string({ min: 1, max: 1400 }), clientDataJSON: s.string({ min: 1, max: 4096 }), authenticatorData: s.string({ min: 1, max: 2048 }), signature: s.string({ min: 1, max: 512 }) }));
/** A code or, in guard mode, a passkey touch (one of the two; the guard takes the passkey when both come). */
const factor = { code: s.optional(code), passkey };
const id = s.integer({ min: 1 });
/** A queue id: negative = a proposal the core has not asked the guard about yet (guard mode). */
const queueId = s.integer({ min: -1_000_000_000 });
/** Routine RPCs take a fresh code or the token of an open approval session (src/approval.ts says which RPC is routine). */
const proof = { ...factor, session: s.optional(s.string({ min: 1, max: 128 })) };
/** `needed: false`: this change needs no touch (it only narrows). */
export type PasskeyChallengeResult = ({ needed: true } & GuardChallenge) | { needed: false };
const batchKind = s.oneOf(["queue", "skill", "drift"] as const);

export const rpcContract = defineRpcContract({
  overview: { input: s.nullValue(), output: s.json<Overview>() },
  "journal.verify": { input: s.nullValue(), output: s.json<JournalReport>() },
  "guard.verify": { input: s.nullValue(), output: s.json<GuardJournalReport | { error: string }>() },
  "approvals.export": { input: s.object({ ...factor }), output: s.json<{ path: string; digest: string; count: number }>() },
  "trusted.set": { input: s.object({ add: s.optional(s.string({ min: 1, max: 140 })), remove: s.optional(s.string({ min: 1, max: 140 })), ...factor }), output: s.json<{ ok: true; repos: string[] }>() },
  "session.open": { input: s.object({ code }), output: s.json<{ token: string; idleMs: number; capMs: number }>() },
  "session.close": { input: s.nullValue(), output: s.json<{ ok: true }>() },
  "batch.prepare": { input: s.object({ items: s.array(s.object({ kind: batchKind, id }), { max: 50 }) }), output: s.json<BatchPrepared>() },
  "batch.approve": { input: s.object({ batchId: s.string({ min: 1, max: 64 }), setHash: s.string({ min: 64, max: 64 }), ...proof }), output: s.json<{ ok: true; results: BatchResult[] }>() },
  "page.ping": { input: s.nullValue(), output: s.json<{ ok: true }>() },
  "totp.begin": {
    input: s.nullValue(),
    output: s.json<{ secret: string; uri: string; matrix: boolean[][] }>(),
  },
  "totp.confirm": { input: s.object({ code }), output: s.json<{ ok: true }>() },
  // Guard mode: a challenge bound to one action (the guard describes it in its own words), and registering a key (token from the console).
  "passkey.challenge": {
    input: s.object({
      kind: s.oneOf(["approve", "window.open", "policy", "touch", "agents.accept"] as const),
      ids: s.optional(s.array(id, { max: 2000 })),
      queueId: s.optional(queueId),
      scope: s.optional(s.oneOf(["tree", "thread"] as const)),
      purpose: s.optional(s.string({ min: 1, max: 80 })),
      acknowledgeBlock: s.optional(s.boolean()),
      windowMin: s.optional(s.integer({ min: 1, max: 1440 })),
      capMin: s.optional(s.integer({ min: 1, max: 1440 })),
      mode: s.optional(s.oneOf(["sliding", "fixed"] as const)),
      cfgWindowMin: s.optional(s.integer({ min: 1, max: 1440 })),
      cfgCapMin: s.optional(s.integer({ min: 1, max: 1440 })),
      cfgMode: s.optional(s.oneOf(["sliding", "fixed"] as const)),
      autoSafe: s.optional(s.boolean()),
    }),
    output: s.json<PasskeyChallengeResult>(),
  },
  "passkey.register": {
    input: s.object({ token: s.string({ min: 1, max: 64 }), clientDataJSON: s.optional(s.string({ min: 1, max: 4096 })), attestationObject: s.optional(s.string({ min: 1, max: 8192 })) }),
    output: s.json<Record<string, unknown>>(),
  },
  "queue.approve": { input: s.object({ id: queueId, ...proof, acknowledgeBlock: s.optional(s.boolean()) }), output: s.json<{ ok: true; note: string }>() },
  "queue.dismiss": { input: s.object({ id: queueId }), output: s.json<{ ok: true }>() },
  "window.open": {
    input: s.object({ queueId: id, ...proof, scope: s.optional(s.oneOf(["tree", "thread"] as const)) }),
    output: s.json<{ ok: true }>(),
  },
  "window.close": { input: s.object({ windowId: id }), output: s.json<{ ok: true }>() },
  "approval.revoke": { input: s.object({ approvalId: id }), output: s.json<{ ok: true }>() },
  // Agent watch (guard mode): a scan on request (the guard serves one at most every 10 s), and accepting differences into the baseline: a touch for exactly these ids.
  "agents.scan": { input: s.nullValue(), output: s.json<AgentsView>() },
  "agents.accept": { input: s.object({ ids: s.array(id, { max: 2000 }), ...factor }), output: s.json<{ ok: true; accepted: number; note: string }>() },
  "watch.scan": { input: s.nullValue(), output: s.json<{ ok: true }>() },
  "watch.acceptAll": { input: s.object({ ...proof }), output: s.json<{ ok: true; items: number }>() },
  "watch.accept": { input: s.object({ id, ...proof }), output: s.json<{ ok: true }>() },
  "watch.rollback": { input: s.object({ id, ...proof }), output: s.json<{ ok: true }>() },
  "watch.rollbackMode": { input: s.object({ enabled: s.boolean(), ...factor }), output: s.json<{ ok: true }>() },
  "watch.window.open": { input: s.object({ scopes: s.array(s.string({ max: 32 }), { max: 16 }), ...proof }), output: s.json<{ ok: true }>() },
  "watch.window.close": { input: s.object({ windowId: id }), output: s.json<{ ok: true }>() },
  "skills.scan": { input: s.nullValue(), output: s.json<{ ok: true }>() },
  "skills.approve": { input: s.object({ id, ...proof, acknowledgeBlock: s.optional(s.boolean()) }), output: s.json<{ ok: true; note: string }>() },
  "skills.remove": { input: s.object({ id }), output: s.json<{ ok: true }>() },
  "skills.removed": { input: s.object({ id }), output: s.json<Array<{ path: string; content: string | null }>>() },
  "skills.trusted": { input: s.object({ add: s.optional(s.string({ min: 1, max: 140 })), remove: s.optional(s.string({ min: 1, max: 140 })), ...factor }), output: s.json<{ ok: true; sources: string[] }>() },
  "ai.settings": {
    input: s.object({
      enabled: s.optional(s.boolean()),
      autoFreeze: s.optional(s.boolean()),
      autoExternal: s.optional(s.boolean()),
      second: s.optional(s.boolean()),
      secondModel: s.optional(s.string({ max: 64 })),
      freezePlugin: s.optional(s.object({ id: s.string({ min: 1, max: 128 }), on: s.boolean() })),
      ...factor,
    }),
    output: s.json<{ ok: true }>(),
  },
  "ai.scan": {
    input: s.object({ pluginId: s.optional(s.string({ min: 1, max: 128 })), queueId: s.optional(id) }),
    output: s.json<{ ok: true; scan: number; status: string }>(),
  },
  "publish.settings": {
    input: s.object({
      enabled: s.optional(s.boolean()),
      repoUrl: s.optional(s.string({ max: 300 })),
      branch: s.optional(s.string({ max: 100 })),
      onApprove: s.optional(s.boolean()),
      ...factor,
    }),
    output: s.json<{ ok: true }>(),
  },
  "publish.run": { input: s.object({ pluginId: s.string({ min: 1, max: 128 }) }), output: s.json<{ ok: true; status: string; note: string }>() },
  "sentinel.settings": {
    input: s.object({
      provider: s.optional(s.oneOf(["typesafe", "openrouter"] as const)),
      enabled: s.optional(s.boolean()),
      allThreads: s.optional(s.boolean()),
      timeoutMs: s.optional(s.integer({ min: 1000, max: 60000 })),
      maxPerMinute: s.optional(s.integer({ min: 1, max: 600 })),
      riskThreshold: s.optional(s.number({ min: 0, max: 2 })),
      threshold: s.optional(s.object({ id: s.string({ min: 1, max: 40 }), value: s.number({ min: 0, max: 1 }) })),
      instruction: s.optional(s.object({ id: s.string({ min: 1, max: 40 }), text: s.string({ max: 2000 }) })),
      ...factor,
    }),
    output: s.json<{ ok: true }>(),
  },
  "policy.set": {
    input: s.object({
      windowMin: s.optional(s.integer({ min: 1, max: 1440 })),
      capMin: s.optional(s.integer({ min: 1, max: 1440 })),
      mode: s.optional(s.oneOf(["sliding", "fixed"] as const)),
      scope: s.optional(s.oneOf(["tree", "thread"] as const)),
      cfgWindowMin: s.optional(s.integer({ min: 1, max: 1440 })),
      cfgCapMin: s.optional(s.integer({ min: 1, max: 1440 })),
      cfgMode: s.optional(s.oneOf(["sliding", "fixed"] as const)),
      autoSafe: s.optional(s.boolean()),
      ...factor,
    }),
    output: s.json<{ ok: true }>(),
  },
});
