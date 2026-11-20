// RPC contract shared by server.ts and app.tsx (the app imports only its type).
import { defineRpcContract } from "@get-bb/plugin-sdk";
import type { Overview } from "./overview.js";
import * as s from "./schema.js";

const code = s.string({ min: 1, max: 16 });
const id = s.integer({ min: 1 });

export const rpcContract = defineRpcContract({
  overview: { input: s.nullValue(), output: s.json<Overview>() },
  "page.ping": { input: s.nullValue(), output: s.json<{ ok: true }>() },
  "totp.begin": {
    input: s.nullValue(),
    output: s.json<{ secret: string; uri: string; matrix: boolean[][] }>(),
  },
  "totp.confirm": { input: s.object({ code }), output: s.json<{ ok: true }>() },
  "queue.approve": { input: s.object({ id, code, acknowledgeBlock: s.optional(s.boolean()) }), output: s.json<{ ok: true; note: string }>() },
  "queue.dismiss": { input: s.object({ id, code }), output: s.json<{ ok: true }>() },
  "window.open": {
    input: s.object({ queueId: id, code, scope: s.optional(s.oneOf(["tree", "thread"] as const)) }),
    output: s.json<{ ok: true }>(),
  },
  "window.close": { input: s.object({ windowId: id, code }), output: s.json<{ ok: true }>() },
  "approval.revoke": { input: s.object({ approvalId: id, code }), output: s.json<{ ok: true }>() },
  "watch.scan": { input: s.nullValue(), output: s.json<{ ok: true }>() },
  "watch.acceptAll": { input: s.object({ code }), output: s.json<{ ok: true; items: number }>() },
  "watch.accept": { input: s.object({ id, code }), output: s.json<{ ok: true }>() },
  "watch.rollback": { input: s.object({ id, code }), output: s.json<{ ok: true }>() },
  "watch.rollbackMode": { input: s.object({ enabled: s.boolean(), code }), output: s.json<{ ok: true }>() },
  "watch.window.open": { input: s.object({ scopes: s.array(s.string({ max: 32 }), { max: 16 }), code }), output: s.json<{ ok: true }>() },
  "watch.window.close": { input: s.object({ windowId: id, code }), output: s.json<{ ok: true }>() },
  "policy.set": {
    input: s.object({
      windowMin: s.optional(s.integer({ min: 1, max: 1440 })),
      capMin: s.optional(s.integer({ min: 1, max: 1440 })),
      mode: s.optional(s.oneOf(["sliding", "fixed"] as const)),
      scope: s.optional(s.oneOf(["tree", "thread"] as const)),
      cfgWindowMin: s.optional(s.integer({ min: 1, max: 1440 })),
      cfgCapMin: s.optional(s.integer({ min: 1, max: 1440 })),
      cfgMode: s.optional(s.oneOf(["sliding", "fixed"] as const)),
      code: s.optional(code),
    }),
    output: s.json<{ ok: true }>(),
  },
});
