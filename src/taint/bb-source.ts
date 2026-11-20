// The pollution tracker's window onto bb: thread events and thread -> project, real SDK calls only.
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { NotApplicableError } from "../watch/collect.js";
import { TAINT_EVENT_TYPES, type EventLike } from "./classify.js";
import type { TaintSource } from "./monitor.js";

type Sdk = BbPluginApi["sdk"];

export function bbTaintSource(sdk: Sdk, envSetup: (projectId: string) => Promise<string | null>): TaintSource {
  return {
    async events(threadId, afterSeq, limit): Promise<EventLike[]> {
      const rows = await sdk.threads.events.list({
        threadId,
        types: [...TAINT_EVENT_TYPES] as unknown as [never, ...never[]],
        order: "asc",
        limit: String(limit),
        ...(afterSeq !== null ? { afterSeq: String(afterSeq) } : {}),
      });
      return rows.map((r) => ({ seq: Number(r.seq), createdAt: Number(r.createdAt), type: String(r.type), data: r.data }));
    },
    async projectOf(threadId) {
      const t = (await sdk.threads.get({ threadId })) as unknown as { projectId?: string | null };
      return t.projectId ?? null;
    },
    async hasEnvSetup(projectId) {
      try {
        return (await envSetup(projectId)) !== null;
      } catch (err) {
        if (err instanceof NotApplicableError) return false; // no local folder: the file cannot exist
        throw err;
      }
    },
  };
}
