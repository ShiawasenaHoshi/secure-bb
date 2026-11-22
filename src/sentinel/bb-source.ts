// The sentinel's window onto bb: real SDK calls only (`threads.events.list`, `threads.interactions.get`).
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import type { ThreadTree } from "../thread-tree.js";
import { humanTaskFromEvents, pendingActionFromEvents } from "./state.js";
import type { SentinelSource } from "./sentinel.js";

type Sdk = BbPluginApi["sdk"];

export function bbSentinelSource(sdk: Sdk, tree: ThreadTree): SentinelSource {
  const taskOf = async (threadId: string): Promise<string | null> => {
    const rows = await sdk.threads.events.list({
      threadId,
      types: ["client/thread/start", "client/turn/requested"] as unknown as [never, ...never[]],
      order: "asc",
      limit: "20",
    });
    return humanTaskFromEvents(rows.map((r) => ({ type: String(r.type), data: r.data })));
  };
  return {
    // A sub-thread's own first message is the parent agent's; the human's request is found up the tree.
    async task(threadId) {
      const own = await taskOf(threadId);
      if (own !== null) return own;
      for (const id of await tree.ancestors(threadId)) {
        const found = await taskOf(id).catch(() => null);
        if (found !== null) return found;
      }
      return null;
    },
    async pending(threadId) {
      const rows = await sdk.threads.events.list({ threadId, types: ["item/started"] as unknown as [never, ...never[]], order: "desc", limit: "10" });
      return pendingActionFromEvents(rows.map((r) => ({ type: String(r.type), data: r.data })));
    },
    async card(threadId, interactionId) {
      try {
        const i = (await sdk.threads.interactions.get({ threadId, interactionId })) as unknown as { status?: string; resolution?: { decision?: string } | null };
        return { status: String(i.status), decision: i.resolution?.decision ?? null };
      } catch (err) {
        if (/not.?found|404/i.test(String(err))) return null;
        throw err;
      }
    },
  };
}
