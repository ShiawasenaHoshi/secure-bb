import type { BbPluginApi } from "@get-bb/plugin-sdk";
export default function (bb: BbPluginApi): void {
  bb.events.on("thread.idle", (e) => {
    bb.log.info(String(e.lastAssistantText));
  });
}
