import { title } from "../../packages/shared/index.ts";
export default function (bb: any): void {
  const z: any = {};
  const rpc = { status: { output: z.object({ ok: z.boolean() }) } };
  for (const ev of ["thread.idle", "thread.failed"]) {
    bb.events.on(ev, async (e: any) => {
      const t = await bb.sdk.threads.get({ threadId: e.thread.id });
      bb.log.info(title(t), JSON.stringify(rpc));
    });
  }
}
