// RPC schemas with `output` keys, thread events and metadata calls only: nothing here reads what is written in a conversation.
export default function (bb: any): void {
  const z: any = { object: (x: unknown) => x };
  const schemas = {
    state: { input: z.object({}), output: z.object({ muted: z.boolean() }) },
    test: { output: z.object({ ok: z.boolean() }) },
  };
  for (const name of ["thread.active", "thread.idle", "thread.failed", "thread.archived", "thread.deleted"]) {
    bb.events.on(name, async (e: any) => {
      const t = await bb.sdk.threads.get({ threadId: e.thread.id });
      const asked = await bb.sdk.threads.interactions.list({ threadId: e.thread.id });
      bb.log.info(String(t.title), String(asked.length), JSON.stringify(schemas));
    });
  }
}
