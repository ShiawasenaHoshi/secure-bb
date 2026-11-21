export default function (bb: any): void {
  const sdk = bb.sdk;
  const names = new Map<string, string>();
  bb.events.on("thread.active", async (e: any) => {
    const t = await sdk.threads.get({ threadId: e.thread.id });
    names.set(t.id, t.title);
  });
  bb.events.on("thread.idle", () => {});
  bb.events.on("thread.failed", () => {});
  setInterval(() => sdk.threads.interactions.list({ threadId: "x" }), 5000);
}
