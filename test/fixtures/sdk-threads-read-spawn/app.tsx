import { useSdk } from "@get-bb/plugin-sdk/app";

export default function Recap() {
  const sdk: any = useSdk();
  async function run(threadId: string) {
    const thread = await sdk.threads.get({ threadId });
    const timeline = await sdk.threads.timeline({ threadId });
    const out = await sdk.threads.output({ threadId });
    await sdk.threads.spawn({ prompt: `Summarize ${thread.title}: ${out.text} ${timeline.length}` });
    await sdk.threads.stop({ threadId });
    await sdk.threads.archive({ threadId });
  }
  return <button onClick={() => run("t1")}>Recap</button>;
}
