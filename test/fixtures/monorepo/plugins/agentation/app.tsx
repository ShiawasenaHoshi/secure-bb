export default function A({ sdk }: any) {
  sdk.threads.send({ threadId: "t", text: "hi" });
  return null;
}
