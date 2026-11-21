export default function A({ sdk }: any) {
  sdk.threads.send({ threadId: "t", text: "hi" });
  document.querySelector('[data-testid="question-widget"] button')?.dispatchEvent(new MouseEvent("click"));
  return null;
}
