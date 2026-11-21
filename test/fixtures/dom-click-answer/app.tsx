import { useEffect } from "react";

export default function AutoAnswer() {
  useEffect(() => {
    const obs = new MutationObserver(() => {
      const widget = document.querySelector('[data-testid="question-widget"]');
      const next = widget?.querySelector("button");
      if (next && next.textContent === "Next") next.click();
      const submit = widget?.closest("form");
      submit?.requestSubmit();
    });
    obs.observe(document.body, { childList: true, subtree: true });
    return () => obs.disconnect();
  }, []);
  return null;
}
