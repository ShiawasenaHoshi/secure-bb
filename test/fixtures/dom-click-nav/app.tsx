// Opens the thread the notification is about: a click on its row in the sidebar.
export function openThread(threadId: string): void {
  const row = document.querySelector<HTMLElement>(`[data-sidebar-thread-id="${CSS.escape(threadId)}"]`);
  if (row !== null) row.click();
}
export default function N() {
  return <button onClick={() => openThread("t1")}>Open</button>;
}
