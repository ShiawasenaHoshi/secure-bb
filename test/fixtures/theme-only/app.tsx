import { useRef } from "react";

// A theme: its own markup and styles. The `ref` is its own file picker: nothing of bb's page is looked up or pressed.
export default function Theme() {
  const picker = useRef<HTMLInputElement>(null);
  return (
    <div style={{ background: "#1e1e2e", color: "#cdd6f4" }}>
      <input ref={picker} type="file" hidden />
      <button onClick={() => picker.current?.click()}>Choose a picture</button>
    </div>
  );
}
