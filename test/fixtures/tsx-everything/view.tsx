import { useState } from 'react';
enum Mode { A, B }
export function View<T>({ items }: { items: T[] }) {
  const [m, setM] = useState<Mode>(Mode.A);
  const pick = <K extends keyof T>(k: K) => items.map((i) => i[k]);
  return <ul onClick={() => fetch('https://tsx.example/y')}>{pick('a' as never).length}</ul>;
}
