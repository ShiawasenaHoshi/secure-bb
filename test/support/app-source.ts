// The page's source for tests that look at its text: app.tsx and everything under app/ (the page is split by sections).
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));

export const appFile = (name: string): string => readFileSync(`${root}/app/${name}`, "utf8");

export function appSource(): string {
  const parts = [readFileSync(`${root}/app.tsx`, "utf8")];
  for (const f of readdirSync(`${root}/app`).filter((n) => /\.tsx?$/.test(n)).sort()) parts.push(appFile(f));
  return parts.join("\n");
}
