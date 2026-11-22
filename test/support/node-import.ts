// A fixture for test/browser-build.test.ts: a module that reaches Node, to see that the browser build notices.
import { createHash } from "node:crypto";

export const digest = (s: string): string => createHash("sha256").update(s).digest("hex");
