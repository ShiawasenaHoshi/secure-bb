import { readFileSync } from "node:fs";
import os from "node:os";
export const accounts = () => JSON.parse(readFileSync(os.homedir() + "/.gemini/google_accounts.json", "utf8"));
